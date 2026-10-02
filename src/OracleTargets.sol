// SPDX-License-Identifier: MIT
// Target contracts for the oracle-manipulation repro:
//   - SpotLender      : reads the pair's raw reserve ratio (VULNERABLE — the
//                       pattern the "oracle-manipulation +probe(oracle-spot)"
//                       signals flag)
//   - TwapGuardLender : consumes the same pair through the TWAP accumulator
//                       plus a spot/TWAP deviation guard (the defense)
pragma solidity ^0.8.0;

import {ERC20Mintable} from "src/tokens/ERC20Mintable.sol";
import {IUniswapV2PairLocal} from "src/interfaces/IUniswapV2PairLocal.sol";

abstract contract BaseLender {
    ERC20Mintable public immutable collateralToken; // token0 of the pair
    ERC20Mintable public immutable borrowToken;     // token1 of the pair
    IUniswapV2PairLocal public immutable pool;
    mapping(address => uint256) public collateralBalance;

    event Borrowed(address indexed account, uint256 price, uint256 amount);

    constructor(address _collateral, address _borrow, address _pool) {
        collateralToken = ERC20Mintable(_collateral);
        borrowToken = ERC20Mintable(_borrow);
        pool = IUniswapV2PairLocal(_pool);
    }

    function depositCollateral(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateralBalance[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 price = _price(); // 1e18-scaled: borrowToken per collateralToken
        uint256 value = collateralBalance[msg.sender] * price / 1e18;
        require(value >= amount, "insufficient collateral");
        borrowToken.transfer(msg.sender, amount);
        emit Borrowed(msg.sender, price, amount);
    }

    function _price() internal virtual returns (uint256);
}

// DANGEROUS: reserve-derived spot price, no TWAP / delay / deviation guard.
// A single large trade moves this price inside one transaction.
contract SpotLender is BaseLender {
    constructor(address _collateral, address _borrow, address _pool)
        BaseLender(_collateral, _borrow, _pool)
    {}

    function _price() internal override returns (uint256) {
        (uint112 r0, uint112 r1, ) = pool.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);
    }
}

// DEFENSE: 30-minute TWAP from the pair's cumulative-price accumulator plus a
// hard spot-vs-TWAP deviation guard. The TWAP checkpoint is taken in the
// constructor (cumulatives only advance on sync, so they are extended to
// `now` with the current spot, exactly like Uniswap's example oracle).
contract TwapGuardLender is BaseLender {
    uint256 public constant WINDOW = 30 minutes;
    uint256 public constant MAX_DEVIATION = 0.05e18; // 5%

    uint256 private checkpointCum;   // UQ112x112 cumulative at checkpointTs
    uint256 private checkpointTs;
    uint256 public lastTwapPrice;

    constructor(address _collateral, address _borrow, address _pool)
        BaseLender(_collateral, _borrow, _pool)
    {
        checkpointCum = _cumulativeNow();
        checkpointTs = block.timestamp;
    }

    function _cumulativeNow() internal view returns (uint256) {
        (uint112 r0, uint112 r1, uint32 tsLast) = pool.getReserves();
        uint256 now32 = uint256(uint32(block.timestamp));
        uint256 elapsedPair = now32 >= uint256(tsLast)
            ? now32 - uint256(tsLast)
            : 2 ** 32 - uint256(tsLast) + now32;
        // token1 per token0 in UQ112x112
        uint256 uqSpot = (uint256(r1) << 112) / uint256(r0);
        return pool.price0CumulativeLast() + elapsedPair * uqSpot;
    }

    function _price() internal override returns (uint256) {
        uint256 cumNow = _cumulativeNow();
        uint256 elapsed = block.timestamp - checkpointTs;
        require(elapsed >= WINDOW, "oracle window too short");

        // Rescale UQ112x112 fixed point (1.0 == 2**112) to 1e18.
        uint256 twap = (cumNow - checkpointCum) * 1e18 / (elapsed * (1 << 112));

        // Rolling checkpoint: the next window starts here.
        checkpointCum = cumNow;
        checkpointTs = block.timestamp;
        lastTwapPrice = twap;

        // Deviation guard: reject if the spot ratio is being pushed away
        // from the TWAP right now (residual same-block manipulation).
        (uint112 s0, uint112 s1, ) = pool.getReserves();
        uint256 spot = (uint256(s1) * 1e18) / uint256(s0);
        uint256 dev = spot > twap ? spot - twap : twap - spot;
        require(dev * 1e18 / twap <= MAX_DEVIATION, "price deviation too high");
        return twap;
    }
}
