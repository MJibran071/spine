// SPDX-License-Identifier: MIT
// Minimal Uniswap V2 pair clone for LOCAL security simulation only.
// Implements the parts of UniswapV2Pair that oracle-manipulation research
// depends on: getReserves (spot price), swap with 0.3% fee + K invariant,
// flash swaps (uniswapV2Call callback) and the cumulative-price TWAP
// accumulators (price0/1CumulativeLast).
pragma solidity ^0.8.0;

interface IERC20Pair {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IUniswapV2Callee {
    function uniswapV2Call(address sender, uint256 amount0Out, uint256 amount1Out, bytes calldata data) external;
}

contract UniswapV2PairLocal {
    address public immutable token0;
    address public immutable token1;

    uint112 private reserve0;
    uint112 private reserve1;
    uint32 private blockTimestampLast;

    // UQ112x112 cumulative prices (token1 per token0, and inverse), as in V2.
    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;

    uint256 public totalSupply; // LP bookkeeping (not used by the exploits)

    event Mint(address indexed to, uint256 amount);
    event Sync(uint112 reserve0, uint112 reserve1);

    constructor(address _token0, address _token1) {
        token0 = _token0;
        token1 = _token1;
    }

    function getReserves() public view returns (uint112, uint112, uint32) {
        return (reserve0, reserve1, blockTimestampLast);
    }

    function addLiquidity(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
        IERC20Pair(token0).transferFrom(msg.sender, address(this), amount0);
        IERC20Pair(token1).transferFrom(msg.sender, address(this), amount1);

        (uint112 r0, uint112 r1, ) = getReserves();
        uint256 balance0 = IERC20Pair(token0).balanceOf(address(this));
        uint256 balance1 = IERC20Pair(token1).balanceOf(address(this));

        liquidity = totalSupply == 0 ? _sqrt(balance0 * balance1) : (balance0 * totalSupply) / uint256(r0);
        totalSupply += liquidity;

        _update(balance0, balance1, r0, r1);
        emit Mint(msg.sender, liquidity);
    }

    // Same semantics as UniswapV2Pair.swap: 0.3% fee, K invariant, and a
    // flash-swap callback when `data` is non-empty. Note the balance checks
    // run against the reserves captured at entry — the property that makes
    // same-block spot manipulation researchable locally.
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
        require(amount0Out > 0 || amount1Out > 0, "INSUFFICIENT_OUTPUT_AMOUNT");
        (uint112 r0, uint112 r1, ) = getReserves();
        require(amount0Out < uint256(r0) && amount1Out < uint256(r1), "INSUFFICIENT_LIQUIDITY");
        require(to != token0 && to != token1, "INVALID_TO");

        if (amount0Out > 0) IERC20Pair(token0).transfer(to, amount0Out);
        if (amount1Out > 0) IERC20Pair(token1).transfer(to, amount1Out);
        if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);

        uint256 balance0 = IERC20Pair(token0).balanceOf(address(this));
        uint256 balance1 = IERC20Pair(token1).balanceOf(address(this));

        uint256 amount0In = balance0 > uint256(r0) - amount0Out ? balance0 - (uint256(r0) - amount0Out) : 0;
        uint256 amount1In = balance1 > uint256(r1) - amount1Out ? balance1 - (uint256(r1) - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, "INSUFFICIENT_INPUT_AMOUNT");

        uint256 balance0Adjusted = balance0 * 1000 - amount0In * 3;
        uint256 balance1Adjusted = balance1 * 1000 - amount1In * 3;
        require(balance0Adjusted * balance1Adjusted >= uint256(r0) * uint256(r1) * 1000 ** 2, "K");

        _update(balance0, balance1, r0, r1);
    }

    function _update(uint256 balance0, uint256 balance1, uint112 r0, uint112 r1) private {
        uint32 blockTimestamp = uint32(block.timestamp % 2 ** 32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired, as in V2
        if (timeElapsed > 0 && r0 != 0 && r1 != 0) {
            // Accumulate the PRE-trade reserves over the elapsed window,
            // exactly like UniswapV2Pair._update — using post-trade balances
            // here would let a single dump poison the TWAP history.
            price0CumulativeLast += _uqdiv(r1, r0) * timeElapsed;
            price1CumulativeLast += _uqdiv(r0, r1) * timeElapsed;
        }
        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = blockTimestamp;
        emit Sync(reserve0, reserve1);
    }

    // UQ112x112 encode(n) / d
    function _uqdiv(uint112 n, uint112 d) private pure returns (uint224) {
        return uint224((uint256(n) << 112) / d);
    }

    function _sqrt(uint256 y) private pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}
