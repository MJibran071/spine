// SPDX-License-Identifier: MIT
// Vulnerable flash-lending pool (Damn Vulnerable DeFi-style).
// BUG: flashLoan trusts the callback; a reentrant deposit() re-inflates
// address(this).balance so the final balance check passes while deposits
// stay on the books.
pragma solidity ^0.8.0;

import {ISideEntranceLenderPool} from "../interfaces/ISideEntranceLenderPool.sol";
import {IFlashLoanEtherReceiver} from "../interfaces/IFreeRiderPool.sol";

contract SideEntranceLenderPool is ISideEntranceLenderPool {
    mapping(address => uint256) public deposits;

    error RepayFailed();

    constructor() {
        deposits[address(this)] = type(uint256).max;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;
        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

        if (address(this).balance < balanceBefore) {
            revert RepayFailed();
        }
    }
}
