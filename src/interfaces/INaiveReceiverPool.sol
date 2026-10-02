// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface INaiveReceiverPool {
    function flashLoan(address borrower, uint256 borrowAmount) external;
    function deposit() external payable;
    function withdraw(uint256 amount, address payable receiver) external;
}
