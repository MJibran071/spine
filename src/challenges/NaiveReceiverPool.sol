// SPDX-License-Identifier: MIT
// Vulnerable flash-lending pool (Damn Vulnerable DeFi-style), native ETH.
// BUG 1 (grief): flashLoan lets the CALLER choose the borrower, so anyone can
// force a victim contract to pay the 1-ETH fixed fee, taken from its credit.
// BUG 2 (drain): withdraw() checks the POOL's total deposits instead of the
// caller's own credit — one wei of credit authorizes draining everything.
pragma solidity ^0.8.0;

import {INaiveReceiverPool} from "../interfaces/INaiveReceiverPool.sol";

interface IFlashLoanReceiver {
    function receiveEther(uint256 fee) external payable;
}

contract NaiveReceiverPool is INaiveReceiverPool {
    uint256 public constant FIXED_FEE = 1 ether;

    mapping(address => uint256) private deposits;
    uint256 public totalDeposits;

    error BorrowerCannotBePool();
    error RepayFailed();
    error InsufficientBalance();

    constructor() {}

    function deposit() external payable override {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount, address payable receiver) external override {
        // BUG: solvency is checked against the POOL's total deposits, not the
        // caller's own credit.
        if (amount > totalDeposits) {
            revert InsufficientBalance();
        }

        (bool ok, ) = receiver.call{value: amount}("");
        require(ok, "transfer failed");

        // Only the caller's credit is cleared — the books no longer add up.
        deposits[msg.sender] = 0;
        totalDeposits -= amount;
    }

    function flashLoan(address borrower, uint256 borrowAmount) external override {
        if (borrower == address(this)) {
            revert BorrowerCannotBePool();
        }

        uint256 balanceBefore = address(this).balance;
        IFlashLoanReceiver(borrower).receiveEther{value: borrowAmount}(FIXED_FEE);

        if (address(this).balance < balanceBefore + FIXED_FEE) {
            revert RepayFailed();
        }

        // BUG: the caller names the borrower — the fee comes out of the
        // borrower's credit whether or not they asked for a loan.
        deposits[address(this)] += FIXED_FEE;
        deposits[borrower] -= FIXED_FEE;
        totalDeposits += FIXED_FEE;
    }

    function depositsOf(address user) external view returns (uint256) {
        return deposits[user];
    }

    receive() external payable {}
}
