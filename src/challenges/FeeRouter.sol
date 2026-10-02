// SPDX-License-Identifier: MIT
// Vulnerable fee router (real incident class: unprotected fee sweep).
//
// FeeToken sends 1% of every transfer to FeeRouter, which records it in a
// per-token ledger. The treasury is meant to sweep the ledger periodically.
//
// BUG: `sweepFees` was specified as `onlyTreasury`, but the access-control
// check was never applied — the function body ships with no guard at all.
// Any address sweeps the entire accumulated fee balance to any recipient.
// This is the exact "value pooled in a fee faucet anyone can sweep" class
// the curiosity engine asks about on live targets.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

contract FeeRouter {
    ERC20Mintable public immutable feeToken;
    address public treasury;

    // Per-recipient fee accounting (records every fee the router receives).
    mapping(address => uint256) public feeCredit;

    event FeesSwept(address indexed caller, address indexed to, uint256 amount);
    event FeeRecorded(address indexed from, uint256 amount);

    error SweepFailed();

    constructor(address _feeToken, address _treasury) {
        feeToken = ERC20Mintable(_feeToken);
        treasury = _treasury;
    }

    // FeeToken calls this on every transfer (1% of the moved amount).
    // Anyone may notify the router of incoming fees — accounting only.
    function recordFee(address from, uint256 amount) external {
        feeCredit[from] += amount;
        emit FeeRecorded(from, amount);
    }

    // Intended: only treasury, and only to the treasury.
    // BUG: no guard, arbitrary destination.
    function sweepFees(address to) external {
        uint256 amount = feeToken.balanceOf(address(this));
        if (amount == 0) revert SweepFailed();
        feeToken.transfer(to, amount);
        emit FeesSwept(msg.sender, to, amount);
    }

    function setTreasury(address _treasury) external {
        require(msg.sender == treasury, "only treasury");
        treasury = _treasury;
    }
}
