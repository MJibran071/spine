// SPDX-License-Identifier: MIT
// Vulnerable merkle airdrop (real incident class: unbound recipient).
//
// BUG: the merkle leaf binds (index, amount) but NOT the account that owns
// the grant. Every claim's proof is a public on-chain artifact, and proofs
// are fully derivable from the public root + the published airdrop spec —
// so anyone can claim ANY unclaimed index to ANY recipient. The honest
// user's grant is drained by a stranger; the airdrop empties to the wrong
// wallets. (Real class: several 2022+ airdrops where leaf = keccak(index,
// amount) let bots frontrun every claim; the fix is binding
// keccak(abi.encode(account, index, amount)).)
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";

contract MerkleAirdrop {
    ERC20Mintable public immutable token;
    bytes32 public immutable merkleRoot;
    uint256 public immutable claimDeadline;

    mapping(uint256 => bool) public claimed; // index => already claimed

    event Claimed(uint256 indexed index, address indexed account, uint256 amount);

    error AlreadyClaimed();
    error InvalidProof();
    error ClaimWindowClosed();

    constructor(address _token, bytes32 _root, uint256 _deadline) {
        token = ERC20Mintable(_token);
        merkleRoot = _root;
        claimDeadline = _deadline;
    }

    // Leaf binds (index, amount) but NOT the account — the bug.
    function claim(uint256 index, address account, uint256 amount, bytes32[] calldata merkleProof) external {
        if (block.timestamp > claimDeadline) revert ClaimWindowClosed();
        if (claimed[index]) revert AlreadyClaimed();

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(index, amount))));
        if (!MerkleProof.verify(merkleProof, merkleRoot, leaf)) revert InvalidProof();

        claimed[index] = true;
        token.transfer(account, amount);
        emit Claimed(index, account, amount);
    }
}

library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = computedHash < proof[i]
                ? keccak256(bytes.concat(computedHash, proof[i]))
                : keccak256(bytes.concat(proof[i], computedHash));
        }
        return computedHash == root;
    }
}
