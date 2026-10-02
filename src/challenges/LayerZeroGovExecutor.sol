// SPDX-License-Identifier: MIT
// Vulnerable cross-chain GOVERNANCE executor (mark-but-never-check family,
// governance flavor — challenge #26).
//
// BUG 1 (proposal replay): executed[proposalHash] is written after every
//   execution but NO require(!executed[...]) gates it. The same captured
//   (srcChain, proposalId, payload) message re-executes the proposal as many
//   times as the attacker calls it — re-voting is impossible cross-chain, so
//   replaying a "transfer treasury" proposal empties it.
//
// BUG 2 (id/operation mismatch, #28): the executed key is the PROPOSAL ID
//   alone, not the full operation hash. Two proposals with the same id but
//   different payloads/targets collide: executing the honest one marks the
//   attacker's variant as done — or worse, the attacker executes their
//   variant FIRST and the honest proposal can never run.
pragma solidity ^0.8.0;

contract LayerZeroGovExecutor {
    struct Origin { uint32 srcEid; bytes32 sender; uint64 nonce; }

    address public owner;
    // trusted source (governance chain)
    uint32 public trustedEid;
    bytes32 public trustedPeer;

    // proposalId => executed flag (written, never read!)
    mapping(uint256 => bool) public executed;

    event ProposalExecuted(uint256 indexed proposalId, address target, uint256 value, bytes payload);
    event Received(uint32 srcEid, bytes32 peer, uint256 proposalId, bytes payload);

    constructor(uint32 _eid, bytes32 _peer) payable {
        owner = msg.sender;
        trustedEid = _eid;
        trustedPeer = _peer;
    }

    receive() external payable {}

    // Inbound governance message from the governance chain.
    // message = abi.encode(proposalId, target, value, payload)
    function lzReceive(
        Origin calldata origin,
        bytes32 /*guid*/,
        bytes calldata message,
        address /*executor*/,
        bytes calldata /*extraData*/
    ) external {
        require(origin.srcEid == trustedEid, "wrong chain");
        require(origin.sender == trustedPeer, "wrong peer");
        require(origin.nonce > govNonce(), "replay/old nonce");
        _setGovNonce(origin.nonce);

        (uint256 proposalId, address target, uint256 value, bytes memory payload) =
            abi.decode(message, (uint256, address, uint256, bytes));

        // BUG 1: executed[] recorded but never enforced.
        executed[proposalId] = true;

        // BUG 2: id-only key — different payloads with the same id collide.
        (bool ok, ) = target.call{value: value}(payload);
        require(ok, "proposal call failed");
        emit ProposalExecuted(proposalId, target, value, payload);
        emit Received(origin.srcEid, origin.sender, proposalId, payload);
    }

    // nonce storage behind getters so the generated harness stays simple
    uint256 internal govNonceVal;
    function govNonce() public view returns (uint256) { return govNonceVal; }
    function _setGovNonce(uint256 n) internal { govNonceVal = n; }
}
