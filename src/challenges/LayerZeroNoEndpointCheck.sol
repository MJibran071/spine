// SPDX-License-Identifier: MIT
// Vulnerable LayerZero V2-style OApp — ENDPOINT IMPERSONATION.
//
// BUG: lzReceive validates the ORIGIN (srcEid + sender == peer) but NEVER
//   checks that msg.sender is the LayerZero endpoint. The endpoint is the
//   only party allowed to call lzReceive — that is what makes a verified
//   Origin meaningful. Without the check, ANY address can call lzReceive
//   directly with a perfectly valid-looking Origin copied from an honest
//   message and pay itself. The peer check alone authenticates nothing
//   because the caller fabricates the entire Origin struct.
//
// This is challenge class "endpoint impersonation" (executor/endpoint
// authorization confusion): trust in Origin is only as strong as the
// guarantee that only the endpoint can deliver it.
pragma solidity ^0.8.0;

contract LayerZeroNoEndpointCheck {
    struct Origin { uint32 srcEid; bytes32 sender; uint64 nonce; }

    address public immutable owner;
    address public endpoint; // set in constructor, then NEVER checked in lzReceive
    mapping(uint32 => bytes32) public peers;
    mapping(uint32 => mapping(bytes32 => uint64)) public inboundNonce;

    event Payout(address indexed to, uint256 amount);

    constructor(address _endpoint) payable {
        owner = msg.sender;
        endpoint = _endpoint;
    }

    receive() external payable {}

    function setPeer(uint32 eid, bytes32 peer) external {
        require(msg.sender == owner, "only owner");
        peers[eid] = peer;
    }

    // VULNERABLE: full peer validation, ZERO endpoint validation.
    function lzReceive(
        Origin calldata origin,
        bytes32 /*guid*/,
        bytes calldata message,
        address /*executor*/,
        bytes calldata /*extraData*/
    ) external {
        bytes32 peer = peers[origin.srcEid];
        require(peer != bytes32(0), "unconfigured chain");
        require(origin.sender == peer, "sender != peer"); // the peer check is flawless...
        // ...but msg.sender is NEVER checked against `endpoint`, so anyone
        // can deliver a fabricated-but-peer-consistent Origin.

        require(origin.nonce > inboundNonce[origin.srcEid][origin.sender], "replay/old nonce");
        inboundNonce[origin.srcEid][origin.sender] = origin.nonce;

        (address recipient, uint256 amount) = abi.decode(message, (address, uint256));
        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "payout failed");
        emit Payout(recipient, amount);
    }

    function oAppVersion() external pure returns (uint64, uint64) { return (2, 2); }
}
