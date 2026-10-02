// SPDX-License-Identifier: MIT
// Vulnerable LayerZero V2-style OApp (training target for the cross-chain
// challenge classes from the LayerZero threat model).
//
// BUG 1 (inbound authorization bypass — weak peer validation): lzReceive only
//   validates the peer when peer[srcEid] is non-empty, and never binds the
//   origin sender at all. A message from ANY source chain with an unset peer
//   is accepted, and on a configured chain any sender address passes because
//   only the chain id is checked. The endpoint normally calls lzReceive, but
//   permission to call lzReceive is not itself authentication — the OApp must
//   fully validate Origin (srcEid + sender) before mutating state.
//
// BUG 2 (message replay — mark-but-never-check nonces): executed() is written
//   for every processed nonce, but no read of executed() ever gates execution.
//   Replaying the same (srcEid, sender, nonce, payload) re-executes the side
//   effect — the classical double-payout on payment-style OApps.
//
// The contract pays out `token` on the message's instruction, so both bugs
// convert directly into fund extraction from the contract's balance.
pragma solidity ^0.8.0;

contract LayerZeroOAppV2 {
    // Mirrors LayerZero V2 Origin struct: (srcEid, sender bytes32, nonce).
    struct Origin {
        uint32 srcEid;
        bytes32 sender;
        uint64 nonce;
    }

    address public immutable owner;

    // peer[srcEid] = trusted remote OApp (bytes32, left-padded address on EVM)
    mapping(uint32 => bytes32) public peers;
    // executed[srcEid][sender] = last processed nonce (written, never read!)
    mapping(uint32 => mapping(bytes32 => uint64)) public inboundNonce;
    // completed message hash => paid (written for replay forensics, unused)
    mapping(bytes32 => bool) public executed;

    event MessageProcessed(uint32 srcEid, bytes32 sender, uint64 nonce, address recipient, uint256 amount);
    event Payout(address indexed to, uint256 amount);

    constructor() payable {
        owner = msg.sender;
    }

    // Fund the payout vault (cross-chain payment rails hold native on the
    // destination for gas refunds and payouts).
    receive() external payable {}

    function setPeer(uint32 eid, bytes32 peer) external {
        require(msg.sender == owner, "only owner");
        peers[eid] = peer;
    }

    // The vulnerable inbound path. Endpoint-style call surface.
    function lzReceive(
        Origin calldata origin,
        bytes32 /*guid*/,
        bytes calldata message,
        address /*executor*/,
        bytes calldata /*extraData*/
    ) external {
        // BUG 1: validation only when a peer is configured for this chain id,
        // and it never binds origin.sender — any caller-supplied sender value
        // passes on a configured chain, and unconfigured chains skip entirely.
        bytes32 peer = peers[origin.srcEid];
        if (peer != bytes32(0)) {
            // intentionally weak: sender is NOT compared to peer
        }

        // BUG 2: mark the nonce but never check it — replay re-executes.
        inboundNonce[origin.srcEid][origin.sender] = origin.nonce;

        // message = abi.encode(recipient, amount): a payment-style instruction.
        (address recipient, uint256 amount) = abi.decode(message, (address, uint256));
        bytes32 key = keccak256(abi.encode(origin.srcEid, origin.sender, origin.nonce, message));
        executed[key] = true; // forensics only — execution is NOT gated on it

        (bool ok, ) = recipient.call{value: amount}("");
        require(ok, "payout failed");
        emit MessageProcessed(origin.srcEid, origin.sender, origin.nonce, recipient, amount);
        emit Payout(recipient, amount);
    }

    // Version surface (OApp standard) — also lets recon fingerprint V2 OApps.
    function oAppVersion() external pure returns (uint64 senderVersion, uint64 receiverVersion) {
        return (2, 2);
    }

    // Sanity view the tests use: is this exact message already consumed?
    function isExecuted(
        uint32 srcEid,
        bytes32 sender,
        uint64 nonce,
        bytes calldata message
    ) external view returns (bool) {
        return executed[keccak256(abi.encode(srcEid, sender, nonce, message))];
    }
}
