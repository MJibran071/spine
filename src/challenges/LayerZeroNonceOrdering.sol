// SPDX-License-Identifier: MIT
// Vulnerable LayerZero OApp — NONCE-ORDERING / STALE-NONCE REPLAY
// (challenge #2, "nonce-ordering bypass", application-side half).
//
// The endpoint itself enforces monotonic inbound nonces (LZ nonce semantics:
// each OApp+srcEid path's inbound nonce strictly increases). But an
// application that keeps ITS OWN nonce/sequence gate and decrements or
// re-increments it independently creates ordering windows:
//
// BUG: the gate accepts ANY nonce GREATER THAN the watermark — a lower
//   bound, not an equality/exact-sequence check. Two consequences:
//   (1) SEQUENCE BRICKING: the first delivery can carry any nonce (e.g. 5),
//       permanently burning nonces 1-4; and because LayerZero V2 supports
//       NON-INCREMENTAL delivery (reordered delivery of already-verified
//       packets — e.g. after a forced revert), a nonce delivered AHEAD of its
//       predecessors makes those delayed messages permanently stale. The
//       victim's in-flight transfers can never apply: funds bricked in flight.
//   (2) NO MESSAGE IDENTITY: the gate counts nonces, not message contents —
//       the same logical transfer re-applies under every fresh nonce.
//
// The honest invariant: an ordered OApp must consume its inbound nonce
// EXACTLY (lastApplied + 1), reject gaps, and derive state from the message
// payload identity — never from a position in a loose numeric sequence.
pragma solidity ^0.8.0;

contract DustToken {
    string public constant name = "Dust";
    string public constant symbol = "DST";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public minters;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        minters[msg.sender] = true;
    }

    function setMinter(address m) external {
        minters[m] = true;
    }

    function mint(address to, uint256 amount) external {
        require(minters[msg.sender], "not minter");
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
}

contract LayerZeroNonceOrdering {
    DustToken public immutable token;
    address public immutable endpoint;
    uint64 public lastAppliedNonce; // watermark the app applies itself

    // ledger of which logical transfers arrived (per user)
    mapping(address => uint256) public deliveredAmount;

    event Delivered(address indexed to, uint64 nonce, uint256 amount);

    constructor(address _token, address _endpoint) {
        token = DustToken(_token);
        endpoint = _endpoint;
        DustToken(_token).setMinter(address(this)); // destination-side mint authority
    }

    // DELIVERY: called by the endpoint with the inbound message's origin.
    // BUG: `>` watermark accepts any HIGHER nonce — including replays of
    // messages that arrived before an out-of-order high nonce, and double-
    // application when the same logical message is delivered under two
    // different nonces.
    function lzReceive(
        uint32 /*srcEid*/,
        bytes32 peer,
        uint64 nonce,
        address to,
        uint256 amount
    ) external {
        require(msg.sender == endpoint, "only endpoint");
        require(peer == bytes32(uint256(uint160(address(this)))), "bad peer");
        require(nonce > lastAppliedNonce, "stale nonce"); // <-- lower bound, not equality
        lastAppliedNonce = nonce;

        deliveredAmount[to] += amount;
        token.mint(to, amount); // <-- fires again for any still-above-watermark nonce
        emit Delivered(to, nonce, amount);
    }
}
