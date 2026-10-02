// SPDX-License-Identifier: MIT
// LayerZero V2 ENDPOINT-CORE testbed — the core-protocol half of the hunt,
// complementing the OApp-side LZ challenges (tests 8/9/10).
//
// What lives here and why the bug classes are real (not strawmen):
//
//  1. LzEndpointMock — a faithful, minimal reproduction of EndpointV2's
//     packet lifecycle (public LayerZero Labs EndpointV2.sol semantics):
//       lazyInboundNonce[receiver][srcEid][sender]      — high-water mark
//       pendingInboundPacket[receiver][srcEid][sender][n] = payload hash
//       verify()  — receive library stages a hash for a VERIFIABLE nonce
//       lzReceive() — PERMISSIONLESS execution that consumes the staged hash
//       nilify()  — the kill switch that unstages a packet
//     THE PRECEDENT: KelpDAO rsETH OFT adapter (Apr 2026, ~116,500 rsETH).
//     An executable payload hash existed for a nonce with no legitimate
//     source-side packet behind it; the drain was ONE permissionless
//     lzReceive call — the OApp's own peer check passed because the endpoint
//     had already staged the hash. Lesson: the OApp's peer check is NOT the
//     defense; the packet-hash lifecycle is. A hole in the core that lets an
//     already-CONSUMED nonce be re-staged turns every payment rail into a
//     replay pump.
//
//  2. LzPaymentRail — an honest V2-style OApp rail (endpoint-only +
//     full-peer (srcEid AND sender) + per-key claim-once + optional
//     exact-sequence gate). `strictClaim`=false simulates rails that trust
//     the endpoint completely (the Kelp failure mode: correct peer check,
//     zero independent replay defense).
//
//  3. LzFuzzableOft — honest OFT baseline (debit-then-burn, FLOOR shared-
//     decimal rounding, endpoint-gated credit) with a `buggyRounding`
//     toggle to reproduce the ceil-rounding dust-inflation class from
//     challenge #19 under the same fuzzing that proves the honest version
//     conserves supply (test/11 invariant suite).
//
// Every invariant in the test suite is a real LayerZero threat-model
// property: claim-once (replay), payin conservation, cross-chain supply
// conservation, nilify effectiveness. Secure configs must HOLD them under
// fuzzing; the toggled-bug configs must VIOLATE them.
pragma solidity ^0.8.0;

import {console2} from "forge-std/console2.sol";

// ---------------------------------------------------------------------------
// Shared Origin shape (mirrors LayerZero V2's Origin struct).
// ---------------------------------------------------------------------------

struct LzOrigin {
    uint32 srcEid;
    bytes32 sender; // left-padded remote OApp address
    uint64 nonce;
}

interface ILayerZeroReceiver {
    function lzReceive(
        LzOrigin calldata origin,
        bytes32 guid,
        bytes calldata message,
        address executor,
        bytes calldata extraData
    ) external payable;
}

// ---------------------------------------------------------------------------
// Plain mintable ERC20 for harness funding.
// ---------------------------------------------------------------------------

contract LzMintToken {
    string public constant name = "LZ Mint";
    string public constant symbol = "LZM";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public minters;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

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

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "insufficient allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function burn(address from, uint256 amount) external {
        require(msg.sender == from, "burn your own tokens");
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }
}

// ---------------------------------------------------------------------------
// LzEndpointMock — EndpointV2 packet lifecycle (see header).
// `coreBug` toggles the core bug class under study: accepting verify() for
// an ALREADY-CONSUMED nonce (re-staging a delivered packet hash).
// ---------------------------------------------------------------------------

contract LzEndpointMock {
    // --- EndpointV2-shaped storage ---
    mapping(address => mapping(uint32 => mapping(bytes32 => uint64))) public lazyInboundNonce;
    mapping(address => mapping(uint32 => mapping(bytes32 => mapping(uint64 => bytes32)))) public pendingInboundPacket;
    mapping(address => mapping(uint32 => mapping(bytes32 => uint64))) public deliveredNonce;
    // receive-library authorization per path (unset => any library, the
    // default-library case, which is how most paths run).
    mapping(address => mapping(uint32 => mapping(bytes32 => address))) public receiveLib;

    bool public immutable coreBug; // true = re-staging consumed nonces allowed

    event PacketVerified(LzOrigin origin, address receiver, bytes32 payloadHash);
    event PacketDelivered(LzOrigin origin, address receiver);
    event PacketNilified(LzOrigin origin, address receiver);

    constructor(bool _coreBug) {
        coreBug = _coreBug;
    }

    function setReceiveLib(address receiver, uint32 srcEid, bytes32 sender, address lib) external {
        receiveLib[receiver][srcEid][sender] = lib;
    }

    function isValidReceiveLibrary(address receiver, uint32 srcEid, bytes32 sender, address lib)
        public
        view
        returns (bool)
    {
        address configured = receiveLib[receiver][srcEid][sender];
        return configured == address(0) || configured == lib;
    }

    // --- verify(): a receive library stages a payload hash for a nonce ---
    function verify(LzOrigin calldata origin, address receiver, bytes32 payloadHash) external {
        require(isValidReceiveLibrary(receiver, origin.srcEid, origin.sender, msg.sender), "LZ_InvalidReceiveLibrary");
        uint64 lazy = lazyInboundNonce[receiver][origin.srcEid][origin.sender];
        // V2 semantics: verifiable = not yet consumed and not beyond lazy+1.
        // BUG (coreBug): the consumed-check is dropped entirely, so a
        // delivered nonce can be re-staged with a fresh payload hash — the
        // exact hole that turns rails into replay pumps (Kelp class).
        if (!coreBug) {
            require(origin.nonce > deliveredNonce[receiver][origin.srcEid][origin.sender], "LZ_PathAlreadyDelivered");
        }
        require(origin.nonce <= lazy + 1, "LZ_PathNotVerifiable");

        pendingInboundPacket[receiver][origin.srcEid][origin.sender][origin.nonce] = payloadHash;
        if (origin.nonce == lazy + 1) {
            lazyInboundNonce[receiver][origin.srcEid][origin.sender] = origin.nonce;
        }
        emit PacketVerified(origin, receiver, payloadHash);
    }

    // --- lzReceive(): PERMISSIONLESS execution of a staged packet ---
    function lzReceive(
        LzOrigin calldata origin,
        address receiver,
        bytes32 guid,
        bytes calldata message,
        bytes calldata extraData
    ) external payable {
        bytes32 staged = pendingInboundPacket[receiver][origin.srcEid][origin.sender][origin.nonce];
        require(staged != bytes32(0), "LZ_NoPendingInboundPacket");
        require(keccak256(abi.encodePacked(guid, message)) == staged, "LZ_InvalidMalformedPacket");

        // Consume BEFORE execution (the honest core clears state first).
        delete pendingInboundPacket[receiver][origin.srcEid][origin.sender][origin.nonce];
        if (origin.nonce > deliveredNonce[receiver][origin.srcEid][origin.sender]) {
            deliveredNonce[receiver][origin.srcEid][origin.sender] = origin.nonce;
        }

        ILayerZeroReceiver(receiver).lzReceive{value: msg.value}(origin, guid, message, msg.sender, extraData);
        emit PacketDelivered(origin, receiver);
    }

    // --- nilify(): the kill switch — unstage without delivering ---
    function nilify(LzOrigin calldata origin, address receiver) external {
        require(isValidReceiveLibrary(receiver, origin.srcEid, origin.sender, msg.sender), "LZ_InvalidReceiveLibrary");
        require(
            pendingInboundPacket[receiver][origin.srcEid][origin.sender][origin.nonce] != bytes32(0),
            "LZ_NoPendingInboundPacket"
        );
        delete pendingInboundPacket[receiver][origin.srcEid][origin.sender][origin.nonce];
        emit PacketNilified(origin, receiver);
    }
}

// ---------------------------------------------------------------------------
// LzPaymentRail — honest V2-style OApp rail.
//   endpoint-only entry, FULL peer check (srcEid AND sender), per-key
//   claim-once, optional exact-sequence gate. `strictClaim=false` models
//   rails that trust the endpoint completely (Kelp failure mode).
// Message format: abi.encode(recipient, amount) — a payment instruction.
// ---------------------------------------------------------------------------

contract LzPaymentRail is ILayerZeroReceiver {
    address public immutable endpoint;
    address public immutable owner;
    bool public immutable strictClaim; // per-key claim-once guard
    bool public immutable enforceSequence; // exact nonce ordering gate

    mapping(uint32 => bytes32) public peers;
    mapping(bytes32 => bool) public claimed; // keccak(srcEid,sender,nonce)
    mapping(uint32 => mapping(bytes32 => uint64)) public lastAppliedNonce;
    uint256 public totalPaidOut;

    event Payout(address indexed to, uint256 amount, uint32 srcEid, uint64 nonce);

    constructor(address _endpoint, bool _strictClaim, bool _enforceSequence) payable {
        endpoint = _endpoint;
        owner = msg.sender;
        strictClaim = _strictClaim;
        enforceSequence = _enforceSequence;
    }

    function setPeer(uint32 eid, bytes32 peer) external {
        require(msg.sender == owner, "only owner");
        peers[eid] = peer;
    }

    receive() external payable {}

    function lzReceive(
        LzOrigin calldata origin,
        bytes32 /*guid*/,
        bytes calldata message,
        address /*executor*/,
        bytes calldata /*extraData*/
    ) external payable override {
        // Gate 1: only the endpoint may deliver.
        require(msg.sender == endpoint, "OnlyEndpoint");
        // Gate 2: FULL peer check — chain AND sender.
        bytes32 peer = peers[origin.srcEid];
        require(peer != bytes32(0) && peer == origin.sender, "OnlyPeer");
        // Gate 3 (strictClaim): per-key claim-once — the OApp's independent
        // replay defense. With strictClaim=false the rail TRUSTS the
        // endpoint's hash lifecycle completely (Kelp failure mode).
        bytes32 key = keccak256(abi.encode(origin.srcEid, origin.sender, origin.nonce));
        if (strictClaim) {
            require(!claimed[key], "AlreadyClaimed");
            claimed[key] = true;
        }
        // Gate 4 (optional): exact-sequence nonce consumption.
        if (enforceSequence) {
            require(origin.nonce == lastAppliedNonce[origin.srcEid][origin.sender] + 1, "NonceGap");
            lastAppliedNonce[origin.srcEid][origin.sender] = origin.nonce;
        }

        (address recipient, uint256 amount) = abi.decode(message, (address, uint256));
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "payout failed");
        totalPaidOut += amount;
        emit Payout(recipient, amount, origin.srcEid, origin.nonce);
    }
}

// ---------------------------------------------------------------------------
// LzFuzzableOft — honest OFT baseline (floor rounding) with a buggyRounding
// toggle for the dust-inflation class (challenge #19).
// ---------------------------------------------------------------------------

contract LzFuzzableOft {
    LzMintToken public immutable token;
    address public immutable endpoint;
    uint8 public constant LOCAL_DECIMALS = 18;
    uint8 public constant SHARED_DECIMALS = 6;
    uint256 public constant LD_PER_SD = 10 ** (LOCAL_DECIMALS - SHARED_DECIMALS);

    bool public immutable buggyRounding; // ceil instead of floor (the #19 bug)

    mapping(address => uint256) public bridgedDebit;
    mapping(address => uint256) public bridgedCredit;
    uint256 public lastOutboundCreditSD; // the message payload the endpoint delivers

    event BridgedOut(address indexed from, uint256 amountSD);
    event BridgedIn(address indexed to, uint256 amountSD);

    constructor(address _token, address _endpoint, bool _buggyRounding) {
        token = LzMintToken(_token);
        endpoint = _endpoint;
        buggyRounding = _buggyRounding;
        LzMintToken(_token).setMinter(address(this));
    }

    function _ld2sd(uint256 amountLD) internal view returns (uint256) {
        if (buggyRounding) {
            return (amountLD + LD_PER_SD - 1) / LD_PER_SD; // BUG: ceil
        }
        return amountLD / LD_PER_SD; // honest: floor, dust dropped
    }

    // SOURCE: pull exact local amount, burn it, message carries the
    // converted shared amount.
    function bridgeOut(uint256 amountLD) external {
        require(token.transferFrom(msg.sender, address(this), amountLD), "transferFrom failed");
        token.burn(address(this), amountLD);
        uint256 amountSD = _ld2sd(amountLD);
        bridgedDebit[msg.sender] += amountSD;
        lastOutboundCreditSD = amountSD;
        emit BridgedOut(msg.sender, amountSD);
    }

    // DESTINATION: endpoint-gated mint of the shared amount in local units.
    function bridgeIn(address to, uint256 amountSD) external {
        require(msg.sender == endpoint, "only endpoint");
        bridgedCredit[to] += amountSD;
        token.mint(to, amountSD * LD_PER_SD);
        emit BridgedIn(to, amountSD);
    }
}
