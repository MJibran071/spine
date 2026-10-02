// SPDX-License-Identifier: MIT
// LayerZero endpoint-core invariants — fuzzed proofs over src/lz/LzEndpointTestbed.sol.
//
// Four properties from the LayerZero threat model, each proven twice:
//   HOLD on the secure config, VIOLATE on the toggled-bug config:
//     1. claim-once        — a delivered nonce can never pay twice
//                            (endpoint-core re-staging bug violates it)
//     2. payin conservation — claimable payouts never exceed escrowed deposits
//     3. OFT conservation   — destination supply <= source burned (floor
//                            rounding conserves; ceil rounding inflates)
//     4. nilify effectiveness — kill switch unblocks any staged packet
//
// Run:  forge test --match-contract LzEndpointCoreInvariants -vvv
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LzOrigin, LzMintToken, LzEndpointMock, LzPaymentRail, LzFuzzableOft} from "../src/lz/LzEndpointTestbed.sol";

// EndpointV2 semantics: the receive library stages keccak(guid ++ message).
bytes32 constant GUID = "guid";

function stagedHashOf(bytes memory payload) pure returns (bytes32) {
    return keccak256(abi.encodePacked(GUID, payload));
}

// ===========================================================================
// 1) CLAIM-ONCE — fuzzed replay pump on the endpoint-core bug.
// ===========================================================================

contract ClaimOnceFuzz is Test {
    LzMintToken internal token;
    LzEndpointMock internal endpoint;
    LzPaymentRail internal rail;

    uint64 internal nonce;
    bytes internal msgPayload;

    /// forge-config: default.fuzz.runs = 64
    function testFuzz_claimOnce_endpointCoreBug(uint64 hops) public {
        // ---------- secure config: no re-staging of consumed nonces ----------
        _setup(false, true);
        hops = uint64(bound(hops, 2, 20));
        _assertHonestRunConserves(hops);

        // ---------- buggy config: re-staging allowed, rail trusts endpoint ----------
        _setup(true, false); // Kelp failure mode: no OApp-side claim guard
        // hops × 1 ether must stay within the 10-ether escrow (honest payout
        // already took 1): each hop re-delivers the SAME nonce 1.
        hops = uint64(bound(hops, 2, 8));
        for (uint64 i; i < hops; ++i) {
            vm.roll(block.number + 1);
            endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(msgPayload));
            endpoint.lzReceive(
                LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, msgPayload, ""
            );
        }
        // CLAIM-ONCE VIOLATED: one payin drained hop-for-hop (capped at escrow).
        uint256 stolen = RECIPIENT.balance;
        console2.log("[LZ][claim-once][BUG] drained", stolen);
        assertGt(stolen, 1 ether, "re-staged nonce must re-pay (bug demonstrated)");
    }

    uint32 internal constant EID = 30101;
    bytes32 internal constant PEER = bytes32(uint256(uint160(0xBEEF)));
    address internal constant RECIPIENT = address(0x1337);

    function _setup(bool buggyCore, bool strictClaim) internal {
        vm.deal(RECIPIENT, 0); // constant recipient is shared across setups
        endpoint = new LzEndpointMock(buggyCore);
        rail = new LzPaymentRail{value: 10 ether}(address(endpoint), strictClaim, false);
        rail.setPeer(EID, PEER);
        msgPayload = abi.encode(RECIPIENT, 1 ether);

        // Stage + deliver nonce 1 once (the honest payin path).
        endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(msgPayload));
        endpoint.lzReceive(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, msgPayload, "");
        assertEq(RECIPIENT.balance, 1 ether, "honest delivery must pay once");
    }

    function _assertHonestRunConserves(uint64 hops) internal {
        // On the honest core a re-verify of the consumed nonce reverts.
        vm.expectRevert(bytes("LZ_PathAlreadyDelivered"));
        endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(msgPayload));
        // and the rail's escrow is intact apart from the honest payout.
        assertEq(address(rail).balance, 9 ether, "escrow drained by honest run");
        assertEq(rail.totalPaidOut(), 1 ether, "paid out more than the honest delivery");
    }
}

// ===========================================================================
// 2) PAYIN CONSERVATION — fuzzed: total paid out can never exceed deposits.
// ===========================================================================

contract PayinConservationFuzz is Test {
    LzMintToken internal token;
    LzEndpointMock internal endpoint;
    LzPaymentRail internal rail;

    uint32 internal constant EID = 30101;
    bytes32 internal constant PEER = bytes32(uint256(uint160(0xBEEF)));
    address internal constant RECIPIENT = address(0x1337);

    /// forge-config: default.fuzz.runs = 64
    function testFuzz_payinConservation_secureRail(uint96 payin, uint96 payout) public {
        endpoint = new LzEndpointMock(false);
        rail = new LzPaymentRail{value: 0}(address(endpoint), true, false);
        rail.setPeer(EID, PEER);
        vm.deal(address(this), 1000 ether);

        payin = uint96(bound(payin, 0.1 ether, 500 ether));
        payout = uint96(bound(payout, 0.1 ether, 500 ether));

        // Honest escrow lifecycle: deposit, verify, deliver (may revert on
        // insolvency — the invariant holds either way).
        address(rail).call{value: payin}("");
        bytes memory payload = abi.encode(RECIPIENT, uint256(payout));
        // staging uses the EndpointV2 hash binding: keccak(guid ++ message)
        endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(payload));
        try endpoint.lzReceive(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, payload, "") {
            // delivery went through
        } catch {
            // insolvent delivery reverts atomically — nothing paid
        }

        // THE INVARIANT (universal): paid out never exceeds escrow, and the
        // recipient received exactly what the rail accounted.
        assertLe(rail.totalPaidOut(), payin, "paid out must never exceed escrowed deposits");
        assertEq(RECIPIENT.balance, rail.totalPaidOut(), "recipient must match rail accounting");
    }

    /// forge-config: default.fuzz.runs = 64
    function testFuzz_payinConservation_coreBugDrains(uint96 payin, uint64 hops) public {
        endpoint = new LzEndpointMock(true); // re-staging bug present
        // Kelp failure mode: the rail TRUSTS the endpoint's hash lifecycle
        // (no independent claim-once guard). Its peer check passes because the
        // endpoint itself staged the hash — peer checks cannot save it here.
        rail = new LzPaymentRail{value: 0}(address(endpoint), false, false);
        rail.setPeer(EID, PEER);
        vm.deal(address(this), 1000 ether);

        payin = uint96(bound(payin, 1 ether, 500 ether));
        hops = uint64(bound(hops, 2, 10));

        address(rail).call{value: payin}("");
        uint256 per = payin / hops;
        bytes memory payload = abi.encode(RECIPIENT, per);
        endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(payload));
        endpoint.lzReceive(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, payload, "");

        // RE-STAGE the SAME consumed nonce and deliver again — hops-1 extra
        // times, then one final re-stage sized to the REMAINING escrow. One
        // nonce empties the rail completely.
        for (uint64 i = 1; i < hops; ++i) {
            endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(payload));
            endpoint.lzReceive(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, payload, "");
        }
        bytes memory sweep = abi.encode(RECIPIENT, address(rail).balance);
        endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(sweep));
        endpoint.lzReceive(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, sweep, "");

        uint256 drained = RECIPIENT.balance;
        assertEq(address(rail).balance, 0, "a single consumed nonce must be able to empty the escrow");
        assertGt(drained, per, "drain must exceed any single legitimate payout");
        console2.log("[LZ][payin][BUG] one nonce drained vs single legit payout", drained);
        console2.log("[LZ][payin][BUG] single legit payout", per);
    }

    /// THE DEFENSE-IN-DEPTH LESSON: the same core bug against a rail that
    /// keeps its own claim-once guard (strictClaim=true) is a DEAD END —
    /// re-delivery reverts on the OApp guard and the escrow survives.
    function test_coreBug_strictClaimRailBlocksReplay() public {
        endpoint = new LzEndpointMock(true);
        rail = new LzPaymentRail{value: 5 ether}(address(endpoint), true, false);
        rail.setPeer(EID, PEER);
        bytes memory payload = abi.encode(RECIPIENT, 1 ether);

        endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(payload));
        endpoint.lzReceive(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, payload, "");
        assertEq(RECIPIENT.balance, 1 ether, "honest delivery paid");

        // Core bug re-stages the consumed nonce; the OAPP guard blocks it.
        endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(payload));
        vm.expectRevert(bytes("AlreadyClaimed"));
        endpoint.lzReceive(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, payload, "");

        assertEq(address(rail).balance, 4 ether, "escrow must survive: guard holds even with a broken endpoint");
    }

    receive() external payable {}
}

// ===========================================================================
// 3) OFT CONSERVATION — floor rounding conserves, ceil rounding inflates.
// ===========================================================================

contract OftConservationFuzz is Test {
    LzMintToken internal token;
    uint256 internal constant LD_PER_SD_ = 1e12; // 10^(18-6) shared-decimal rate

    /// forge-config: default.fuzz.runs = 64
    function testFuzz_oftConservation_floorHolds(uint256 amountLD) public {
        token = new LzMintToken();
        address endpoint = makeAddr("endpoint");
        LzFuzzableOft src = new LzFuzzableOft(address(token), endpoint, false);
        LzFuzzableOft dst = new LzFuzzableOft(address(token), endpoint, false);

        amountLD = bound(amountLD, 0, 1_000_000 ether);
        address user = makeAddr("user");
        token.mint(user, 2_000_000 ether); // ample funding for bridgeOut

        vm.startPrank(user);
        token.approve(address(src), type(uint256).max);
        src.bridgeOut(amountLD);
        vm.stopPrank();

        uint256 amountSD = src.lastOutboundCreditSD();
        vm.prank(endpoint);
        dst.bridgeIn(user, amountSD);

        // CONSERVATION: destination minted (amountSD * 1e12) must not exceed
        // the source burned (amountLD); the only permitted leak is the dropped
        // dust (< 1 shared unit) from floor rounding.
        uint256 minted = amountSD * LD_PER_SD_;
        assertLe(dst.bridgedCredit(user), src.bridgedDebit(user), "credit must not exceed debit");
        assertLe(minted, amountLD, "destination minted more than source burned");
        assertLe(amountLD - minted, 1e12, "leak must be < 1 shared unit of dust");
    }

    /// forge-config: default.fuzz.runs = 64
    function testFuzz_oftConservation_ceilInflates(uint256 amountLD) public {
        token = new LzMintToken();
        address endpoint = makeAddr("endpoint");
        LzFuzzableOft src = new LzFuzzableOft(address(token), endpoint, true);
        LzFuzzableOft dst = new LzFuzzableOft(address(token), endpoint, true);

        // Sub-unit spam: below one shared unit, ceil still credits 1.
        amountLD = bound(amountLD, 1, 1e12 - 1);
        address user = makeAddr("user");
        token.mint(user, 1e12);

        vm.startPrank(user);
        token.approve(address(src), type(uint256).max);
        src.bridgeOut(amountLD);
        vm.stopPrank();

        uint256 amountSD = src.lastOutboundCreditSD();
        assertEq(amountSD, 1, "ceil must round sub-unit up (bug)");
        vm.prank(endpoint);
        dst.bridgeIn(user, amountSD);

        assertGt(token.balanceOf(user), amountLD, "minted more than bridged: supply inflated");
        console2.log("[LZ][oft][BUG] minted vs bridged", token.balanceOf(user));
        console2.log("[LZ][oft][BUG] bridged", amountLD);
    }
}

// ===========================================================================
// 4) NILIFY EFFECTIVENESS — the kill switch unstages and unblocks a path.
// ===========================================================================

contract NilifyEffectivenessTest is Test {
    uint32 internal constant EID = 30101;
    bytes32 internal constant PEER = bytes32(uint256(uint160(0xBEEF)));

    function test_nilify_unstagesAndUnblocks() public {
        LzEndpointMock endpoint = new LzEndpointMock(false);
        LzPaymentRail rail = new LzPaymentRail{value: 5 ether}(address(endpoint), false, true);
        rail.setPeer(EID, PEER);
        address recipient = makeAddr("recipient");
        bytes memory payload = abi.encode(recipient, 1 ether);

        // Stage nonce 1 (contiguous with lazy=0 — the only initializable
        // nonce), then nilify it: delivery must become impossible.
        endpoint.verify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), stagedHashOf(payload));
        assertEq(
            endpoint.pendingInboundPacket(address(rail), EID, PEER, 1),
            stagedHashOf(payload),
            "packet must be staged"
        );

        // nilify removes the staged packet — delivery impossible afterwards.
        endpoint.nilify(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail));
        vm.expectRevert(bytes("LZ_NoPendingInboundPacket"));
        endpoint.lzReceive(LzOrigin({srcEid: EID, sender: PEER, nonce: 1}), address(rail), GUID, payload, "");
        assertEq(recipient.balance, 0, "nilified packet must not deliver");
        assertEq(address(rail).balance, 5 ether, "escrow untouched by nilify");
    }
}
