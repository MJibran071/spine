// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {CrossChainBridge} from "../src/challenges/CrossChainBridge.sol";
import {BridgeReplayAttacker} from "../src/attackers/BridgeReplayAttacker.sol";
import {ERC20Mintable} from "../src/tokens/ERC20Mintable.sol";

contract BridgeChallengeTest is Test {
    CrossChainBridge internal bridge;
    BridgeReplayAttacker internal attacker;
    ERC20Mintable internal token;
    address internal deployer;
    address internal relayer; // threshold-1 hot key
    uint256 internal relayerPk; // its key (test-only: we must forge signatures)
    address internal user;
    address internal attackerEoa;
    bytes internal relayerSig;

    bytes32 internal constant PAYOUT_TX = keccak256("source chain payout tx");
    uint256 internal constant USER_DEPOSIT = 500_000 ether;
    uint256 internal constant BRIDGED_OUT = 100_000 ether; // divides the vault balance so replay drains it fully

    function setUp() public {
        deployer = makeAddr("deployer");
        (relayer, relayerPk) = makeAddrAndKey("relayer");
        user = makeAddr("user");
        attackerEoa = makeAddr("attackerEoa");

        vm.startPrank(deployer);
        token = new ERC20Mintable("Bridge Token", "BRG");
        token.mint(user, USER_DEPOSIT);
        bridge = new CrossChainBridge(address(token), relayer);
        vm.stopPrank();

        // Honest flow: the user bridges out 300k; on the far side it was paid,
        // so the relayer signs the reverse-direction payout on this chain.
        vm.startPrank(user);
        token.approve(address(bridge), type(uint256).max);
        bridge.deposit(1, USER_DEPOSIT);
        vm.stopPrank();

        relayerSig = _sign(BRIDGED_OUT);
        vm.prank(user);
        bridge.withdraw(PAYOUT_TX, 7, user, BRIDGED_OUT, relayerSig);

        vm.prank(attackerEoa);
        attacker = new BridgeReplayAttacker(address(bridge));
    }

    function _sign(uint256 amount) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encode(PAYOUT_TX, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_bridgeHoldsUserCollateral() public view {
        assertEq(token.balanceOf(address(bridge)), USER_DEPOSIT - BRIDGED_OUT, "bridge holds net user collateral");
    }


    function test_validClaimOnlyPaysOnce() public {
        // The one legitimate claim already executed in setUp; re-submitting the
        // exact same claim must fail (this is the protection that replay bypasses).
        vm.expectRevert();
        vm.prank(user);
        bridge.withdraw(PAYOUT_TX, 7, user, BRIDGED_OUT, relayerSig);
    }
    function test_claimReplayDrain() public {
        uint256 before = token.balanceOf(address(bridge));
        assertGt(before, 0, "nothing to drain");

        vm.startPrank(attackerEoa);
        attacker.replay(PAYOUT_TX, BRIDGED_OUT, relayerSig, 10); // fresh logIndex each time
        vm.stopPrank();

        assertEq(token.balanceOf(address(bridge)), 0, "bridge not fully drained");
        assertEq(token.balanceOf(attackerEoa), before, "attacker did not capture the funds");
    }

    function test_falseDepositCreditsWithoutCollateral() public {
        // Qubit-class: the express deposit path credits the ledger without
        // pulling collateral.
        vm.prank(attackerEoa);
        attacker.falseDeposit(42, 1_000_000 ether);
        assertEq(bridge.outboundCredit(42), 1_000_000 ether, "credit not booked");
        assertEq(token.balanceOf(attackerEoa), 0, "no collateral moved (bug: credit for nothing)");
    }

    function test_honestDepositStillPullsCollateral() public {
        uint256 bridgeBefore = token.balanceOf(address(bridge));
        vm.prank(user);
        bridge.deposit(2, 1 ether);
        assertEq(token.balanceOf(address(bridge)), bridgeBefore + 1 ether, "honest path must pull collateral");
    }
}
