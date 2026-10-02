// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {FeeRouter} from "../src/challenges/FeeRouter.sol";
import {FeeSweepAttacker} from "../src/attackers/FeeSweepAttacker.sol";
import {ERC20Mintable} from "../src/tokens/ERC20Mintable.sol";

contract FeeRouterChallengeTest is Test {
    ERC20Mintable internal token;
    FeeRouter internal router;
    FeeSweepAttacker internal attacker;
    address internal deployer;
    address internal treasury;
    address internal attackerEoa;
    uint256 internal constant FEES_ACCRUED = 50 ether;

    function setUp() public {
        deployer = makeAddr("deployer");
        treasury = makeAddr("treasury");
        attackerEoa = makeAddr("attackerEoa");

        vm.startPrank(deployer);
        token = new ERC20Mintable("FEE", "FEE");
        router = new FeeRouter(address(token), treasury);
        // Simulate accumulated protocol fees sitting in the router.
        token.mint(address(router), FEES_ACCRUED);
        attacker = new FeeSweepAttacker(address(router));
        vm.stopPrank();
    }

    function test_routerHoldsAccumulatedFees() public view {
        assertEq(token.balanceOf(address(router)), FEES_ACCRUED);
    }

    function test_treasurySweepStillWorks() public {
        vm.prank(treasury);
        router.sweepFees(treasury);
        assertEq(token.balanceOf(treasury), FEES_ACCRUED, "honest sweep broken");
        assertEq(token.balanceOf(address(router)), 0);
    }

    function test_permissionlessSweepDrainsRouter() public {
        vm.prank(attackerEoa);
        attacker.drain();

        // The router must be completely drained.
        assertEq(token.balanceOf(address(router)), 0, "router not drained");

        // The attacker holds the entire fee balance.
        assertEq(token.balanceOf(attacker.owner()), FEES_ACCRUED, "attacker did not capture the fees");
    }
}
