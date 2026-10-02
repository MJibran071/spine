// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {SideEntranceLenderPool} from "../src/challenges/SideEntranceLenderPool.sol";
import {SideEntranceAttacker} from "../src/attackers/SideEntranceAttacker.sol";

contract SideEntranceChallengeTest is Test {
    SideEntranceLenderPool internal pool;
    SideEntranceAttacker internal attacker;
    address internal deployer;
    address internal attackerEoa;
    uint256 internal constant POOL_INITIAL_BALANCE = 1000 ether;

    function setUp() public {
        deployer = makeAddr("deployer");
        attackerEoa = makeAddr("attackerEoa");
        vm.deal(deployer, POOL_INITIAL_BALANCE);

        vm.startPrank(deployer);
        pool = new SideEntranceLenderPool();
        pool.deposit{value: POOL_INITIAL_BALANCE}();
        vm.stopPrank();

        vm.prank(attackerEoa);
        attacker = new SideEntranceAttacker(address(pool));
    }

    function test_poolHasInitialBalance() public view {
        assertEq(address(pool).balance, POOL_INITIAL_BALANCE);
    }

    function test_sideEntranceDrain() public {
        vm.startPrank(attackerEoa);
        attacker.attack(POOL_INITIAL_BALANCE);
        vm.stopPrank();

        // The pool must be completely drained.
        assertEq(address(pool).balance, 0, "pool not fully drained");

        // The attacker EOA holds the loot.
        assertEq(attackerEoa.balance, POOL_INITIAL_BALANCE, "attacker did not capture the funds");
    }
}
