// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {NaiveReceiverPool} from "../src/challenges/NaiveReceiverPool.sol";
import {NaiveReceiverVictim} from "../src/challenges/NaiveReceiverVictim.sol";
import {NaiveReceiverAttacker} from "../src/attackers/NaiveReceiverAttacker.sol";

contract NaiveReceiverChallengeTest is Test {
    NaiveReceiverPool internal pool;
    NaiveReceiverVictim internal victim;
    NaiveReceiverAttacker internal attacker;
    address internal deployer;
    address internal attackerEoa;
    address internal lender;

    uint256 internal constant POOL_INITIAL_BALANCE = 1000 ether;
    uint256 internal constant VICTIM_INITIAL_BALANCE = 10 ether;
    uint256 internal constant FIXED_FEE = 1 ether;

    function setUp() public {
        deployer = makeAddr("deployer");
        attackerEoa = makeAddr("attackerEoa");
        lender = makeAddr("lender");
        vm.deal(deployer, POOL_INITIAL_BALANCE);

        vm.startPrank(deployer);
        pool = new NaiveReceiverPool();
        pool.deposit{value: POOL_INITIAL_BALANCE}();
        victim = new NaiveReceiverVictim(address(pool));
        vm.stopPrank();

        // The victim borrower holds 10 ETH it will repay loans from.
        deal(address(victim), VICTIM_INITIAL_BALANCE);

        vm.prank(attackerEoa);
        attacker = new NaiveReceiverAttacker(address(pool), address(victim));
        deal(address(attacker), 0.1 ether); // funds the attacker's seed deposit
    }

    function test_poolHasInitialBalance() public view {
        assertEq(address(pool).balance, POOL_INITIAL_BALANCE);
        assertEq(address(victim).balance, VICTIM_INITIAL_BALANCE);
    }

    function test_feeGriefing_andDrain() public {
        vm.startPrank(attackerEoa);
        attacker.attack(10); // 10 forced fee-charged loans, then the drain
        vm.stopPrank();

        // The victim lost all 10 ETH to the fixed fee.
        assertEq(address(victim).balance, 0, "victim was not fully fee-griefed");

        // The attacker captured the whole pool (1000) + the 10 ETH of griefed
        // fees; the extra 0.1 is the seed it deposited to prime the bug.
        assertEq(
            attackerEoa.balance,
            POOL_INITIAL_BALANCE + 10 * FIXED_FEE + 0.1 ether,
            "attacker did not capture pool + fees"
        );
        assertEq(address(pool).balance, 0, "pool not fully drained");
    }
}
