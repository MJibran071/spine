// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {TrusterLenderPool} from "../src/challenges/TrusterLenderPool.sol";
import {TrusterAttacker} from "../src/attackers/TrusterAttacker.sol";
import {ERC20Mintable} from "../src/tokens/ERC20Mintable.sol";

contract TrusterChallengeTest is Test {
    TrusterLenderPool internal pool;
    TrusterAttacker internal attacker;
    ERC20Mintable internal token;
    address internal deployer;
    address internal attackerEoa;

    uint256 internal constant TOKEN_INITIAL_SUPPLY = 1_000_000 ether;
    uint256 internal constant POOL_INITIAL_TOKEN_BALANCE = 1_000_000 ether;

    function setUp() public {
        deployer = makeAddr("deployer");
        attackerEoa = makeAddr("attackerEoa");

        vm.startPrank(deployer);
        token = new ERC20Mintable("Damn Valuable Token", "DVT");
        token.mint(deployer, TOKEN_INITIAL_SUPPLY);

        pool = new TrusterLenderPool(address(token));
        token.transfer(address(pool), POOL_INITIAL_TOKEN_BALANCE);
        vm.stopPrank();

        vm.prank(attackerEoa);
        attacker = new TrusterAttacker(address(pool));
    }

    function test_poolHasInitialTokenBalance() public view {
        assertEq(token.balanceOf(address(pool)), POOL_INITIAL_TOKEN_BALANCE);
    }

    function test_drainAllFunds() public {
        uint256 poolBalanceBefore = token.balanceOf(address(pool));
        assertEq(poolBalanceBefore, POOL_INITIAL_TOKEN_BALANCE);

        vm.startPrank(attackerEoa);
        attacker.attack();
        vm.stopPrank();

        assertEq(token.balanceOf(attackerEoa), POOL_INITIAL_TOKEN_BALANCE, "attacker did not capture pool tokens");
        assertEq(token.balanceOf(address(pool)), 0, "pool not fully drained");
    }
}
