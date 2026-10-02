---
name: offensive-defi-attacks
description: "DeFi protocol attack methodology across the major money-lego patterns: lending pools and flash-loan griefing, AMM spot-price manipulation, ERC-4626 vault share-price inflation and first-depositor attacks, NFT marketplace batch-purchase overcredit, uncollateralized borrowing, donation/peg attacks, and liquidation mechanics abuse. Covers attack economics (flash-loan cost vs extractable value, MEV profitability, slippage windows), composable-protocol interaction bugs (token + vault + AMM + oracle chains), and per-protocol families (Aave/Compound-style accounts, Uniswap V2/V3 math, Curve invariant assumptions). Each pattern includes the invariant the protocol should hold (solvency, wealth conservation, credit conservation) and how to express it as a Foundry invariant test so the fuzzer finds the breaking sequence. Use when hunting pool-drain bugs on an authorized engagement, reproducing DeFi exploit post-mortems, or validating a protocol's economic invariants on a local fork."
---

# DeFi Protocol Attack Patterns

DeFi bugs are rarely one contract's bug — they are contradictions between
protocols that each assume the other behaves. Flash loans make every
precondition on price, balance, or liquidity *instantly forgeable* by anyone,
which collapses the gap between a 1-attacker bug and a 100M-attacker bug. This
skill trains the pattern-matching: see the money leg, recall the broken
assumption, write the invariant.

**Scope guard:** test against local chains and read-only forks only. A
simulated drain is a finding; a broadcast drain is a crime.

## Quick Workflow

1. Map the money legs: what holds value, who can move it, what triggers movement.
2. For each leg, write the invariant that must always hold (solvency, conservation, credit).
3. Ask what a flash loan makes forgeable in one transaction: prices, balances, approvals, liquidity depth, collateral ratios.
4. Build the Foundry harness; let the fuzzer or a scripted sequence find the violating call chain.
5. Measure economics: extraction minus gas, loan fees, slippage, and MEV competition.
6. Report with the invariant violation as the headline (see offensive-reporting).

---

## 1. Lending pools

- **Flash-loan fee griefing:** a borrower's fee is computed on an attacker-inflated balance (e.g. fee = 0.1% of pool balance after attacker donates). The victim's flash loan then overpays. Invariant: *fee owed is independent of attacker-controlled state*.
- **Arbitrary-call flash loans:** if the loan executes `target.call(data)` chosen by the borrower, the "flash loan" is an everyone-wins RCE. Invariant: *borrower controls parameters, protocol controls the callback target*.
- **Uncollateralized borrowing:** shares/borrows minted before collateral accrues, or borrow limit checked against a manipulated price. Invariant: *account health stays >= 1 across every external call*.
- **Donation/peg attacks:** a pool that trusts `token.balanceOf(this)` lets anyone inflate it and mint themselves value. Invariant: *internal accounting never equals raw balance when donations are possible*.

## 2. AMM spot-price manipulation

Spot price is the *instant* marginal price — and instantly forgeable. The
classic chain: borrow via flash loan → dump on the AMM that the victim reads as
an oracle → borrow/mint against the crushed price → restore the pool. Cost is
fees + slippage, not the principal.

Invariants to test: *borrow value ≤ collateral value evaluated at TWAP, not spot*;
*no single block can move a protocol-critical price beyond bounds*. Fix family:
TWAP oracles (Uniswap V3 observe), Chainlink with deviation/heartbeat checks,
or internal reservation pricing.

## 3. ERC-4626 vaults

- **Inflation / first-depositor:** deposit 1 wei, donate the vault directly so the next depositor's shares round to zero. Invariant: *share price cannot increase without vault activity attributable to shares*.
- **Round-trip leakage:** `deposit → redeem` must never profit from rounding; test both directions and mid-size amounts (`vault.fuzz_roundtrip`).
- **Fee-on-transfer / rebasing tokens:** shares minted on `amount` while the vault received `amount - fee`; rebases corrupt `balanceOf(this)` accounting. Invariant: *assets accounted == assets actually held, under weird tokens*.
- **View-function manipulation:** `convertToAssets` / `totalAssets` trusting live balances — feeds read-only reentrancy downstream.

## 4. NFT marketplaces and batch flows

Batch purchase paths that credit per-item refunds computed from a shared pool
balance (the Free-Rider class): buy N items, get refunded `n * price` from the
pool's balance because each refund re-reads the pool's ETH. Invariant:
*total refunds ≤ total escrowed by the buyer; pool balance change equals fee
income only*. Related: purchase callbacks (`onERC721Received`) used to fund the
buy with the seller's own payment, decimals in price oracles for NFT floors.

## 5. Liquidation and incentive mechanics

- Unhealthy-position griefing: manipulating a user's collateral price to force liquidation with penalty capture.
- Dutch-auction liquidations exploitable at boundaries (start price logic off-by-block).
- Bad-debt socialization races — first liquidator takes all, last absorbs loss.

## 6. Composability interactions

Token standards are attack surface: ERC-777 hooks reenter everything,
ERC-20 return-value lies (USDT), fee-on-transfer skims, rebases mid-tx. For
every protocol touched, ask: what does *this* token do differently, and did the
integration assume the happy path?

## Foundry invariant harness pattern

```solidity
function invariant_pool_solvent() public {
    assertGe(pool.totalAssets(), pool.totalLiabilities());
}
function invariant_wealth_conserved() public {
    assertLe(handler.ghostExtracted(), handler.ghostDeposited());
}
```

Bind handler functions to every user-reachable action (deposit, withdraw,
borrow, repay, liquidate, donate, flash-loan) and let the fuzzer compose them.
A violation IS the exploit path — reconstruct it from the call trace.

## References

- EIP-4626 and its known pitfalls write-ups
- Uniswap V2/V3/Curve whitepapers — read the math before attacking the math
- Post-mortem corpora: rekt.news, Immunefi bug class taxonomies
