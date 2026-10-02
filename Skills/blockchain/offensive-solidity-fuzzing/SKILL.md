---
name: offensive-solidity-fuzzing
description: "Foundry/Echidna fuzzing and invariant testing methodology for smart contracts: property selection from the universal DeFi invariant catalog (solvency, wealth conservation, credit conservation, ERC-4626 round-trip), stateful handler design, ghost-variable tracking, Echidna/Medusa property modes, symbolic execution with Halmos, coverage-guided harness improvement, and deduplication/triage of violating sequences into minimal repros. Covers harness anti-patterns (over-constrained fuzzers that find nothing, under-constrained ones that find only reverts), bound and whitelist patterns for external calls, handling oracles and time via vm.warp/vm.roll, and converting a failing sequence into a human-readable exploit path. Use when writing invariant tests for a protocol, fuzzing for unknown bug classes in deployed contracts, verifying a fix actually closes the bug, or automating vulnerability discovery the way this repo's generic harness engine does."
---

# Solidity Fuzzing and Invariant Testing

A fuzzed invariant is the strongest statement you can make about a contract:
"no sequence of reachable calls can violate this property." When the fuzzer
breaks it, the failing call sequence *is* the exploit. This skill covers
building harnesses that find real bugs instead of reverts — the same design the
generic harness engine in this repo automates across lender-native,
lender-asset, ERC-4626, oracle-spot, and marketplace-batch shapes.

## Quick Workflow

1. State the property in one sentence a non-cryptographer understands ("the pool can never be drained", "nobody can profit by depositing and withdrawing").
2. Choose the harness: Foundry `invariant_` stateful fuzz, Echidna properties, Medusa multi-chain, Halmos symbolic.
3. Write handlers that cover every user-reachable action — including attacker-shaped ones (donate, flash-loan, direct token transfer).
4. Add ghost variables for value that entered/left the system; assert conservation.
5. Run bounded campaigns; triage each violation into a minimal repro (foundry's `--rerun` + sequence logs).
6. Fix, then keep the test: a bug you can't regress is a bug you'll re-meet.

---

## 1. The universal invariant catalog

Properties that apply to nearly any DeFi shape:

| Property | Statement |
|---|---|
| Solvency | `totalAssets() >= totalLiabilities()` at every reachable state |
| Wealth conservation | sum of user credits ≤ value ever deposited (nothing minted from nothing) |
| Credit conservation | a user's balance only changes via protocol-sanctioned flows |
| ERC-4626 round-trip | `deposit(x); redeem();` returns ~x (≥ x − fees), both directions, at any share price |
| Peg conservation (bridges) | minted supply ≤ locked backing |
| Monotonic fees/accrual | interest indices never decrease |
| Liveness | any user can always withdraw their entitled amount |

For a target with no known shape, instantiate these against its ABI: any
function that increases someone's balance is a candidate "mint", any that
decreases is a "burn"; conservation must hold across their composition.

## 2. Handler design

```solidity
contract PoolHandler is Test {
    uint256 public ghostDeposited;
    uint256 public ghostWithdrawn;

    function deposit(uint256 amount) external {
        amount = bound(amount, 0, token.balanceOf(currentActor));
        vm.prank(currentActor);
        token.approve(address(pool), amount);
        vm.prank(currentActor);
        pool.deposit(amount);
        ghostDeposited += amount;
    }
    // ... withdraw, borrow, repay, liquidate, flashLoan, donate ...
}
```

Rules that separate finding-bugs from finding-reverts:

- **Bound every input** to reachable ranges; an unbound fuzz is a revert generator.
- **Include the malicious actors**: `donate()` (send tokens directly to the pool), forced ETH (`vm.deal`), direct token transfers. Most first-depositor and donation bugs die without a donor handler.
- **Use an actor pool** (fuzz over which user acts) — cross-user bugs (credit confusion, first-depositor) never appear with a single `address(this)` actor.
- **Ghost variables** track cumulative flows so conservation is checkable without trusting the contract's own accounting.
- **Whitelist external calls** the handler may make; a handler that calls arbitrary addresses becomes an exploit oracle, not a test.

## 3. Fuzzer configuration

| Fuzzer | Strength | Notes |
|---|---|---|
| Foundry (`forge test` invariants) | integrated, fast iteration | `runs`, `depth`, `fail_on_revert` tuning |
| Echidna | mature, mode:property/assertion | good for large protocols; slither integration |
| Medusa | parallel, multi-chain target support | newer, strong stateful search |
| Halmos | symbolic (SMT) | exhaustive over bounded paths; proves absence, not just absence-yet |

Campaign sizing: start `runs=64, depth=128`; scale up when clean. For
adversarial audits, run 10× and add seed corpora from known exploit traces —
seeding with a rekt-news attack sequence finds its cousins quickly.

## 4. Triage: from failure to finding

1. Capture the failing sequence (Foundry prints the call log; Echidna gives the transaction list).
2. Shrink it: remove calls until the invariant still breaks — the minimal repro.
3. Classify the primitive that made it possible (flash loan? donation? rounding? reentrancy?).
4. Convert the sequence into a narrative PoC: attacker contract + `vm.` cheats + assertion of extracted profit.
5. Verify the fix fails the same harness. Fix without regression test = unfixed.

## 5. Common harness anti-patterns

- `vm.assume` on too much: assuming away the interesting states.
- Asserting implementation details (`assertEq(x, 1000e18)`) instead of properties — passes while the vault is being drained.
- Handlers that can't fail: wrapping everything in try/catch hides real reverts that are the bug.
- Fuzzing only the happy path: no donor, no attacker, no flash loaner, no reentrancy actor.
- One invariant per bug class: you can't find reentrancy with an accounting-only invariant.

## References

- Foundry book — Invariant testing chapter
- Echidna/Medusa docs (Trail of Bits)
- This repo's `agent/src` generic harness engine — the same property catalog, automated
