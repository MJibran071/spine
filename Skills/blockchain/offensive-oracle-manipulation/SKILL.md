---
name: offensive-oracle-manipulation
description: "Price oracle attack methodology for DeFi and on-chain finance: AMM spot-price manipulation (single-block dump/pump via flash-loaned liquidity), stale and never-updating oracle feeds, Chainlink round/lifecycle abuse (deviation thresholds, heartbeat gaps, sequencer uptime feeds on L2s), TWAP manipulation windows and their costs, hardcoding-vs-oracle mismatches, and L2 sequencer feed failure modes. Covers identifying every consumer of every oracle in a protocol, the manipulation cost model (liquidity depth, fees, slippage, MEV competition) versus extractable value, and defensive fixes (TWAP windows, deviation bounds, multiple-source median, sanity ceilings/floors). Includes Foundry patterns for proving a price can be moved and held within one transaction. Use when auditing any protocol that prices collateral, mints against a feed, settles derivatives, or reads reserves — and when investigating why a lending market suddenly became 100% collateralized by nothing."
---

# Price Oracle Manipulation

Every on-chain price is either forgeable-in-one-transaction (AMM spot), stale
(reads a feed that hasn't updated), or expensive-to-move (TWAP/median). Attack
value = extractable value − manipulation cost. Your job is to find where that
gap is widest, and the job of every protocol you audit is to have closed it.

**Scope guard:** all proofs run on local forks. Moving a price on a live AMM to
drain a live protocol is theft, not research.

## Quick Workflow

1. Inventory every price read: `latestAnswer`, `getReserves`, `slot0`, `observe`, `totalAssets`, custom getters.
2. Classify each source: AMM spot (forgeable now), TWAP (forgeable with time+capital), signed feed (trust the signer), static/hardcoded (stale by design).
3. For each forgeable source, compute the manipulation cost: pool depth at the target move, fee tier, slippage curve, price-recovery path.
4. Find consumers who act *within the same block* — same-block read-and-act is where spot manipulation pays.
5. Prove on a local fork: move the price, read the consumer's derived value, execute the money-leg.
6. Report with the cost/extractable-value math — that ratio is the severity.

---

## 1. AMM spot manipulation

The canonical one-block chain:

```
flash loan (or own liquidity)
  → swap against AMM to move reserves
  → victim protocol reads spot price → lends/mints/liquidates on the fake price
  → swap back, keep the difference
```

Cost: pool fee + slippage on both legs. A deep pool makes manipulation
prohibitively expensive; a thin or long-tail pool makes it trivial. Check
`getReserves()`/`slot0` consumers first — `slot0` is the instantaneous price
and the most dangerous read.

Foundry proof shape:

```solidity
function test_spot_manipulation() public {
    deal(address(token), address(this), 1_000e18);
    token.transfer(address(pair), 1_000e18);          // dump to crash price
    pair.swap(...);
    uint256 collateralValue = oracle.getPrice();      // read post-swap
    emit log_named_uint("manipulated value", collateralValue);
}
```

## 2. Staleness classes

- **Never-updating feeds:** dev-only `setPrice`, oracles owned by a defunct team, testnets feeding mainnet. Check `updatedAt`/`answeredInRound` and owner history.
- **Heartbeat gaps:** Chainlink feeds update on deviation *or* heartbeat; between updates the price is the old truth. Volatile assets + long heartbeats = free arbitrage against the stale side.
- **Sequencer feeds (L2s):** Arbitrum/Optimism uptime feeds — consumers that skip the `startedAt` check accept prices from a sequencer that just came back, when user-submitted stale positions are suddenly profitable.
- **Manual setter authority:** who can call `setPrice`, and is that key a timelock, a multisig, or an EOA?

## 3. TWAP mechanics and windows

Uniswap V3 `observe()` returns the arithmetic mean over a window. Short
windows (e.g. 30 min) are manipulable with time + capital: push the price, hold
it, let the average drift. Cost model: capital × time × fees vs extractable
value. Long windows push the attack toward "move the market for hours," which
is visible and expensive — the defense is cost, not impossibility.

## 4. Consumer-side defenses worth checking for

| Defense | What it stops | What it doesn't |
|---|---|---|
| TWAP window | single-block spot moves | funded multi-hour pushes |
| Deviation bound (vs secondary source) | runaway feeds | correlated source failure |
| `updatedAt` staleness check | dead feeds | *living lies* (fresh but manipulated) |
| Sanity min/max ceilings | feed corruption | values inside the band |
| Median of N sources | single-source compromise | shared upstream dependency |

## 5. Non-price oracles

Anything feeding decisions is an oracle: `balanceOf` (donation attacks),
`totalSupply` (mint/burn games), block timestamps (miners, ±1s rules),
`msg.value` accounting, off-chain signatures (replay). The manipulation frame
above applies to each.

## References

- Chainlink data-feeds docs (deviation, heartbeat, L2 sequencer feeds)
- Uniswap V3 core `Observe`/TWAP math
- Known incidents: Mango (spot), bZx (funding rate), Compound (COMP ratio bug class)
