---
name: offensive-smart-contract-vulns
description: "Smart contract vulnerability class taxonomy and exploitation methodology for EVM chains (Ethereum, L2s, BSC, Avalanche). Covers reentrancy (classic, cross-function, cross-contract, read-only), integer/rounding bugs, unchecked return values, access-control flaws (missing onlyOwner, uninitialized proxies, delegatecall injection), storage collisions, signature replay and malleability, tx.origin auth, front-running and sandwich mechanics, uninitialized storage, arbitrary external calls, and DoS patterns (block gas limit, unbounded loops). Maps each class to its detection signature (Slither, aderyn, manual review), a minimal Foundry PoC pattern, and the corresponding fix (checks-effects-interactions, ReentrancyGuard, SafeERC20, OZ initializers). Use when auditing Solidity, building exploit PoCs against deployed contracts, reproducing audit findings, or triaging a live incident — in an authorized engagement or a local-only fork."
---

# Smart Contract Vulnerability Classes (EVM)

Solidity vulnerabilities are finite and classifiable. An auditor's job is to map
every state transition a contract exposes onto this taxonomy; an attacker's job
is to find the one transition the developers got wrong. This skill covers the
core EVM bug classes, how to detect each one, and how to prove it with a
minimal Foundry PoC — the same loop this repo's lab automates.

**Scope guard:** all testing happens against local chains, local forks, or
contracts you are authorized to test. Simulating a drain on a local fork of a
live pool is legal; broadcasting one is theft, regardless of what the contract
permits (see *US v. Avraham Eisenberg*, SDNY 2023).

## Quick Workflow

1. Get verified source (Etherscan/Blockscout/Sourcify) or decompile bytecode (`heimdall-rs`).
2. Run static analysis first: `slither .`, `aderyn .` — treat output as leads, not verdicts.
3. Identify trust boundaries: who can call what, which calls go to untrusted addresses, which state is read-then-written.
4. Classify against the taxonomy below; for each candidate, ask "what external call or external state read sits between the check and the effect?"
5. Prove it: minimal Foundry test with `vm.deal` / `vm.prank`, assert the money moves. A test that drains is the finding.
6. Score impact (value at risk, preconditions, attacker cost), then write it up (see offensive-reporting).

---

## 1. Reentrancy

The invariant: external calls must happen after all state changes
(checks-effects-interactions). Any external call — token transfer, ETH send,
arbitrary callback — is a reentrancy boundary.

- **Classic (single function):** withdraw sends ETH before zeroing the balance.
- **Cross-function:** `withdrawA()` reenters `withdrawB()` sharing state.
- **Cross-contract:** a trusted collaborator contract calls back into the victim.
- **Read-only reentrancy:** the attacker poisons state mid-view-call; a
  *view* function (e.g. an exchange rate or `getReserves`) returns a corrupted
  value to an innocent third protocol. No guard helps — the reader must not
  trust view state while a callback can fire.

PoC shape (Foundry):

```solidity
function test_drain() public {
    attacker.claim(); // attacker contract's fallback reenters pool.withdraw()
    assertEq(address(pool).balance, 0);
}
```

Detection: Slither `reentrancy-*` detectors; manually, list every `call`,
`transfer`, `send`, `safeTransfer`, and every non-view external call, then walk
backwards to the state it depends on. Fix: effects before interactions,
`ReentrancyGuard` (note: does NOT fix read-only reentrancy), transient-storage
locks (EIP-1153), or pull-payment patterns.

## 2. Access control and privilege bugs

- Missing modifiers on state-changing functions; `tx.origin` instead of `msg.sender` (phishable).
- Uninitialized implementation storage: UUPS proxies where `initialize` has no initializer guard, or proxy admin slots collide with implementation slots.
- `delegatecall` into a user-supplied address, or into storage-layout-mismatched logic (upgrade bugs).
- Role confusion: `DEFAULT_ADMIN_ROLE` over-broad, open Zeppelin access-managed functions.

Detection: enumerate every external function's caller constraints; diff the
proxy's storage layout between implementations (`forge inspect <C> storage-layout`).

## 3. Arithmetic, rounding, and accounting

- Rounding direction: share/price math must always round **against** the user with the incentive (vault rounds shares down, withdrawals round assets up). `mulDiv` rounding differences between deposit and redeem paths are where value leaks.
- Truncation in basis-point math (fee on 997/1000 style splits).
- Type narrowing (uint256 → uint128 downcast overflow), pre-0.8 under/overflow.
- Unchecked `transfer` return values (non-reentrant tokens: USDT, BNB, ZRX) — a failed transfer that "succeeds" locally corrupts accounting.

## 4. Signature and replay bugs

- Missing `nonce` or `chainId` in EIP-712 digests → cross-chain/cross-fork replay.
- `ecrecover` returning `address(0)` on malformed sigs; signature malleability (`s` high-half flips) breaking dedup-by-signature.
- Signing the wrong domain separator (name/version/salt mismatch lets one deployment's sigs replay on another).
- Missing `deadline` — long-lived approvals and permits.

## 5. External call and flash-loan primitives

- Arbitrary-call flash loans (`transfer` then arbitrary `target.call(data)`) hand the attacker a one-transaction privilege escalation — never let the borrower choose the callback.
- Pull over push: callbacks into untrusted code during state transitions (`onFlashLoan`, `uniswapV3SwapCallback`, ERC-777 hooks, ERC-721 `onReceived`).
- Unchecked low-level calls swallowing reverts; bubble or require.

## 6. Denial of service and griefing

- Unbounded loops over user-growable arrays (block gas limit DoS).
- Shared storage writes that let one user brick another's action (auction outbidding, donation-to-peg games).
- ETH forced into contracts with `selfdestruct`/coinbase tricks breaking `address(this).balance == x` assumptions (relevant to `receive()`-less accounting).

## 7. Proxies and upgrades

- Storage layout drift between versions; renamed/removed state variables.
- `delegatecall` to immutable-address patterns where the immutable was set in the proxy's context.
- Transparent-proxy admin function collisions; beacon impersonation.

## Reference tooling

| Purpose | Tool |
|---|---|
| Static analysis | Slither, aderyn, semgrep solidity rules |
| Fuzz/invariant | Foundry (forge), Echidna, Medusa, Halmos (symbolic) |
| Fork testing | `anvil --fork-url` (simulation only) |
| Bytecode → source | heimdall-rs, panoramix |
| Formal | Certora, Halmos |

## References

- SWC registry (Smart Contract Weakness Classification)
- OpenZeppelin security guides; `forge inspect` docs
- damnvulnerabledefi.xyz — the canonical challenge set this taxonomy trains on
