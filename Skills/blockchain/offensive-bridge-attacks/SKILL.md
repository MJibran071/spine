---
name: offensive-bridge-attacks
description: "Cross-chain bridge and messaging attack methodology: burn-and-mint vs lock-and-mint trust models, message replay (missing nonce/chain-id/source binding, signature reuse across forks), fake deposits and false burn proofs, verifier and multisig compromise (Ronin-class key threshold attacks), optimistic-fraud-proof window abuse, canonical vs third-party bridging races, and LayerZero-style OApp bugs (missing endpoint sender checks, nonce/ordering assumptions, decimal-dust conversion, fee-on-transfer OFTs). Includes the attacker economics of bridged-asset double-spends and the Foundry/anvil patterns for proving replay paths against local forks and deployed message protocols. Maps each attack to the property it violates (uniqueness of messages, soundness of attestations, conservation of pegged supply). Use when auditing bridges, messaging layers (LayerZero, CCIP, Wormhole, Hyperlane), and any protocol holding a chain's wrapped-native or canonical representation of another chain's assets."
---

# Cross-Chain Bridge Attacks

A bridge is a distributed claim: a state change on chain A should cause exactly
one state change on chain B, attested by someone. Every bridge exploit is a
violation of one of three properties — **message uniqueness** (replay), **attestation soundness** (fake or forged proofs), or **pegged-supply conservation** (mint without burn/lock). This skill maps the attack surface onto those properties, with the LayerZero OApp classes included since they are the most commonly deployed custom-messaging bugs.

**Scope guard:** bridge testing happens against local forks, lab bridges, and testnet deployments only. Live bridge exploitation is theft at ecosystem scale.

## Quick Workflow

1. Identify the trust model: who attests messages (multisig, MPC, oracle network, optimistic fraud proof, light client)?
2. Trace one message end-to-end: what binds it — nonce, source chain, sender, recipient, payload hash? Anything missing is replay surface.
3. Trace the mint path: what proves burn/lock, and is the proof unique and single-use?
4. Check the upgrade/admin path: who can pause, who can change verifiers, what happens on key compromise.
5. Write the invariant: *every mint has a unique burn/lock; every message applies exactly once*.
6. Prove replay/double-mint on a local fork (testnet at most) before reporting.

---

## 1. Message replay

- Digest omits `chainId` of source or destination → same message replays across deployments/forks.
- Digest omits nonce or uses a nonce incremented by the *recipient* → reordering and reapplication.
- Signature checked with `ecrecover` on a digest that doesn't include the claim id/recipient (the classic "claim signature replay" — the signature proves *someone* wants a payout, not *which* payout).
- Optimistic bridges: message finalized before the fraud-proof window closes; `executeAfter` compared with `>=` vs `>` off-by-one.
- Retry semantics: failed delivery must not reset the nonce backward.

Foundry proof shape:

```solidity
function test_claim_replay() public {
    bytes32 digest = keccak256(abi.encodePacked(amount)); // missing claimId + recipient
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(claimerKey, digest);
    bridge.claim(amount, victim, v, r, s);
    bridge.claim(amount, attacker, v, r, s); // second claim, same sig — pays twice
}
```

## 2. Fake deposits and proof forgery

- Deposit proofs that verify "a deposit event exists" without binding it to the specific deposit id/leaf.
- Merkle inclusion proofs with a root that anyone can propose (unpermissioned root updates).
- VAA/oracle attestation where quorum is reached by a small colluding set — enumerate the actual key set and their operational security (Ronin-class: five-of-nine keys phishable).
- Light-client fraud: header submission without honest-minority assumption enforcement.

## 3. Pegged-supply conservation

For every wrapped asset: `wrappedSupply ≤ locked/native backing` — across
*all* chains, counting upgrades. Audit the escrow: `escrowBalance ==
wrappedSupply` on the canonical chain, invariants expressible as Foundry state
tests. Watch upgrade paths that remint, migration scripts, and emergency
mint/governance functions — a guardian `mint` with no burn is a canonically
misnamed backdoor.

## 4. LayerZero-style OApp classes

Deployed on thousands of contracts; recurring bug classes:

- **Missing endpoint sender check:** `lzReceive` trusts `srcAddress`/`srcChainId` without verifying `msg.sender == endpoint` and the composed path — anyone can spoof a remote sender.
- **Nonce/ordering assumptions:** relying on ordered delivery when the channel is unordered, or vice versa; replaying nonce windows.
- **Decimal-dust conversion:** share/amount conversion between chains with different token decimals truncating into free value on repeated micro-transfers.
- **Fee-on-transfer OFTs:** debit `amount`, credit `amount` — the fee skim is minted from nothing.
- **Peer/config misbinding:** `setPeer` to the wrong address silently reroutes a channel.

## 5. Admin and lifecycle

- Pause/guardian keys: can a guardian unilaterally freeze withdrawals (censorship) or force-migrate?
- Upgradeable bridge cores: storage layout drift → message-store corruption; or worse, an upgrade that re-points the verifier set.
- Chain restart/fork handling: after a reorg, do nonces reset? (Historically: yes, painfully.)

## Reference tooling

| Purpose | Tool |
|---|---|
| Local multi-chain sim | two anvil instances + relayer script, or Foundry multi-fork tests |
| Message decode | cast --to-ray? (no) — `cast abi-decode` on payloads |
| Invariant | Foundry invariants on the bridge contract pair |

## References

- LayerZero/OApp docs and audit post-mortems; Wormhole, Ronin, Nomad, Harmony incident write-ups (rekt.news)
- Nomad's zero-root bug: the canonical "proof verification inverted" class
