---
name: offensive-race-conditions
description: "Race condition checklist: limit-overrun TOCTOU (single-use codes, balances, votes, rate limits) and hidden multi-step sub-state exploitation, single-packet attack (HTTP/2, 20-30 requests in one TCP packet), last-byte sync for HTTP/1, the state-machine methodology (predict collisions, probe for clues, prove the concept with a useful impact), Turbo Intruder gate technique, and server-side jitter management. Use on any state-changing flow where two identical requests could collide."
---

# SKILL: Race Conditions

## Metadata
- **Skill Name**: race-conditions
- **Folder**: offensive-race-conditions
- **Source**: PortSwigger Web Security Academy — Race conditions (https://portswigger.net/web-security/race-conditions)

## Description
Race condition checklist: limit-overrun TOCTOU (single-use codes, balances, votes, rate limits) and hidden multi-step sub-state exploitation, single-packet attack (HTTP/2, 20-30 requests in one TCP packet), last-byte sync for HTTP/1, the state-machine methodology (predict collisions, probe for clues, prove the concept with a useful impact), Turbo Intruder gate technique, and server-side jitter management. Use on any state-changing flow where two identical requests could collide.

## Trigger Phrases
Use this skill when the conversation involves any of:
`race condition, toctou, time of check, single packet attack, last byte sync, turbo intruder, parallel requests, limit overrun, double spend, sub-state, state machine race`

## Description (Full)
Race conditions occur when sites process requests concurrently without adequate safeguards — threads collide on the same data within a "race window", producing unintended behavior. Attackers line up collisions deliberately: beyond classic limit overruns, hidden multi-step sequences expose logic flaws that only exist mid-request.

## Full Methodology

# Race Conditions

## Shortcut

- Identify single-use or rate-limited endpoints with security impact: coupons, gift cards, transfers, votes, CAPTCHA reuse, password reset limits.
- Send 20-30 parallel requests (single-packet attack on HTTP/2; last-byte sync on HTTP/1) — benchmark first, then vary.
- Anything that deviates from the benchmark is a clue; build a repeatable exploit around it.
- For deeper bugs, model the request as a state machine and find the sub-state where a check hasn't fired yet.

## Limit-overrun races (TOCTOU)

The classic: check-then-act without synchronization.

```
1. Check you haven't used this code
2. Apply discount
3. Record that you used it
```

Two simultaneous requests both pass step 1. Variations: redeem a gift card repeatedly, rate a product many times, over-withdraw past balance, reuse one CAPTCHA solution, bypass anti-brute-force counters.

## Technique: parallel request mechanics

Network jitter ruins naive parallelism; the fixes:

- **Single-packet attack (HTTP/2)**: complete 20-30 requests inside one TCP packet — near-zero jitter. Burp Repeater "Send group in parallel (single-packet attack)" or Turbo Intruder with `engine=Engine.BURP2`, `concurrentConnections=1`, gate grouping via `engine.queue(target.req, gate='1')` then `engine.openGate('1')`.
- **Last-byte sync (HTTP/1)**: queue requests over one connection holding the final byte; release simultaneously (classic Turbo Intruder gate).

Many requests (not just 2) mitigate server-side jitter during discovery.

## Hidden multi-step sequences

A single request can transition through multiple hidden sub-states — entering and exiting them mid-processing. Example (MFA bypass race):

```
session['userid'] = user.userid      # temporarily logged-in, MFA not yet enforced
if user.mfa_enabled: session['enforce_mfa'] = True
# generate and send MFA code; redirect to entry form
```

Race the login against a request to a sensitive authenticated endpoint — if it lands inside the sub-state, you're in without MFA.

## The state-machine methodology

1. **Predict potential collisions** — security-critical endpoints only; you need 2+ requests that touch the same record (password reset for the same user, not different users).
2. **Probe for clues** — benchmark the group sequentially (separate connections), then in parallel; any deviation in responses or second-order effects (email, callbacks, behavior change on later requests) is a lead.
3. **Prove the concept** — reconstruct the winning request sequence, tune timing/placement, and demonstrate a useful, reproducible impact. Apply the skill even if some clues only appear once — sub-states are fickle.

## Impact ideas beyond overruns

- Full account takeover (MFA skip, email-change races)
- Payment/logic state corruption (refund + withdrawal overlap)
- Rate-limit neutralization on auth endpoints (chains into brute force)

## Prevention

- Atomic state transitions (DB-level transactions with proper isolation, `SELECT ... FOR UPDATE`, idempotency keys).
- No security decision in a sub-state: enforce MFA/authorization atomically with the state change.
- Per-entity (not per-request) limits on sensitive counters.

## Notes for the fleet

- On-chain racing is native: liquidation competitions, front-running, and flash-loan atomicity are literally race conditions with money attached. The fleet's reentrancy class IS the TOCTOU family (check-effects-interactions).
- The sub-state lesson maps to multi-tx exploit windows: the "mid-flight" state between two transactions (e.g. after initialize, before role grant) is where on-chain setup races live.
