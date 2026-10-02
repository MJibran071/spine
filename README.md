# DeFi Exploit Lab + Autonomous Agent

A **local-only** security lab where an autonomous agent finds and proves pool-drain vulnerabilities. Practice on vulnerable challenge pools, then point the same machinery at real mainnet pools through a **read-only local fork**.

## The legal line (read this first)

- ✅ **Legal:** exploiting the lab's own vulnerable contracts; forking mainnet locally and simulating exploits against real state (nothing is broadcast); reporting findings via a bug bounty.
- ❌ **Illegal:** executing a drain against a live pool you don't own — that is theft regardless of what the contract allows (see: *US v. Avraham Eisenberg*, SDNY 2023, convicted on exactly this theory).
- 💰 **How findings become money:** bug bounties. Immunefi pays up to $1M+ for pool-drain-class bugs; Code4rena, Sherlock, and Cantina run ongoing contests. The agent drafts the report for you.

## Layout

```
src/challenges/   5 vulnerable pools (side-entrance, naive-receiver, puppet,
                  truster, free-rider) + support actors (victim, buyer)
src/attackers/    5 ground-truth exploit contracts, one per bug class
src/tokens/       WETH9, mintable ERC20, minimal ERC721
src/uniswap/      minimal Uniswap V1 (factory + exchange)
test/             challenge tests, invariants (fuzzed)
agent/            autonomous agent (TypeScript, zero deps, Node >= 22)
  src/            lab loop, fork mode, bounty reports, safety rails, execution tracing
  templates/      Solidity harness templates the agent fills + compiles
reports/          SCOREBOARD.md + bounty-draft-*.md land here
```

## Quickstart

```bash
# 0) Foundry + Node 22 required (forge/anvil/cast on PATH)

# 1) Run the lab suite (11 suites, 16 tests incl. fuzzed invariants)
forge test

# 2) Watch the agent solve all 5 challenges on its own
cd agent && npm run lab
# -> reports/SCOREBOARD.md

# 2c) ...with the live dashboard (any mode accepts --ui)
cd agent && npm run lab -- --ui
# -> http://127.0.0.1:7333 — challenges, watchlist, findings, KB, activity log

# 2d) ...or let it hunt continuously (daemon mode)
cd agent && npm run daemon -- --interval 120 --ui \
  --fork-url <PUBLIC_RPC> \
  --watch 0xAaAbBbCcC... --watch 0xDdEeFf00...
# - re-solves instantly when any challenge file changes
# - re-probes watchlist pools every cycle (state changes every block)
# - auto-drafts a bounty report on any reproduced drain
# - knowledge base (reports/knowledge.json) makes each run smarter

# 3) ...or let it DISCOVER drains it has no template for (fuzz synthesis)
cd agent && npm run synth
# - generates invariant harnesses ("the pool can never be drained"), lets the
#   fuzzer find the breaking sequence from PRIMITIVES, and reconstructs the
#   exploit path from [SYNTH_PATH] logs. Discovery evidence: reports/synth/

# 3b) GENERIC harness mode — no templates, no recipes: the agent parses the
cd agent && npm run harness
#     target's ABI, detects its shape (lender-native, lender-asset,
#     lender-arbitrary-call, erc4626, token, oracle-spot, marketplace-batch),
#     and emits a fuzzed invariant harness from a universal property catalog
#     (solvency, native/wealth conservation, victim credit, ERC-4626
#     round-trip). A violated invariant IS the discovered bug — even for
#     shapes the agent has never seen. Covers all 7 lab challenges.

# 3c) Static detector pass over all challenges (signal, not verdict)
npm run analysis

# 4) Check the safety rails
npm run safety   # run from agent/

# 4) Test a live pool through a read-only local fork
npm run fork -- --fork-url <PUBLIC_RPC> --pool <POOL_ADDRESS>

# 4b) ...or attach to an already-running local chain
npm run fork -- --attach http://127.0.0.1:8545 --pool <POOL_ADDRESS>

# Integration: deploy a vulnerable pool on a local chain, let the agent find
# it, simulate the drain, hit the approval gate, and emit a bounty draft:
anvil --port 8555 &
forge script test/integration/DeployLabPool.s.sol:DeployLabPool \
  --fork-url http://127.0.0.1:8555 --broadcast --unlocked \
  --sender 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
cd agent && npm run fork -- --attach http://127.0.0.1:8555 --pool <DEPLOYED_POOL>
```

## How the agent works

1. **Discover** — scans `src/challenges/`, extracts features (flash loan? caller-chosen borrower? arbitrary call? AMM-priced oracle? NFT marketplace?).
2. **Match** — scores five technique templates against those features.
3. **Generate** — fills a Solidity harness template with the matched attacker contract.
4. **Execute** — compiles and runs it with `forge test`; parses pass/fail and profit.
5. **Mutate** — on failure, retries with different parameters (bounded loop). Failed probes now carry their **deepest reverted frame** (parsed from the forge trace), so retries adjust based on which subcall reverted instead of blind re-rolls.
6. **Report** — writes `reports/SCOREBOARD.md`.
7. **Remember** — every win is stored in `reports/knowledge.json` keyed by the challenge's feature signature; the next run (or the daemon) tries known-winning technique + parameters first.

### The generic engine learns too (`reports/genlearn.json`)

The universal invariant engine (the one that finds bugs on never-seen shapes) keeps its own memory: proven violating paths per shape are embedded in every future harness of that shape as a deterministic `fuzz_replayLearned` attack (honest targets no-op through it; buggy same-shape targets violate in fuzz run 1), setUp dead ends are recorded once and skipped thereafter, and per-shape outcome priors feed the LLM triage prompt. Smoke test: `npm run genlearn-test` (from `agent/`).

### The agent learns techniques on its own (`reports/techniques.json`)

Every proven drain — a template win in the lab, a fuzz-synthesis discovery, a generic-invariant violation, a triage-probe drain on a live fork — is captured into a **self-learned technique library**: technique, shape, the exact step path, profit, and which target(s) it drained. When `LAB_LLM_KEY` is set, the daemon periodically hands the newest captures to the LLM to be **generalized** into transferable notes ("a lender whose flashLoan callback credits deposits without checking msg.sender can be re-entered from the callback") — the model writes the note, but only the fleet's own proven evidence gets into the library, and proven facts always outrank distilled prose. The library feeds back everywhere:

- **Triage + attack-idea prompts** receive a "TECHNIQUES THE FLEET ITSELF PROVED" block (retrieved by shape-token overlap, so lab tags match live prose shapes) — the model starts from what actually worked, not from scratch.
- **The curiosity question catalog grows itself**: every learned technique becomes an askable question ("could what drained X work here?") over untested targets; signals re-flag them into the standard probe pipeline.
- **The dashboard Memory tab** shows the library growing live, and the daily digest reports its size.

Smoke test: `npm run techniques-test` (from `agent/`).

### Daemon mode

`npm run daemon` runs the loop forever:

- **Lab watch** — keeps a fingerprint of `src/challenges/`; the moment a challenge is added or edited it is re-attacked automatically.
- **Technique distillation** — at consolidation time the fleet's newest proven drains are generalized into the self-learned technique library (bounded per run; proven facts survive even with the LLM off).
- **Fork watch** — re-probes the `--watch` list through a read-only local fork every cycle, because live pool state changes every block. A reproduced drain **auto-drafts** a bug-bounty report (unattended mode has no interactive gate, and still broadcasts nothing).
- **Bounded** — attempts per challenge per cycle are capped; a cycle error never kills the hunt.

### Unknown-shape investigation (no more dead end)

~80% of live targets classify as `unknown shape → no probe`. Instead of logging a dead end, the scanner and the daemon's fork watch now run a full investigation on each unknown target — locally, read-only:

1. **Verified source** (Etherscan V2 with `LAB_ETHERSCAN_KEY`, keyless Blockscout, Sourcify) feeds the static detector suite.
2. **LLM triage** (set `LAB_LLM_KEY`; any OpenAI-compatible endpoint via `LAB_LLM_URL`/`LAB_LLM_MODEL`) receives recon + detectors + source (or bytecode head when unverified) plus the knowledge base's prior wins, and returns a JSON hypothesis + probe spec. Every probe field is regex-validated; unrecognized probe classes are recorded, never executed.
3. **The proposed probe runs on the local fork** through the same execution path as the hand-written templates (`executeSim`) — 127.0.0.1 RPC only, no broadcast, the LLM never executes anything.

Triage results are cached per target under `reports/triage-cache/`; probes that reproduce a drain still flow into the bounty-draft pipeline.

### Curiosity engine (the agent asks its own questions)

Beyond probing known shapes, the daemon runs a scored **question catalog** over watched targets on the local fork every cycle — "is there value pooled in a fee faucet anyone can sweep?", "does this target read an AMM spot price it never sanitizes?", "is this a live OFT/bridge adapter with a reachable credit path?", "does unbonding pay from the balance the stake funds?", "is this a router holding lifetime approvals?" — plus **derived questions the catalog learned from its own proven drains** (one per self-learned technique: "could what drained X work here?"). Questions are ranked by **novelty** (ask-count decay), **wealth** (native float on the target), **success** (question classes with recorded wins stay hot from long-term memory), **bounty flag**, and **mutability** (first sightings first); every answer — signal or honest negative — is persisted to memory and `reports/curiosity.json`, cooldowns prevent re-asking the same question, and a per-cycle budget keeps curiosity from crowding the probe queue. A **SIGNAL** re-flags the target into the existing probe → verify-on-fresh-forks → bounty-draft pipeline. All experiments are read-only `eth_call`/`eth_getCode`/`eth_getBalance` at fork head. One-shot: `npm run curiosity -- [--fork-url URL] [--budget N] 0xTarget…`.

### LLM key pool (per-provider routing + dead-key quarantine)

The triage pool rotates ANY mix of free keys: Groq (`gsk_…`), Cerebras
(`csk-…`), and OpenRouter (`sk-or-v1…`) — endpoints and model ids are derived
from each key's prefix, never one shared URL (a shared URL is what once sent
the OpenRouter keys to Groq and produced 401 auth-error storms).
`LAB_LLM_URL` can still override one provider, named by
`LAB_LLM_URL_PROVIDER` (default groq).

- **Dead-key quarantine** — a key rejected with 401/403 is removed from the
  fleet-shared pool immediately (`reports/llm-key-quarantine.json`, 24h TTL;
  `clearKeyQuarantine()` restores it in-process) instead of being retried
  forever. Quota-shaped rejections never quarantine — cooldowns handle those.
- **Retirement-proof model defaults** — Groq → `openai/gpt-oss-120b`, Cerebras
  → `gpt-oss-120b`, OpenRouter → `nex-agi/nex-n2.5-mini:free` (the old
  `google/gemma-3-27b-it:free` and `llama-3.3-70b-versatile` slugs are retired).
- **Observability** — `triageHealth()` carries per-key cooldown state and
  quarantine counts; the daemon log prints `keys N` (live pool size) and
  per-reason counters every watch cycle.

### Sieve structured scrape lane (optional)

`SIEVE_API_KEY` (Sieve, `scrape.usesieve.com`) adds a *structured* scraping lane beside Firecrawl: instead of markdown, a run returns schema-checked columns (upgrade authority, pause power, listed audits, admin custody) plus delivered CSV/JSON files. Nothing runs without a key, and nothing spends credits until you ask.

- **Key** — `npm run sieve-login` (device-code flow, one browser approval; the key is written into `agent/.env` and never printed). If the device endpoint is unavailable on your deployment, create a key in Settings → API keys and `pbpaste | npm run sieve-login -- --paste`.
- **CLI** — `npm run sieve -- status | run --instruction "…" --url <page> --wait | resume | followup <id> --instruction "…" | download <id> | credits`.
- **Daemon** — polls in-flight sessions one step per cycle (5s→30s backoff, schedule persisted on disk), so a crash RESUMES the same run instead of starting a duplicate, and a Sieve outage is contained to that block.
- **Credits** — `POST /api/scrapes` is the only call that spends, it has no idempotency key, and it is therefore NEVER retried after a timeout/network error (the first call may have succeeded; such starts are recorded as unknown outcomes and are not retried). 429/5xx retries are safe. `LAB_SIEVE_DAILY_MAX` caps accepted runs per day; polling is free.
- **Honesty** — `schema_conformance` is surfaced, never smoothed over: a `fail` run is labeled NOT CLEAN in `reports/SIEVE.md` and in the CLI. `LAB_SIEVE_OSINT=1` opts the OSINT cycle into auto-starting one protocol-intel run per cycle (off by default — a 24/7 fleet must not start spending because a key appeared).
- **Tests** — `npm run sieve-test`: 152 hermetic checks at the HTTP boundary (request building, statuses, follow-up turn check, error mapping, never-retry-on-timeout, durable resume, secret-store writer).

### Dedicated ERC-4626 vault loop

Vault-shaped watchlist rows (recon shape "erc-4626-style vault", scanner tag
`erc4626-vault`) get their own probe loop instead of the general 3-cycle
rotation — unaudited share math is where live bugs ship. The loop is
chain-aware (each vault forks from its OWN chain's registered endpoints —
`LAB_FORK_URL` stays Ethereum-only), selects stalest-first with bounty-flagged
vaults jumping the queue, runs the standard template probe + the full
unknown-shape investigation when needed, and funnels signals through the same
2/2 fresh-fork verification bar. The idea→execution loop is closed too: every
persisted attack idea now seeds a hypothesis-ledger row (`origin: "idea"`)
whose slug maps share-inflation/reentrancy/oracle/mint prose onto the
executable probe classes — ideas become simulated, refuted-or-proven rows.

### First responder (hack-in-progress watchdog)

`--respond` (on by default in daemon mode) sweeps watched protocols every cycle and fires on a ≥5% drop between sweeps in **native ETH or any tracked major asset** — Ethereum: WETH, USDC, USDT, DAI, WBTC, cbBTC, wstETH, USDe; Arbitrum: WETH, USDC.e, USDT0, WBTC; Base: WETH, USDC (every address verified on-chain before inclusion; rebasing stETH is deliberately excluded — wstETH is the tracked wrapper). Each asset carries a **decimals-scaled incident floor** (0.5 BTC-class units, $25k stable units, 10 ETH-class units) so a 0.5-BTC payload is never ignored and stable dust never cries wolf. Asset addresses are runtime-verified (code + readable `balanceOf`) before they enter a baseline, endpoints must pass the WETH canary, and pre-asset baselines are rekeyed automatically. On an incident: local fork at head → forensic snapshot → `reports/INCIDENT-*.md` → desktop/webhook alert. First accurate reports are exactly what first-responder bounty programs pay premiums for.

### Live dashboard

Any mode with `--ui` (or standalone `npm run ui`) serves a read-only dashboard at `http://127.0.0.1:7333`:

- **Challenges** — per-challenge status, matched technique, attempts
- **Mainnet watchlist** — shape, last probe time, result per pool
- **Live findings** — the moment a fork probe reproduces a drain, it lands here
- **Generic engine** — per-target results from the template-free invariant engine: detected shape, held/violation per universal property, and which invariant fired
- **Knowledge base** — recorded wins (the agent's memory)
- **Activity** — the rolling event log (also persisted to `reports/state.json`)

The server binds loopback only, is GET-only, and cannot mutate anything. `npm run snapshot` writes a static copy to `reports/dashboard.html` for sharing.

Fork mode adds: local anvil fork (the agent itself never talks to the remote RPC), interface-shape recon (`eth_getCode` selector scan), a technique probe as a `forge script` (no `--broadcast` — simulation only), and on a reproduced drain it **halts at an approval gate** where you choose the next step. The only artifact it produces is a bug-bounty draft.

## Execution tracing (the mechanism tool)

Outcomes say WHAT happened; traces say HOW. Both tracers run on the local fork only (observation — nothing broadcasts):

- **Call graph** (`callTracer`) — who called whom, with what value, gas per frame, and exactly where a call reverted.
- **State diff** (`prestateTracer` diffMode) — the exact per-account storage and balance deltas of one call. "These 3 slots changed" instead of "profit came out".
- **Trace-backed mutation** — failed probes parse their forge trace and surface the deepest reverted frame, so retries and re-triage know WHICH subcall reverted.

```bash
# Full recon + trace one call (selector[:args], value, optional caller):
npm run toolbox -- 1 0xTarget… --trace 0xd0e30db0 --trace-value 1000000000000000
# Programmatic: traceCall(fork, target, calldata, { from?, valueWei? }) in agent/src/toolbox.ts
```

## Safety rails (non-bypassable)

- Agent RPC calls go to `127.0.0.1` / `localhost` only — hard allowlist, refuses anything else (self-tested).
- No `--broadcast`, no `--private-key`, no ledger/trezor/keystore flags anywhere — refused at the arg level (self-tested).
- No private keys are handled at all; fork sims fund the "attacker" with ephemeral `vm.deal`.
- Remote chains are forked read-only by **anvil**; the agent's JSON-RPC client physically points at the local fork.

### Supported chains

| Chain | Discovery | Notes |
|---|---|---|
| Ethereum (1) | hot pairs + factory + seeds | verified addresses |
| BNB Chain (56) | factory + seeds | Pancake V2/V3, WBNB verified |
| Avalanche (43114) | hot pairs + seeds | wrapped native bootstrap-verified via `Balancer.WETH()` |
| Sonic (146) | hot pairs + seeds | behavioral factory discovery |
| Gnosis (100) | factory + seeds | WXDAI verified |
| Base (8453) | hot pairs | rate-limit aware discovery |
| Arbitrum (42161) | factory + hot pairs | Camelot/Sushi factories |
| Optimism (10) | hot pairs | — |
| Polygon (137) | factory + hot pairs + seeds | unlocked 2026-09-18: `polygon.drpc.org` serves topic-only and address-less `eth_getLogs` on the free tier (live-verified); QuickSwap V3 + UniV3 factories + 4626-vault discovery all work without a paid RPC |
| Linea (59144) | seeds | WETH verified |
| Scroll (534352) | factory + seeds | UniV3 deterministic factory |
| Berachain (80094) | seeds | WBERA verified |
| Blast (81457) | seeds | WETH verified |
| HyperEVM (999) | factory + seeds | UniV3 deterministic factory |
| Robinhood Chain (4663) | factory + hot pairs + vaults + seed | unlocked 2026-09-18: official RPC `rpc.mainnet.chain.robinhood.com` serves address-less + full-range factory `eth_getLogs` free (429s bursts — `callRetry` handles it); PancakeSwap V3 factory verified live (374 pools, `dataWordIndex: 1` — Pancake indexes 3 topics, not 4); L2 WETH `0x0Bd7…AD73` from docs (non-canonical address); USDG stablecoin wired into TVL ranking; tokenized stocks (AMZN/USDG etc.) are the marquee surface — nobody else's free fleet is scanning this chain |

**Non-EVM** (honest out of scope — `anvil` cannot fork them): **Solana** (Sealevel/BPF), **Tron** (TVM). Adding them means a native toolchain, not a registry entry.

Every address in the registry was verified on-chain before inclusion (code presence, `symbol()`, live factory logs, or `Balancer.WETH()` bootstrap) — a memory-sourced wrong WAVAX address was caught exactly this way.

```bash
cd agent
npm run scan                              # all chains
npm run scan -- --only base,bsc --top 5   # specific chains, more probes
```
- Findings on live pools produce a disclosure draft, never an exploit payload for a drain.

## What a finding looks like

```
APPROVAL GATE — the agent has stopped and is waiting for you.
A drain reproduced against pool 0x… on the local fork.
What should the agent do with this evidence?
  1) Generate a bug-bounty report draft (recommended, legal)
  2) Print the finding only
  3) Discard
```

Then `reports/bounty-draft-*.md` — summary, local-fork reproduction steps, impact estimate, remediation notes, and a disclosure checklist to submit via Immunefi/Code4rena/Sherlock or the protocol's security contact.

## 24/7 autonomous operation

`./start.sh daemon` (from `agent/`) runs the full hunt forever:

- **Lab watch** — solves all challenges; re-solves instantly when any source file changes.
- **Watchlist probes** — re-probes watched live pools every cycle through a read-only fork; a live-state finding auto-drafts the bounty report.
- **Rotating full-market scan** — one chain per scheduled cycle across all 9 registered chains, so the whole market is surveyed continuously without hammering any single public endpoint.
- **Governance scan** — read-only authority analysis (Safe thresholds/owners, timelocks, proxy admins, shared-owner risk) written to `reports/GOVERNANCE.md`.
- **Self-healing** — the local fork is recycled periodically so chain state stays fresh; every cycle error is caught, logged, and the loop continues. Tunables: `--interval`, `--scan-every`, `--gov-every`, `--digest-hours`.
- **Instant alerts** — a real finding fires a macOS desktop notification and, if `LAB_WEBHOOK_URL` is set, a webhook (Slack/Discord/phone). Rate-limited to one ping/minute so the hunt never spams.
- **Auto-enlistment** — when the scanner classifies a live Ethereum target as a probeable class (side-entrance lender, ERC-4626 vault), it joins the continuous watchlist automatically and is re-probed every cycle. New vaults are where unaudited share math ships.
- **Fork-source failover** — fork spawns retry across all registered endpoints; only a completed anvil boot counts as proof (endpoints pass `eth_chainId` while refusing fork fetches). Default fork RPC: `rpc.flashbots.net` — override with `LAB_FORK_URL` (a private Alchemy/Infura/QuickNode endpoint is strongly recommended).
- **Daily digest** — `reports/DIGEST-LATEST.md` (and dated copies) summarize findings, drafts, watchlist, scans, governance, and lab status for the last window.
- **Parallel everywhere** — lab solving runs on N forge workers (`--workers`, default 4), watchlist probes run one local fork per slot (`--probe-workers`, default 2), and per-chain scans probe their top-N through concurrent local forks. Port ranges are partitioned (8545 watch / 8546 rotation / 8565+ scan slots / 8600+ probe slots) so nothing collides. In attached mode probes serialize automatically: one shared chain cannot take concurrent state mutations.
- **RPC failover** — the daemon health-checks its fork source every cycle and fails over to a chainId-verified mainnet fallback when it goes dark (publicnode died mid-hunt once; the hunt did not). Chain reachability checks retry before a chain is skipped.
- **LLM triage (optional)** — `LAB_LLM_KEY` enables reasoning-model triage of unknown-shape bytecode/verified source; the model proposes, the local fork disposes.
- **Crash forensics** — uncaught exceptions/rejections are persisted to `reports/daemon.crash.log`; the process tees its own output to `reports/daemon.log` so a supervisor that cannot redirect stdout still leaves a full trail. Generated sims are EIP-55-checksummed at render time and probe reverts keep their reason strings.
- **Admin-plane surveillance** — beyond balance drops, the incident watch sweeps the whole watchlist for ownership transfers, role grants/revocations, proxy upgrades, **timelock calls scheduled** (the upgrade/config window opening — with the target contract surfaced) and **pause/unpause events**; upgrades, scheduled timelock calls and pauses fire an operator notification (rate-limited like every alert), and each newly-seen upgrade still gets its implementation diff audited.
- **Monitor coverage of the watchdogs themselves** — `npm run monitor` (and the dashboard's Fleet Health strip) now also checks that the first-responder baseline is fresh (never-written or >6h old = live-exploit detection is offline) and reports the self-learned technique library's growth, so a learning loop that silently stopped is visible too.

### Bounty reward payout address

Every generated bounty draft and governance report includes the researcher's payout address (where a bounty program sends the reward):

```bash
export LAB_BOUNTY_PAYOUT=0x…   # override; default is baked into agent/src/config.ts
```

## Coverage

- **DeFi pool classes:** reentrancy, forced-fee griefing, spot-oracle manipulation, arbitrary-call flash loans, NFT batch overcredit.
- **Bridge classes:** claim-signature replay (binding omits claim id/recipient) and false deposits (credit without collateral).
- **LayerZero endpoint-core classes:** packet-hash lifecycle re-staging (consumed nonce re-verifiable → one permissionless `lzReceive` replays the side effect — the KelpDAO rsETH class), OApp claim-once defense-in-depth, nilify kill-switch effectiveness, OFT shared-decimal conservation under fuzzing (`src/lz/LzEndpointTestbed.sol` + `test/11_LayerZeroEndpointCore.t.sol`, the endpoint-core half of the LayerZero threat model).
- **Token/vault classes:** ERC-4626 share inflation (donation attack) — with a live-fork probe: the scanner detects vault-shaped contracts and simulates a donation + late-depositor harm test locally (no broadcast, fork-state funding only).
- **Key management:** threshold/EOA-owner/shared-key risks on multisigs, proxy admins, timelocks.

Each class ships as: vulnerable lab challenge + ground-truth test + attacker contract + agent template + fuzz-synthesis recipe + static detector.

## Extending

- **New technique:** add `src/attackers/<Name>Attacker.sol` + `agent/templates/<name>.tmpl.sol` + a `Strategy` entry in `agent/src/strategies.ts`.
- **New synth recipe:** add an invariant harness in `agent/src/synth.ts` (`SYNTH_RECIPES`) — the fuzzer then discovers the bug class from primitives alone.
- **New generic shape/invariant:** extend `detectShape` + the property catalog in `agent/src/genharness.ts` — the generic engine then harnesses every contract with that shape, template-free.
- **New pool shape in fork mode:** extend `reconPool`'s selector table and add a probe renderer in `agent/src/fork.ts`.
- **Stronger discovery:** swap the regex feature extractor for bytecode-shape fingerprints; the pipeline is unchanged.
