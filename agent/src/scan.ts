// Chain registry + on-chain target discovery for the full-market scanner.
//
// SAFETY MODEL (same as the rest of the agent):
//  - Simulation RPCs go ONLY to a local anvil fork (127.0.0.1, enforced in
//    AnvilFork.rpc). Nothing is ever broadcast.
//  - The one remote touchpoint is infraRpcWithFailover() below: strictly
//    read-only calls (eth_chainId / eth_blockNumber / eth_getLogs /
//    eth_getBalance) against PUBLIC endpoints, used to discover and rank
//    targets. No state-changing call is possible through this helper.
//
// Every address here was verified on-chain (eth_getCode) before inclusion —
// the registry never trusts memory alone.
export interface ChainSpec {
  id: string; // decimal chain id
  name: string;
  /** Endpoints tried in order for read-only DISCOVERY. */
  rpcs: string[];
  wrappedNative: string;
  factories: FactorySpec[];
}

export interface FactorySpec {
  label: string; // e.g. "uniswap-v3"
  address: string;
  event: string; // event signature (documentation / rehashing)
  topic0: string; // keccak256 of the event signature (verified)
  /** Index of the topic carrying the new pool address (topics[0] = sig). */
  pairTopicIndex?: number;
  /** Fallback: pool address inside `data` at this 32-byte word (0-based). */
  dataWordIndex?: number;
}

export interface ScanTarget {
  chain: ChainSpec;
  address: string;
  source: "factory" | "seed" | "hot-pair";
  factory?: string;
}

const UNIV2_PAIR_CREATED = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9";
const UNIV3_POOL_CREATED = "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118";

export const CHAINS: ChainSpec[] = [
  {
    id: "1",
    name: "ethereum",
    // Fork-capable endpoints verified 2026-09-12 (blastapi first — fastest, full archive).
    // cloudflare/ankr/publicnode removed: -32046 rate-limit or auth paywall on archive.
    rpcs: ["https://eth-mainnet.public.blastapi.io", "https://eth.merkle.io", "https://public.1rpc.io/eth", "https://ethereum-public.nodies.app", "https://mainnet.gateway.tenderly.co", "https://rpc.mevblocker.io", "https://rpc.flashbots.net", "https://eth.drpc.org", "https://ethereum-rpc.publicnode.com"], // publicnode eth re-added 2026-09-28 (chainId 0x1 verified; the old -32046 note applied to a stale host)
    wrappedNative: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH — verified
    factories: [
      {
        label: "uniswap-v2",
        address: "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", // verified on-chain
        event: "PairCreated(address,address,address,uint256)",
        topic0: UNIV2_PAIR_CREATED,
        dataWordIndex: 0, // pair addr = 1st non-indexed word (verified on live BSC logs)
      },
      {
        label: "uniswap-v3",
        address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", // verified on-chain
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 0, // sig + 4 indexed topics → pool is 1st data word (ABI)
      },
    ],
  },
  {
    id: "56",
    name: "bsc",
    // 1rpc added after live diagnosis: publicnode serves bsc getLogs as
    // SUCCESSFUL EMPTY ARRAYS under load (throttle wall disguised as a quiet
    // chain), blastapi/binance hard rate-limit — 1rpc is the one free
    // endpoint that answers topic-filtered queries honestly here.
    rpcs: ["https://bsc-rpc.publicnode.com", "https://1rpc.io/bnb", "https://bsc-mainnet.public.blastapi.io", "https://bsc-dataseed.binance.org"],
    wrappedNative: "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", // WBNB — verified (symbol + balancer.WETH())
    factories: [
      {
        label: "pancake-v2",
        address: "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73", // verified on-chain + live PairCreated logs
        event: "PairCreated(address,address,address,uint256)",
        topic0: UNIV2_PAIR_CREATED,
        dataWordIndex: 0, // pair addr = 1st non-indexed word (verified on live logs)
      },
      {
        label: "pancake-v3",
        address: "0x0BFbCF9fa4f9C56B0F40a671Ad40E0805A091865", // verified on-chain
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 0, // sig + 4 indexed topics → pool is 1st data word (ABI)
      },
    ],
  },
  {
    id: "43114",
    name: "avalanche",
    rpcs: ["https://api.avax.network/ext/bc/C/rpc", "https://avalanche.drpc.org", "https://avalanche-c-chain-rpc.publicnode.com"],
    wrappedNative: "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7", // WAVAX — bootstrap-verified via balancer.WETH() + symbol
    factories: [], // memory-sourced factory addresses all failed verification; hot-pair path on api.avax.network works
  },
  {
    id: "146",
    name: "sonic",
    rpcs: ["https://rpc.soniclabs.com", "https://sonic.drpc.org"], // drpc added 2026-09-28 (0x92 verified): soniclabs alone = single point of failure
    wrappedNative: "0x039e2fb66102314ce7b64ce5ce3e5183bc94ad38", // wS — verified on-chain
    factories: [], // active v3-style factories exist (discovered behaviorally) but event sigs unverified; hot-pair path works
  },
  {
    id: "100",
    name: "gnosis",
    rpcs: ["https://gnosis-rpc.publicnode.com", "https://gnosis.drpc.org", "https://rpc.gnosischain.com"],
    wrappedNative: "0xe91d153e0b41518a2ce8dd3d7944fa863463a97d", // WXDAI — verified
    factories: [
      {
        label: "honeyswap-v2",
        address: "0xA818b4F111Ccac7AA31D0BCc0806d64F2E0737D7", // verified on-chain
        event: "PairCreated(address,address,address,uint256)",
        topic0: UNIV2_PAIR_CREATED,
        dataWordIndex: 0,
      },
    ],
  },
  {
    id: "8453",
    name: "base",
    rpcs: ["https://mainnet.base.org", "https://base.drpc.org", "https://base-rpc.publicnode.com"],
    wrappedNative: "0x4200000000000000000000000000000000000006", // WETH — verified
    factories: [
      {
        label: "uniswap-v3",
        address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", // deterministic cross-chain deployment — verified
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 4,
      },
      {
        label: "sushi-v2",
        address: "0xc35DADB65012eC5796536bD9864eD8773aBc74C4", // verified on-chain
        event: "PairCreated(address,address,address,uint256)",
        topic0: UNIV2_PAIR_CREATED,
        dataWordIndex: 0,
      },
    ],
  },
  {
    id: "42161",
    name: "arbitrum",
    rpcs: ["https://arb1.arbitrum.io/rpc", "https://arbitrum.drpc.org", "https://arbitrum-one-rpc.publicnode.com"],
    wrappedNative: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", // WETH — verified
    factories: [
      {
        label: "uniswap-v3",
        address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", // verified on-chain
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 4,
      },
      {
        label: "sushi-v2",
        address: "0xc35DADB65012eC5796536bD9864eD8773aBc74C4", // verified on-chain
        event: "PairCreated(address,address,address,uint256)",
        topic0: UNIV2_PAIR_CREATED,
        dataWordIndex: 1,
      },
      {
        label: "camelot-v2",
        address: "0x6EcCab422D763aC031210895C81787E87B43A652", // verified on-chain
        event: "PairCreated(address,address,address,uint256)", // topic confirmed on-chain
        topic0: UNIV2_PAIR_CREATED,
        dataWordIndex: 0,
      },
    ],
  },
  {
    id: "10",
    name: "optimism",
    rpcs: ["https://mainnet.optimism.io", "https://optimism.drpc.org", "https://optimism-rpc.publicnode.com"],
    wrappedNative: "0x4200000000000000000000000000000000000006", // WETH — verified
    factories: [
      {
        label: "uniswap-v3",
        address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", // verified on-chain
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 4,
      },
    ],
  },
  {
    id: "137",
    name: "polygon",
    // 2026-09-18 UNLOCK: the old list led with polygon-rpc.com, which is now
    // DEAD (tenant disabled, -32051) and returned string-shaped error bodies
    // that extracted as "RPC …: undefined". Live-verified getLogs support
    // (2026-09-18, free tier, no auth): polygon.drpc.org serves BOTH
    // topic-only and address-less eth_getLogs (≤10k-block windows on the
    // free plan — the adaptive shrink in getLogsWithFailover handles it);
    // polygon-bor-rpc.publicnode.com serves address-less and allows
    // topic-only with a res: restriction. Factory + hot-pair + vault
    // discovery now run on Polygon with zero paid RPC.
    rpcs: ["https://polygon.drpc.org", "https://polygon-bor-rpc.publicnode.com", "https://1rpc.io/matic"], // 1rpc added 2026-09-28 (0x89 verified)
    wrappedNative: "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", // WMATIC — verified
    factories: [
      {
        label: "uniswap-v3",
        address: "0x1F98431c8aD98523631AE4a59f267346ea31F984", // verified on-chain
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 4,
      },
      {
        label: "quickswap-v2",
        address: "0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32", // verified on-chain
        event: "PairCreated(address,address,address,uint256)",
        topic0: UNIV2_PAIR_CREATED,
        dataWordIndex: 0,
      },
    ],
  },
  // ---- Chains added 2026-09-14 (RPC + wrapped-native verified live before inclusion) ----
  {
    id: "59144",
    name: "linea",
    rpcs: ["https://rpc.linea.build", "https://linea.drpc.org", "https://linea-rpc.publicnode.com"],
    wrappedNative: "0xe5D7C2a44FfDDf6b295A15c148167daaAf5Cf34f", // WETH — verified (6250-char code)
    factories: [], // hot-pair discovery covers it until a factory is verified
  },
  {
    id: "534352",
    name: "scroll",
    rpcs: ["https://rpc.scroll.io", "https://scroll.drpc.org", "https://scroll-rpc.publicnode.com"],
    wrappedNative: "0x5300000000000000000000000000000000000004", // WETH — verified via symbol()="WETH"
    factories: [
      {
        label: "uniswap-v3", // deterministic cross-chain deployment — verified on-chain (4220-char code)
        address: "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 4,
      },
    ],
  },
  {
    id: "80094",
    name: "berachain",
    rpcs: ["https://rpc.berachain.com", "https://berachain.drpc.org", "https://berachain-rpc.publicnode.com"],
    wrappedNative: "0x6969696969696969696969696969696969696969", // WBERA — verified (5194-char code)
    factories: [], // hot-pair discovery covers it until a factory is verified
  },
  {
    id: "81457",
    name: "blast",
    rpcs: ["https://rpc.blast.io", "https://blast.drpc.org", "https://blast-rpc.publicnode.com"],
    wrappedNative: "0x4300000000000000000000000000000000000004", // WETH — verified (3236-char code)
    factories: [], // hot-pair discovery covers it (thruster/agni sigs unverified)
  },
  {
    id: "999",
    name: "hyperevm",
    rpcs: ["https://rpc.hyperliquid.xyz/evm", "https://hyperliquid.drpc.org"], // drpc added 2026-09-28 (0x3e7 verified): official endpoint alone = single point of failure
    wrappedNative: "0x5555555555555555555555555555555555555555", // WHYPE — verified (4084-char code)
    factories: [
      {
        label: "uniswap-v3", // deterministic cross-chain deployment — verified on-chain (4220-char code)
        address: "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 4,
      },
    ],
  },
  // ---- Chain added 2026-09-18 (RPC + factory + wrapped-native verified live before inclusion) ----
  {
    id: "4663",
    name: "robinhood",
    // 2026-09-18 UNLOCK (live-verified): the official RPC serves BOTH
    // address-less eth_getLogs (1281 logs/3 blocks) AND full-range factory
    // topic-only getLogs (374 PancakeSwap V3 PoolCreated events) — but it
    // 429s bursts, which callRetry + the 4-wide chunking in discoverHotPairs
    // already tolerate. publicnode is the basic fallback (it 403s getLogs
    // outright), ordofi serves address-less getLogs only.
    // rpc.arrowrpc.com is DEAD (error 1033) — deliberately not added.
    rpcs: ["https://rpc.mainnet.chain.robinhood.com", "https://robinhood-rpc.publicnode.com", "https://rpc.ordofi.network"], // ordofi added 2026-09-28 (0x1237 = 4663 verified)
    wrappedNative: "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73", // L2 Weth per docs.robinhood.com/chain/protocol-contracts — NON-canonical address (canonical 0x4200…0006/0x82aF… are empty here), verified live (code + decimals 18)
    factories: [
      {
        // PancakeSwap V3 is the chain's active Uniswap-family deployment —
        // verified on-chain (7720-char code) with 374 live PoolCreated events
        // full-range. NOTE: Pancake's PoolCreated indexes only token0/token1/fee
        // (tickSpacing is NOT indexed, unlike UniV3), so the pool address is the
        // 2nd data word — extracted pool's token0()/token1() answered with real
        // ERC20s (AMZN, USDG), which pins this empirically.
        label: "pancakeswap-v3",
        address: "0x0BFbCF9fa4f9C56B0F40a671Ad40E0805A091865",
        event: "PoolCreated(address,address,uint24,int24,address)",
        topic0: UNIV3_POOL_CREATED,
        dataWordIndex: 1,
      },
    ],
  },
];

const RPC_TIMEOUT_MS = 12_000;

/** Single read-only JSON-RPC call against one PUBLIC endpoint. Exported for
 * the responder's canary-validated balance reads (native + tracked assets). */
export async function infraRpcOnce(url: string, method: string, params: unknown[], timeoutMs: number): Promise<any> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const ct = res.headers.get("content-type") ?? "";
  if (!ct.includes("json")) throw new Error(`non-JSON response from ${new URL(url).host}`);
  const j: any = await res.json();
  if (j.error) {
    // Some providers stringify the error (polygon-rpc.com:
    // {"error":"message: API key disabled…"}) — extract honestly either way.
    const msg = typeof j.error === "string" ? j.error : j.error?.message ?? JSON.stringify(j.error).slice(0, 160);
    throw new Error(`RPC ${method}: ${msg}`);
  }
  return j.result;
}

/** Read-only JSON-RPC with endpoint failover. Discovery only — never simulation. */
export async function infraRpcWithFailover(chain: ChainSpec, method: string, params: unknown[] = []): Promise<any> {
  let lastErr: Error | null = null;
  for (const url of chain.rpcs) {
    try {
      return await infraRpcOnce(url, method, params, RPC_TIMEOUT_MS);
    } catch (e) {
      lastErr = e as Error;
    }
  }
  throw lastErr ?? new Error(`all endpoints failed for ${method}`);
}

/**
 * eth_getLogs with EMPTY-RESULT CONSENSUS.
 *
 * infraRpcWithFailover trusts the first endpoint that answers without error —
 * but several free endpoints respond to getLogs under load with a THROTTLE
 * WALL shaped as a successful empty array (observed live on bsc publicnode:
 * 0 logs for a window that eth_getBlockByNumber proves holds ~2,000 events,
 * minutes after the same query returned 1,988). The result: "quiet chain"
 * illusions, zero hot pairs, and failover logic that never fires because
 * nothing ever errors.
 *
 * Fix: an empty result is only believed when EVERY endpoint agrees. The first
 * non-empty answer wins; a lying endpoint's empty answer can no longer mask
 * activity another endpoint would have reported. Cost is bounded: extra calls
 * only happen when an endpoint returns empty (common exactly where the bug
 * bites, rare on healthy chains).
 */
export async function getLogsConsensus(chain: ChainSpec, filter: Record<string, unknown>): Promise<any[]> {
  let lastErr: Error | null = null;
  let sawEmpty = false;
  for (const url of chain.rpcs) {
    try {
      const r = (await infraRpcOnce(url, "eth_getLogs", [filter], RPC_TIMEOUT_MS)) as any[];
      const logs = Array.isArray(r) ? r : [];
      if (logs.length > 0) return logs; // non-empty: trust it
      sawEmpty = true; // one honest-looking empty — but keep asking
    } catch (e) {
      lastErr = e as Error; // endpoint dead / errored: try the next
    }
  }
  // Every endpoint that ANSWERED said empty → genuinely quiet (at least one
  // answer was seen). If nothing ever answered, rethrow: the shrink/escalation
  // stages are error-driven (policy walls, range caps) and must see the error.
  if (!sawEmpty && lastErr) throw lastErr;
  return [];
}

export async function chainReachable(chain: ChainSpec): Promise<boolean> {
  // Two attempts: a transient timeout on a free endpoint should not cost a
  // whole rotation visit (the 24/7 daemon revisits every cycle).
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const id = await infraRpcWithFailover(chain, "eth_chainId");
      if (BigInt(id).toString() === chain.id) return true;
    } catch {
      // fall through to retry
    }
    if (attempt === 0) await new Promise((r) => setTimeout(r, 1_500));
  }
  return false;
}

/** eth_getLogs with adaptive window shrinking: endpoints cap archive depth. */
export async function getLogsWithFailover(
  chain: ChainSpec,
  filter: Record<string, unknown>,
  blocksBack: number
): Promise<{ logs: any[]; actualBack: number }> {
  let back = blocksBack;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const heightHex = (await infraRpcWithFailover(chain, "eth_blockNumber")) as string;
      const start = "0x" + (BigInt(heightHex) - BigInt(back)).toString(16);
      const logs = (await infraRpcWithFailover(chain, "eth_getLogs", [
        { ...filter, fromBlock: start, toBlock: "latest" },
      ])) as any[];
      return { logs: Array.isArray(logs) ? logs : [], actualBack: back };
    } catch (e) {
      const msg = (e as Error).message.toLowerCase();
      // "results"/"10000" = the endpoint's result-count cap (drpc), which on
      // busy chains fires long before any archive-range error would.
      if (/archive|limit|range|token|too large|50 block|results|10000|more than/.test(msg) && back > 50) {
        back = Math.max(50, Math.floor(back / 5));
        continue; // shrink window and retry
      }
      throw e;
    }
  }
  return { logs: [], actualBack: 0 };
}

/**
 * Discover AMM pools from factory events over a bounded recent window.
 * eth_getLogs is read-only; the window shrinks automatically when the
 * endpoint rejects deep archive queries.
 */
export async function discoverAmmTargets(chain: ChainSpec, blocksBack = 200_000, maxPerFactory = 15): Promise<ScanTarget[]> {
  const targets: ScanTarget[] = [];

  for (const factory of chain.factories) {
    try {
      const { logs } = await getLogsWithFailover(
        chain,
        { address: factory.address, topics: [factory.topic0] },
        blocksBack
      );
      for (const log of logs) {
        const topics: string[] = log.topics ?? [];
        const data: string = typeof log.data === "string" ? log.data : "0x";
        let addr: string | null = null;

        if (factory.pairTopicIndex !== undefined && topics.length > factory.pairTopicIndex) {
          addr = `0x${topics[factory.pairTopicIndex]!.slice(-40)}`;
        } else if (factory.dataWordIndex !== undefined && data.length >= 2 + (factory.dataWordIndex + 1) * 64) {
          const word = data.slice(2 + factory.dataWordIndex * 64, 2 + (factory.dataWordIndex + 1) * 64);
          if (/^[0-9a-fA-F]{64}$/.test(word) && BigInt("0x" + word) !== 0n) {
            addr = `0x${word.slice(-40)}`;
          }
        }
        if (addr && /^0x[0-9a-fA-F]{40}$/.test(addr)) {
          targets.push({ chain, address: addr.toLowerCase(), source: "factory", factory: factory.label });
        }
      }
    } catch {
      continue; // endpoint refused even a tiny window — skip this factory
    }
  }
  // newest last in getLogs order; keep the most recent creations, dedup
  const tail = targets.slice(-maxPerFactory);
  const seen = new Set<string>();
  return tail.filter((t) => (seen.has(t.address) ? false : (seen.add(t.address), true)));
}

/** Curated high-value starting points (all verified on-chain). */
export const SEED_TARGETS: Record<string, string[]> = {
  "1": [
    "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", // Aave V2 lending pool — verified
    "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", // Aave V3 pool — verified
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified
  ],
  "56": [
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified (WETH() responded)
    "0x0eD7e52944161450477ee417DE9Cd3a859b14fD0", // PancakeSwap V2 pair CAKE/WBNB — high TVL
  ],
  "43114": [
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified (WETH() responded)
    "0x512eb749541b7cf294be882d636218c84a5e9e5f", // v2-style factory — behaviorally discovered (4 active pairs)
  ],
  "146": [
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified (WETH() responded)
    "0xcd2d0637c94fe77c2896bbcbb174ceffb08de6d7", // v3-style factory — behaviorally discovered (13 active pairs)
    "0x56cfc796bc88c9c7e1b38c2b0af9b7120b079aef", // v3-style factory — behaviorally discovered (4 active pairs)
  ],
  "100": [
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified (WETH() responded)
  ],
  // Base — Aave V3 + Balancer + Aerodrome (largest Base DEX)
  "8453": [
    "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5", // Aave V3 Pool on Base — verified
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified (WETH() responded)
    "0xcDAC0d6c6C59727a65F871236188350531885C43", // Aerodrome Finance Router — largest Base DEX
  ],
  // Arbitrum — Aave V3 + Balancer + GMX vault
  "42161": [
    "0x794a61358D6845594F94dc1DB02A252b5b4814aD", // Aave V3 Pool on Arbitrum — verified
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified (WETH() responded)
    "0x489ee077994B6658eAfA855C308275EAd8097C4A", // GMX Vault on Arbitrum — high TVL
  ],
  // Optimism — Aave V3 + Balancer + Velodrome
  "10": [
    "0x794a61358D6845594F94dc1DB02A252b5b4814aD", // Aave V3 Pool on Optimism — verified
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified (WETH() responded)
    "0x9c12939390052919aF3155f41Bf4160Fd3666A6f", // Velodrome Finance Router — largest Optimism DEX
  ],
  // Polygon — Aave V3 + Balancer + QuickSwap
  "137": [
    "0x794a61358D6845594F94dc1DB02A252b5b4814aD", // Aave V3 Pool on Polygon — verified
    "0xBA12222222228d8Ba445958a75a0704d566BF2C8", // Balancer vault — verified (WETH() responded)
    "0xf5b509bB0909a69B1c207E495f687a596C168E12", // QuickSwap V3 Factory on Polygon — verified
  ],
  // Robinhood Chain — tokenized-equities AMM pool, verified live 2026-09-18
  // (PancakeSwap V3 PoolCreated full-range; token0 = AMZN stock token,
  // token1 = USDG — both answered symbol() on-chain)
  "4663": [
    "0xc91ef991cf16916ebdd29fd25dfbbf3a3cd161ba", // PancakeSwap V3 pool AMZN/USDG — verified
  ],
};

/**
 * Non-EVM chains: honestly out of scope for the anvil-based fork machinery.
 * The scanner reports them as "requires native toolchain" instead of silently
 * skipping or (worse) pretending an EVM fork represents them.
 */
export const NON_EVM_CHAINS: { name: string; vm: string; status: string }[] = [
  {
    name: "solana",
    vm: "Sealevel (Rust/BPF programs)",
    status: "requires native toolchain (Anchor + a Solana fork/simulator); not reachable through anvil",
  },
  {
    name: "tron",
    vm: "TVM (EVM-adjacent, distinct RPC)",
    status: "requires fullnode + triggerconstantcontract flow; not reachable through anvil",
  },
];

export function seedTargets(chain: ChainSpec): ScanTarget[] {
  return (SEED_TARGETS[chain.id] ?? []).map((address) => ({
    chain,
    address: address.toLowerCase(),
    source: "seed" as const,
  }));
}

// ---------------- hot-market discovery (free-endpoint friendly) ------------
// Factory PoolCreated events are RARE; deep getLogs windows need paid endpoints.
// Active markets, however, emit Swap events CONSTANTLY — and small chain-wide
// log windows are allowed on most endpoints. Pre-filter emitters by canonical
// Swap topics (UniV2/UniV3), then classify by behavior (getReserves = v2,
// slot0/liquidity = v3) and rank by wrapped-native exposure.
const SEL_GETRESERVES = "0902f1ac"; // getReserves()
const SEL_TOKEN0 = "0dfe1681"; // token0()
const SEL_TOKEN1 = "d21220a7"; // token1()
const SEL_LIQUIDITY = "1a686508"; // liquidity()
// cast-verified Swap topics (UniV2 / UniV3) — exported so probes, tests and
// tooling share one source of truth.
export const TOPIC_V2_SWAP = "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822";
export const TOPIC_V3_SWAP = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67";
export const SWAP_TOPICS = [TOPIC_V2_SWAP, TOPIC_V3_SWAP];

export interface HotPair {
  address: string;
  kind: "v2" | "v3";
  token0: string;
  token1: string;
  reserve0: bigint;
  reserve1: bigint;
  /** Reserve held on the wrapped-native side (0 if neither side is native). */
  nativeReserve: bigint;
  /** v3 in-range liquidity (0 for v2 pools). */
  liquidity?: bigint;
}

function padAddr(addr: string): string {
  return addr.replace(/^0x/, "").toLowerCase().padStart(64, "0");
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Read-only call that tolerates endpoint rate limits (wait + retry). */
async function callRetry(chain: ChainSpec, method: string, params: unknown[], retries = 2): Promise<any> {
  for (let a = 0; ; a++) {
    try {
      return await infraRpcWithFailover(chain, method, params);
    } catch (e) {
      if (a < retries && /rate limit|too many|429/i.test((e as Error).message)) {
        await sleep(1500 * (a + 1));
        continue;
      }
      throw e;
    }
  }
}

export async function discoverHotPairs(
  chain: ChainSpec,
  blocksBack = 40,
  maxCandidates = 120,
  maxPairs = 40
): Promise<HotPair[]> {
  const heightHex = (await infraRpcWithFailover(chain, "eth_blockNumber")) as string;
  const height = BigInt(heightHex);

  // Chain-wide logs over a tiny recent window. High-throughput chains can
  // exceed endpoint result caps, so the window shrinks until the query fits.
  // POLICY WALLS are different from range caps: publicnode-style endpoints
  // reject every UNADDRESSED query outright ("Please specify an address…") —
  // shrinking the window can never fix a policy error, and 6 whole chains
  // (blast/bsc/arbitrum/linea/scroll/berachain) were silently producing ZERO
  // hot pairs because of it. For those, fall back to a TOPIC-ONLY Swap-event
  // filter: same discovery value (live pools are Swap emitters), accepted by
  // endpoints that refuse unaddressed queries.
  let logs: any[] | null = null;
  let back = blocksBack; // stage 0: unaddressed all-events window (shrink on range caps)
  let swapOnly = false; // stage 1: topic-only Swap filter; stage 2 below: wide last chance
  for (let attempt = 0; attempt < 10 && logs === null; attempt++) {
    const from = "0x" + (height - BigInt(back)).toString(16);
    const filter: Record<string, unknown> = swapOnly
      ? { topics: [[TOPIC_V2_SWAP, TOPIC_V3_SWAP]], fromBlock: from, toBlock: "latest" }
      : { fromBlock: from, toBlock: "latest" };
    try {
      // Empty-result consensus: a throttled endpoint's empty-success must not
      // be believed alone (see getLogsConsensus — this exact lie zeroed bsc).
      const result = (await getLogsConsensus(chain, filter)) as any[];
      logs = Array.isArray(result) ? result : [];
    } catch (e) {
      const msg = (e as Error).message.toLowerCase();
      if (!swapOnly && /specify an address|restrictions/.test(msg)) {
        swapOnly = true; // policy wall → same window, topic-filtered
        continue;
      }
      if (/limit|too large|range|timeout|capacity|5000|10000|exceed/.test(msg) && back > 1) {
        // An ALL-EVENTS window that hits a provider's result/range cap has two
        // escapes: shrink the window, or filter by topic. Shrinking blindly
        // NEVER re-enables chains whose caps are tiny relative to chain
        // activity (bsc: even ~5 all-events blocks exceed caps; arbitrum the
        // same) — so instead of over-shrinking, escalate to the TOPIC-ONLY
        // stage: topic-filtered queries are index-backed and cheap for
        // providers. Once topic-only, keep a generous 150-block floor:
        // low-activity chains simply have few Swap events per window.
        if (swapOnly) {
          back = Math.max(150, Math.floor(back / 4));
        } else {
          swapOnly = true;
          if (back <= 60) back = Math.max(back, 600); // quiet chains need a real window
        }
        continue;
      }
      if (back <= 1) return []; // even the smallest window is refused this round
      throw e;
    }
  }
  if (!logs) return [];

  // A tiny accepted window (aggressive shrink on a quiet chain) often contains
  // zero Swap events. Topic-only queries are index-backed and cheap for
  // providers, so give discovery one WIDE last chance before reporting zero —
  // the difference between "no live pools" and "window too small to see one".
  if (logs.length === 0 && back < 600) {
    try {
      const from = "0x" + (height - 600n).toString(16);
      // callRetry: free endpoints 429 bursts, and this query is the one that
      // turns "0 pairs" into real coverage — worth the retry.
      const wide = (await getLogsConsensus(chain, {
        topics: [SWAP_TOPICS], fromBlock: from, toBlock: "latest",
      })) as any[];
      if (Array.isArray(wide) && wide.length > 0) {
        logs = wide;
        back = 600;
      }
    } catch { /* zero stays zero — honest */ }
  }

  // Pre-filter by canonical Swap topics: emitters of UniV2/UniV3 Swap events
  // are almost certainly live AMM pools — this avoids burning eth_getCode
  // calls on the token-transfer noise that dominates raw windows.
  const swapEmitters = new Set<string>();
  for (const l of logs) {
    const t0 = String(l.topics?.[0] ?? "").toLowerCase();
    if (t0 === TOPIC_V2_SWAP || t0 === TOPIC_V3_SWAP) {
      const a = String(l.address ?? "").toLowerCase();
      if (a) swapEmitters.add(a);
    }
  }
  if (swapEmitters.size === 0) return [];

  // Classify by behavior and read market state. Free endpoints rate-limit
  // bursts (observed on base: every eth_call in an 8-wide chunk rejected),
  // so: small chunks, spacing between chunks, and per-call rate-limit retry.
  const scope = [...swapEmitters].slice(0, maxCandidates);
  const pairs: HotPair[] = [];
  const wn = chain.wrappedNative.toLowerCase();
  for (let i = 0; i < scope.length; i += 4) {
    const chunk = scope.slice(i, i + 4);
    const settled = await Promise.all(chunk.map((pair) => classifyPool(chain, pair, wn)));
    for (const p of settled) if (p) pairs.push(p);
    if (i + 4 < scope.length) await sleep(200); // stay under burst limits
  }

  pairs.sort((a, b) => (b.nativeReserve > a.nativeReserve ? 1 : b.nativeReserve < a.nativeReserve ? -1 : 0));
  if (pairs.length > 0) return pairs.slice(0, maxPairs);
  // Window paths (all-events, topic-only, wide last chance) all yielded zero —
  // the chain is either genuinely quiet or sitting behind a throttle wall that
  // rejects chain-wide queries. Fall back to per-pool ADDRESS-filtered Swap
  // counting: the one query shape every free endpoint serves (publicnode-style
  // policy walls REQUIRE an address), scored against factory-discovered pools.
  return discoverHotPairsAddressed(chain, 600, Math.min(maxCandidates, 24), Math.min(maxPairs, 12));
}

/** Behavior classifier shared by both hot-pair discovery paths: emits Swap and
 * reads as v2 (real reserves) or v3 (in-range liquidity) → HotPair; else null. */
async function classifyPool(chain: ChainSpec, pair: string, wn: string): Promise<HotPair | null> {
  try {
    const t0 = (await callRetry(chain, "eth_call", [{ to: pair, data: `0x${SEL_TOKEN0}` }, "latest"])) as string;
    const t1 = (await callRetry(chain, "eth_call", [{ to: pair, data: `0x${SEL_TOKEN1}` }, "latest"])) as string;
    if (typeof t0 !== "string" || typeof t1 !== "string" || t0.length < 66 || t1.length < 66) return null;
    const token0 = `0x${t0.slice(-40)}`.toLowerCase();
    const token1 = `0x${t1.slice(-40)}`.toLowerCase();
    const res = (await callRetry(chain, "eth_call", [{ to: pair, data: `0x${SEL_GETRESERVES}` }, "latest"]).catch(() => null)) as string | null;
    if (typeof res === "string" && res.length >= 194) {
      // v2-style: reserves are real balances
      const reserve0 = BigInt(`0x${res.slice(2 + 0, 2 + 64)}`);
      const reserve1 = BigInt(`0x${res.slice(2 + 64, 2 + 128)}`);
      const nativeReserve = token0 === wn ? reserve0 : token1 === wn ? reserve1 : 0n;
      return { address: pair, kind: "v2" as const, token0, token1, reserve0, reserve1, nativeReserve };
    }
    // v3-style: reserves are virtual; rank by in-range liquidity instead
    const liq = (await callRetry(chain, "eth_call", [{ to: pair, data: `0x${SEL_LIQUIDITY}` }, "latest"]).catch(() => null)) as string | null;
    if (typeof liq === "string" && liq.length >= 66) {
      const L = BigInt(liq);
      if (L > 0n) {
        return { address: pair, kind: "v3" as const, token0, token1, reserve0: 0n, reserve1: 0n, nativeReserve: L, liquidity: L };
      }
      return null;
    }
    return null; // emits Swap but neither v2- nor v3-shaped — skip
  } catch {
    return null; // not a readable pool — skip
  }
}

/**
 * Address-filtered hot-pair discovery — the throttle-wall-proof fallback.
 *
 * Instead of chain-wide windows (which high-traffic chains + free endpoints
 * refuse, silently or loudly), take the chain's factory-discovered pools and
 * count Swap events PER POOL over a recent window, then classify the most
 * active ones. Every endpoint serves address-filtered getLogs; the "hot"
 * signal is real swap activity rather than raw reserve size.
 */
export async function discoverHotPairsAddressed(
  chain: ChainSpec,
  blocksBack = 600,
  maxPools = 20,
  maxPairs = 12
): Promise<HotPair[]> {
  const height = BigInt(await infraRpcWithFailover(chain, "eth_blockNumber"));
  const from = "0x" + (height - BigInt(blocksBack)).toString(16);
  const poolTargets = await discoverAmmTargets(chain, 300_000, Math.max(maxPools, 20));
  const scored: { addr: string; swaps: number }[] = [];
  for (const t of poolTargets.slice(0, maxPools)) {
    try {
      const logs = await getLogsConsensus(chain, {
        address: t.address,
        topics: [SWAP_TOPICS],
        fromBlock: from,
        toBlock: "latest",
      });
      if (logs.length > 0) scored.push({ addr: t.address, swaps: logs.length });
    } catch {
      // pool query refused this round — skip
    }
    await sleep(120); // stay under burst limits
  }
  scored.sort((a, b) => b.swaps - a.swaps);
  const wn = chain.wrappedNative.toLowerCase();
  const pairs: HotPair[] = [];
  for (const s of scored.slice(0, maxPairs)) {
    const p = await classifyPool(chain, s.addr, wn);
    if (p) pairs.push(p);
  }
  pairs.sort((a, b) => (b.nativeReserve > a.nativeReserve ? 1 : b.nativeReserve < a.nativeReserve ? -1 : 0));
  return pairs;
}

// ERC-4626 Deposit event topic — keccak256("Deposit(address,address,uint256,uint256)") (cast-verified).
// Exported for fork.ts's depositor resolver (guarded-vault impersonation).
export const TOPIC_ERC4626_DEPOSIT = "0xdcbc1c05240f31ff3ad067ef1ee35ce4997762752e3a095284754544f4c709d7";
// ERC-4626 Withdraw event topic — keccak256("Withdraw(address,address,address,uint256,uint256)") (cast-verified)
const TOPIC_ERC4626_WITHDRAW = "0xfbde797d201c681b91056529119e0b02407c7bb96a4a2c75c01fc9667232c8db";

/** Discover active ERC-4626 vaults by scanning for recent Deposit/Withdraw events.
 * This finds yield-bearing vaults (staking, lending, yield aggregators) that the
 * AMM Swap-event path completely misses. Runs after hot-pair discovery so it
 * reuses the same block window without an extra eth_blockNumber call. */
export async function discoverHotVaults(
  chain: ChainSpec,
  blocksBack = 40,
  maxVaults = 20
): Promise<ScanTarget[]> {
  const heightHex = (await infraRpcWithFailover(chain, "eth_blockNumber")) as string;
  const height = BigInt(heightHex);
  let logs: any[] | null = null;
  let back = blocksBack;
  for (let attempt = 0; attempt < 6 && logs === null; attempt++) {
    const from = "0x" + (height - BigInt(back)).toString(16);
    try {
      const result = (await infraRpcWithFailover(chain, "eth_getLogs", [
        { topics: [[TOPIC_ERC4626_DEPOSIT, TOPIC_ERC4626_WITHDRAW]], fromBlock: from, toBlock: "latest" },
      ])) as any[];
      logs = Array.isArray(result) ? result : [];
    } catch (e) {
      const msg = (e as Error).message.toLowerCase();
      if (/limit|too large|range|timeout|capacity|exceed|address|restrictions/.test(msg) && back > 1) {
        back = Math.max(1, Math.floor(back / 4));
        continue;
      }
      return []; // endpoint doesn't support this query — skip silently
    }
  }
  if (!logs || logs.length === 0) return [];

  const vaultAddrs = new Set<string>();
  for (const l of logs) {
    const a = String(l.address ?? "").toLowerCase();
    if (a && /^0x[0-9a-f]{40}$/.test(a)) vaultAddrs.add(a);
  }

  return [...vaultAddrs].slice(0, maxVaults).map((address) => ({
    chain,
    address,
    source: "hot-pair" as const, // reuse existing source type; label differentiates
    factory: "erc4626-vault",
  }));
}
export async function nativeBalanceWei(chain: ChainSpec, address: string): Promise<bigint> {
  try {
    const hex = (await infraRpcWithFailover(chain, "eth_getBalance", [address, "latest"])) as string;
    return BigInt(hex);
  } catch {
    return 0n;
  }
}

/** Read-only wrapped-native balance (balanceOf via eth_call). */
export async function wrappedBalanceWei(chain: ChainSpec, address: string): Promise<bigint> {
  try {
    const data = `0x70a08231${address.replace(/^0x/, "").padStart(64, "0")}`; // balanceOf(address)
    const hex = (await infraRpcWithFailover(chain, "eth_call", [
      { to: chain.wrappedNative, data },
      "latest",
    ])) as string;
    return BigInt(hex);
  } catch {
    return 0n;
  }
}

// Major stablecoins per chain for full TVL ranking. Stablecoin-heavy pools
// (Aave, Curve, Compound) would rank below dust ETH pairs without this.
const STABLECOINS: Record<string, string[]> = {
  "1":     ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","0xdac17f958d2ee523a2206206994597c13d831ec7","0x6b175474e89094c44da98b954eedeac495271d0f"],
  "56":    ["0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d","0x55d398326f99059ff775485246999027b3197955","0xe9e7cea3dedca5984780bafc599bd69add087d56"],
  "8453":  ["0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","0x50c5725949a6f0c72e6c4a641f24049a917db0cb"],
  "42161": ["0xaf88d065e77c8cc2239327c5edb3a432268e5831","0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9","0xda10009cbd5d07dd0cecc66161fc93d7c9000da1"],
  "10":    ["0x7f5c764cbc14f9669b88837ca1490cca17c31607","0x94b008aa00579c1307b0ef2c499ad98a8ce58e58"],
  "137":   ["0x2791bca1f2de4661ed88a30c99a7a9449aa84174","0xc2132d05d31c914a87c6611c10748aeb04b58e8f"],
  "4663":  ["0x5fc5360d0400a0fd4f2af552add042d716f1d168"], // USDG — verified live (decimals 6); equities pools are USDG-heavy
};
// USDC/USDT have 6 decimals; 1 USDC ≈ 1/2500 ETH → multiply by 10^12 / 2500
// DAI has 18 decimals; 1 DAI ≈ 1/2500 ETH → multiply by 1 / 2500
const STABLE_6DEC = new Set(["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","0xdac17f958d2ee523a2206206994597c13d831ec7","0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d","0x55d398326f99059ff775485246999027b3197955","0xe9e7cea3dedca5984780bafc599bd69add087d56","0x833589fcd6edb6e08f4c7c32d4f71b54bda02913","0xaf88d065e77c8cc2239327c5edb3a432268e5831","0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9","0x7f5c764cbc14f9669b88837ca1490cca17c31607","0x94b008aa00579c1307b0ef2c499ad98a8ce58e58","0x2791bca1f2de4661ed88a30c99a7a9449aa84174","0xc2132d05d31c914a87c6611c10748aeb04b58e8f","0x5fc5360d0400a0fd4f2af552add042d716f1d168"]); // last: USDG (Robinhood Chain)

async function erc20BalanceOf(chain: ChainSpec, token: string, holder: string): Promise<bigint> {
  try {
    const data = `0x70a08231${holder.replace(/^0x/, "").padStart(64, "0")}`;
    const hex = (await infraRpcWithFailover(chain, "eth_call", [{ to: token, data }, "latest"])) as string;
    return typeof hex === "string" && hex.startsWith("0x") ? BigInt(hex) : 0n;
  } catch { return 0n; }
}

/** Full TVL estimate: native ETH + wrapped-native + major stablecoins,
 * ETH-normalized. Stablecoin pools rank correctly against ETH pools. */
export async function totalTvlWei(chain: ChainSpec, address: string): Promise<bigint> {
  let total = await nativeBalanceWei(chain, address);
  total += await wrappedBalanceWei(chain, address);
  for (const stable of STABLECOINS[chain.id] ?? []) {
    const bal = await erc20BalanceOf(chain, stable, address);
    if (bal === 0n) continue;
    // Normalize 6-dec stables: bal * 10^12 / 2500 ≈ ETH-wei equivalent
    total += STABLE_6DEC.has(stable) ? (bal * 10n ** 12n) / 2500n : bal / 2500n;
  }
  return total;
}
