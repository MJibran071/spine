// Flash-loan source selector — realism for probe harnesses.
//
// The template probes flash "the pool's own ETH". Real exploits borrow from
// dedicated venues (Balancer charges 0, Aave v3 0.05%), and several real
// exploits are ONLY reachable with a borrowed asset the target itself does
// not hold. This module maps (chain, asset) -> the best LIVE flash-loan
// source and renders the Solidity blocks the generated harness needs.
//
// Read-only: `pickFlashSource` probes venues with a cheap eth_getCode on the
// LOCAL fork, so a venue that is absent/deployed-elsewhere at fork head is
// skipped — the harness never renders a borrow against a missing contract.
//
// Safety: everything runs against the local anvil fork; nothing here
// broadcasts. Venue constants are chain-1 mainnet deployments.

export const WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
export const BALANCER_VAULT = "0xba12222222228d8Ba445958a75a0704d566BF2C8";
export const AAVE_V3_POOL = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2";

export interface FlashVenue {
  name: string;
  address: string;
  /** Fee in basis points (Balancer = 0). */
  feeBps: number;
  /** Assets this venue lends (lowercased). "native" covers WETH borrows too
   * (the harness wraps after receiving, as real exploits do). */
  assets: string[];
  /** The borrow call the exploit contract makes. */
  renderBorrow: (asset: string, amountWei: string) => string;
  /** The receiver-callback body that repays (principal + fee). */
  renderReceiver: (asset: string, amountWei: string) => string;
}

const MAINNET_STABLES = [
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
  "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI
  "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
];

const VENUES: FlashVenue[] = [
  {
    name: "balancer-v2",
    address: BALANCER_VAULT,
    feeBps: 0,
    assets: [WETH, "native", ...MAINNET_STABLES],
    renderBorrow: (asset, amountWei) => `// Balancer Vault flashLoan — 0 fee
address[] memory flTokens = new address[](1);
flTokens[0] = ${asset};
uint256[] memory flAmounts = new uint256[](1);
flAmounts[0] = ${amountWei};
IVault(BALANCER_VAULT).flashLoan(address(this), flTokens, flAmounts, "");`,
    renderReceiver: (asset, amountWei) => `// Balancer receiver callback — repay principal only (0 fee)
IERC20(${asset}).transfer(BALANCER_VAULT, ${amountWei});`,
  },
  {
    name: "aave-v3",
    address: AAVE_V3_POOL,
    feeBps: 5,
    assets: [WETH, "native", ...MAINNET_STABLES],
    renderBorrow: (asset, amountWei) => `// Aave v3 flashLoanSimple — 0.05% fee
IPool(AAVE_V3_POOL).flashLoanSimple(address(this), ${asset}, ${amountWei}, "", 0);`,
    renderReceiver: (asset, amountWei) => `// Aave receiver callback — repay principal + 0.05%
IERC20(${asset}).transfer(AAVE_V3_POOL, (${amountWei}) * 10005 / 10000);`,
  },
];

/** Cheapest live venue lending `asset`. Venues are tried in fee order and the
 * first one whose contract exists at fork head (when `probe` is given) wins.
 * Null = no known venue for this asset. */
export async function pickFlashSource(
  asset: string,
  opts?: { probe?: (address: string) => Promise<boolean> }
): Promise<{ venue: FlashVenue } | null> {
  const a = asset.toLowerCase();
  const candidates = VENUES.filter((v) => v.assets.includes(a) || (a === WETH && v.assets.includes("native"))).sort(
    (x, y) => x.feeBps - y.feeBps
  );
  for (const v of candidates) {
    if (!opts?.probe) return { venue: v };
    try {
      if (await opts.probe(v.address)) return { venue: v };
    } catch {
      // dead endpoint at fork head — try the next venue
    }
  }
  return null;
}

/** Convenience for the common case: the best WETH source, verified by code
 * presence on the local fork's RPC. Null when no known venue has code. */
export async function wethFlashSource(
  rpc: (method: string, params: unknown[]) => Promise<unknown>
): Promise<{ name: string; address: string; feeBps: number } | null> {
  const hasCode = async (addr: string) => {
    const code = (await rpc("eth_getCode", [addr, "latest"])) as string;
    return typeof code === "string" && code.length > 2;
  };
  const picked = await pickFlashSource(WETH, { probe: hasCode });
  return picked ? { name: picked.venue.name, address: picked.venue.address, feeBps: picked.venue.feeBps } : null;
}
