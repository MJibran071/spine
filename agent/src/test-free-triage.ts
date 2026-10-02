// One-off: live-test free OpenRouter candidates against a mini triage prompt.
// Usage: OPENROUTER_KEY=sk-or-… node agent/src/test-free-triage.ts
const KEY = process.env.OPENROUTER_KEY ?? "";
const CANDIDATES = [
  "nex-agi/nex-n2.5-mini:free",
  "nvidia/nemotron-3.5-lightning:free",
  "cohere/north-mini-code:free",
  "dots-studio/dots-3-note-preview:free",
  "nex-agi/nex-n2.5-pro:free",
];

const SYSTEM = `You are a smart-contract security triage analyst. Reply with ONLY a JSON object (no markdown fence):
{"hypothesis":"<one sentence>","technique":"<tag>","confidence":<0..1>,"probe":null|{"class":"<side-entrance|erc4626-inflation|flash-arbitrary-call|oracle-spot>","rationale":"<why>"}}`;

const USER = `TARGET 0xabc0000000000000000000000000000000000123 on chain 1
Interface shape classification: unknown
Detected function selectors: deposit, withdraw, flashLoan
Native balance: 1500000000000000000000 wei; wrapped-native balance: 0 wei
Static detector signals: reentrancy-eth, credit-balance-confusion

VERIFIED SOURCE:
\`\`\`solidity
contract LenderPool {
    IERC20 public immutable weth;
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    constructor(IERC20 _weth) { weth = _weth; }
    function deposit(uint256 amount) external { weth.transferFrom(msg.sender, address(this), amount); deposits[msg.sender] += amount; totalDeposits += amount; }
    function withdraw() external {
        uint256 bal = weth.balanceOf(address(this));
        require(bal >= totalDeposits, "insolvent");
        uint256 owed = deposits[msg.sender];
        (bool ok, ) = msg.sender.call{value: owed}(""); require(ok, "fail"); // simplified
        deposits[msg.sender] = 0; totalDeposits -= owed;
    }
    function flashLoan(uint256 amount) external {
        (bool ok, ) = msg.sender.call{value: amount}(""); require(ok, "loan failed");
        require(address(this).balance >= totalDeposits, "repay failed");
    }
    receive() external payable { deposits[msg.sender] += msg.value; }
}
\`\`\`
Produce the JSON triage object now.`;

for (const model of CANDIDATES) {
  const t0 = Date.now();
  try {
    const res = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${KEY}` },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: SYSTEM },
          { role: "user", content: USER },
        ],
        temperature: 0.2,
        max_tokens: 4000,
        reasoning: { enabled: false, exclude: true },
      }),
      signal: AbortSignal.timeout(60_000),
    });
    const ms = Date.now() - t0;
    if (!res.ok) {
      const body = await res.text();
      console.log(`${model.padEnd(42)} HTTP ${res.status} (${ms}ms): ${body.slice(0, 140).replace(/\n/g, " ")}`);
      continue;
    }
    const j: any = await res.json();
    const content = j.choices?.[0]?.message?.content ?? "";
    const reasoning = j.choices?.[0]?.message?.reasoning ?? "";
    const usage = j.usage ?? {};
    const rDetail = usage.completion_tokens_details?.reasoning_tokens;
    // parse like triage.ts does
    let text = content.trim();
    const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fence) text = fence[1]!.trim();
    const s = text.indexOf("{");
    const e = text.lastIndexOf("}");
    let verdict = "UNPARSEABLE";
    if (s !== -1 && e > s) {
      try {
        const p = JSON.parse(text.slice(s, e + 1));
        const cls = p.probe?.class ?? "null";
        verdict = `technique=${p.technique} conf=${p.confidence} probeClass=${cls}`;
      } catch {
        /* unparseable */
      }
    }
    console.log(`${model.padEnd(42)} OK ${String(ms).padStart(5)}ms  in=${usage.prompt_tokens ?? "?"} out=${usage.completion_tokens ?? "?"} (reasoning=${rDetail ?? 0})  ${verdict}${reasoning && !content ? "  [reasoning-only response]" : ""}`);
    console.log(`${" ".repeat(44)}-> ${content.replace(/\s+/g, " ").slice(0, 150)}`);
  } catch (err) {
    console.log(`${model.padEnd(42)} ERROR (${Date.now() - t0}ms): ${(err as Error).message.slice(0, 100)}`);
  }
  await new Promise((r) => setTimeout(r, 1500)); // free-tier pacing
}
