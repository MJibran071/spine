// One-off: list genuinely FREE OpenRouter models (prompt=0 AND completion=0),
// ranked for triage suitability (context >= 32k, recent, supports completions).
// Usage: OPENROUTER_KEY=sk-or-… node agent/src/list-free-models.ts [limit]
const KEY = process.env.OPENROUTER_KEY ?? "";
const res = await fetch("https://openrouter.ai/api/v1/models", {
  headers: KEY ? { authorization: `Bearer ${KEY}` } : {},
  signal: AbortSignal.timeout(20_000),
});
if (!res.ok) {
  console.error("models list failed:", res.status, await res.text().then((t) => t.slice(0, 200)));
  process.exit(1);
}
const j = (await res.json()) as {
  data: Array<{
    id: string;
    name: string;
    created: number;
    context_length: number;
    pricing: { prompt: string; completion: string };
    supported_parameters?: string[];
    architecture?: { input_modalities?: string[] };
  }>;
};
const free = j.data
  .filter((m) => m.pricing?.prompt === "0" && m.pricing?.completion === "0")
  .filter((m) => (m.context_length ?? 0) >= 32_000)
  .sort((a, b) => b.created - a.created);
console.log(`free models with context >= 32k: ${free.length}\n`);
const limit = parseInt(process.argv[2] ?? "25", 10);
for (const m of free.slice(0, limit)) {
  const days = Math.round((Date.now() / 1000 - m.created) / 86400);
  const params = (m.supported_parameters ?? []).filter((p) => /temperature|max_tokens|structured/.test(p)).join(",");
  console.log(`${m.id.padEnd(52)} ctx=${String(m.context_length).padStart(8)}  age=${String(days).padStart(4)}d  [${params}]`);
}
