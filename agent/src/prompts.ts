// Approval gate: the agent HALTS here when a live-pool finding is made.
// The user chooses what happens to the evidence.
import * as readline from "node:readline/promises";
import { stdin, stdout } from "node:process";

export async function askApproval(question: string, options: string[]): Promise<string> {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    console.log(`\n${"=".repeat(70)}`);
    console.log("APPROVAL GATE — the agent has stopped and is waiting for you.");
    console.log("=".repeat(70));
    console.log(question);
    options.forEach((o, i) => console.log(`  ${i + 1}) ${o}`));
    const answer = await rl.question("Choose 1-" + options.length + ": ");
    const idx = parseInt(answer.trim(), 10);
    if (Number.isNaN(idx) || idx < 1 || idx > options.length) return options[0]!;
    return options[idx - 1]!;
  } finally {
    rl.close();
  }
}
