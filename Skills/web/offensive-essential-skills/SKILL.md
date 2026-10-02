---
name: offensive-essential-skills
description: "Essential skills checklist: obfuscating attacks using encodings (HTML entity variants, URL single/double encoding, Unicode/c0-af style tricks, chunked and nested encodings) to exploit parser discrepancies between defenses and consumers; scanner-assisted manual testing workflow; and the mystery-lab mindset for identifying unknown vulnerability classes without prior knowledge. Use when a payload is blocked and you need to find the encoding the filter misses."
---

# SKILL: Essential Skills — Obfuscation & Unknown-Vulnerability Hunting

## Metadata
- **Skill Name**: essential-skills
- **Folder**: offensive-essential-skills
- **Source**: PortSwigger Web Security Academy — Essential skills (https://portswigger.net/web-security/essential-skills)

## Description
Essential skills checklist: obfuscating attacks using encodings (HTML entity variants, URL single/double encoding, Unicode/c0-af style tricks, chunked and nested encodings) to exploit parser discrepancies between defenses and consumers; scanner-assisted manual testing workflow; and the mystery-lab mindset for identifying unknown vulnerability classes without prior knowledge. Use when a payload is blocked and you need to find the encoding the filter misses.

## Trigger Phrases
Use this skill when the conversation involves any of:
`obfuscation, encoding bypass, double encoding, html entities, filter evasion, scanner assisted testing, mystery lab, unknown vulnerability, payload encoding`

## Description (Full)
Copy-pasting lab attacks onto real targets stops at the first filter. The essential skill is adapting techniques: obfuscate payloads through encoding layers so flawed defenses and the components behind them disagree about what the input means.

## Full Methodology

# Essential Skills

## Shortcut

- When blocked, enumerate what the filter saw vs what the consumer will see — the gap is the exploit.
- Try the encoding ladder: exact string → HTML entity variants → URL encode → double URL encode → mixed/nested encodings → parser-specific quirks.
- Let a scanner (Burp) do the breadth work; you do the exploitation depth.
- On unknown targets, classify the bug class first (the mystery-lab mindset) before choosing techniques.

## Obfuscation using encodings

Filters often check a decoded (or under-decoded) form while the consumer decodes further — exploit the difference:

- **HTML entity variants**: named (`&quot;`), decimal (`&#34;`), hex (`&#x22;`), trailing-semicolon omissions where parsers tolerate it.
- **URL encoding**: `%22`; **double URL encoding**: `%2522` for backends that decode twice.
- **Mixed/nested**: encode only part of a payload so the filter's signature misses while the consumer reassembles it.
- **Non-standard encodings**: overlong UTF-8 (`%c0%af` for `/`), Unicode fullwidth characters, chunked encodings where the parser reassembles.

The recurring principle: every boundary (filter → framework → database → filesystem → browser) is a decode point. Two boundaries that decode differently = a bypass.

## Lab-to-live adaptation

Labs show one variation of a bug class; live targets have patched variants. When your attack is blocked:
1. Identify which defense fired (message, status, behavior).
2. Assume the underlying bug still exists — the patch is often only as wide as the last payload.
3. Re-derive the payload in a form the defense doesn't recognize.

## Scanner-assisted manual testing

Manual injection across every input is impractical; use the scanner for breadth:
- Active scans for injection classes on entry points you've found.
- Use scan findings as leads, not verdicts — you confirm and escalate manually.
- Keep human attention on what automation can't do: chaining, business logic, impact.

## Identifying unknown vulnerabilities (mystery-lab mindset)

On live targets nobody tells you the bug class. Discipline:
1. Observe everything anomalous (behavior, timing, errors, state changes).
2. Form hypotheses across classes (injection, access control, logic, race).
3. Test the cheapest discriminating probe first; iterate.
4. Classify before escalating — the wrong class wastes the whole budget.

## Notes for the fleet

- The fleet already lives the encoding principle: selector/ABI encodings are the on-chain analog, and calldata crafting is payload obfuscation with type semantics.
- The "classify before escalating" habit is the fleet's triage stage — this skill is the web-side justification for it.
