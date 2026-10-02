---
name: offensive-portswigger-checklists
description: "PortSwigger Web Security Academy condensed checklists: business logic vulnerabilities (assumption violation, unconventional input, workflow states, high-volume abuse) plus the master index of every Academy topic with its core hunting shortcut — SQLi, XSS, CSRF, clickjacking, CORS, XXE, SSRF, request smuggling, command injection, SSTI, insecure deserialization, path traversal, access control, authentication, OAuth, logic flaws, WebSockets, DOM-based, cache poisoning/deception, Host header, information disclosure, file upload, JWT, prototype pollution, GraphQL, race conditions, NoSQL injection, API testing, Web LLM attacks. Source: https://portswigger.net/web-security"
---

# SKILL: PortSwigger Academy Condensed Checklists

## Metadata
- **Skill Name**: portswigger-checklists
- **Folder**: offensive-portswigger-checklists
- **Source**: PortSwigger Web Security Academy — https://portswigger.net/web-security

## Description
PortSwigger Web Security Academy condensed checklists: business logic vulnerabilities plus the master index of every Academy topic with its core hunting shortcut. Source: https://portswigger.net/web-security

## Trigger Phrases
Use this skill when the conversation involves any of:
`portswigger, web security academy, web app testing, owasp, web vulnerability, web bug bounty, web methodology, checkout flow, logic flaw, web checklist`

## Description (Full)
The PortSwigger Web Security Academy is the reference curriculum for web exploitation. This skill condenses its universal testing logic — the business-logic methodology scanners cannot automate — and indexes every topic's one-line hunting shortcut so triage can reach the right specialist checklist fast.

## Full Methodology

# Business Logic Vulnerabilities (the universal checklist)

## Shortcut

- Map the workflow end-to-end and list every rule the flow assumes.
- Violate each assumption: wrong order, missing/repeated steps, absurd values (negative, zero, max-int, wrong types), parameters the UI never sends.
- Watch transitions between sub-states — checks silently don't apply mid-flight.
- Combine flaws: one flaw is noise; two chained flaws are an exploit.

## How they arise

Flawed assumptions about user behavior:
- Users only submit data via a browser → client-side validation trusted.
- Input validated once is trusted forever ("it was safe when stored") — second-order logic flaws.
- Complex systems nobody fully understands: component authors assume wrong things about each other.

## Common patterns

- **Excessive trust in client-side controls**: price/quantity/role validated in the browser only.
- **Unconventional input mishandled**: negative quantities, type confusion, missing optional fields, duplicate parameters, JSON-vs-form discrepancies.
- **Incomplete workflow states**: reach a later state without completing earlier ones (confirmation without payment, MFA skipped).
- **Nested workflow states**: one request passes through hidden sub-states — race-condition flavored logic bugs.
- **High-volume abuse**: per-item limits enforced per-request, not per-entity.
- **Time-based**: expiry checked at start, not at finish.

## Testing methodology

1. Reconstruct the developer's assumed model: states, transitions, invariants.
2. For each invariant, design the request sequence that breaks it.
3. Absurd-value sweep on every parameter.
4. Sequence abuse: skip, replay, interleave.
5. Aim at what the app protects: money, privilege, data integrity.

## Impact

Authentication bypass, privilege escalation, financial loss, data corruption. Fix "quirky" behavior even when you can't exploit it — someone else will.

## Prevention

- Document assumptions about user behavior at every stage.
- Enforce assumptions server-side before acting on input.
- Clear design docs; post-mortem every logic bug for the process flaw.

# Master index: Academy topics → one-line shortcut

- **SQL injection** — probe `'`, booleans, time delays, OAST at every entry point; UNION for visible data, blind techniques otherwise.
- **XSS** — reflect a canary everywhere; break context (body/attribute/JS string); escalate PoC to session theft.
- **CSRF** — three preconditions (relevant action, cookie-only session, predictable params); attack tokens, SameSite, Referer separately.
- **Clickjacking** — framable + one-click sensitive action; overlay with transparent iframe; bypass frame busters with `sandbox="allow-forms"`.
- **CORS** — ACAO reflected from Origin, parsing mistakes in whitelists (prefix/suffix domains), null origin whitelisted, trust chains through subdomains.
- **XXE** — DOCTYPE entities for file read; blind via OOB; XInclude when you only control a data value; XML hides in uploads (SVG/DOCX) and tolerant content types.
- **SSRF** — server fetches user URL → loopback/internal targets; bypass blacklists (IP representations, encodings, redirects) and whitelists (URL parsing inconsistencies); blind via OAST.
- **Request smuggling** — CL.TE / TE.CL / TE.TE framing desync between proxies; detect by timing + poison-then-probe; capture victims' requests.
- **OS command injection** — shell metacharacters into features that shell out; blind via delays/redirects/OAST DNS exfil.
- **SSTI** — polyglot fuzz `${{<%[%'"}}%\`, math probes `{{7*7}}`; identify engine by decision tree; escalate to RCE via gadget chains/sandboxes.
- **Insecure deserialization** — recognize serialized state (O:, rO0AB, 04 08); tamper attributes; gadget chains (ysoserial/phpggc) for RCE; signatures must be checked before deserialization.
- **Path traversal** — `../` ladder: absolute paths, nested `....//`, URL/double encoding, null-byte truncation; canonical-path defense is the only robust one.
- **Access control** — two accounts, force-browse privileged URLs, tamper role params, IDOR swap; platform bypasses (X-Original-URL) and URL-matching discrepancies.
- **Authentication** — brute-forceable logins, username enumeration, flawed 2FA (forced browsing, brute-forceable tokens), logic bypasses everywhere.
- **OAuth** — recon `/.well-known/openid-configuration`; implicit-flow token trust, state-less CSRF, redirect_uri bypasses, code leakage, flawed scope validation.
- **WebSockets** — tamper messages both directions; handshake manipulation; cross-site WebSocket hijacking (CSRF on the handshake).
- **DOM-based** — source→sink taint flow (location→innerHTML etc.); web messages without origin checks; DOM clobbering to reach hidden sinks.
- **Web cache poisoning** — find unkeyed inputs (Param Miner), elicit harmful reflected response, get it cached under a shared key.
- **Web cache deception** — static-extension/delimiter discrepancies make the cache store the victim's private dynamic response; steal it.
- **HTTP Host header attacks** — password reset poisoning, cache poisoning via Host, routing-based SSRF, vhost brute-force; override headers (X-Forwarded-Host).
- **Information disclosure** — verbose errors, debug endpoints, backups/.git, response comparison for enumeration; grade by what it enables.
- **File upload** — web shell path; MIME trust, blacklist gaps, polyglot content, filename traversal; second-order execution via converters/parsers.
- **JWT attacks** — alg:none, verify-vs-decode, hashcat `-m 16500` secret brute force, jwk/jku/kid header injection, RS256→HS256 confusion.
- **Prototype pollution** — `__proto__` through merges (URL/JSON/messages); confirm with canary; find gadgets (config → sink) for XSS/RCE.
- **GraphQL** — universal query `query{__typename}`; introspection + newline bypass; IDOR via arguments; alias-based rate-limit bypass; suggestions mining.
- **Race conditions** — single-packet attack (HTTP/2) for limit overruns; sub-state methodology for hidden multi-step sequences (MFA skip).
- **NoSQL injection** — Mongo fuzz string; conditional confirmation; condition override + null-byte; operator injection `[$ne]`/JSON `$ne` for auth bypass; `$where`/`$regex` extraction.
- **API testing** — docs discovery (/swagger, /openapi.json, JS mining); method + content-type fuzzing; hidden params; mass assignment via readable fields.
- **Web LLM attacks** — map inputs and APIs the LLM can reach; excessive agency; classic exploits through LLM APIs; indirect prompt injection; insecure output handling.
- **Essential skills** — encoding-obfuscation ladder across every parse boundary; scanner for breadth, human for depth; classify before escalating.

## Notes for the fleet

- The business-logic methodology is the fleet's native on-chain discipline translated to web: every vault/liquidation/flash-loan flow is a state machine with money at stake.
- Use the index to route: match a triage context's keywords to the topic, then load the specialist skill (this library has deep skills for most of these topics).
