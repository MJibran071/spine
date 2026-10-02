---
name: offensive-cache-poisoning
description: "Web cache poisoning checklist: identifying unkeyed inputs (Param Miner, manual header fuzzing), eliciting harmful responses reflected into cached pages, cache-key mechanics, exploitation via header reflection (X-Forwarded-Host, X-Forwarded-Scheme), fat GET, cache design flaws vs implementation flaws, and cache-buster hygiene. Use when a target is fronted by any caching layer and responses reflect request metadata."
---

# SKILL: Web Cache Poisoning

## Metadata
- **Skill Name**: cache-poisoning
- **Folder**: offensive-cache-poisoning
- **Source**: PortSwigger Web Security Academy — Web cache poisoning (https://portswigger.net/web-security/web-cache-poisoning)

## Description
Web cache poisoning checklist: identifying unkeyed inputs (Param Miner, manual header fuzzing), eliciting harmful responses reflected into cached pages, cache-key mechanics, exploitation via header reflection (X-Forwarded-Host, X-Forwarded-Scheme), fat GET, cache design flaws vs implementation flaws, and cache-buster hygiene. Use when a target is fronted by any caching layer and responses reflect request metadata.

## Trigger Phrases
Use this skill when the conversation involves any of:
`cache poisoning, unkeyed input, param miner, cache key, x-forwarded-host, fat get, cached xss, web cache entanglement, header reflection, poisoned response`

## Description (Full)
Web cache poisoning makes a cache serve a harmful response to other users: find an unkeyed input the back-end reflects or acts on, elicit a malicious response, and get it cached under a key other users share. A poisoned cache is a distribution channel for XSS, open redirects, and JS injection.

## Full Methodology

# Web Cache Poisoning

## Shortcut

- Fuzz for unkeyed inputs (headers, params) with Param Miner ("Guess headers") plus manual probes — always with a cache buster.
- When a header changes the response (reflected URL, redirect target, generated links), weaponize it into a payload.
- Confirm the response caches (`X-Cache: hit` on repeat), then deliver the poisoned URL to victims.

## Cache mechanics

- The **cache key** (typically request line + Host) decides equivalence; everything else is **unkeyed** and ignored by the cache — but may still influence the back-end's response.
- The poisoned response is served to every subsequent user whose request matches the key until expiry (attacks can be scripted to re-poison indefinitely).

## Step 1 — identify unkeyed inputs

- Manual: append random headers/params; diff responses (Burp Comparer).
- Automated: Param Miner "Guess headers" against its built-in lists (65k+ param names).
- Always add a cache buster (unique query param) so test responses are only ever served to you.

## Step 2 — elicit a harmful response

Look for the input being reflected unsanitized, used to build absolute URLs, redirects, resource paths, or CSPs. Classic vectors:

- `X-Forwarded-Host` reflected into generated script/src URLs
- `X-Forwarded-Scheme: http` forcing a redirect to an attacker host
- `X-Original-URL` / `X-Rewrite-URL` affecting routing
- Fat GET (body params parsed on GET requests)

## Step 3 — get the response cached

Caching depends on file extension, content type, route, status code, response headers. Study what the target caches; sometimes poisoning only lands on specific pages or with specific status codes.

## Exploitation flavors

- **Design flaws**: unkeyed inputs by default (some CDNs key nothing but path), fat GET tolerated, missing key components (no method, no host).
- **Implementation quirks**: key exclusion lists ("UTM only"), cache-control parsing differences, normalization mismatches.
- **Entanglement**: web cache entanglement — poisoning via multiple intertwined caches and layered headers.
- **Chaining**: combine with XSS (payload in cached page), open redirect, response queue poisoning, or DOM sinks for full delivery.

## Prevention

- Disable caching of dynamic responses; restrict to static, genuinely static.
- Exclude nothing from the key unless you rewrite the request instead.
- Don't support fat GET.
- Disable unused headers at the CDN; strip anything not needed.
- Patch client-side vulnerabilities even if "unexploitable" — caches make them exploitable.

## Notes for the fleet

- Poisoning = the "one write, many readers" model — the same amplification logic as an on-chain storage slot poisoning a read-many view (oracle reading a manipulated spot price). Both are "the cache is the attack surface, the origin is the trigger."
- Triage signal: DeFi sites served through CDNs with dynamically generated absolute URLs are prime candidates.
