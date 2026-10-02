---
name: offensive-api-testing
description: "API testing checklist (REST/JSON focus): API recon (documentation discovery at /api, /swagger, /openapi.json, JS analysis), identifying endpoints and supported methods/content-types, machine-readable doc parsing, hidden endpoint discovery with Intruder, hidden parameter discovery (Param Miner, mass assignment / auto-binding), and vulnerability mapping to the OWASP API Security Top 10. Use when a target exposes REST or JSON APIs beyond its web UI."
---

# SKILL: API Testing

## Metadata
- **Skill Name**: api-testing
- **Folder**: offensive-api-testing
- **Source**: PortSwigger Web Security Academy — API testing (https://portswigger.net/web-security/api-testing)

## Description
API testing checklist (REST/JSON focus): API recon (documentation discovery at /api, /swagger, /openapi.json, JS analysis), identifying endpoints and supported methods/content-types, machine-readable doc parsing, hidden endpoint discovery with Intruder, hidden parameter discovery (Param Miner, mass assignment / auto-binding), and vulnerability mapping to the OWASP API Security Top 10. Use when a target exposes REST or JSON APIs beyond its web UI.

## Trigger Phrases
Use this skill when the conversation involves any of:
`api testing, rest api, json api, openapi, swagger, endpoint discovery, hidden parameter, mass assignment, auto binding, http method fuzzing, content type change, server-side parameter pollution`

## Description (Full)
All dynamic websites are APIs underneath; this checklist covers testing the API surface not fully used by the front-end — undocumented endpoints, hidden parameters, mass assignment, and method/content-type confusion.

## Full Methodology

# API Testing

## Shortcut

- Recon docs: crawl for `/api`, `/swagger/index.html`, `/openapi.json`; dig into JS files for endpoint references; parse machine-readable docs with the OpenAPI Parser BApp.
- For each endpoint: fuzz HTTP methods (GET/POST/PUT/PATCH/DELETE/OPTIONS) and content types (JSON ↔ XML ↔ form-encoded) — errors reveal behavior, methods reveal hidden operations.
- Enumerate objects returned by the API: fields you can read hint at fields you can write (mass assignment).
- Test hidden params with Intruder + Param Miner wordlists.

## API recon

- **Documentation**: human-readable first, then machine-readable (OpenAPI/Swagger). Investigate the base path of any discovered endpoint (`/api/swagger/v1/users/123` → check `/api/swagger/v1`, `/api/swagger`, `/api`).
- **Endpoints from the UI**: browse with Burp's browser; look for `/api/` patterns and mine JS files (JS Link Finder BApp) for references never triggered directly.
- **Interacting**: use Repeater/Intruder; study error messages — they often hand you the valid request shape.

## Identifying supported methods and content types

- Cycle HTTP methods (built-in HTTP verbs list) on low-priority objects — an endpoint accepting GET/DELETE reveals operations the UI never calls.
- Change `Content-Type` (JSON → XML → form-urlencoded) and reformat the body: error messages disclose processing logic; some APIs are safe with JSON but injectable with XML.

## Hidden endpoints

From a known endpoint (`PUT /api/user/update`), fuzz the path segment with a wordlist of functions (`delete`, `add`, `export`) and naming conventions; include target-relevant terms from your recon.

## Hidden parameters and mass assignment

1. Read object representations: `GET /api/users/123` returns `{"id":123,"name":"John Doe","email":"john@example.com","isAdmin":"false"}` while the UI only lets you edit username/email.
2. Add the hidden fields to the edit request (`PATCH /api/users/123` with `"isAdmin": true`).
3. Probe with an invalid value (`"isAdmin": "foo"`) — different behavior for valid vs invalid suggests the field is processed.
4. If the value binds without validation: privilege escalation via auto-binding.

Use Param Miner (65k+ param names per request) and Intruder with common param-name wordlists for parameters never exposed in responses.

## Server-side parameter pollution

When the front-end builds an internal API call from your input, inject URL syntax (`#`, `&`, `=`) into parameters to manipulate the second-tier query — errors and differential responses map the internal API.

## Mapping to OWASP API Security Top 10 (2023)

| Academy topic | OWASP API |
|---|---|
| Access control / IDOR | API1 BOLA / API5 BFLA |
| Authentication | API2 Broken Authentication |
| Mass assignment | API3 BOPLA |
| Information disclosure | API4 Unrestricted Resource Consumption (context) / API8 Security Misconfiguration |
| Injection (SQLi/NoSQLi) | API9 Improper Inventory / API10 Unsafe Consumption of APIs |

## Prevention

- Secure docs if the API isn't public; keep docs current.
- Allow-list methods and content types; validate at every tier.
- Block mass assignment: explicit field allow-lists for updates.
- Rate-limit and authenticate per endpoint (treat LLM-proxied APIs as public).

## Notes for the fleet

- DeFi protocols are API-first: subgraphs, price APIs, wallet-backends. The mass-assignment mindset maps to on-chain "any field the struct exposes can be set by the caller" (unvalidated calldata).
- Hidden-parameter discovery is the same skill the fleet uses hunting unused admin selectors in verified bytecode.
