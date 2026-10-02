---
name: offensive-access-control
description: "Access control vulnerability checklist: vertical privilege escalation (unprotected functionality, URL-leaked admin paths, parameter-based roles), platform misconfiguration bypasses (X-Original-URL, method overrides), URL-matching discrepancies (case, trailing slash, suffix matching), horizontal privilege escalation (IDOR, GUID leakage), context-dependent flaws, and testing methodology (multiple accounts, never trust the UI). Use on every target with user roles or multi-tenant data."
---

# SKILL: Access Control Vulnerabilities

## Metadata
- **Skill Name**: access-control
- **Folder**: offensive-access-control
- **Source**: PortSwigger Web Security Academy — Access control (https://portswigger.net/web-security/access-control)

## Description
Access control vulnerability checklist: vertical privilege escalation (unprotected functionality, URL-leaked admin paths, parameter-based roles), platform misconfiguration bypasses (X-Original-URL, method overrides), URL-matching discrepancies (case, trailing slash, suffix matching), horizontal privilege escalation (IDOR, GUID leakage), context-dependent flaws, and testing methodology (multiple accounts, never trust the UI). Use on every target with user roles or multi-tenant data.

## Trigger Phrases
Use this skill when the conversation involves any of:
`access control, privilege escalation, idor, broken access control, vertical escalation, horizontal escalation, unprotected admin, x-original-url, parameter based access control, forced browsing`

## Description (Full)
Access control decides whether a user may perform an action — built on authentication (who you are) and session management (which requests are yours). Broken access control is common and often critical: users reach functionality or data that is not theirs.

## Full Methodology

# Access Control Vulnerabilities

## Shortcut

- Create two accounts with different roles (and one admin if you can). Compare everything: URLs, requests, responses, JS.
- Force-browse privileged URLs as a normal user; check robots.txt, JS bundles, and comments for hidden admin paths.
- Tamper role/permission parameters (`?admin=true`, cookies, hidden fields).
- Swap object IDs between accounts (IDOR); try GUIDs leaked in messages/reviews.
- Attack the platform layer: X-Original-URL, method overrides, case/suffix/trailing-slash discrepancies.

## Models

- **Vertical** — different user types see different functions (admin vs user).
- **Horizontal** — same function, but scoped to each user's own resources.
- **Context-dependent** — correct order/state enforced (no cart edits after payment).

## Vertical privilege escalation

- **Unprotected functionality**: `/admin` reachable by anyone; obfuscated paths (`/administrator-panel-yb556`) leak in JS bundles (`var isAdmin = false; ... setAttribute('href', ...)`) — the script is served to everyone even when the link isn't rendered.
- **Parameter-based access control**: role stored in user-controllable locations:
  ```
  https://insecure-website.com/login/home.jsp?admin=true
  https://insecure-website.com/login/home.jsp?role=1
  ```
  Tamper the value (and its position: cookie, hidden field, query string).
- **Platform misconfiguration**:
  - URL-override headers: `X-Original-URL: /admin/deleteUser` bypassing front-end URL rules.
  - Method mismatches: rule denies `POST /admin/deleteUser` but the app also accepts GET.
- **URL-matching discrepancies**: `/ADMIN/` vs `/admin/`, trailing slashes, Spring's `useSuffixPatternMatch` (`/admin/deleteUser.anything` mapping to the same endpoint). The access-control layer and the routing layer disagree — exploit the difference.

## Horizontal privilege escalation

- **IDOR**: `/myaccount?id=123` → change the id. Direct object references without authorization checks.
- **GUIDs**: not guessable, but leak in other places (messages, reviews, redirect parameters) — collect, then swap.
- **Redirect leaks**: the app detects unauthorized access and redirects to login, but the redirect response body still contains the target's data.

## Context-dependent flaws

Break the intended sequence: access step 3 directly, replay step 2 after step 4, or run two flows in parallel (overlaps with race conditions).

## Methodology notes

- Never trust the UI: it hides links, not authority. Test every function at every role.
- Where possible test with account pairs (A acting on B's data), and with the same account in two sessions to separate session bugs from role bugs.

## Prevention

- Deny by default; enforce on the server for every request, per record, per action.
- Never rely on hidden URLs, UI omission, or client-side checks.
- Centralize policy; test with automated role-matrix checks.

## Notes for the fleet

- On-chain: `tx.origin` checks, missing role checks on administrative functions (`onlyOwner` absent), and initializer reuse are the same vertical-escalation class; arbitrary `from`/`to` on internal ledgers are the horizontal one.
- The fleet's unauthorized-mint and governance probes already encode this skill's core: authority must be enforced where the action executes, not where the UI decides.
