---
name: offensive-oauth
description: "OAuth 2.0 authentication vulnerability checklist: identifying OAuth flows (/authorization with client_id, redirect_uri, response_type), recon via /.well-known/openid-configuration, client-side flaws (implicit-flow token trust, missing/weak state CSRF), service-side flaws (redirect_uri validation bypass, code/leak paths, scope validation, pre-account-takeover via unverified registration), and OpenID Connect dynamics. Use when a target offers 'log in with X' or delegates auth."
---

# SKILL: OAuth Authentication Vulnerabilities

## Metadata
- **Skill Name**: oauth
- **Folder**: offensive-oauth
- **Source**: PortSwigger Web Security Academy — OAuth authentication (https://portswigger.net/web-security/oauth)

## Description
OAuth 2.0 authentication vulnerability checklist: identifying OAuth flows (/authorization with client_id, redirect_uri, response_type), recon via /.well-known/openid-configuration, client-side flaws (implicit-flow token trust, missing/weak state CSRF), service-side flaws (redirect_uri validation bypass, code/leak paths, scope validation, pre-account-takeover via unverified registration), and OpenID Connect dynamics. Use when a target offers 'log in with X' or delegates auth.

## Trigger Phrases
Use this skill when the conversation involves any of:
`oauth, oauth2, log in with, authorization code, implicit grant, redirect_uri, state parameter, openid connect, sso bypass, account takeover oauth, scope validation`

## Description (Full)
OAuth 2.0 is both extremely common and inherently prone to implementation mistakes — the spec is flexible, most security features are optional, and the same mechanism is reused for authentication (SSO), where mistakes become full account takeover.

## Full Methodology

# OAuth Authentication Vulnerabilities

## Shortcut

- Spot OAuth: login options like "Log in with X"; confirm via the first request to `/authorization?client_id=...&redirect_uri=...&response_type=...`.
- Recon the provider: `GET /.well-known/openid-configuration` reveals endpoints and supported features.
- Client-side: test implicit-flow token trust and state-parameter CSRF.
- Service-side: attack `redirect_uri` validation, code/token leakage via referrers or browser history, and flawed scope validation.

## The flows that matter

- **Authorization code** (most common): client gets a code via browser, exchanges it server-side for the token.
- **Implicit**: token delivered directly in the URL fragment — tokens transit the browser.

## Client-side vulnerabilities

### Improper implicit-flow implementations
The client posts the token + user data to its server to log in — but the server has no secret to compare. If it doesn't verify the token actually belongs to the submitting user, an attacker swaps the parameters and impersonates anyone.

### Flawed CSRF protection (state)
No `state` parameter in the authorization request = session-swap CSRF: attacker's OAuth account gets linked to the victim's session. Weak/unpredictable state (short, per-flow-reusable) is nearly as bad.

### redirect_uri validation bypass
Client-app `redirect_uri` validation done by prefix/suffix matching or naive regex: register `client-app.com.evil-user.net` or path tricks under an allowed subdomain to catch codes/tokens.

### Code/token leakage
Codes and (implicit) tokens leak via Referer headers on external resources, browser history, and logs. Combined with weak redirect validation, a leaked code is replayable within its short lifetime.

## Service-side vulnerabilities

### Flawed scope validation
The client app trusts the service's token response, but the service issues broader scopes than the user consented to — escalate from read-only to account-modifying by replaying the flow with modified `scope` (or by reusing a code across scopes when the service doesn't bind them).

### Unverified user registration
Services that let anyone register a developer account and don't verify email/identity let attackers create apps that impersonate legitimate ones (pre-account takeover against users who approve the wrong app).

### OpenID Connect dynamics
Dynamic client registration endpoints may allow minting clients freely; `request` parameter and `claims` handling can smuggle identity assertions the client never intended.

## Methodology for testing

1. Walk the full flow in Burp and map every request/response (grant type, scopes, state handling).
2. For each parameter (redirect_uri, state, scope, client_id, nonce), test: removal, tampering, replay, and cross-account reuse.
3. Attempt the classic account-takeover chains: code interception via redirect bypass, state-less CSRF linking, implicit-flow impersonation.

## Prevention

- Enforce exact-match `redirect_uri` (no prefix matching); bind authorization codes to client + redirect_uri.
- Require and validate `state`; use PKCE for all clients.
- Server-side: bind tokens to client_id, validate scopes per request, verify app registrations.
- Never use the implicit flow for server-side apps; treat tokens in browser history as compromised.

## Notes for the fleet

- OAuth's core risk — authority decided by an unvalidated redirect/parameter — parallels the fleet's arbitrary-call and unvalidated-recipient probes on-chain: the destination of a privileged flow must be bound before the flow starts.
- DeFi dashboards with wallet-as-login (SIWE + OAuth hybrids) are realistic targets where these flaws chain into asset-touching sessions.
