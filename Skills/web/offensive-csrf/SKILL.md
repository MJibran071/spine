---
name: offensive-csrf
description: "Cross-site request forgery checklist: the three CSRF preconditions (relevant action, cookie-only session, predictable parameters), PoC construction (auto-submitting form, self-contained GET img), and bypasses of CSRF tokens (not tied to session, method-dependent validation), SameSite cookie restrictions, and Referer validation. Use when testing state-changing actions for forged-request susceptibility."
---

# SKILL: Cross-Site Request Forgery

## Metadata
- **Skill Name**: csrf
- **Folder**: offensive-csrf
- **Source**: PortSwigger Web Security Academy — CSRF (https://portswigger.net/web-security/csrf)

## Description
Cross-site request forgery checklist: the three CSRF preconditions (relevant action, cookie-only session, predictable parameters), PoC construction (auto-submitting form, self-contained GET img), and bypasses of CSRF tokens (not tied to session, method-dependent validation), SameSite cookie restrictions, and Referer validation. Use when testing state-changing actions for forged-request susceptibility.

## Trigger Phrases
Use this skill when the conversation involves any of:
`csrf, cross-site request forgery, forged request, csrf token bypass, samesite, referer validation, session riding, auto submit form, poc html, email change`

## Description (Full)
CSRF allows an attacker to induce users to perform actions they do not intend to perform — changing email, changing password, transferring funds — by forging requests the victim's browser sends with their credentials attached.

## Full Methodology

# Cross-Site Request Forgery

## Shortcut

- Map state-changing actions: email change, password change, role grants, transfers.
- Check the three preconditions. If all hold, generate the PoC.
- If a defense exists, classify it (token / SameSite / Referer) and attack its specific weakness.
- Deliver the exploit the same way you would a reflected XSS link.

## The three preconditions

1. **A relevant action** — something the attacker benefits from inducing (privilege change, data modification).
2. **Cookie-based session handling** — no other mechanism tracks/validates the requester; the browser auto-attaches the session cookie.
3. **No unpredictable request parameters** — the attacker can determine all values (e.g. no current-password requirement).

## Constructing the PoC

Auto-submitting form:

```html
<html>
<body>
<form action="https://vulnerable-website.com/email/change" method="POST">
<input type="hidden" name="email" value="pwned@evil-user.net" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

Self-contained GET (no external site needed):

```html
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```

## Common defenses and their bypasses

### CSRF tokens
- Token not tied to the user's session: use your own valid token pair from one account against another.
- Token tied to a session cookie but cookies have no SameSite/strict separation: forge a matching cookie via a separate request (e.g. session-transport weakness).
- Token validation depends on request method: drop the token entirely and switch POST → GET — validation is only applied to POST.
- Token delivered via a predictable or shared pool: mine older responses/tokens.

### SameSite cookies
- `Lax` (Chrome default since 2021) still sends cookies on top-level GET navigations — GET-based state changes remain exploitable.
- `Strict` blocks it; look for a same-site gadget: another page on the site (or a sibling subdomain) that issues the request for you, or client-side redirects within the site.

### Referer validation
- Validation checks the *presence* only: strip the Referer with `<meta name="referrer" content="no-referrer">`.
- Validation checks the *domain substring* only: register `normal-website.com.evil-user.net` or path-plant `evil.net/normal-website.com`.
- Validation compares against a configured value that can be smuggled in a query parameter: use Referer-stripping plus history manipulation.

## XSS vs CSRF

XSS lets you read responses and execute arbitrary JS in-session; CSRF only induces requests. But an XSS in a *trusted* context can also defeat CSRF defenses (it can read the token). Where you have XSS, CSRF defenses rarely matter; where you only have CSRF, token strength is the whole game.

## Prevention

- CSRF tokens: unique per session, unpredictable, tied to the session, validated on every state-changing request regardless of method.
- SameSite `Strict`/`Lax` on session cookies (defense in depth, never the only control).
- Not cookie-only authentication for sensitive actions (re-authentication step).
- Content-Type validation (JSON-only endpoints are hard to forge cross-site without CORS).

## Notes for the fleet

- CSRF thinking maps to on-chain "approval phishing" and delegated-call trust: a protocol that acts on `msg.sender`-derived authority embedded in off-chain signed payloads shares the forged-instruction shape.
- The precondition analysis (action + implicit credential + predictable inputs) is the same trio the fleet uses when judging whether a live target's off-chain signature flows are replayable.
