---
name: offensive-host-header
description: "HTTP Host header attack checklist: exploiting implicit trust in the Host header for password reset poisoning, web cache poisoning, routing-based SSRF, authentication bypass, and virtual host brute-forcing; override headers (X-Forwarded-Host, X-Original-URL); detection via duplicate Host and absolute-URL probes. Use when the app builds absolute URLs from request headers or routes on Host."
---

# SKILL: HTTP Host Header Attacks

## Metadata
- **Skill Name**: host-header
- **Folder**: offensive-host-header
- **Source**: PortSwigger Web Security Academy — HTTP Host header attacks (https://portswigger.net/web-security/host-header)

## Description
HTTP Host header attack checklist: exploiting implicit trust in the Host header for password reset poisoning, web cache poisoning, routing-based SSRF, authentication bypass, and virtual host brute-forcing; override headers (X-Forwarded-Host, X-Original-URL); detection via duplicate Host and absolute-URL probes. Use when the app builds absolute URLs from request headers or routes on Host.

## Trigger Phrases
Use this skill when the conversation involves any of:
`host header, host header injection, password reset poisoning, x-forwarded-host, x-original-url, virtual host, routing ssrf, host override, absolute url from host`

## Description (Full)
Host header attacks exploit sites that implicitly trust the mandatory HTTP/1.1 Host header. Because it is user-controllable, an unvalidated Host becomes a vector for password reset poisoning, cache poisoning, routing-based SSRF, and auth bypass.

## Full Methodology

# HTTP Host Header Attacks

## Shortcut

- Find where Host influences behavior: absolute links in emails/pages, redirects, routing decisions.
- Probe: swap Host to your domain, duplicate Host headers, absolute-URL request lines, override headers (X-Forwarded-Host).
- Password reset flows are the highest-value target: poisoned Host = reset link sent to attacker.

## Why it arises

Off-the-shelf apps often don't know their own domain and build absolute URLs from the Host header:

```php
<a href="https://<?php echo $_SERVER['HOST'] ?>/support">Contact support</a>
```

The header is user-controlled; the app treats it as configuration. Infrastructure components (load balancers, CDNs) may also honor override headers the site owner doesn't know about.

## Attacks

### Password reset poisoning
Intercept the reset-email flow; change Host (or X-Forwarded-Host) to your domain; the generated reset link now points to your host with the victim's token:

```
Host: evil-user.net
→ https://evil-user.net/reset?token=<victim-token>
```

The email is still sent to the victim (the token is bound to them); the link lands in your logs. Fetch the link with the victim's token to take over the account.

### Web cache poisoning
Host as an unkeyed input reflected into cached responses (see the cache poisoning skill).

### Routing-based SSRF
Reverse proxies route on Host; supplying an internal host name can make the intermediary proxy to internal systems — SSRF without a fetch feature.

### Authentication bypass
Access control keyed on Host (e.g. `localhost` or internal vhosts allowed unauthenticated): forge the Host to reach admin vhosts.

### Virtual host brute-forcing
Enumerate vhosts by cycling Host values against a single IP; look for differently-sized responses. Internal-only vhosts are common finds.

## Detection probes

1. Change Host to a benign-looking domain; observe changes in redirects/links/errors.
2. Send two Host headers (proxy takes first, backend takes last, or vice versa).
3. Send an absolute URL as the request line with a different Host header.
4. Test override headers: `X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`.

## Prevention

- Build absolute URLs from a configured domain, never from request headers.
- Validate Host against an allow-list (e.g. Django's `ALLOWED_HOSTS`).
- Disable override headers at the edge (X-Forwarded-Host especially).
- Restrict proxy routing to allow-listed upstreams; keep internal vhosts off public IPs.

## Notes for the fleet

- "Authority derived from a user-controlled routing field" is the exact shape of chain-ID confusion and replay across forks in the fleet's on-chain work: a message signed for one context replayed against another that doesn't re-bind context.
- Triage signal: any off-chain component generating links (emails, webhooks, invoice URLs) from headers deserves a poisoning check.
