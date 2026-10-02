---
name: offensive-cache-deception
description: "Web cache deception checklist: tricking a cache into storing a victim's private dynamic response via path-mapping discrepancies (REST-style vs filesystem mapping), delimiter discrepancies (; %00 .format), static-extension cache rules, cache busters, X-Cache detection headers, and the poison-then-fetch workflow. Distinct from cache poisoning: here you steal the victim's data, not inject content. Use on any site fronted by a CDN or caching layer."
---

# SKILL: Web Cache Deception

## Metadata
- **Skill Name**: cache-deception
- **Folder**: offensive-cache-deception
- **Source**: PortSwigger Web Security Academy — Web cache deception (https://portswigger.net/web-security/web-cache-deception)

## Description
Web cache deception checklist: tricking a cache into storing a victim's private dynamic response via path-mapping discrepancies (REST-style vs filesystem mapping), delimiter discrepancies (; %00 .format), static-extension cache rules, cache busters, X-Cache detection headers, and the poison-then-fetch workflow. Distinct from cache poisoning: here you steal the victim's data, not inject content. Use on any site fronted by a CDN or caching layer.

## Trigger Phrases
Use this skill when the conversation involves any of:
`cache deception, wcd, cache rule, static extension, path mapping, delimiter discrepancy, cache buster, x-cache, private response cached, cdn cache, profile.css`

## Description (Full)
Web cache deception tricks a cache into storing a victim's sensitive dynamic response: the victim visits an attacker-crafted URL that the origin answers with private data but the cache mistakes for a static resource and stores. The attacker then fetches the same URL and reads the victim's data.

## Full Methodology

# Web Cache Deception

## Shortcut

- Pick a sensitive GET endpoint (`/api/orders/123`, `/settings/profile`).
- Append a bogus path segment (`/foo`) — same data = origin ignores the segment.
- Append a static extension (`/foo.css`, `/foo.js`, `/foo.ico`) — cached = deception confirmed.
- Craft the victim URL, let the victim (or their browser preload) fetch it, then fetch the same URL yourself for the cached private response.

## Deception vs poisoning

- **Poisoning** manipulates cache keys to inject malicious content served to *other users*.
- **Deception** exploits cache *rules* to store the *victim's* private response for the attacker to read.

## Cache rules that matter

- **Static file extension rules** — `.css`, `.js`, `.ico`
- **Static directory rules** — prefixes like `/static`, `/assets`
- **File name rules** — `robots.txt`, `favicon.ico`

## Finding discrepancies

### Path mapping
Traditional mapping treats the path as a filesystem location; REST-style mapping abstracts it into endpoint + parameters:

```
/api/orders/123/foo.css
```

Origin (REST): `/api/orders/123` + ignored `foo` → private data. Cache (traditional): a `.css` file → cached under the full path.

Test the origin: add an arbitrary segment — data still returned means abstraction. Test the cache: make the segment look static (`foo.js`) — stored means the rule matched.

### Delimiter discrepancies
Frameworks disagree about which characters delimit the path:

- `;` — Java Spring matrix parameters (origin truncates at `;`)
- `.` — Ruby on Rails format suffixes
- `%00` — OpenLiteSpeed encoded null

Craft `/profile;foo.css`, `/profile%00foo.js`, `/profile.ico` — one side truncates/normalizes, the other treats everything as path. If the cache sees a static extension where the origin sees the bare endpoint, the private response is cached.

## Technique requirements

- **Cache buster**: every test request needs a unique cache key (unique query param, or Burp Param Miner's dynamic cachebuster) so you never read someone else's cached response (or your own).
- **Detecting cached responses**: `X-Cache: hit/miss/dynamic/refresh`, `Cache-Control: public, max-age>0`, and response-time differences.
- **Victim-side delivery**: same channels as reflected XSS (link, email, embedded); avoid fetching the victim URL in your own browser first — some apps invalidate on session mismatch.

## Prevention

- Cache only genuinely static content; never key on filename patterns alone.
- Make the origin 404 on unknown path segments instead of ignoring them.
- Align delimiter handling between cache and origin; reject encoded nulls and stray delimiters.
- `Cache-Control: private, no-store` on authenticated, dynamic responses.

## Notes for the fleet

- The discrepancy discipline (two parsers disagree → authority confusion) is the fleet's bread and butter; this is the same bug class as reserve/reserve-sync disagreements in AMMs.
- DeFi dashboards behind CDNs with authenticated API endpoints are realistic WCD targets — worth a passive check whenever triaging a protocol's web stack.
