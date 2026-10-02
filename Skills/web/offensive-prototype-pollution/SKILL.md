---
name: offensive-prototype-pollution
description: "Prototype pollution checklist: sources (URL query/fragment, JSON input, web messages), the __proto__ merge mechanism, client-side vs server-side vectors, finding gadgets (config properties that flow into sinks), escalation to DOM XSS or server-side RCE, and defenses (Object.create(null), key sanitization). Use when testing JS-heavy apps, Node.js backends, or merge/recursive-extend code paths."
---

# SKILL: Prototype Pollution

## Metadata
- **Skill Name**: prototype-pollution
- **Folder**: offensive-prototype-pollution
- **Source**: PortSwigger Web Security Academy — Prototype pollution (https://portswigger.net/web-security/prototype-pollution)

## Description
Prototype pollution checklist: sources (URL query/fragment, JSON input, web messages), the __proto__ merge mechanism, client-side vs server-side vectors, finding gadgets (config properties that flow into sinks), escalation to DOM XSS or server-side RCE, and defenses (Object.create(null), key sanitization). Use when testing JS-heavy apps, Node.js backends, or merge/recursive-extend code paths.

## Trigger Phrases
Use this skill when the conversation involves any of:
`prototype pollution, __proto__, object merge, recursive extend, gadget chain, client side pollution, server side pollution, nodejs rce, config gadget, json parse pollution`

## Description (Full)
Prototype pollution lets an attacker add arbitrary properties to global object prototypes (usually Object.prototype), which are then inherited by user-defined objects. Alone it is often not exploitable, but chained with a gadget that passes an inherited property into a sink it becomes DOM XSS (client-side) or RCE (server-side).

## Full Methodology

# Prototype Pollution

## Shortcut

- Find merge/extend code paths that process user input without key sanitization.
- Inject `__proto__[prop]=value` via URL, JSON body, or web message.
- Confirm pollution with a benign canary property observed in an unrelated object.
- Hunt gadgets: config-style properties (`transport_url`, `env`, `NODE_OPTIONS`, `exposeFunction` names) consumed without own-property checks.

## How it arises

A recursive merge assigns nested properties of a user-controlled object onto a target. `targetObject.__proto__.evilProperty = 'payload'` writes to the *prototype*, not the instance — every object inheriting Object.prototype now has `evilProperty`.

### Sources
- **URL** — `?__proto__[evilProperty]=payload` (query and fragment variants)
- **JSON input** — `JSON.parse('{"__proto__": {"evilProperty": "payload"}}')` produces an own `__proto__` key that merge functions then follow
- **Web messages** — postMessage data parsed into objects

### Exploitation requirements
1. A **source** (above)
2. A **sink** — a function or DOM element that executes/renders its input
3. A **gadget** — a property passed into a sink without filtering, inheritable by the polluted object (not defined directly on the instance)

## Gadget hunting

Libraries read config options with defaults:

```js
let transport_url = config.transport_url || defaults.transport_url;
let script = document.createElement('script');
script.src = `${transport_url}/example.js`;
```

If `config` doesn't define `transport_url` on itself, polluting the prototype sets it:

```
?__proto__[transport_url]=data:,alert(1);//
```

Server-side Node gadgets to check: `child_process` spawn options (`env`, `shell`), Express res locals, JNDI-like library options, `NODE_OPTIONS` (when spawning), Buffer/`--inspect` flags. Client-side: DOM XSS via script src, iframe src, element attribute defaults.

## Detection tips

- Client-side: add a property like `?__proto__[foo]=bar` then in the console check `({}).foo`.
- Use DOM Invader (Burp's browser) to automate canary-based detection.
- Server-side: look for error message changes, or pollute a property the app echoes back; distinguish own vs inherited with `hasOwnProperty`.

## Prevention

- Sanitize keys: block `__proto__`, `constructor`, `prototype` in merge inputs.
- Prefer `Map` over plain objects for user-controlled key-value data.
- Create config objects with `Object.create(null)` so they inherit nothing.
- Freeze sensitive prototypes (`Object.freeze(Object.prototype)` — blunt but effective in some runtimes).

## Notes for the fleet

- Conceptual parallel on-chain: inheritance and fallback behavior mean "state a contract never explicitly set" can still be read (e.g. uninitialized proxies, UUPS storage gaps). "Where does un-set state get inherited from?" is the same question.
- DeFi front-ends are in-scope for this class when reviewing a protocol's full attack surface.
