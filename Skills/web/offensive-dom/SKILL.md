---
name: offensive-dom
description: "DOM-based vulnerability checklist: taint-flow analysis (sources like location/document.cookie/window.name to sinks like innerHTML/eval/document.write), the full sink-vulnerability mapping table, DOM XSS, open redirection, cookie manipulation, web-message manipulation, DOM clobbering (global variable overwrite via anchor elements), and prevention via whitelisting and encoding. Use on client-side heavy apps where attacker data flows through browser JavaScript."
---

# SKILL: DOM-Based Vulnerabilities

## Metadata
- **Skill Name**: dom
- **Folder**: offensive-dom
- **Source**: PortSwigger Web Security Academy — DOM-based vulnerabilities (https://portswigger.net/web-security/dom-based)

## Description
DOM-based vulnerability checklist: taint-flow analysis (sources like location/document.cookie/window.name to sinks like innerHTML/eval/document.write), the full sink-vulnerability mapping table, DOM XSS, open redirection, cookie manipulation, web-message manipulation, DOM clobbering (global variable overwrite via anchor elements), and prevention via whitelisting and encoding. Use on client-side heavy apps where attacker data flows through browser JavaScript.

## Trigger Phrases
Use this skill when the conversation involves any of:
`dom based, dom xss, taint flow, source sink, dom clobbering, web message, postmessage, window.name, location hash, client side vulnerability`

## Description (Full)
DOM-based vulnerabilities arise when client-side JavaScript takes attacker-controllable data (a source) and passes it into a dangerous function or API (a sink). Taint flow is the unifying frame; the class covers XSS, open redirection, cookie manipulation, JS injection, and more.

## Full Methodology

# DOM-Based Vulnerabilities

## Shortcut

- Map sources → sinks in the page's JS (Burp DOM Invader automates the canary flow).
- For each source, deliver a payload through the URL (query + fragment) and watch the DOM.
- Where filters block direct flow, look for clobbering: named DOM elements overwriting globals the script trusts.
- Web-message sources (`postMessage`) are a favorite: check `addEventListener('message')` handlers for missing origin validation.

## Sources

Common attacker-controllable properties:

```
document.URL, document.documentURI, document.baseURI
location (href/search/hash)
document.cookie, document.referrer, window.name
history.pushState / replaceState
localStorage, sessionStorage, IndexedDB
```

Plus data arriving from: reflected input, stored content, and **web messages**.

## Sinks by vulnerability

| Vulnerability | Example sink |
|---|---|
| DOM XSS | `document.write()` |
| Open redirection | `window.location` |
| Cookie manipulation | `document.cookie` |
| JavaScript injection | `eval()` |
| Document-domain manipulation | `document.domain` |
| WebSocket-URL poisoning | `WebSocket()` |
| Link manipulation | `element.src` |
| Web message manipulation | `postMessage()` |
| Ajax request-header manipulation | `setRequestHeader()` |
| Local file-path manipulation | `FileReader.readAsText()` |
| Client-side SQL injection | `ExecuteSql()` |
| HTML5-storage manipulation | `sessionStorage.setItem()` |
| Client-side XPath injection | `document.evaluate()` |
| Client-side JSON injection | `JSON.parse()` |
| DOM-data manipulation | `element.setAttribute()` |
| Denial of service | `RegExp()` |

## Classic flow example

```js
goto = location.hash.slice(1)
if (goto.startsWith('https:')) { location = goto; }
```

→ DOM open redirection via `https://site.com/example#https://evil-user.net`.

## DOM clobbering

Inject HTML to overwrite JavaScript globals/properties using named elements (anchor `id`/`name` attributes become window properties):

```html
<a id="config"></a>
```

If the page does `config.transport_url || default`, your injected element shadows the real config. Chain two elements with a form for nested properties (`x[y]` shape). Use clobbering to reach sinks the taint flow can't reach directly: pollute a config value that a later script feeds into `innerHTML`, `fetch(url)`, or a script `src`.

## Web-message manipulation

`window.addEventListener('message', ...)` handlers that skip `event.origin` validation and pass `event.data` to a sink — exploitable from any hostile page via `targetWindow.postMessage(payload, '*')`.

## Prevention

- Avoid passing untrusted-source data to sinks at all.
- Whitelist-validate; otherwise context-correct encoding (HTML, URL, JS, CSS in the right sequence).
- Validate `origin` on every message handler; treat postMessage data as untrusted.
- Defend against clobbering by checking `hasOwnProperty` on config reads and freezing critical globals.

## Notes for the fleet

- Source→sink discipline is the fleet's native model: on-chain, msg.sender-driven state into external calls is taint flow too.
- DeFi front-ends are the practical target: wallet-connected pages with URL-driven state and web-message integrations (wallet postMessage APIs) are where DOM bugs meet money.
