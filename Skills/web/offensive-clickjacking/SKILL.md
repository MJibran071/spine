---
name: offensive-clickjacking
description: "Clickjacking (UI redressing) checklist: iframe overlay attacks with CSS (opacity, z-index, precise positioning), Clickbandit PoC generation, prefilled form input attacks, frame-busting bypass via iframe sandbox, multistep clickjacking, combination with DOM XSS, and defenses (X-Frame-Options, CSP frame-ancestors). Use when testing whether sensitive actions can be framed and click-napped."
---

# SKILL: Clickjacking

## Metadata
- **Skill Name**: clickjacking
- **Folder**: offensive-clickjacking
- **Source**: PortSwigger Web Security Academy — Clickjacking (https://portswigger.net/web-security/clickjacking)

## Description
Clickjacking (UI redressing) checklist: iframe overlay attacks with CSS (opacity, z-index, precise positioning), Clickbandit PoC generation, prefilled form input attacks, frame-busting bypass via iframe sandbox, multistep clickjacking, combination with DOM XSS, and defenses (X-Frame-Options, CSP frame-ancestors). Use when testing whether sensitive actions can be framed and click-napped.

## Trigger Phrases
Use this skill when the conversation involves any of:
`clickjacking, ui redressing, frame busting, x-frame-options, frame-ancestors, iframe overlay, clickbandit, hidden iframe, clicknap`

## Description (Full)
Clickjacking tricks a user into clicking actionable content on a hidden website by overlaying it under decoy content. Unlike CSRF, the user performs a real click — CSRF tokens do not mitigate it, because the session is genuine; only the click is stolen.

## Full Methodology

# Clickjacking

## Shortcut

- Check whether the target can be framed at all (no X-Frame-Options / frame-ancestors).
- Identify a single-click sensitive action (delete, follow, transfer-confirm).
- Build the overlay: transparent iframe over a decoy button; align positions.
- For protections: test frame-buster bypass with `sandbox="allow-forms"`; use Clickbandit for fast PoCs.

## The overlay

```html
<head>
<style>
#target_website { position:relative; width:128px; height:128px; opacity:0.00001; z-index:2; }
#decoy_website  { position:absolute; width:300px; height:400px; z-index:1; }
</style>
</head>
<body>
<div id="decoy_website">...decoy content...</div>
<iframe id="target_website" src="https://vulnerable-website.com"></iframe>
</body>
```

- Absolute+relative positioning keeps alignment across screens; `z-index` stacks the layers; opacity near 0.0 hides the target (staying above browser transparency-detection thresholds, e.g. Chrome's iframe checks).

## Clickjacking with prefilled form input

Sites allowing GET-parameter form prepopulation let the attacker pre-fill fields (email, amount) via the target URL; the transparent submit button then rides a decoy click.

## Frame busting bypass

Client-side busting scripts are circumvented with the HTML5 iframe `sandbox` attribute:

```html
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

`allow-forms`/`allow-scripts` permit actions inside the frame while omitting `allow-top-navigation` — the frame cannot check whether it is the top window, so the bust script never fires.

## Multistep clickjacking

Multiple decoy pages/iframes, one per step (add to basket → confirm order): considerable precision, but enables full multi-action flows.

## Combined with DOM XSS

Clickjacking is a delivery channel: aim the transparent click at a URL whose DOM XSS payload executes after the user's click — user-triggered, real-session XSS delivery.

## Defenses

- **X-Frame-Options**: `deny` / `sameorigin` (inconsistent browser support; `allow-from` is dead).
- **CSP frame-ancestors**: the modern, correct control — `frame-ancestors 'none'` or `'self'` (or an allow-list).
- Frame-busting scripts alone are not a defense.

## Notes for the fleet

- Lower direct relevance to on-chain work, but DeFi front-ends with one-click confirmations (approve, swap, delegate) are exactly the surface clickjacking rides — a wallet-connected page that can be framed is worth a passive X-Frame-Options check during triage.
