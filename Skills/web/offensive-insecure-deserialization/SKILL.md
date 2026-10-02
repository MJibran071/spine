---
name: offensive-insecure-deserialization
description: "Insecure deserialization checklist: recognizing serialized objects (PHP O:, Java rO0/AC ED, Ruby MARSHAL, Python pickle), manipulating object attributes for privilege escalation, magic-method gadget chains (POP chains) for RCE, pre-built chains (ysoserial, phpggc), signed-cookie bypasses, and why post-deserialization validation is too late. Use when a target passes structured state in cookies, params, or API fields."
---

# SKILL: Insecure Deserialization

## Metadata
- **Skill Name**: insecure-deserialization
- **Folder**: offensive-insecure-deserialization
- **Source**: PortSwigger Web Security Academy — Insecure deserialization (https://portswigger.net/web-security/deserialization)

## Description
Insecure deserialization checklist: recognizing serialized objects (PHP O:, Java rO0/AC ED, Ruby MARSHAL, Python pickle), manipulating object attributes for privilege escalation, magic-method gadget chains (POP chains) for RCE, pre-built chains (ysoserial, phpggc), signed-cookie bypasses, and why post-deserialization validation is too late. Use when a target passes structured state in cookies, params, or API fields.

## Trigger Phrases
Use this skill when the conversation involves any of:
`insecure deserialization, object injection, php serialization, java deserialization, gadget chain, pop chain, ysoserial, pickle, marshal, session cookie deserialization, magic method`

## Description (Full)
Deserialization converts a byte stream back into live objects — including their private fields and state. When that stream is user-controllable, attackers can pass harmful data into application code, swap object classes entirely, and trigger attacks during deserialization itself (often before any validation runs).

## Full Methodology

# Insecure Deserialization

## Shortcut

- Spot serialized state: session cookies or params starting with `O:` (PHP), `rO0`/base64 of `AC ED` (Java), `MARSHAL`/hex `04 08` (Ruby), `8003 80` (Python pickle), or large opaque blobs.
- Modify attributes (admin flags, user IDs, expiry) and re-encode — privilege escalation is the first probe.
- If signatures guard the data, look for signature-verification flaws before deserialization logic.
- For RCE: identify the language/framework, find gadget chains (pre-built: ysoserial for Java, phpggc for PHP), craft and fire.

## Serialization vs deserialization

Serialization flattens object state (including private fields) to a stream; deserialization revives it as a fully functional object. The revived class is whatever the stream says — "object injection": any class available to the site may be instantiated regardless of what the app expected.

## Why it's dangerous

- Attacks often complete *during* deserialization (magic methods like PHP's `__wakeup`/`__destruct`, Java `readObject`) — before the app's logic ever inspects the object.
- Validation after deserialization is structurally too late.
- Dependency webs provide a huge pool of classes → unpredictable method chains → hard-to-anticipate data flows.

## Recognizing formats

| Language | Serialized marker |
|---|---|
| PHP | `O:<len>:"ClassName":...` |
| Java (binary) | `AC ED 00 05` hex / `rO0AB...` base64 |
| Ruby | `04 08` / `MARSHAL::` |
| Python | pickle opcodes, `8003 80` |
| .NET | `AAEAAAD/////` base64 |

## Exploitation ladder

1. **Attribute manipulation**: decode, edit privileges/IDs, re-encode. Even binary formats are attacker-editable — "developers think users can't read it" is the recurring mistake.
2. **Signed objects**: if the cookie is signed (HMAC), first hunt signature-verification flaws (unsigned compare, length-extended, key reuse) — see the JWT skill for the same patterns.
3. **Gadget chains (POP)**: chain existing class methods so the payload's magic method kicks off a sequence ending in a sink (exec, file write, SSRF). Use pre-built chains:
   - Java: ysoserial (Commons Collections, Hibernate, Spring...)
   - PHP: phpggc (framework-specific chains)
   - Ruby/.NET: chain catalogs per library set
4. **Application-functionality exploitation**: when no ready chain exists, use the site's own classes — e.g. a class whose destructor deletes files, or one that performs requests.

## Prevention (and why bypasses work)

- Never deserialize untrusted input; prefer simple data formats (JSON) with schema validation.
- Integrity checks must run *before* deserialization — signatures checked after are theater.
- "Try to eliminate gadget chains" is impractical: cross-library dependency webs and future memory-corruption bugs make the surface unbounded.

## Notes for the fleet

- The "trust decided before validation runs" structure is exactly the fleet's signature-replay lesson on-chain: verify at execution time, against execution context, never trust prior handling.
- Off-chain APIs that pass base64 state blobs (session tickets, premium features, referral payloads) are the usual place this appears in a DeFi target's scope.
