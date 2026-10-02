---
name: offensive-jwt
description: "JWT attack checklist: signature-verification flaws (verify vs decode, alg:none acceptance and obfuscation), secret brute-forcing with hashcat -m 16500, header parameter injections (jwk self-signed embedding, jku URL pinning, kid path traversal / SQLi), algorithm confusion RS256→HS256, and re-signing workflows. Use when a target uses JSON web tokens for auth, sessions, or access control."
---

# SKILL: JWT Attacks

## Metadata
- **Skill Name**: jwt
- **Folder**: offensive-jwt
- **Source**: PortSwigger Web Security Academy — JWT attacks (https://portswigger.net/web-security/jwt)

## Description
JWT attack checklist: signature-verification flaws (verify vs decode, alg:none acceptance and obfuscation), secret brute-forcing with hashcat -m 16500, header parameter injections (jwk self-signed embedding, jku URL pinning, kid path traversal / SQLi), algorithm confusion RS256→HS256, and re-signing workflows. Use when a target uses JSON web tokens for auth, sessions, or access control.

## Trigger Phrases
Use this skill when the conversation involves any of:
`jwt, json web token, alg none, hs256, rs256, jwk, jku, kid injection, algorithm confusion, hashcat jwt, jwt brute force, token tampering, signature bypass`

## Description (Full)
JWT attacks send modified tokens to bypass authentication and access controls — usually by exploiting flawed signature verification or leaking/brute-forcing the signing key. Impact is typically account takeover or privilege escalation.

## Full Methodology

# JWT Attacks

## Shortcut

- Decode the token (jwt.io / Burp JWT Editor): inspect `alg`, claims, and header extras (jwk/jku/kid).
- Try the classic ladder: unsigned `alg:none` → claim tampering without resigning → key brute-force (`hashcat -a 0 -m 16500 <jwt> <wordlist>`) → header parameter injection → algorithm confusion.
- Re-sign with whatever key material you control; escalate the claim you can change (role, isAdmin, sub).

## Structure

Header.payload.signature — header and payload are base64url JSON; the signature is the trust anchor:

```json
{"alg": "HS256", "typ": "JWT"}
{"username": "carlos", "isAdmin": false}
```

## Signature-verification flaws

- **verify() vs decode()**: some implementations only call the library's decode — the signature is never checked. Tamper freely.
- **alg:none**: the header is user-controlled *before* verification, so an attacker can claim the token is unsigned. Filters often block exact `none` — try `None`, `nOnE`, or unexpected encodings. Trailing dot still required after an empty signature.
- **Claim tampering with signature kept**: some servers verify then trust claims the signature never covered (or verify the wrong part).

## Brute-forcing the secret

HS256 keys are arbitrary strings; weak/default/example secrets fall to wordlists:

```
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

Output: `<jwt>:<identified-secret>` (add `--show` on reruns). With the secret, mint any token.

## Header parameter injections

- **jwk** (embedded key): sign with your own RSA key and embed the matching public key in the header's `jwk` — misconfigured servers verify against the embedded key. Burp JWT Editor's "Embedded JWK" attack automates it.
- **jku** (key URL): header points to a JWKS URL — host your own JWKS file and point `jku` at it if the server fetches user-controlled URLs (pair with SSRF thinking; pin to the original host with SSRF bypasses if validated).
- **kid** (key ID): often used to build a filesystem path or SQL query.
  - Path traversal: `kid: "../../../../dev/null"` with an empty symmetric secret (sign with a blank key).
  - SQL injection: `kid: "x' UNION SELECT 'secret' -- "` to control the returned key material.

## Algorithm confusion (RS256 → HS256)

Server verifies RS256 tokens but the algorithm is taken from the token: re-sign the token as HS256 using the *public* RSA key (which is public!) as the HMAC secret. Servers that fetch the public key and then let the header pick HS256 accept your forgery. Steps: obtain the public key (JWKS endpoint), sign HS256 with it as the secret, submit with `alg: HS256`.

## Prevention

- Pin the algorithm server-side; reject `none` and any header-specified algorithm.
- Never verify against keys delivered in the token (jwk/jku) or keys selectable via unvalidated kid.
- Enforce strong, high-entropy signing secrets; rotate and never reuse example keys.
- Validate issuer/audience/expiry claims explicitly.

## Notes for the fleet

- On-chain analog: signature malleability and cross-chain replay (the fleet's lz-sig-cross-chain-replay class). A JWT's "the header decides how to verify" flaw is the same family as "the payload decides how to authenticate" — authority must never be derived from the unverified portion.
- DeFi session systems, dashboard logins, and off-chain APIs are the usual places JWTs appear in scope.
