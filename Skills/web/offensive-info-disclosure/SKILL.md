---
name: offensive-info-disclosure
description: "Information disclosure (information leakage) checklist: sensitive data in error messages, verbose debug output, source code via backups and git dirs, robots.txt and directory listings, response comparison for enumeration (vs hidden fields), Fuzzing for hidden paths, and severity assessment. Use during recon of any target to map what its responses reveal before attacking further."
---

# SKILL: Information Disclosure

## Metadata
- **Skill Name**: info-disclosure
- **Folder**: offensive-info-disclosure
- **Source**: PortSwigger Web Security Academy — Information disclosure (https://portswigger.net/web-security/information-disclosure)

## Description
Information disclosure (information leakage) checklist: sensitive data in error messages, verbose debug output, source code via backups and git dirs, robots.txt and directory listings, response comparison for enumeration (vs hidden fields), Fuzzing for hidden paths, and severity assessment. Use during recon of any target to map what its responses reveal before attacking further.

## Trigger Phrases
Use this skill when the conversation involves any of:
`information disclosure, info leak, error message, debug output, source code disclosure, robots.txt, directory listing, backup file, .git, version disclosure, enumeration`

## Description (Full)
Information disclosure is when a website unintentionally reveals sensitive information — user data, business data, or technical details that become the missing piece of a high-severity exploit chain.

## Full Methodology

# Information Disclosure

## Shortcut

- Fuzz for files/dirs that shouldn't exist publicly: robots.txt, /.git, /backup, /debug, /phpinfo, /.env, error pages with stack traces.
- Compare responses across states (existing vs non-existing user, valid vs invalid param) — enumeration is disclosure too.
- Strip away inputs one at a time (method override, content-type change) to trigger verbose errors.
- Grade what you find by what it *enables*, not by its presence.

## Classic examples

- Hidden directory structure via `robots.txt` or directory listings
- Source code via temp backups (`file.php.bak`, `file.php~`, `.git/`, `.svn/`)
- Database table/column names in error messages
- Credit card / PII exposure in API responses
- Hard-coded API keys, IPs, DB credentials in source
- Subtle behavioral differences hinting at resource existence (user enumeration)

## How it arises

1. **Internal content left public** — dev comments, debug endpoints, default docs.
2. **Insecure configuration** — verbose errors, debug flags, default settings (stack traces on, directory listing on).
3. **Flawed design** — different responses for different error states enable enumeration (valid user vs invalid password timing/messages).

## Finding it

- Fuzz common paths and filenames (Burp Intruder wordlists: backup file extensions, config paths).
- Trigger errors by breaking inputs (bad types, oversized values, wrong methods, malformed headers/cookies) and read everything the response says — framework versions, file paths, SQL fragments.
- Compare paired requests (existent vs non-existent resources; two users) with Burp Comparer — tiny deltas (message wording, timing, cookie presence) carry the signal.
- Review JS source for API keys, endpoint maps, and comments; review meta generators and headers for versions.

## Severity assessment

- User/business data leaks: severe on their own.
- Technical leaks: severity = what they enable. A framework version is noise on a patched build and critical on a vulnerable one; a leaked key is critical by itself.
- Common-sense rule: report the *exploitable chain*, not the leak alone (unless the leak is inherently sensitive).

## Prevention

- Audit code/comments before shipping; automate comment stripping in builds.
- Generic error messages; log details server-side only.
- Disable debug/diagnostic endpoints in production.
- Understand third-party tech defaults; turn off what you don't use.

## Notes for the fleet

- The fleet's own discipline mirrors this: recon summaries record versions and shapes but never treat them as findings — the chain matters.
- On-chain parallel: verified source repos often leak deployment scripts, private RPC keys, or internal endpoints in git history — a passive recon lane when a protocol's GitHub is in scope.
