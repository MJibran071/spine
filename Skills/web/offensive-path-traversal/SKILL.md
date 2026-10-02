---
name: offensive-path-traversal
description: "Path traversal (directory traversal) checklist: reading arbitrary files via ../ sequences, bypassing filters with absolute paths, nested sequences (....//), URL and double URL-encoding (%2e%2e%2f, %252e%252e%252f), non-standard encodings, null-byte truncation, base-folder and extension requirements, and canonical-path defenses. Use when any feature loads files by user-controlled name/path."
---

# SKILL: Path Traversal

## Metadata
- **Skill Name**: path-traversal
- **Folder**: offensive-path-traversal
- **Source**: PortSwigger Web Security Academy — Path traversal (https://portswigger.net/web-security/file-path-traversal)

## Description
Path traversal (directory traversal) checklist: reading arbitrary files via ../ sequences, bypassing filters with absolute paths, nested sequences (....//), URL and double URL-encoding (%2e%2e%2f, %252e%252e%252f), non-standard encodings, null-byte truncation, base-folder and extension requirements, and canonical-path defenses. Use when any feature loads files by user-controlled name/path.

## Trigger Phrases
Use this skill when the conversation involves any of:
`path traversal, directory traversal, dot dot slash, arbitrary file read, file path, ../, traversal filter bypass, null byte truncation, canonical path, loadImage, filename parameter`

## Description (Full)
Path traversal vulnerabilities enable an attacker to read arbitrary files on the server running the application — application code, back-end credentials, sensitive OS files — and sometimes to write files, ultimately taking full control of the server.

## Full Methodology

# Path Traversal

## Shortcut

- Find features that load files by name: `/loadImage?filename=218.png`, report downloads, attachment views, template includes.
- Try `../../../etc/passwd` (Unix) and `..\..\..\windows\win.ini` (Windows) first.
- If blocked, escalate through the filter-bypass ladder below, one rung at a time.
- Confirm by reading a known file; then target app code, config, and credentials.

## The basic attack

The app appends user input to a base directory and reads it with a filesystem API:

```
/var/www/images/218.png            # intended
/var/www/images/../../../etc/passwd  # injected — steps up to filesystem root
```

## Filter-bypass ladder

1. **Absolute path** — `filename=/etc/passwd` (no traversal sequences at all).
2. **Nested sequences** — `....//` or `....\/` — revert to `../` when the inner sequence is stripped.
3. **URL encoding** — `%2e%2e%2f` (`../`); **double URL encoding** — `%252e%252e%252f` for servers that recursively decode.
4. **Non-standard encodings** — `..%c0%af`, `..%ef%bc%8f`.
5. **Base-folder required** — the input must *start with* the expected folder: `/var/www/images/../../../etc/passwd`.
6. **Extension required** — the input must *end with* the expected extension: `../../../etc/passwd%00.png` (null byte truncation).

Burp Intruder's `Fuzzing - path traversal` payload list packages most of these encodings.

## High-value targets once file read works

- Application source code and configuration
- Back-end credentials (DB configs, API keys)
- `/etc/passwd`, logs, SSH keys, cloud-instance metadata endpoints

## Prevention

- Best: never pass user-supplied input to filesystem APIs — rewrite the feature.
- Otherwise, two layers:
  1. Validate input against a whitelist (or strict alphanumerics) before processing.
  2. Append to the base directory, canonicalize the path with a platform API, and verify the canonicalized path still starts with the expected base directory.

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) { /* process */ }
```

## Notes for the fleet

- The escalation pattern (filter → encoding mismatch → parser discrepancy) is the same discipline as the fleet's URL-validation-bypass thinking in SSRF work.
- Off-chain components of DeFi projects (IPFS fetchers, static asset servers, report generators) are realistic traversal targets worth flagging during triage of a protocol's full stack.
