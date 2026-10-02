#!/usr/bin/env python3
"""Generate claude-skills.json manifest from Skills/ tree.

Reads YAML frontmatter from each SKILL.md and emits a compact JSON manifest
of all skills, grouped by category, for tooling that needs a machine-readable
index of the library.

Usage:
  python3 tools/build_manifest.py           # (re)generate claude-skills.json
  python3 tools/build_manifest.py --check   # exit 1 if the manifest is stale

Check mode is meant for CI / pre-commit: it rebuilds the manifest in memory
and fails if the committed JSON differs.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "Skills"
OUT = ROOT / "claude-skills.json"

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)

# 1024 chars keeps descriptions scannable; the longest current ones are ~1.9k,
# so anything over this almost certainly means prose leaked into the field.
MAX_DESCRIPTION_LENGTH = 2048


class ManifestError(Exception):
    pass


def parse_frontmatter(text: str) -> dict:
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    block = m.group(1)
    out: dict[str, str] = {}
    current_key: str | None = None
    buf: list[str] = []
    for line in block.splitlines():
        if not line.strip():
            continue
        if ":" in line and not line.startswith(" "):
            if current_key is not None:
                out[current_key] = "\n".join(buf).strip().strip('"')
                buf = []
            key, _, val = line.partition(":")
            current_key = key.strip()
            val = val.strip()
            if val:
                buf.append(val)
        else:
            buf.append(line.strip())
    if current_key is not None:
        out[current_key] = "\n".join(buf).strip().strip('"')
    return out


def build_manifest() -> dict:
    if not SKILLS_DIR.is_dir():
        raise ManifestError(f"{SKILLS_DIR} not found")

    manifest: dict = {
        "name": "claude-red",
        "version": "0.3.0",
        "license": "MIT",
        "homepage": "https://github.com/SnailSploit/claude-red",
        "categories": {},
        "skills": [],
    }
    seen_names: dict[str, Path] = {}
    errors: list[str] = []

    for category_dir in sorted(SKILLS_DIR.iterdir()):
        if not category_dir.is_dir():
            continue
        category = category_dir.name
        manifest["categories"][category] = []
        for skill_dir in sorted(category_dir.iterdir()):
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.is_file():
                continue
            fm = parse_frontmatter(skill_md.read_text(encoding="utf-8"))
            name = fm.get("name") or skill_dir.name
            description = fm.get("description", "").strip()

            if not description:
                errors.append(
                    f"{skill_md}: missing or empty 'description' in frontmatter"
                )
            if len(description) > MAX_DESCRIPTION_LENGTH:
                errors.append(
                    f"{skill_md}: description is {len(description)} chars "
                    f"(max {MAX_DESCRIPTION_LENGTH})"
                )
            if name in seen_names:
                errors.append(
                    f"{skill_md}: duplicate skill name '{name}' "
                    f"(already used by {seen_names[name]})"
                )
            seen_names[name] = skill_md

            entry = {
                "name": name,
                "category": category,
                "path": str(skill_md.relative_to(ROOT)),
                "description": description,
            }
            manifest["categories"][category].append(name)
            manifest["skills"].append(entry)

    if errors:
        raise ManifestError("manifest validation failed:\n  " + "\n  ".join(errors))

    manifest["skill_count"] = len(manifest["skills"])
    manifest["category_count"] = len(manifest["categories"])
    return manifest


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    try:
        manifest = build_manifest()
    except ManifestError as e:
        for line in str(e).splitlines():
            print(line, file=sys.stderr)
        return 1

    rendered = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"

    if check_only:
        if OUT.is_file() and OUT.read_text(encoding="utf-8") == rendered:
            print(f"OK: {OUT} is in sync ({manifest['skill_count']} skills, "
                  f"{manifest['category_count']} categories).")
            return 0
        print(f"STALE: {OUT} does not match Skills/ tree. "
              f"Run: python3 tools/build_manifest.py", file=sys.stderr)
        return 1

    OUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUT} with {manifest['skill_count']} skills across "
          f"{manifest['category_count']} categories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
