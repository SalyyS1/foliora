---
date: 2026-09-13
session: "260913-1255-sync-durability-hardening"
---

# Sync durability hardening

## Context

Harden sync GC, root migration, and restore verification. Initial passing tests
missed failure modes found during review. See the [evidence record](../verification-2026-09-13.md).

## What happened

- Review exposed delayed DELETE after repair/commit, timestamp ordering mistaken
  for root identity, and inventories that omitted untracked payload hashes.
- New/repair writes now use fresh random physical generations. Root migration
  requires unique active original-transaction evidence: device/vault creation
  timestamps must match. Streamed inventory hashes every `v1` entry, including untracked data.
- Main confirmed 196 workspace tests and all five explicitly run environment
  tests passed: four PG16.11 + LocalFS scenarios and one PG-only migration test
  containing nine fixtures. Restore matched five physical keys and SHA-256 hashes.
- Frontend/site checks, formatting, workspace Clippy, and Actionlint passed.

## Reflection

Green tests covered the modeled sequence, not every storage failure ordering.
Review-driven fixtures made delayed completion, root evidence, and inventory
coverage explicit. LocalFS restore success does not establish S3 behavior.

## Decisions

- Retain committed history; keep integrity maintenance streaming and read-only,
  without migrations, HTTP startup, or background writes; stop writers during verification.
- Keep S3 unverified and release/user-pilot gates open; claim no full release.
- AgentWiki/external publishing skipped: no external write authorization.

## Next steps

Run the disposable S3/MinIO restore and inventory comparison; complete remaining
release gates and reconcile old-plan user/pilot acceptance with the roadmap.
