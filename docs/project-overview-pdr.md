# Foliora — Product Requirements Document

## Product promise

Foliora turns a user's selected documents into a small, reviewable context pack
with exact evidence. The product makes sharing useful context safer by showing
where every value came from, keeping ambiguity visible, and requiring explicit
approval for sensitive data.

Vietnamese is the first-class launch locale. English is shipped alongside it;
all user-visible safety states, export guidance, and accessibility labels must
have both translations.

## Principles

1. Offline core: vault creation, ingestion, review, composition and export work
   without an account, cloud service, AI provider or network.
2. Human trust: a candidate is never silently promoted; conflicts and missing
   fields remain visible; every export has an exact preview and audit hash.
3. Minimal disclosure: source files stay local by default. Sync sends only
   client-encrypted objects and signed metadata.
4. Safe failure: malformed inputs, stale previews, revoked devices, oversized
   payloads and uncertain mappings fail closed.
5. Open by default: application code is AGPL-3.0-or-later; schemas and protocol
   definitions are Apache-2.0.

## Primary journeys

- Create a vault, create and save a recovery kit, import a document, inspect
  evidence, confirm a claim, compose a pack, preview it, and export JSON/PDF.
- Configure optional E2EE sync against a self-hosted or hosted endpoint.
- Pair a second device by copy/paste request and grant, compare a confirmation
  code out of band, then download the initial remote snapshot.
- Authorize a browser extension for one exact HTTPS origin and a selected claim
  subset for five minutes; never submit a form automatically.
- Optionally inspect and redact the complete payload for one text source, send
  it with a transient OpenAI API key, then choose which grounded suggestions
  become review-required candidates.

## V1 acceptance criteria

- All local data is encrypted at rest with authenticated encryption and a
  passphrase-derived key; plaintext passphrases, recovery codes and sync
  credentials are not returned to the webview.
- Source-backed claims retain exact byte/page/region provenance and explicit
  status transitions.
- Optional provider requests require an exact hash-bound preview and explicit
  consent; suggestions cannot bypass ordinary evidence or review validation.
- JSON, clipboard, archive and PDF exports cannot include unconfirmed,
  conflicting, expired, missing-evidence or unapproved sensitive claims.
- Sync detects concurrent heads and refuses last-write-wins. The service cannot
  decrypt vault content.
- Desktop/site/extension TypeScript checks, Rust fmt/clippy/tests, and artifact
  validators are green in CI.

## Explicit non-goals for V1

No automatic form submission, background scraping, server-side plaintext OCR,
silent AI extraction, password recovery without the recovery materials, or
automatic conflict resolution.
