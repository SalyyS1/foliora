# Changelog

All notable changes to Foliora are documented here.

## 0.5.0 - 2026-11-18

Interactive HTML/SVG citation graph explorer, coordinate-aware native PDF table extraction pipeline, and Ed25519 cryptographic bundle attestation.

### Included

- Added deterministic SVG (`render_svg`) and offline self-contained interactive HTML/SVG (`render_html`, `foliora graph --format html|svg`) citation graph bundle generators in `foliora-export` with 3-tier Bezier lineage layout, interactive node provenance inspection, sensitivity and search filtering, strict Content-Security-Policy, and script-breakout escaping.
- Added coordinate-aware native PDF table extraction (`extract_pdf_tables`, `extract_pdf_tables_with_password`, `candidate_from_pdf_table_cell`, `foliora tables`) in `foliora-ingestion` decoding bounded PDF content stream operators (`Tm`, `Td`, `TD`, `T*`, `Tf`, `Tj`, `TJ`, `cm`, `q`/`Q`) into user-space `(x, y)` spans, segmenting multi-column tables away from surrounding prose, reconstructing Markdown/CSV/JSON cell matrices, and anchoring cell candidates with `SourceLocator::Region`.
- Added Ed25519 cryptographic bundle signing and strict verification (`generate_signing_keypair`, `sign_reviewed_bundle`, `sign_reviewed_bundle_inline`, `verify_bundle_signature`, `foliora keygen`, `foliora sign`, `foliora verify-sig`) in `foliora-export` over domain-separated canonical JSON digests (`FOLIORA-REVIEWED-BUNDLE-SIG-V1`) with pinned public-key enforcement and constant-time digest validation.

## 0.4.0 - 2026-11-18

Structured citation graph exports (DOT and Mermaid), semantic TF-IDF chunk deduplication, streaming context-pack diff engine, and standalone foliora CLI.

### Included

- Added structured citation graph export (`export_citation_graph`, `render_dot`, `render_mermaid`) in `foliora-export` tracing complete evidence attribution chains from evidence sources to reviewed claims with exact locator annotations, deterministic layout styles, script-injection escaping, and SHA-256 audit fingerprint binding.
- Added semantic chunk deduplication using cosine similarity on TF-IDF vectors (`with_semantic_threshold`, `tfidf_cosine_similarity`) in `foliora-ingestion` alongside exact SHA-256 deduplication, merging paraphrased or near-duplicate clauses into shared evidence chains while tracking `semantic_deduplicated_count` and saving LLM context tokens.
- Added streaming context-pack diff engine (`diff_reviewed_bundles`, `diff_jsonl_streams`, `render_diff_markdown`) in `foliora-export` computing exact SHA-256 payload digests, claim lifecycle changes (added, removed, modified), evidence provenance modifications, and Jaccard citation overlap metrics.
- Added standalone `foliora` CLI binary (`crates/export/src/bin/foliora.rs`) supporting `foliora diff <file_a> <file_b> [--format summary|markdown|json]`, `foliora graph <file> [--format dot|mermaid|json]`, and `foliora verify <file>`.

## 0.3.0 - 2026-11-15

Multi-modal `.docx` ingestion, SHA-256 cross-document chunk deduplication, token-budget Markdown allocation, streaming JSONL context-pack pipeline, and client-side browser bundle unpacker on GitHub Pages.

### Included

- Added bounded offline OOXML `.docx` WordprocessingML ingestion (`import_docx`, `candidate_from_docx_span`) in `foliora-ingestion` with OLE2/OOXML encryption detection (`EncryptedDocx`), fail-closed DTD/XXE rejection, per-entry ZIP decompression caps, table/paragraph extraction, and tracked-deletion (`w:delText`) / field-code (`w:instrText`) exclusion.
- Added multi-modal sliding-window chunking (`chunk_text`, `chunk_pdf`, `chunk_docx`) with exact UTF-8 byte and PDF page-span provenance plus `ChunkDeduplicator` performing whitespace-normalized SHA-256 deduplication across PDF, DOCX, Markdown, and plain-text sources while retaining cross-source provenance trails.
- Added `export_budgeted_markdown` (`TokenBudgetPolicy`, `BudgetedMarkdownExport`) in `foliora-export` enforcing hard LLM token ceilings with pinned-claim priority tiers, shared-evidence marginal token cost amortization, and transitive evidence pruning.
- Added `StreamingPackBuilder`, `write_reviewed_bundle_jsonl`, and `verify_jsonl_stream` in `foliora-export` for incremental SHA-256-bound JSONL context-pack streaming and bounded-memory verification with `FP001`-`FP004` hazard scanning.
- Upgraded `@foliora/site` (`https://salyys1.github.io/foliora/`) into a zero-upload WebCrypto `.foliora-pack` (`.zip`) unpacker, SHA-256 manifest verifier, `FP001`-`FP004` prompt-injection scanner, `.docx`/`.md`/`.txt` chunk deduplicator, and interactive token-budget lab.

## 0.2.0 - 2026-11-14

Context pack verification, indirect prompt-injection scanning, Markdown context export, and dependency security hardening.

### Included

- Added fail-closed `verify_reviewed_bundle` and `verify_portable_archive` in `foliora-export` enforcing schema contracts, canonical UTC timestamps, bundle expiry, referential evidence integrity, orphan-evidence rejection, conflict checks, bounded 16 MiB per-entry ZIP extraction, and constant-time SHA-256 `ExportAuditEvent` binding.
- Added `scan_bundle_hazards` detecting indirect prompt-injection and smuggling patterns (`FP001` Unicode BiDi controls, `FP002` Plane-14 tag and zero-width characters, `FP003` ChatML/XML/instruction-override markers, and `FP004` external Markdown image beacons) across nested JSON claim values and evidence titles.
- Added deterministic citation-grounded Markdown context pack exporter (`export_reviewed_markdown`) with control/table-injection escaping and transitive evidence pruning.
- Upgraded `zip` to 9.5, `object_store` to 0.14, `rustls` to 0.23.46, `rustls-webpki` to 0.103.17, `webpki-roots` to 1.0.12, `quinn-proto` to 0.11.19, and `quinn-udp` to 0.5.16 while preserving Rust 1.88.0 MSRV compatibility and embedding sync SQL migrations without `sqlx-macros`.
- Added automated GitHub Pages deployment workflow for `@foliora/site` and restored disposable S3 durability CI against `motoserver/moto:5.2.3`.

## 0.1.0 - 2026-09-23

Initial engineering release candidate for review.

### Included

- Offline-first encrypted vault with Argon2id and XChaCha20-Poly1305.
- Bounded text, Markdown, PDF, email, PNG/JPEG ingestion with source evidence.
- Review-required claims, provenance, expiry, conflict and completeness checks.
- Deterministic reviewed JSON, PDF, clipboard and portable archive exports.
- Bilingual Vietnamese/English desktop shell, public preview site and browser extension.
- Preview-first optional BYOK model suggestions with literal redaction and exact quote checks.
- End-to-end encrypted sync protocol with PostgreSQL metadata and opaque S3-compatible objects.
- Durable quota, pairing, revocation, migration, restart and backup/restore tests.
- Windows Tauri native build and native-host fail-closed smoke coverage.

### Verification

- Workspace Rust tests: 196 passed, 0 failed, 5 environment tests ignored by default.
- Rust 1.88 Windows workspace tests: 196 passed, 0 failed, 5 environment tests ignored.
- Rust fmt and Clippy: passed.
- JavaScript checks, tests, site artifact validation and desktop web build: passed.
- Local PostgreSQL 16 + Moto 5.2.3 S3-compatible durability and destructive restore drill: passed.
- Windows Tauri `build --no-bundle` and native-host smoke: passed.

### Release limits

This is an engineering release candidate. Tesseract runtime assets, signed
installers, macOS/Linux packaging, MinIO-specific CI evidence, hosted operations,
independent security review and user pilot acceptance remain release gates.
