export const MAX_ARCHIVE_ENTRY_BYTES: number;
export const EXPORT_SCHEMA_VERSION: number;
export const DOMAIN_SCHEMA_VERSION: number;
export const ARCHIVE_SCHEMA_VERSION: number;

export type SourceLocator =
  | { kind: 'page'; page: number }
  | { kind: 'span'; start: number; end: number }
  | { kind: 'page_span'; page: number; start: number; end: number }
  | { kind: 'region'; page: number; x: number; y: number; width: number; height: number };

export interface ExportedProvenance {
  source_id: string | null;
  locator: SourceLocator | null;
  user_entered_at: string | null;
}

export interface ExportedClaim {
  id: string;
  claim_type: string;
  subject: string;
  value: unknown;
  sensitivity: 'public' | 'internal' | 'private' | 'highly_sensitive';
  provenance: ExportedProvenance;
}

export interface EvidenceSource {
  id: string;
  fingerprint: string;
  media_type: string;
  title: string | null;
  captured_at: string;
}

export interface ReviewedBundle {
  schema_version: number;
  domain_schema_version: number;
  id: string;
  purpose: string;
  exported_at: string;
  expires_at: string | null;
  claims: ExportedClaim[];
  evidence: EvidenceSource[];
}

export interface PromptHazard {
  rule_id: string;
  kind: string;
  target_id: string;
  field: string;
  detail: string;
}

export interface BundleVerificationResult {
  ok: boolean;
  errors: string[];
  hazards: PromptHazard[];
  claimCount: number;
  evidenceCount: number;
}

export interface ArchiveEntryReport {
  path: string;
  bytes: number;
  sha256: string;
  verified: boolean;
}

export interface PortableArchiveManifest {
  schema_version: number;
  format: string;
  bundle_id: string;
  exported_at: string;
  includes_original_sources: boolean;
  entries: Array<{ path: string; bytes: number; sha256: string }>;
}

export interface UnpackedArchiveReport {
  ok: boolean;
  outerSha256: string;
  manifest: PortableArchiveManifest | null;
  bundle: ReviewedBundle | null;
  entryReports: ArchiveEntryReport[];
  errors: string[];
  hazards: PromptHazard[];
}

export interface BudgetedMarkdownResult {
  ok: boolean;
  markdown: string;
  usedTokens: number;
  maxTokens: number;
  includedClaimIds: string[];
  droppedClaimIds: string[];
  prunedEvidenceIds: string[];
}

export interface LocalDocInput {
  name: string;
  mediaType: string;
  rawBytes: Uint8Array;
  text: string;
}

export function crc32(bytes: Uint8Array): number;
export function sha256Hex(bytes: Uint8Array | ArrayBuffer): Promise<string>;
export function estimatePackTokens(text: string): number;
export function scanBundleHazards(bundle: ReviewedBundle): PromptHazard[];
export function verifyReviewedBundle(bundle: unknown, verifiedAt?: string): BundleVerificationResult;
export function readZipEntriesBounded(
  zipBytes: Uint8Array | ArrayBuffer,
  maxEntries?: number,
  maxEntryBytes?: number,
): Promise<Map<string, Uint8Array>>;
export function unpackAndVerifyPortableArchive(
  zipBytes: Uint8Array | ArrayBuffer,
  verifiedAt?: string,
): Promise<UnpackedArchiveReport>;
export function buildPortableArchiveZip(
  bundle: ReviewedBundle,
  locale?: 'vi' | 'en',
): Promise<{
  bytes: Uint8Array;
  manifest: PortableArchiveManifest;
  auditEvent: {
    event_type: string;
    bundle_id: string;
    exported_at: string;
    payload_sha256: string;
    claim_ids: string[];
  };
}>;
export function renderReviewedMarkdown(
  bundle: ReviewedBundle,
  excludedClaimIds?: Set<string>,
  locale?: 'vi' | 'en',
): {
  markdown: string;
  claims: ExportedClaim[];
  evidence: EvidenceSource[];
  usedTokens: number;
} | null;
export function allocateBudgetedMarkdown(
  bundle: ReviewedBundle,
  maxTokens: number,
  excludedClaimIds?: Set<string>,
  locale?: 'vi' | 'en',
): BudgetedMarkdownResult;
export function extractLocalDocxText(bytes: Uint8Array | ArrayBuffer): Promise<string>;
export function buildBundleFromLocalDocuments(
  docs: LocalDocInput[],
  capturedAt?: string,
): Promise<{ bundle: ReviewedBundle; deduplicatedChunks: number }>;
