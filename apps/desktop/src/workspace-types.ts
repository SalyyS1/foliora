export type ClaimStatus = 'candidate' | 'confirmed' | 'rejected' | 'superseded';

export interface SourceSummary {
  id: string;
  title: string | null;
  mediaType: string;
  capturedAt: string;
  byteLength: number;
}

export interface SourceRecord {
  schema_version: number;
  id: string;
  fingerprint: string;
  media_type: string;
  title: string | null;
  captured_at: string;
  sensitivity: string;
  expires_at: string | null;
}

export type SourceDetail =
  | { kind: 'text'; source: SourceRecord; text: string; truncated: boolean }
  | { kind: 'pdf'; source: SourceRecord; pages: Array<{ page: number; text: string; truncated: boolean }> }
  | {
      kind: 'email'; source: SourceRecord; subject: string | null; from: string | null;
      to: string[]; dateHeader: string | null; bodySourceId: string; attachments: SourceSummary[];
    }
  | {
      kind: 'image'; source: SourceRecord; format: 'png' | 'jpeg'; encodedWidth: number;
      encodedHeight: number; displayWidth: number; displayHeight: number; orientation: string;
    }
  | { kind: 'unsupported'; source: SourceRecord };

export interface Claim {
  id: string;
  claim_type: string;
  subject: string;
  value: unknown;
  status: ClaimStatus;
  revision: number;
  sensitivity: 'public' | 'internal' | 'private' | 'highly_sensitive';
  provenance: {
    kind: string;
    source_id?: string;
    locator?: { kind: string; start?: number; end?: number };
  };
}

export interface BundleDraft {
  schema_version: number;
  id: string;
  purpose: string;
  claim_ids: string[];
  expires_at: string | null;
}

export interface BundleComposition {
  template_id: string;
  template_version: number;
  subject: string;
  draft: BundleDraft | null;
  score: { confirmed_required: number; total_required: number; percent: number };
  missing_questions: Array<{ claim_type: string; priority: number; vi: string; en: string }>;
  expired_claim_ids: string[];
  candidate_claim_ids: string[];
}

export interface ExportReceipt {
  path: string;
  bytes: number;
  payloadSha256: string;
  bundleId: string;
}

export interface JsonExportPreview {
  content: string;
  bytes: number;
  payloadSha256: string;
  bundleId: string;
  exportedAt: string;
}

export interface ClipboardExportPreview {
  content: string;
  bytes: number;
  payloadSha256: string;
  bundleId: string;
  exportedAt: string;
  includedClaimIds: string[];
}

export interface ClipboardReceipt {
  bytes: number;
  payloadSha256: string;
  bundleId: string;
}

export interface ArchiveExportPreview {
  manifest: {
    schema_version: number;
    format: string;
    bundle_id: string;
    exported_at: string;
    includes_original_sources: boolean;
    entries: Array<{ path: string; bytes: number; sha256: string }>;
  };
  bytes: number;
  payloadSha256: string;
  bundleId: string;
  exportedAt: string;
}

export interface PdfExportPreview {
  bytes: number;
  payloadSha256: string;
  bundleId: string;
  exportedAt: string;
}

export interface ConflictSet {
  id: string;
  claim_ids: string[];
  claim_type: string;
  subject: string;
}

export interface WorkspaceSnapshot {
  sources: SourceSummary[];
  claims: Claim[];
  conflicts: ConflictSet[];
}

export interface ModelRequestPreview {
  schemaVersion: number;
  provider: string;
  endpoint: string;
  model: string;
  sourceId: string;
  sourceFingerprint: string;
  payload: string;
  payloadSha256: string;
  disclosedBytes: number;
  omittedBytes: number;
  redactionCount: number;
}

export interface ModelSuggestion {
  claimType: string;
  subject: string;
  quote: string;
  start: number;
  end: number;
}

export interface ModelSuggestionBatch {
  sourceId: string;
  sourceFingerprint: string;
  payloadSha256: string;
  suggestions: ModelSuggestion[];
}

export interface AuthorizedExtensionGrant {
  id: string;
  topOrigin: string;
  approvedClaimIds: string[];
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface OcrStatus {
  available: boolean;
  engineVersion: string | null;
  languages: string[];
}

export interface OcrRegion {
  text: string;
  x: number;
  y: number;
  width: number;
  height: number;
  confidenceMilli: number;
}

export interface OcrPage {
  page: number;
  width: number;
  height: number;
  engine: string;
  engineVersion: string;
  languages: string[];
  regions: OcrRegion[];
}
