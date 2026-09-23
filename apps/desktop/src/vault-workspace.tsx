import { invoke } from '@tauri-apps/api/core';
import { FormEvent, SyntheticEvent, useEffect, useRef, useState } from 'react';
import type { Copy } from './copy';
import { utf8EvidenceSelection, type EvidenceSelection } from './evidence-offsets';
import { ImageOcrPreview } from './image-ocr-preview';
import { ExtensionAccess } from './extension-access';
import { ModelAssistant } from './model-assistant';
import type { ArchiveExportPreview, BundleComposition, Claim, ClipboardExportPreview, ClipboardReceipt, ExportReceipt, JsonExportPreview, PdfExportPreview, SourceDetail, WorkspaceSnapshot } from './workspace-types';

type SelectedEvidence = EvidenceSelection & { page?: number };

export function VaultWorkspace({ t }: { t: Copy }) {
  const [workspace, setWorkspace] = useState<WorkspaceSnapshot | null>(null);
  const [selectedSource, setSelectedSource] = useState<SourceDetail | null>(null);
  const [selectedSourceId, setSelectedSourceId] = useState('');
  const [sourcePdfPassword, setSourcePdfPassword] = useState('');
  const [sourcePasswordRequired, setSourcePasswordRequired] = useState(false);
  const [imageUrl, setImageUrl] = useState('');
  const [selection, setSelection] = useState<SelectedEvidence | null>(null);
  const [selectedPage, setSelectedPage] = useState(1);
  const [importPath, setImportPath] = useState('');
  const [pdfPassword, setPdfPassword] = useState('');
  const [claimType, setClaimType] = useState('custom.note');
  const [subject, setSubject] = useState('personal:me');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [workflow, setWorkflow] = useState('project_handoff');
  const [bundleSubject, setBundleSubject] = useState('project:1');
  const [composition, setComposition] = useState<BundleComposition | null>(null);
  const [approvals, setApprovals] = useState<string[]>([]);
  const [exportPath, setExportPath] = useState('');
  const [exportReceipt, setExportReceipt] = useState<ExportReceipt | null>(null);
  const [jsonPreview, setJsonPreview] = useState<JsonExportPreview | null>(null);
  const [excludedClaims, setExcludedClaims] = useState<string[]>([]);
  const [clipboardPreview, setClipboardPreview] = useState<ClipboardExportPreview | null>(null);
  const [clipboardReceipt, setClipboardReceipt] = useState<ClipboardReceipt | null>(null);
  const [archivePreview, setArchivePreview] = useState<ArchiveExportPreview | null>(null);
  const [archivePath, setArchivePath] = useState('');
  const [archiveReceipt, setArchiveReceipt] = useState<ExportReceipt | null>(null);
  const [pdfPreview, setPdfPreview] = useState<PdfExportPreview | null>(null);
  const [pdfUrl, setPdfUrl] = useState('');
  const [pdfPath, setPdfPath] = useState('');
  const [pdfReceipt, setPdfReceipt] = useState<ExportReceipt | null>(null);
  const sourceRequest = useRef(0);

  useEffect(() => { void loadWorkspace(); }, []);
  useEffect(() => () => { if (imageUrl) URL.revokeObjectURL(imageUrl); }, [imageUrl]);
  useEffect(() => () => { if (pdfUrl) URL.revokeObjectURL(pdfUrl); }, [pdfUrl]);
  useEffect(() => { setClipboardPreview(null); setClipboardReceipt(null); setArchivePreview(null); setArchiveReceipt(null); setPdfPreview(null); setPdfUrl(''); setPdfReceipt(null); }, [t.languageCode]);

  async function loadWorkspace() {
    try {
      setWorkspace(await invoke<WorkspaceSnapshot>('workspace_snapshot'));
    } catch (reason) {
      setError(String(reason));
    }
  }

  async function importFile(event: FormEvent) {
    event.preventDefault();
    const isPdf = /\.pdf$/i.test(importPath.trim());
    await mutate(() => invoke<WorkspaceSnapshot>('import_document', {
      path: importPath,
      pdfPassword: isPdf && pdfPassword ? pdfPassword : null,
    }));
    setImportPath('');
    setPdfPassword('');
  }

  async function openSource(sourceId: string, pdfPassword = sourcePdfPassword) {
    const request = ++sourceRequest.current;
    setError('');
    setSelection(null);
    setImageUrl('');
    setSelectedSource(null);
    setSourcePasswordRequired(false);
    setSelectedSourceId(sourceId);
    const source = workspace?.sources.find((item) => item.id === sourceId);
    const isPdf = source?.mediaType === 'application/pdf';
    try {
      const detail = await invoke<SourceDetail>('source_detail', {
        id: sourceId,
        pdfPassword: isPdf && pdfPassword ? pdfPassword : null,
      });
      if (request !== sourceRequest.current) return;
      setSelectedSource(detail);
      setSourcePasswordRequired(false);
      setSourcePdfPassword('');
      if (detail.kind === 'pdf') setSelectedPage(detail.pages[0]?.page ?? 1);
      if (detail.kind === 'image') {
        const bytes = await invoke<ArrayBuffer>('source_image_bytes', { id: sourceId });
        if (request !== sourceRequest.current) return;
        setImageUrl(URL.createObjectURL(new Blob([bytes], { type: 'image/png' })));
      }
    } catch (reason) {
      if (isPdf && String(reason).toLowerCase().includes('encrypted pdf')) {
        setSourcePasswordRequired(true);
      }
      setError(String(reason));
    }
  }

  async function unlockSelectedPdf(event: FormEvent) {
    event.preventDefault();
    if (selectedSourceId && sourcePdfPassword) await openSource(selectedSourceId, sourcePdfPassword);
  }

  function selectEvidence(event: SyntheticEvent<HTMLTextAreaElement>) {
    const input = event.currentTarget;
    const evidence = currentEvidence(selectedSource, selectedPage);
    if (!evidence) {
      setSelection(null);
      return;
    }
    const selected = utf8EvidenceSelection(input.value, input.selectionStart, input.selectionEnd);
    setSelection(selected ? { ...selected, page: evidence.page } : null);
  }

  async function addCandidate(event: FormEvent) {
    event.preventDefault();
    if (!selectedSource || !selection) return;
    await mutate(() => invoke<WorkspaceSnapshot>('create_evidence_candidate', {
      sourceId: selectedSource.source.id,
      claimType,
      subject,
      page: selection.page,
      start: selection.start,
      end: selection.end,
    }));
    setSelection(null);
  }

  async function review(claim: Claim, status: 'confirmed' | 'rejected') {
    await mutate(() => invoke<WorkspaceSnapshot>('review_claim', { id: claim.id, status }));
  }

  async function previewBundle(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setExportReceipt(null);
    try {
      const result = await invoke<BundleComposition>('compose_bundle', { workflow, subject: bundleSubject });
      setComposition(result);
      setApprovals([]);
      setJsonPreview(null);
      setExcludedClaims([]);
      setClipboardPreview(null);
      setClipboardReceipt(null);
      setArchivePreview(null);
      setArchiveReceipt(null);
      setPdfPreview(null);
      setPdfUrl('');
      setPdfReceipt(null);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function prepareJsonPreview() {
    setBusy(true);
    setError('');
    setExportReceipt(null);
    try {
      setJsonPreview(await invoke<JsonExportPreview>('preview_bundle_json', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals,
      }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function exportJson(event: FormEvent) {
    event.preventDefault();
    if (!jsonPreview) return;
    setBusy(true);
    setError('');
    try {
      const receipt = await invoke<ExportReceipt>('export_bundle_json', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals, path: exportPath,
        exportedAt: jsonPreview.exportedAt, expectedSha256: jsonPreview.payloadSha256,
      });
      setExportReceipt(receipt);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  function toggleApproval(id: string) {
    setApprovals((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
    setJsonPreview(null);
    setExportReceipt(null);
    setClipboardPreview(null);
    setClipboardReceipt(null);
    setArchivePreview(null);
    setArchiveReceipt(null);
    setPdfPreview(null);
    setPdfUrl('');
    setPdfReceipt(null);
  }

  function toggleClipboardClaim(id: string) {
    setExcludedClaims((current) => current.includes(id) ? current.filter((item) => item !== id) : [...current, id]);
    setClipboardPreview(null);
    setClipboardReceipt(null);
  }

  async function prepareClipboardPreview() {
    setBusy(true);
    setError('');
    setClipboardReceipt(null);
    try {
      setClipboardPreview(await invoke<ClipboardExportPreview>('preview_bundle_clipboard', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals,
        excludedClaimIds: excludedClaims, locale: t.languageCode,
      }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function copyClipboard() {
    if (!clipboardPreview) return;
    setBusy(true);
    setError('');
    try {
      setClipboardReceipt(await invoke<ClipboardReceipt>('copy_bundle_clipboard', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals,
        excludedClaimIds: excludedClaims, locale: t.languageCode,
        exportedAt: clipboardPreview.exportedAt, expectedSha256: clipboardPreview.payloadSha256,
      }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function prepareArchivePreview() {
    setBusy(true);
    setError('');
    setArchiveReceipt(null);
    try {
      setArchivePreview(await invoke<ArchiveExportPreview>('preview_bundle_archive', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals, locale: t.languageCode,
      }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function exportArchive(event: FormEvent) {
    event.preventDefault();
    if (!archivePreview) return;
    setBusy(true);
    setError('');
    try {
      setArchiveReceipt(await invoke<ExportReceipt>('export_bundle_archive', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals,
        locale: t.languageCode, exportedAt: archivePreview.exportedAt,
        expectedSha256: archivePreview.payloadSha256, path: archivePath,
      }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function preparePdfPreview() {
    setBusy(true);
    setError('');
    setPdfReceipt(null);
    setPdfUrl('');
    try {
      const preview = await invoke<PdfExportPreview>('preview_bundle_pdf', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals, locale: t.languageCode,
      });
      const bytes = await invoke<ArrayBuffer>('preview_bundle_pdf_bytes', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals,
        locale: t.languageCode, exportedAt: preview.exportedAt, expectedSha256: preview.payloadSha256,
      });
      setPdfPreview(preview);
      setPdfUrl(URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' })));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function exportPdf(event: FormEvent) {
    event.preventDefault();
    if (!pdfPreview) return;
    setBusy(true);
    setError('');
    try {
      setPdfReceipt(await invoke<ExportReceipt>('export_bundle_pdf', {
        workflow, subject: bundleSubject, approvedSensitiveClaimIds: approvals,
        locale: t.languageCode, exportedAt: pdfPreview.exportedAt,
        expectedSha256: pdfPreview.payloadSha256, path: pdfPath,
      }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function mutate(operation: () => Promise<WorkspaceSnapshot>) {
    setBusy(true);
    setError('');
    try {
      setWorkspace(await operation());
      setComposition(null);
      setJsonPreview(null);
      setClipboardPreview(null);
      setClipboardReceipt(null);
      setArchivePreview(null);
      setArchiveReceipt(null);
      setPdfPreview(null);
      setPdfUrl('');
      setPdfReceipt(null);
      setExportReceipt(null);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="workspace">
      <div className="workspace-title"><div><p className="eyebrow">{t.workspace}</p><h2>{t.reviewSources}</h2></div><span>{t.offlineBadge}</span></div>
      <form className="import-row" onSubmit={(event) => void importFile(event)}>
        <div className="import-fields">
          <label>{t.importPath}<input value={importPath} onChange={(event) => setImportPath(event.target.value)} placeholder={t.importHint} required /></label>
          <label>{t.pdfPassword}<input type="password" value={pdfPassword} onChange={(event) => setPdfPassword(event.target.value)} placeholder={t.pdfPasswordHint} autoComplete="off" /></label>
        </div>
        <button className="primary" disabled={busy}>{t.importAction}</button>
      </form>
      <p className="microcopy">{t.importSupport}</p>

      {error && <div className="error" role="alert"><strong>{t.workspaceError}</strong><span>{error}</span></div>}
      <div className="workspace-grid">
        <section className="source-list" aria-label={t.sources}>
          <h3>{t.sources} <small>{workspace?.sources.length ?? 0}</small></h3>
          {workspace?.sources.map((source) => (
            <button key={source.id} className={selectedSourceId === source.id ? 'selected' : ''} onClick={() => void openSource(source.id)}>
              <strong>{source.title ?? t.untitled}</strong><span>{formatBytes(source.byteLength)} · {source.mediaType.split(';')[0]}</span>
            </button>
          ))}
          {!workspace?.sources.length && <p className="blank">{t.noSources}</p>}
        </section>

        <section className="evidence-viewer">
          <h3>{t.evidence}</h3>
          {sourcePasswordRequired && <form className="pdf-unlock" onSubmit={(event) => void unlockSelectedPdf(event)}>
            <p>{t.pdfUnlockRequired}</p>
            <label>{t.pdfPassword}<input type="password" value={sourcePdfPassword} onChange={(event) => setSourcePdfPassword(event.target.value)} placeholder={t.pdfPasswordHint} autoComplete="off" required /></label>
            <button className="outline" disabled={busy}>{t.unlockPdf}</button>
          </form>}
          {selectedSource?.kind === 'email' ? <EmailPreview detail={selectedSource} t={t} onOpenSource={(id) => void openSource(id)} /> : selectedSource?.kind === 'image' ? <ImageOcrPreview detail={selectedSource} imageUrl={imageUrl} t={t} onWorkspace={(snapshot) => { setWorkspace(snapshot); setComposition(null); }} /> : selectedSource?.kind === 'unsupported' ? <p className="blank">{t.unsupportedPreview}</p> : selectedSource ? <>
            {selectedSource.kind === 'pdf' && <div className="page-tabs" aria-label={t.pdfPages}>{selectedSource.pages.map((page) => <button key={page.page} aria-pressed={selectedPage === page.page} onClick={() => { setSelectedPage(page.page); setSelection(null); }}>{t.page} {page.page}</button>)}</div>}
            <textarea readOnly value={currentEvidence(selectedSource, selectedPage)?.text ?? ''} onSelect={selectEvidence} aria-label={t.sourceText} />
            {currentEvidence(selectedSource, selectedPage)?.truncated && <p className="warning">{t.previewTruncated}</p>}
            <form className="candidate-form" onSubmit={(event) => void addCandidate(event)}>
              <p>{selection ? <><b>{t.selectedEvidence}</b> “{selection.text.slice(0, 100)}”</> : t.selectEvidence}</p>
              <div><label>{t.claimType}<input value={claimType} onChange={(event) => setClaimType(event.target.value)} required /></label><label>{t.subject}<input value={subject} onChange={(event) => setSubject(event.target.value)} required /></label></div>
              <button className="primary" disabled={!selection || busy}>{t.createCandidate}</button>
            </form>
          </> : <p className="blank">{t.chooseSource}</p>}
        </section>
      </div>

      <ModelAssistant
        source={selectedSource?.kind === 'text' ? selectedSource : null}
        t={t}
        disabled={busy}
        onWorkspace={(snapshot) => { setWorkspace(snapshot); setComposition(null); }}
      />

      <section className="ledger">
        <h3>{t.claimLedger} <small>{workspace?.claims.length ?? 0}</small></h3>
        {!!workspace?.conflicts.length && <div className="warning" role="status">{t.conflicts}: {workspace.conflicts.length}. {t.conflictHelp}</div>}
        <div className="claim-list">
          {workspace?.claims.map((claim) => <article key={claim.id}>
            <span className={`claim-status ${claim.status}`}>{t[claim.status]}</span>
            <div><strong>{displayValue(claim.value)}</strong><span>{claim.claim_type} · {claim.subject} · r{claim.revision}</span></div>
            {claim.status === 'candidate' && <div className="review-actions"><button disabled={busy} onClick={() => void review(claim, 'confirmed')}>{t.confirm}</button><button disabled={busy} onClick={() => void review(claim, 'rejected')}>{t.reject}</button></div>}
          </article>)}
          {!workspace?.claims.length && <p className="blank">{t.noClaims}</p>}
        </div>
      </section>

      <ExtensionAccess workspace={workspace} t={t} busy={busy} setBusy={setBusy} setError={setError} />

      <section className="bundle-composer">
        <h3>{t.bundleComposer}</h3>
        <form onSubmit={(event) => void previewBundle(event)}>
          <div><label>{t.bundleTemplate}<select value={workflow} onChange={(event) => { setWorkflow(event.target.value); setComposition(null); setJsonPreview(null); }}><option value="warranty_insurance">{t.warrantyTemplate}</option><option value="medical_visit">{t.medicalTemplate}</option><option value="project_handoff">{t.projectTemplate}</option></select></label><label>{t.bundleSubject}<input value={bundleSubject} onChange={(event) => { setBundleSubject(event.target.value); setComposition(null); setJsonPreview(null); }} required /></label></div>
          <button className="outline" disabled={busy}>{t.previewBundle}</button>
        </form>
        {composition && <div className="bundle-preview">
          <div className="bundle-score"><strong>{composition.score.percent}%</strong><span>{composition.score.confirmed_required}/{composition.score.total_required} {t.requiredFields}</span></div>
          {!!composition.missing_questions.length && <div className="missing-questions"><b>{t.missingInformation}</b>{composition.missing_questions.map((question) => <p key={question.claim_type}>{t.languageCode === 'vi' ? question.vi : question.en}</p>)}</div>}
          {composition.draft ? <>
            <div className="export-claims"><b>{t.exportClaims}</b>{composition.draft.claim_ids.map((id) => {
              const claim = workspace?.claims.find((item) => item.id === id);
              const sensitive = claim?.sensitivity === 'private' || claim?.sensitivity === 'highly_sensitive';
              return <label key={id}><input type="checkbox" checked={!sensitive || approvals.includes(id)} disabled={!sensitive} onChange={() => toggleApproval(id)} /><span><strong>{claim ? displayValue(claim.value) : id}</strong>{sensitive ? t.sensitiveApproval : t.nonSensitive}</span></label>;
            })}</div>
            <button className="outline" disabled={busy} onClick={() => void prepareJsonPreview()}>{t.prepareJson}</button>
            {jsonPreview && <div className="exact-preview"><div><strong>{t.exactPreview}</strong><code>{jsonPreview.payloadSha256}</code></div><pre>{jsonPreview.content}</pre></div>}
            <form className="export-row" onSubmit={(event) => void exportJson(event)}><label>{t.exportPath}<input value={exportPath} onChange={(event) => setExportPath(event.target.value)} placeholder={t.exportHint} required /></label><button className="primary" disabled={busy || !jsonPreview}>{t.exportJson}</button></form>
            <div className="clipboard-panel"><h4>{t.clipboardExport}</h4><p>{t.clipboardHelp}</p><div className="clipboard-claims">{composition.draft.claim_ids.map((id) => { const claim = workspace?.claims.find((item) => item.id === id); return <label key={id}><input type="checkbox" checked={!excludedClaims.includes(id)} onChange={() => toggleClipboardClaim(id)} /><span>{claim ? displayValue(claim.value) : id}</span></label>; })}</div><button className="outline" disabled={busy || excludedClaims.length === composition.draft.claim_ids.length} onClick={() => void prepareClipboardPreview()}>{t.previewClipboard}</button></div>
            {clipboardPreview && <div className="exact-preview"><div><strong>{t.clipboardExactPreview}</strong><code>{clipboardPreview.payloadSha256}</code></div><pre>{clipboardPreview.content}</pre><button className="primary" disabled={busy} onClick={() => void copyClipboard()}>{t.copyClipboard}</button></div>}
            {clipboardReceipt && <div className="export-success" role="status"><strong>{t.clipboardComplete}</strong><code>{clipboardReceipt.payloadSha256}</code></div>}
            <div className="archive-panel"><h4>{t.archiveExport}</h4><p>{t.archiveHelp}</p><button className="outline" disabled={busy} onClick={() => void prepareArchivePreview()}>{t.previewArchive}</button></div>
            {archivePreview && <><div className="exact-preview"><div><strong>{t.archiveExactPreview}</strong><code>{archivePreview.payloadSha256}</code></div><pre>{JSON.stringify(archivePreview.manifest, null, 2)}</pre></div><form className="export-row" onSubmit={(event) => void exportArchive(event)}><label>{t.archivePath}<input value={archivePath} onChange={(event) => setArchivePath(event.target.value)} placeholder={t.archiveHint} required /></label><button className="primary" disabled={busy}>{t.exportArchive}</button></form></>}
            {archiveReceipt && <div className="export-success" role="status"><strong>{t.archiveComplete}</strong><span>{archiveReceipt.path} · {formatBytes(archiveReceipt.bytes)}</span><code>{archiveReceipt.payloadSha256}</code></div>}
            <div className="pdf-panel"><h4>{t.pdfExport}</h4><p>{t.pdfHelp}</p><button className="outline" disabled={busy} onClick={() => void preparePdfPreview()}>{t.previewPdf}</button></div>
            {pdfPreview && pdfUrl && <><div className="pdf-exact-preview"><div><strong>{t.pdfExactPreview}</strong><code>{pdfPreview.payloadSha256}</code></div><iframe src={pdfUrl} title={t.pdfPreviewTitle} /></div><form className="export-row" onSubmit={(event) => void exportPdf(event)}><label>{t.pdfPath}<input value={pdfPath} onChange={(event) => setPdfPath(event.target.value)} placeholder={t.pdfHint} required /></label><button className="primary" disabled={busy}>{t.exportPdf}</button></form></>}
            {pdfReceipt && <div className="export-success" role="status"><strong>{t.pdfComplete}</strong><span>{pdfReceipt.path} · {formatBytes(pdfReceipt.bytes)}</span><code>{pdfReceipt.payloadSha256}</code></div>}
          </> : <p className="blank">{t.noExportableClaims}</p>}
          {exportReceipt && <div className="export-success" role="status"><strong>{t.exportComplete}</strong><span>{exportReceipt.path} · {formatBytes(exportReceipt.bytes)}</span><code>{exportReceipt.payloadSha256}</code></div>}
        </div>}
      </section>
    </div>
  );
}

function displayValue(value: unknown): string {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function formatBytes(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`;
}

function currentEvidence(detail: SourceDetail | null, page: number): { text: string; truncated: boolean; page?: number } | null {
  if (detail?.kind === 'text') return { text: detail.text, truncated: detail.truncated };
  if (detail?.kind === 'pdf') {
    const selected = detail.pages.find((item) => item.page === page);
    return selected ? { ...selected } : null;
  }
  return null;
}

function EmailPreview({ detail, t, onOpenSource }: { detail: Extract<SourceDetail, { kind: 'email' }>; t: Copy; onOpenSource: (id: string) => void }) {
  return <div className="email-preview">
    <dl>
      <div><dt>{t.emailSubject}</dt><dd>{detail.subject ?? '—'}</dd></div>
      <div><dt>{t.emailFrom}</dt><dd>{detail.from ?? '—'}</dd></div>
      <div><dt>{t.emailTo}</dt><dd>{detail.to.join(', ') || '—'}</dd></div>
      <div><dt>{t.emailDate}</dt><dd>{detail.dateHeader ?? '—'}</dd></div>
    </dl>
    <button className="outline" onClick={() => onOpenSource(detail.bodySourceId)}>{t.openEmailBody}</button>
    {!!detail.attachments.length && <div className="attachments"><b>{t.attachments}</b>{detail.attachments.map((attachment) => <button key={attachment.id} onClick={() => onOpenSource(attachment.id)}>{attachment.title ?? t.untitled} · {formatBytes(attachment.byteLength)}</button>)}</div>}
  </div>;
}
