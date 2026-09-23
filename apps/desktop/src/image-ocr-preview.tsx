import { invoke } from '@tauri-apps/api/core';
import { FormEvent, useEffect, useState } from 'react';
import type { Copy } from './copy';
import type { OcrPage, OcrStatus, SourceDetail, WorkspaceSnapshot } from './workspace-types';

type ImageDetail = Extract<SourceDetail, { kind: 'image' }>;

export function ImageOcrPreview({
  detail, imageUrl, t, onWorkspace,
}: {
  detail: ImageDetail;
  imageUrl: string;
  t: Copy;
  onWorkspace: (snapshot: WorkspaceSnapshot) => void;
}) {
  const [status, setStatus] = useState<OcrStatus | null>(null);
  const [ocr, setOcr] = useState<OcrPage | null>(null);
  const [regionIndex, setRegionIndex] = useState<number | null>(null);
  const [claimType, setClaimType] = useState('custom.note');
  const [subject, setSubject] = useState('personal:me');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState(false);

  useEffect(() => {
    setOcr(null);
    setRegionIndex(null);
    setCreated(false);
    setError('');
    void invoke<OcrStatus>('ocr_status').then(setStatus).catch((reason) => setError(String(reason)));
  }, [detail.source.id]);

  async function recognize() {
    setBusy(true);
    setError('');
    setCreated(false);
    try {
      const result = await invoke<OcrPage>('run_image_ocr', { id: detail.source.id });
      setOcr(result);
      setRegionIndex(result.regions.length ? 0 : null);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function createCandidate(event: FormEvent) {
    event.preventDefault();
    if (regionIndex === null) return;
    setBusy(true);
    setError('');
    setCreated(false);
    try {
      const snapshot = await invoke<WorkspaceSnapshot>('create_ocr_candidate', {
        sourceId: detail.source.id, regionIndex, claimType, subject,
      });
      onWorkspace(snapshot);
      setCreated(true);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  return <div className="image-preview">
    <div className="ocr-image-stage">
      {imageUrl ? <img src={imageUrl} alt={detail.source.title ?? t.imageAlt} /> : <p className="blank">{t.imageLoading}</p>}
      {ocr && imageUrl && ocr.regions.map((region, index) => <button
        key={`${region.x}-${region.y}-${index}`}
        className={regionIndex === index ? 'ocr-region selected' : 'ocr-region'}
        style={{ left: `${region.x / ocr.width * 100}%`, top: `${region.y / ocr.height * 100}%`, width: `${region.width / ocr.width * 100}%`, height: `${region.height / ocr.height * 100}%` }}
        aria-label={`${region.text}, ${t.ocrConfidence} ${Math.round(region.confidenceMilli / 10)}%`}
        aria-pressed={regionIndex === index}
        onClick={() => { setRegionIndex(index); setCreated(false); }}
      />)}
    </div>
    <dl><div><dt>{t.imageFormat}</dt><dd>{detail.format.toUpperCase()}</dd></div><div><dt>{t.imageDimensions}</dt><dd>{detail.displayWidth} × {detail.displayHeight}</dd></div><div><dt>{t.imageOrientation}</dt><dd>{detail.orientation}</dd></div></dl>
    <div className={status?.available ? 'ocr-status ready' : 'ocr-status'} role="status">
      <span>{status?.available ? t.ocrReady : t.ocrUnavailable}</span>
      {status?.available && <small>Tesseract {status.engineVersion} · {status.languages.join(' + ')}</small>}
    </div>
    <button className="outline" disabled={!status?.available || busy || !imageUrl} onClick={() => void recognize()}>{busy ? t.ocrRunning : t.runOcr}</button>
    {error && <div className="error" role="alert"><span>{error}</span></div>}
    {ocr && <div className="ocr-review">
      <h4>{t.ocrRegions} <small>{ocr.regions.length}</small></h4>
      {!ocr.regions.length ? <p className="blank">{t.ocrNoText}</p> : <>
        <div className="ocr-region-list" role="list">{ocr.regions.map((region, index) => <button key={index} role="listitem" className={regionIndex === index ? 'selected' : ''} aria-pressed={regionIndex === index} onClick={() => { setRegionIndex(index); setCreated(false); }}><span>{region.text}</span><small>{t.ocrConfidence}: {Math.round(region.confidenceMilli / 10)}%</small></button>)}</div>
        <form className="candidate-form" onSubmit={(event) => void createCandidate(event)}>
          <p>{regionIndex === null ? t.ocrSelectRegion : `“${ocr.regions[regionIndex].text}”`}</p>
          <div><label>{t.claimType}<input value={claimType} onChange={(event) => setClaimType(event.target.value)} required /></label><label>{t.subject}<input value={subject} onChange={(event) => setSubject(event.target.value)} required /></label></div>
          <button className="primary" disabled={regionIndex === null || busy}>{t.createOcrCandidate}</button>
          {created && <span className="success-note" role="status">{t.ocrCandidateCreated}</span>}
        </form>
      </>}
    </div>}
  </div>;
}
