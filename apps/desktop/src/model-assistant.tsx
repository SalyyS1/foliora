import { invoke } from '@tauri-apps/api/core';
import { FormEvent, useEffect, useRef, useState } from 'react';
import type { Copy } from './copy';
import type { ModelRequestPreview, ModelSuggestionBatch, SourceDetail, WorkspaceSnapshot } from './workspace-types';

type TextSource = Extract<SourceDetail, { kind: 'text' }>;
type ErrorKind = 'stale' | 'invalidKey' | 'invalidModel' | 'invalidSource' | 'providerError';

const words = {
  vi: {
    title: 'Trợ lý model tùy chọn',
    summary: 'Đề xuất dữ kiện có nguồn bằng API key của bạn',
    help: 'Foliora chỉ gửi nội dung sau khi bạn xem chính xác payload. AI không tự xác nhận hay lưu dữ kiện.',
    unavailable: 'Chọn một nguồn văn bản để dùng trợ lý. PDF, email và ảnh chưa được gửi tới model.',
    model: 'Tên model trong tài khoản OpenAI',
    modelHint: 'Ví dụ: model bạn đang được cấp quyền dùng',
    redact: 'Cụm từ cần che — mỗi dòng một cụm',
    redactHint: 'Số tài khoản\nĐịa chỉ riêng',
    preview: 'Chuẩn bị bản xem trước',
    exact: 'Chính xác JSON sẽ gửi tới OpenAI',
    disclosed: 'byte được tiết lộ',
    omitted: 'byte cuối nguồn không được gửi',
    redactions: 'lượt che',
    reviewed: 'Tôi đã đọc payload và đồng ý gửi đúng nội dung này tới OpenAI.',
    apiKey: 'OpenAI API key',
    keyHint: 'Chỉ giữ trong bộ nhớ cho lần gửi này',
    send: 'Gửi và nhận gợi ý',
    keySafety: 'Key không được ghi vào vault, log hay cấu hình và sẽ bị xóa khỏi ô ngay sau thao tác.',
    providerTerms: 'OpenAI sẽ xử lý các byte này theo điều khoản của họ. Yêu cầu dùng store:false nhưng không đảm bảo không có lưu giữ vì mục đích an toàn.',
    suggestions: 'Gợi ý chưa được lưu',
    evidence: 'Trích dẫn chính xác',
    create: 'Tạo candidate để duyệt',
    empty: 'Model không tìm thấy dữ kiện đủ căn cứ.',
    failed: 'Không thể hoàn tất trợ lý model',
    stale: 'Nguồn hoặc cấu hình đã đổi. Hãy xem lại payload.',
    invalidKey: 'API key không hợp lệ hoặc không được tài khoản chấp nhận.',
    invalidModel: 'Tên model trống, quá dài hoặc tài khoản không được dùng model này.',
    invalidSource: 'Nguồn không còn phù hợp hoặc trích dẫn không còn khớp chính xác.',
    providerError: 'Nhà cung cấp không trả về kết quả hoàn chỉnh, hợp lệ. Hãy thử lại sau.',
  },
  en: {
    title: 'Optional model assistant',
    summary: 'Suggest source-backed claims with your API key',
    help: 'Foliora sends content only after you inspect the exact payload. AI never confirms or saves a claim by itself.',
    unavailable: 'Choose a text source to use the assistant. PDFs, email, and images are not sent to a model.',
    model: 'Model name available to your OpenAI account',
    modelHint: 'For example: a model your account can access',
    redact: 'Phrases to redact — one per line',
    redactHint: 'Account number\nPrivate address',
    preview: 'Prepare exact preview',
    exact: 'Exact JSON that will be sent to OpenAI',
    disclosed: 'bytes disclosed',
    omitted: 'trailing source bytes not sent',
    redactions: 'redactions',
    reviewed: 'I reviewed the payload and agree to send exactly this content to OpenAI.',
    apiKey: 'OpenAI API key',
    keyHint: 'Held in memory for this request only',
    send: 'Send and get suggestions',
    keySafety: 'The key is never written to the vault, logs, or configuration and is cleared from this field after the request.',
    providerTerms: 'OpenAI processes these bytes under its terms. The request uses store:false, but that does not guarantee zero safety retention.',
    suggestions: 'Unsaved suggestions',
    evidence: 'Exact evidence quote',
    create: 'Create candidate for review',
    empty: 'The model found no sufficiently grounded facts.',
    failed: 'Could not complete model assistance',
    stale: 'The source or configuration changed. Preview the payload again.',
    invalidKey: 'The API key is invalid or was not accepted by the account.',
    invalidModel: 'The model name is empty, too long, or unavailable to this account.',
    invalidSource: 'The source is no longer eligible or the quote no longer matches exactly.',
    providerError: 'The provider did not return a complete valid result. Try again later.',
  },
} as const;

export function ModelAssistant({ source, t, disabled, onWorkspace }: {
  source: TextSource | null;
  t: Copy;
  disabled: boolean;
  onWorkspace: (workspace: WorkspaceSnapshot) => void;
}) {
  const copy = words[t.languageCode];
  const [model, setModel] = useState('');
  const [redactionText, setRedactionText] = useState('');
  const [preview, setPreview] = useState<ModelRequestPreview | null>(null);
  const [reviewed, setReviewed] = useState(false);
  const [apiKey, setApiKey] = useState('');
  const [suggestions, setSuggestions] = useState<ModelSuggestionBatch | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ErrorKind | ''>('');
  const requestVersion = useRef(0);
  const sourceId = source?.source.id ?? '';
  const sourceIdRef = useRef(sourceId);
  sourceIdRef.current = sourceId;

  useEffect(() => {
    requestVersion.current += 1;
    setPreview(null);
    setReviewed(false);
    setSuggestions(null);
    setApiKey('');
    setError('');
  }, [source?.source.id]);

  function redactions() {
    return redactionText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  }

  function invalidatePreview() {
    requestVersion.current += 1;
    setPreview(null);
    setReviewed(false);
    setSuggestions(null);
  }

  async function prepare(event: FormEvent) {
    event.preventDefault();
    if (!source) return;
    const requestedSourceId = source.source.id;
    const version = ++requestVersion.current;
    setBusy(true);
    setError('');
    setSuggestions(null);
    try {
      const result = await invoke<ModelRequestPreview>('preview_model_request', {
        sourceId: source.source.id,
        model,
        redactions: redactions(),
      });
      if (requestVersion.current !== version || sourceIdRef.current !== requestedSourceId) return;
      setPreview(result);
      setReviewed(false);
    } catch (reason) {
      setPreview(null);
      if (requestVersion.current === version) setError(classifyError(reason));
    } finally {
      setBusy(false);
    }
  }

  async function run(event: FormEvent) {
    event.preventDefault();
    if (!source || !preview || !reviewed) return;
    const requestedSourceId = source.source.id;
    const requestedPayload = preview.payloadSha256;
    const version = ++requestVersion.current;
    setBusy(true);
    setError('');
    try {
      const result = await invoke<ModelSuggestionBatch>('run_model_suggestions', {
        sourceId: source.source.id,
        model,
        redactions: redactions(),
        expectedPayloadSha256: preview.payloadSha256,
        apiKey,
      });
      if (requestVersion.current !== version || sourceIdRef.current !== requestedSourceId) return;
      if (result.sourceId !== requestedSourceId || result.payloadSha256 !== requestedPayload) {
        setError('stale');
        return;
      }
      setSuggestions(result);
    } catch (reason) {
      setSuggestions(null);
      if (requestVersion.current === version) setError(classifyError(reason));
    } finally {
      setApiKey('');
      setBusy(false);
    }
  }

  async function createCandidate(index: number) {
    if (!source || !suggestions) return;
    if (source.source.id !== suggestions.sourceId || source.source.fingerprint !== suggestions.sourceFingerprint) {
      setError('stale');
      return;
    }
    const suggestion = suggestions.suggestions[index];
    setBusy(true);
    setError('');
    try {
      const workspace = await invoke<WorkspaceSnapshot>('create_model_candidate', {
        sourceId: suggestions.sourceId,
        expectedSourceFingerprint: suggestions.sourceFingerprint,
        expectedQuote: suggestion.quote,
        claimType: suggestion.claimType,
        subject: suggestion.subject,
        start: suggestion.start,
        end: suggestion.end,
      });
      onWorkspace(workspace);
      setSuggestions((current) => current ? { ...current, suggestions: current.suggestions.filter((_, itemIndex) => itemIndex !== index) } : null);
    } catch (reason) {
      setError(classifyError(reason));
    } finally {
      setBusy(false);
    }
  }

  function editSuggestion(index: number, field: 'claimType' | 'subject', value: string) {
    setSuggestions((current) => current ? { ...current, suggestions: current.suggestions.map((item, itemIndex) => itemIndex === index ? { ...item, [field]: value } : item) } : null);
  }

  return <details className="model-assistant">
    <summary><span><strong>{copy.title}</strong><small>{copy.summary}</small></span><span className="optional-badge">BYOK</span></summary>
    <div className="model-assistant-body">
      <p>{copy.help}</p>
      {!source ? <p className="blank">{copy.unavailable}</p> : <>
        <form onSubmit={(event) => void prepare(event)}>
          <label>{copy.model}<input value={model} onChange={(event) => { setModel(event.target.value); invalidatePreview(); }} placeholder={copy.modelHint} maxLength={128} required /></label>
          <label>{copy.redact}<textarea value={redactionText} onChange={(event) => { setRedactionText(event.target.value); invalidatePreview(); }} placeholder={copy.redactHint} /></label>
          <button className="outline" disabled={disabled || busy}>{copy.preview}</button>
        </form>
        {preview && <div className="model-preview">
          <div><strong>{copy.exact}</strong><code>{preview.payloadSha256}</code></div>
          <p className="model-destination">{preview.provider} · {preview.endpoint}</p>
          <dl><div><dt>{copy.disclosed}</dt><dd>{preview.disclosedBytes}</dd></div><div><dt>{copy.omitted}</dt><dd>{preview.omittedBytes}</dd></div><div><dt>{copy.redactions}</dt><dd>{preview.redactionCount}</dd></div></dl>
          <pre>{preview.payload}</pre>
          <form onSubmit={(event) => void run(event)}>
            <label className="model-consent"><input type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} /><span>{copy.reviewed}</span></label>
            <p className="model-provider-warning">{copy.providerTerms}</p>
            <label>{copy.apiKey}<input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder={copy.keyHint} autoComplete="off" minLength={20} maxLength={512} required /></label>
            <small>{copy.keySafety}</small>
            <button className="primary" disabled={disabled || busy || !reviewed}>{copy.send}</button>
          </form>
        </div>}
        {suggestions && <div className="model-suggestions" aria-live="polite"><h4>{copy.suggestions} <small>{suggestions.suggestions.length}</small></h4>
          {suggestions.suggestions.length === 0 ? <p className="blank">{copy.empty}</p> : suggestions.suggestions.map((suggestion, index) => <article key={`${suggestion.start}:${suggestion.end}:${index}`}>
            <blockquote><b>{copy.evidence}</b>“{suggestion.quote}”</blockquote>
            <div><label>{t.claimType}<input value={suggestion.claimType} onChange={(event) => editSuggestion(index, 'claimType', event.target.value)} maxLength={128} required /></label><label>{t.subject}<input value={suggestion.subject} onChange={(event) => editSuggestion(index, 'subject', event.target.value)} maxLength={256} required /></label></div>
            <button className="outline" disabled={disabled || busy || !suggestion.claimType.trim() || !suggestion.subject.trim()} onClick={() => void createCandidate(index)}>{copy.create}</button>
          </article>)}
        </div>}
      </>}
      {error && <div className="error" role="alert"><strong>{copy.failed}</strong><span>{copy[error]}</span></div>}
    </div>
  </details>;
}

function classifyError(reason: unknown): ErrorKind {
  const message = String(reason).toLowerCase();
  if (message.includes('changed after preview') || message.includes('request new suggestions')) return 'stale';
  if (message.includes('api key') || message.includes('http 401') || message.includes('http 403')) return 'invalidKey';
  if (message.includes('model name') || message.includes('http 404')) return 'invalidModel';
  if (message.includes('source') || message.includes('quote')) return 'invalidSource';
  return 'providerError';
}
