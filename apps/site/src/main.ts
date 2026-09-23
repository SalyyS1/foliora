type Language = 'vi' | 'en';

const translations: Record<Language, Record<string, string>> = {
  vi: {
    skip: 'Đến nội dung chính', navHow: 'Cách hoạt động', navWorkspace: 'Không gian thử', navPrinciples: 'Nguyên tắc', inDev: 'Đang phát triển', navLabel: 'Điều hướng chính', productStatus: 'Trạng thái sản phẩm', languageLabel: 'Đổi ngôn ngữ', verified: 'Đã xác minh', conflictAria: 'Mâu thuẫn', pendingAria: 'Đang chờ xác minh', progressLabel: '2 trên 3 mục đã chọn',
    eyebrow: 'A calmer way to share context', heroTitle: 'Đọc kỹ nguồn.', heroTitleEm: 'Chia sẻ có chủ ý.', heroLede: 'Foliora giúp bạn gom tài liệu thành một context pack có nguồn rõ ràng — để bạn biết chính xác điều gì đang được chia sẻ.', startReview: 'Bắt đầu xem thử ↘', readPrinciples: 'Đọc nguyên tắc →', noteKicker: 'Một lời nhắc nhỏ', noteBody: 'Đây là bản xem trước đang phát triển. Chưa có tài liệu nào rời khỏi thiết bị của bạn.', noteMeta: 'LOCAL-FIRST · NO ACCOUNT',
    processEyebrow: 'The review loop', processTitle: 'Ba bước, không có hộp đen.', step1Title: 'Nhập tài liệu', step1Body: 'Chọn những file bạn muốn xem xét. Không tự động tải lên.', step2Title: 'Kiểm tra bằng chứng', step2Body: 'Theo dõi từng dữ kiện về đúng nguồn của nó.', step3Title: 'Xem trước bundle', step3Body: 'Chọn phần cần chia sẻ, rồi xuất một bản đã duyệt.',
    workspaceEyebrow: 'Private workspace · demo', workspaceTitle: 'Xem thử quy trình', demoBadge: 'DỮ LIỆU MẪU', notConnected: 'CHƯA KẾT NỐI', importTitle: 'Chọn tài liệu để bắt đầu', importBody: 'Bản demo chỉ đọc tên file trên trình duyệt. Bộ phân tích cục bộ sẽ đến sau.', dropTitle: 'Thả file vào đây', dropHint: 'hoặc chọn từ thiết bị · PDF, MD, TXT', localNote: 'Chỉ xem cục bộ · không tải lên', reviewState: 'CẦN XEM LẠI', evidenceTitle: 'Bằng chứng & nguồn', evidenceBody: 'Mỗi dòng đều có đường về tài liệu gốc.', evidence1: 'Mục tiêu dự án', high: 'RÕ', evidence2: 'Thời hạn giao hàng', conflict: 'MÂU THUẪN', evidence3: 'Người liên hệ', verify: 'XÁC MINH', showConflicts: 'Xem 1 điểm cần chú ý →', previewState: 'BẢN XEM TRƯỚC', bundleTitle: 'Context pack của bạn', bundleBody: 'Một bản tóm tắt có thể kiểm tra trước khi rời khỏi tay bạn.', bundleDraft: 'BẢN NHÁP · 3 MỤC', included: 'Đã chọn', previewButton: 'Xem bản bundle ↗', honestNote: 'Xuất file chưa khả dụng trong bản demo.',
    principlesEyebrow: 'What we protect', principlesTitle: 'Quyền quyết định|vẫn ở bạn.', principle1: 'Nguồn luôn hiển thị. Không có dữ kiện “từ trên trời rơi xuống”.', principle2: 'Mâu thuẫn được đánh dấu, không bị làm phẳng thành một câu trả lời.', principle3: 'Không tuyên bố đã kiểm tra tên, trademark hay domain. Foliora chỉ là tên tạm thời.', footerText: 'Bản xem trước đang phát triển · xây dựng cho sự rõ ràng'
  },
  en: {
    skip: 'Skip to main content', navHow: 'How it works', navWorkspace: 'Demo workspace', navPrinciples: 'Principles', inDev: 'In development', navLabel: 'Main navigation', productStatus: 'Product status', languageLabel: 'Switch language', verified: 'Verified', conflictAria: 'Conflict', pendingAria: 'Pending verification', progressLabel: '2 of 3 items selected',
    eyebrow: 'A calmer way to share context', heroTitle: 'Read the source.', heroTitleEm: 'Share with intention.', heroLede: 'Foliora turns your documents into a source-linked context pack — so you know exactly what is being shared.', startReview: 'Start the preview ↘', readPrinciples: 'Read our principles →', noteKicker: 'A small note', noteBody: 'This is an early preview in development. No document has left your device.', noteMeta: 'LOCAL-FIRST · NO ACCOUNT',
    processEyebrow: 'The review loop', processTitle: 'Three steps, no black box.', step1Title: 'Import documents', step1Body: 'Choose the files you want to review. Nothing uploads automatically.', step2Title: 'Review evidence', step2Body: 'Trace every fact back to its source.', step3Title: 'Preview a bundle', step3Body: 'Choose what to share, then export an approved snapshot.',
    workspaceEyebrow: 'Private workspace · demo', workspaceTitle: 'See the flow', demoBadge: 'SAMPLE DATA', notConnected: 'NOT CONNECTED', importTitle: 'Choose documents to begin', importBody: 'The demo reads file names in your browser only. Local analysis is coming later.', dropTitle: 'Drop files here', dropHint: 'or choose from your device · PDF, MD, TXT', localNote: 'Local preview only · never uploaded', reviewState: 'NEEDS REVIEW', evidenceTitle: 'Evidence & sources', evidenceBody: 'Every row traces back to an original document.', evidence1: 'Project goal', high: 'CLEAR', evidence2: 'Delivery deadline', conflict: 'CONFLICT', evidence3: 'Point of contact', verify: 'VERIFY', showConflicts: 'Review 1 item to resolve →', previewState: 'PREVIEW', bundleTitle: 'Your context pack', bundleBody: 'A summary you can inspect before it leaves your hands.', bundleDraft: 'DRAFT · 3 ITEMS', included: 'Included', previewButton: 'Preview bundle ↗', honestNote: 'File export is not available in this demo.',
    principlesEyebrow: 'What we protect', principlesTitle: 'The decision|stays with you.', principle1: 'Sources stay visible. No facts appear “from nowhere.”', principle2: 'Conflicts are marked, never flattened into one answer.', principle3: 'No claim that the name, trademark, or domain is cleared. Foliora is a provisional name.', footerText: 'Preview in development · built for clarity'
  }
};

const languageToggle = document.querySelector<HTMLButtonElement>('.language-toggle');
const filePicker = document.querySelector<HTMLInputElement>('#file-picker');
const selectedFiles = document.querySelector<HTMLElement>('.selected-files');
const evidenceCard = document.querySelector<HTMLElement>('.evidence-card');
let language: Language = 'vi';

function renderLanguage(next: Language): void {
  language = next;
  document.documentElement.lang = next;
  document.querySelectorAll<HTMLElement>('[data-i18n]').forEach((node) => {
    const key = node.dataset.i18n;
    const value = key ? translations[next][key] : undefined;
    if (!value) return;
    const [plain, emphasis] = value.split('|');
    node.replaceChildren(document.createTextNode(plain));
    if (emphasis !== undefined) {
      node.append(document.createElement('br'));
      const emphasisNode = document.createElement('em');
      emphasisNode.textContent = emphasis;
      node.append(emphasisNode);
    }
  });
  document.querySelector<HTMLElement>('[data-i18n-aria="navLabel"]')?.setAttribute('aria-label', translations[next].navLabel);
  document.querySelector<HTMLElement>('[data-i18n-aria="productStatus"]')?.setAttribute('aria-label', translations[next].productStatus);
  languageToggle?.setAttribute('aria-label', translations[next].languageLabel);
  document.querySelector<HTMLElement>('[data-i18n-aria="verified"]')?.setAttribute('aria-label', translations[next].verified);
  document.querySelector<HTMLElement>('[data-i18n-aria="conflictAria"]')?.setAttribute('aria-label', translations[next].conflictAria);
  document.querySelector<HTMLElement>('[data-i18n-aria="pendingAria"]')?.setAttribute('aria-label', translations[next].pendingAria);
  document.querySelector<HTMLElement>('[data-i18n-aria="progressLabel"]')?.setAttribute('aria-label', translations[next].progressLabel);
  languageToggle?.classList.toggle('is-english', next === 'en');
  languageToggle?.setAttribute('aria-pressed', String(next === 'en'));
}

languageToggle?.addEventListener('click', () => renderLanguage(language === 'vi' ? 'en' : 'vi'));
filePicker?.addEventListener('change', () => {
  if (!selectedFiles || !filePicker.files) return;
  selectedFiles.replaceChildren(...Array.from(filePicker.files).map((file) => {
    const row = document.createElement('span');
    row.textContent = `${file.name} · ${Math.max(1, Math.round(file.size / 1024))} KB`;
    return row;
  }));
});
document.querySelector<HTMLButtonElement>('[data-action="show-conflicts"]')?.addEventListener('click', () => {
  const conflict = evidenceCard?.querySelector<HTMLElement>('.conflict');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  conflict?.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'center' });
  if (!reducedMotion) {
    conflict?.animate(
      [{ backgroundColor: 'transparent' }, { backgroundColor: '#f1ddd5' }, { backgroundColor: 'transparent' }],
      { duration: 850 },
    );
  }
});
document.querySelector<HTMLButtonElement>('[data-action="preview"]')?.addEventListener('click', (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  button.textContent = language === 'vi' ? 'Bản demo — chưa xuất file' : 'Demo only — no file export';
  window.setTimeout(() => {
    button.replaceChildren(document.createTextNode(language === 'vi' ? 'Xem bản bundle ' : 'Preview bundle '));
    const arrow = document.createElement('span');
    arrow.setAttribute('aria-hidden', 'true');
    arrow.textContent = '↗';
    button.append(arrow);
  }, 2500);
});
renderLanguage('vi');

export const siteBoundary = 'public-site';
