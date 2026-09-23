export {};

const statusElement = document.querySelector<HTMLElement>('#status')!;
const rows = document.querySelector<HTMLElement>('#rows')!;
const prepare = document.querySelector<HTMLButtonElement>('#prepare')!;
const fill = document.querySelector<HTMLButtonElement>('#fill')!;

prepare.addEventListener('click', async () => {
  setBusy(true, 'Đang tạo bản xem trước an toàn…');
  const response = await chrome.runtime.sendMessage({type: 'foliora.prepare'});
  if (!response?.ok) { setBusy(false, response?.error ?? 'Không thể tạo preview.'); return; }
  rows.replaceChildren(...response.rows.map((row: PreviewRow) => rowElement(row)));
  fill.hidden = false;
  setBusy(false, 'Chọn từng trường rồi bấm Điền. Foliora sẽ không gửi biểu mẫu.');
});

fill.addEventListener('click', async () => {
  const indexes = Array.from(rows.querySelectorAll<HTMLInputElement>('input:checked')).map((input) => Number(input.value));
  setBusy(true, 'Đang kiểm tra lại trang…');
  const response = await chrome.runtime.sendMessage({type: 'foliora.fill', mappingIndexes: indexes});
  setBusy(false, response?.ok ? `Đã điền ${response.filled} trường. Hãy tự kiểm tra và gửi.` : response?.error ?? response?.reason ?? 'Không thể điền.');
});

function rowElement(row: PreviewRow): HTMLElement {
  const label = document.createElement('label');
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox'; checkbox.value = String(row.index); checkbox.checked = true;
  const text = document.createElement('span');
  const strong = document.createElement('strong'); strong.textContent = `${row.label} → ${row.field}`;
  const value = document.createElement('small'); value.textContent = `${row.value} · ${Math.round(row.confidenceMilli / 10)}%`;
  text.append(strong, value); label.append(checkbox, text); return label;
}

function setBusy(busy: boolean, message: string) { prepare.disabled = busy; fill.disabled = busy; statusElement.textContent = message; }
interface PreviewRow { index: number; label: string; value: string; field: string; confidenceMilli: number }
