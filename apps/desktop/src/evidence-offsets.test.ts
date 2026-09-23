import { describe, expect, it } from 'vitest';
import { utf8EvidenceSelection } from './evidence-offsets';

describe('utf8EvidenceSelection', () => {
  it('maps Vietnamese UTF-16 positions to exact UTF-8 byte offsets', () => {
    const text = 'Mã bảo hành: VN-123';
    const start = text.indexOf('VN-123');
    const selection = utf8EvidenceSelection(text, start, text.length);
    expect(selection).toEqual({
      start: new TextEncoder().encode('Mã bảo hành: ').length,
      end: new TextEncoder().encode(text).length,
      text: 'VN-123',
    });
    const bytes = new TextEncoder().encode(text);
    expect(new TextDecoder().decode(bytes.slice(selection!.start, selection!.end))).toBe('VN-123');
  });

  it('counts a preserved BOM and rejects empty or invalid ranges', () => {
    const text = '\u{feff}Bằng chứng';
    expect(utf8EvidenceSelection(text, 1, text.length)?.start).toBe(3);
    expect(utf8EvidenceSelection(text, 2, 2)).toBeNull();
    expect(utf8EvidenceSelection(text, -1, 2)).toBeNull();
    expect(utf8EvidenceSelection(text, 0, text.length + 1)).toBeNull();
  });
});
