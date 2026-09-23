export interface EvidenceSelection {
  start: number;
  end: number;
  text: string;
}

export function utf8EvidenceSelection(text: string, start: number, end: number): EvidenceSelection | null {
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start || end > text.length) {
    return null;
  }
  const encoder = new TextEncoder();
  return {
    start: encoder.encode(text.slice(0, start)).length,
    end: encoder.encode(text.slice(0, end)).length,
    text: text.slice(start, end),
  };
}
