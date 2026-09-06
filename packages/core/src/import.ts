export interface ImportedPassword { title: string; url: string; username: string; password: string; note?: string }
export interface ImportIssue { row: number; message: string }
export interface ImportResult { accepted: ImportedPassword[]; duplicates: ImportedPassword[]; issues: ImportIssue[] }

export function parseCsv(text: string, maxRows = 100_000): string[][] {
  if (text.length > 50_000_000) throw new Error('Import file is too large');
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index]!;
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') { field += '"'; index++; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"' && field.length === 0) quoted = true;
    else if (char === ',') { row.push(field); field = ''; }
    else if (char === '\n') { row.push(field.replace(/\r$/u, '')); rows.push(row); row = []; field = ''; if (rows.length > maxRows) throw new Error('Too many rows'); }
    else field += char;
  }
  if (quoted) throw new Error('Unterminated quoted field');
  if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
}

export function importChromeCsv(text: string): ImportResult {
  const rows = parseCsv(text);
  const header = rows.shift()?.map(value => value.trim().toLowerCase().replace(/^\uFEFF/u, ''));
  if (!header) throw new Error('CSV is empty');
  const locate = (names: string[]): number => header.findIndex(value => names.includes(value));
  const indices = { title: locate(['name', 'title']), url: locate(['url']), username: locate(['username']), password: locate(['password']), note: locate(['note']) };
  if (indices.url < 0 || indices.username < 0 || indices.password < 0) throw new Error('Unsupported CSV header');
  const accepted: ImportedPassword[] = [], duplicates: ImportedPassword[] = [], issues: ImportIssue[] = [];
  const seen = new Set<string>();
  rows.forEach((values, offset) => {
    const item = {
      title: indices.title >= 0 ? values[indices.title]?.trim() ?? '' : '',
      url: values[indices.url]?.trim() ?? '', username: values[indices.username] ?? '', password: values[indices.password] ?? '',
      ...(indices.note >= 0 && values[indices.note] ? { note: values[indices.note] } : {})
    };
    try {
      const url = new URL(item.url);
      if (!['http:', 'https:'].includes(url.protocol) || !item.password) throw new Error('Invalid URL or empty password');
      item.title ||= url.hostname;
      const key = `${url.origin}\u0000${item.username}\u0000${item.password}`;
      if (seen.has(key)) duplicates.push(item); else { seen.add(key); accepted.push(item); }
    } catch { issues.push({ row: offset + 2, message: 'Invalid URL or empty password' }); }
  });
  return { accepted, duplicates, issues };
}

