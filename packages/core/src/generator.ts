export interface PasswordOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  avoidAmbiguous?: boolean;
}

const AMBIGUOUS = new Set('Il1O0o|`\'"'.split(''));

function randomIndex(max: number): number {
  if (max < 1 || max > 256) throw new Error('Invalid character set');
  const limit = 256 - (256 % max);
  const byte = new Uint8Array(1);
  do globalThis.crypto.getRandomValues(byte); while (byte[0]! >= limit);
  return byte[0]! % max;
}

export function generatePassword(options: PasswordOptions): string {
  if (!Number.isInteger(options.length) || options.length < 12 || options.length > 256) throw new Error('Length must be between 12 and 256');
  const requested = [
    options.lowercase ? 'abcdefghijklmnopqrstuvwxyz' : '',
    options.uppercase ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : '',
    options.numbers ? '0123456789' : '',
    options.symbols ? '!@#$%^&*()-_=+[]{}:,.?' : ''
  ].filter(Boolean).map(set => options.avoidAmbiguous ? [...set].filter(char => !AMBIGUOUS.has(char)).join('') : set);
  if (requested.length === 0) throw new Error('Select at least one character set');
  const all = requested.join('');
  const chars = requested.map(set => set[randomIndex(set.length)]!);
  while (chars.length < options.length) chars.push(all[randomIndex(all.length)]!);
  for (let index = chars.length - 1; index > 0; index--) {
    const swap = randomIndex(index + 1);
    [chars[index], chars[swap]] = [chars[swap]!, chars[index]!];
  }
  return chars.join('');
}

