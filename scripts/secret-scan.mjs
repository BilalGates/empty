import { execFileSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';

const patterns = [
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
  '(?i)(password|secret|token|api[_-]?key)\\s*[:=]\\s*["\\x27][^"\\x27\\n]{16,}["\\x27]'
];

let files = [];
try { files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8' }).trim().split(/\r?\n/u).filter(Boolean); }
catch { files = execFileSync('rg', ['--files', '-g', '!node_modules/**', '-g', '!dist/**'], { encoding: 'utf8' }).trim().split(/\r?\n/u).filter(Boolean); }
if (files.length === 0) {
  files = execFileSync('rg', ['--files', '-g', '!node_modules/**', '-g', '!dist/**', '-g', '!.git/**'], { encoding: 'utf8' }).trim().split(/\r?\n/u).filter(Boolean);
}
files = [...new Set(files)].filter(file => existsSync(file) && statSync(file).isFile());

const findings = [];
for (const pattern of patterns) {
  try {
    const output = execFileSync('rg', ['-n', '--pcre2', '--', pattern, ...files], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    if (output.trim()) findings.push(output.trim());
  } catch (error) {
    if (error.status !== 1) throw error;
  }
}
if (findings.length) { console.error(findings.join('\n')); process.exit(1); }
console.log(`Secret scan passed (${files.length} tracked and untracked candidate files).`);
