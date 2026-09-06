import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { basename, join, relative, resolve, sep } from 'node:path';
import { ZipFile } from 'yazl';

const source = resolve('apps/extension/dist');
const artifacts = resolve('artifacts');
const output = join(artifacts, 'space-chrome.zip');
const epochSeconds = Number(process.env.SOURCE_DATE_EPOCH ?? 946_684_800);
if (!Number.isSafeInteger(epochSeconds) || epochSeconds < 315_532_800) throw new Error('SOURCE_DATE_EPOCH must be a ZIP-compatible Unix timestamp');
const mtime = new Date(epochSeconds * 1000);

async function filesBelow(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await filesBelow(path));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

if (!(await stat(join(source, 'manifest.json'))).isFile()) throw new Error('Built extension manifest is missing');
await mkdir(artifacts, { recursive: true });
const zip = new ZipFile();
for (const file of (await filesBelow(source)).sort()) {
  zip.addFile(file, relative(source, file).split(sep).join('/'), { mtime, mode: 0o100644 });
}
zip.end({ forceZip64Format: false });
await new Promise((resolveWrite, rejectWrite) => {
  const destination = createWriteStream(output);
  zip.outputStream.once('error', rejectWrite);
  destination.once('error', rejectWrite);
  destination.once('close', resolveWrite);
  zip.outputStream.pipe(destination);
});
const digest = createHash('sha256').update(await readFile(output)).digest('hex');
await writeFile(`${output}.sha256`, `${digest}  ${basename(output)}\n`);
console.log(`${basename(output)} ${digest}`);

