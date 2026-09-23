#!/usr/bin/env node

import {createHash} from 'node:crypto';
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import {dirname, isAbsolute, join, relative, resolve, sep} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const ENGINE_VERSION = '5.5.0';
const MODEL_REVISION = '87416418657359cb625c412a48b6e1d6d41c29bd';
const MODELS = {
  eng: {bytes: 4113088, sha256: '7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2'},
  vie: {bytes: 531275, sha256: '79df64caf7bcfb2a27df5042ecb6121e196eada34da774956995747636d5bfa1'},
};
const MAX_RUNTIME_BYTES = 512 * 1024 * 1024;

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const resourceDirectory = resolve(scriptDirectory, '../src-tauri/resources/ocr');
const lockPath = join(resourceDirectory, 'resource-lock.json');

function parseArguments(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || !value) throw new Error(`Invalid argument near ${key ?? '<end>'}`);
    values.set(key.slice(2), value);
  }
  return values;
}

function requireArgument(argumentsMap, name) {
  const value = argumentsMap.get(name);
  if (!value) throw new Error(`Missing required --${name}`);
  return value;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function artifact(path) {
  const bytes = readFileSync(join(resourceDirectory, path));
  return {path, bytes: bytes.length, sha256: sha256(bytes)};
}

function listFiles(directory, prefix = '') {
  const output = [];
  for (const entry of readdirSync(directory, {withFileTypes: true})) {
    const path = join(directory, entry.name);
    const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink() || lstatSync(path).isSymbolicLink()) {
      throw new Error(`Symbolic links are not allowed in OCR resources: ${relativePath}`);
    }
    if (entry.isDirectory()) output.push(...listFiles(path, relativePath));
    else if (entry.isFile() && !['README.md', 'resource-lock.json'].includes(relativePath)) output.push(relativePath);
    else if (!entry.isFile()) throw new Error(`Unsupported OCR resource: ${relativePath}`);
  }
  return output.sort();
}

function resetResources(executableName) {
  mkdirSync(resourceDirectory, {recursive: true});
  for (const entry of readdirSync(resourceDirectory)) {
    if (entry !== 'README.md') rmSync(join(resourceDirectory, entry), {recursive: true, force: true});
  }
  writeFileSync(lockPath, `${JSON.stringify({
    schemaVersion: 1,
    available: false,
    engineVersion: ENGINE_VERSION,
    executable: {path: executableName, bytes: 0, sha256: ''},
    models: {
      vie: {path: 'tessdata/vie.traineddata', bytes: 0, sha256: ''},
      eng: {path: 'tessdata/eng.traineddata', bytes: 0, sha256: ''},
    },
    runtimeDependencies: [],
  }, null, 2)}\n`);
}

async function downloadModel(language) {
  const expected = MODELS[language];
  const url = `https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/${MODEL_REVISION}/${language}.traineddata`;
  const response = await fetch(url, {redirect: 'error'});
  if (!response.ok) throw new Error(`Failed to download ${language}: HTTP ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length !== expected.bytes || sha256(bytes) !== expected.sha256) {
    throw new Error(`Pinned ${language} model failed size/SHA-256 verification`);
  }
  writeFileSync(join(resourceDirectory, 'tessdata', `${language}.traineddata`), bytes);
  return url;
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const platform = args.get('platform') ?? process.platform;
  if (!['win32', 'darwin', 'linux'].includes(platform)) throw new Error(`Unsupported platform: ${platform}`);
  const executableName = platform === 'win32' ? 'tesseract.exe' : 'tesseract';
  const runtimeInput = requireArgument(args, 'runtime-dir');
  if (!isAbsolute(runtimeInput)) throw new Error('--runtime-dir must be absolute');
  const runtimeDirectory = realpathSync(runtimeInput);
  const relativeToResource = relative(resourceDirectory, runtimeDirectory);
  if (relativeToResource === '' || (!relativeToResource.startsWith(`..${sep}`) && relativeToResource !== '..')) {
    throw new Error('--runtime-dir must be outside the generated resource directory');
  }
  const runtimeSourceUrl = requireArgument(args, 'runtime-source-url');
  if (!runtimeSourceUrl.startsWith('https://')) throw new Error('--runtime-source-url must use HTTPS');
  const runtimeRevision = requireArgument(args, 'runtime-revision');
  const licenseInventory = realpathSync(requireArgument(args, 'license-inventory'));
  if (!statSync(licenseInventory).isFile()) throw new Error('--license-inventory must be a file');
  const executableSource = join(runtimeDirectory, executableName);
  if (!existsSync(executableSource) || !statSync(executableSource).isFile()) {
    throw new Error(`Runtime does not contain ${executableName} at its root`);
  }
  const version = spawnSync(executableSource, ['--version'], {
    cwd: runtimeDirectory,
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  });
  if (version.status !== 0 || !`${version.stdout}\n${version.stderr}`.includes(`tesseract ${ENGINE_VERSION}`)) {
    throw new Error(`Runtime must execute as Tesseract ${ENGINE_VERSION}`);
  }

  resetResources(executableName);
  for (const entry of readdirSync(runtimeDirectory, {withFileTypes: true})) {
    if (entry.name === 'tessdata') continue;
    cpSync(join(runtimeDirectory, entry.name), join(resourceDirectory, entry.name), {
      recursive: true,
      dereference: true,
      force: true,
    });
  }
  mkdirSync(join(resourceDirectory, 'tessdata'), {recursive: true});
  const [engUrl, vieUrl] = await Promise.all([downloadModel('eng'), downloadModel('vie')]);
  cpSync(licenseInventory, join(resourceDirectory, 'THIRD_PARTY_NOTICES.txt'), {force: true});
  writeFileSync(join(resourceDirectory, 'provenance.json'), `${JSON.stringify({
    tesseract: {version: ENGINE_VERSION, sourceUrl: runtimeSourceUrl, revision: runtimeRevision},
    tessdataFast: {revision: MODEL_REVISION, files: {eng: engUrl, vie: vieUrl}},
  }, null, 2)}\n`);

  const files = listFiles(resourceDirectory);
  const totalBytes = files.reduce((total, path) => total + statSync(join(resourceDirectory, path)).size, 0);
  if (totalBytes > MAX_RUNTIME_BYTES) throw new Error(`OCR resource tree exceeds ${MAX_RUNTIME_BYTES} bytes`);
  const executable = artifact(executableName);
  const vie = artifact('tessdata/vie.traineddata');
  const eng = artifact('tessdata/eng.traineddata');
  const fixed = new Set([executable.path, vie.path, eng.path]);
  const runtimeDependencies = files.filter((path) => !fixed.has(path)).map(artifact);
  writeFileSync(lockPath, `${JSON.stringify({
    schemaVersion: 1,
    available: true,
    engineVersion: ENGINE_VERSION,
    executable,
    models: {vie, eng},
    runtimeDependencies,
  }, null, 2)}\n`);
  process.stdout.write(`Staged ${files.length} verified OCR files (${totalBytes} bytes) for ${platform}.\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
