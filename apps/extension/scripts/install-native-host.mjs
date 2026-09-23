import {existsSync, mkdirSync, rmSync, writeFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {dirname, isAbsolute, join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';

const HOST_NAME = 'app.foliora.desktop';
const FIREFOX_ID = 'extension@foliora.app';
const args = new Map();
for (let index = 2; index < process.argv.length; index += 1) {
  const key = process.argv[index];
  if (!key.startsWith('--')) throw new Error(`Unexpected argument: ${key}`);
  if (['--dry-run', '--uninstall'].includes(key)) args.set(key, true);
  else args.set(key, process.argv[++index]);
}

const dryRun = args.has('--dry-run');
const uninstall = args.has('--uninstall');
const chromiumId = args.get('--chromium-extension-id');
const binary = args.get('--host-binary');
if (!uninstall) {
  if (!binary || !isAbsolute(binary) || (!dryRun && !existsSync(binary))) {
    throw new Error('--host-binary must be an existing absolute foliora-native-host path');
  }
  if (!chromiumId || !/^[a-p]{32}$/.test(chromiumId)) {
    throw new Error('--chromium-extension-id must be the exact 32-character Chromium extension ID');
  }
}

const escapedBinary = binary ? resolve(binary) : '';
const chromium = JSON.stringify({
  name: HOST_NAME,
  description: 'Foliora preview-first native bridge',
  path: escapedBinary,
  type: 'stdio',
  allowed_origins: [`chrome-extension://${chromiumId}/`],
}, null, 2);
const firefox = JSON.stringify({
  name: HOST_NAME,
  description: 'Foliora preview-first native bridge',
  path: escapedBinary,
  type: 'stdio',
  allowed_extensions: [FIREFOX_ID],
}, null, 2);

const actions = platformActions();
if (dryRun) {
  console.log(JSON.stringify(actions, null, 2));
  process.exit(0);
}
for (const action of actions) {
  if (action.kind === 'file') {
    if (uninstall) rmSync(action.path, {force: true});
    else {
      mkdirSync(dirname(action.path), {recursive: true});
      writeFileSync(action.path, action.browser === 'firefox' ? firefox : chromium, {encoding: 'utf8', mode: 0o600});
    }
  } else {
    const commandArgs = uninstall
      ? ['delete', action.key, '/f']
      : ['add', action.key, '/ve', '/t', 'REG_SZ', '/d', action.manifest, '/f'];
    const result = spawnSync('reg.exe', commandArgs, {stdio: 'inherit'});
    if (result.status !== 0 && !(uninstall && result.status === 1)) throw new Error(`Registry update failed: ${action.key}`);
  }
}
console.log(uninstall ? 'Foliora native host registration removed.' : 'Foliora native host registered for Chromium and Firefox.');

function platformActions() {
  if (process.platform === 'win32') {
    const base = join(process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'), 'Foliora', 'NativeMessaging');
    const chromeManifest = join(base, 'chromium.json');
    const firefoxManifest = join(base, 'firefox.json');
    return [
      {kind: 'file', browser: 'chromium', path: chromeManifest},
      {kind: 'file', browser: 'firefox', path: firefoxManifest},
      {kind: 'registry', key: `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}`, manifest: chromeManifest},
      {kind: 'registry', key: `HKCU\\Software\\Chromium\\NativeMessagingHosts\\${HOST_NAME}`, manifest: chromeManifest},
      {kind: 'registry', key: `HKCU\\Software\\Mozilla\\NativeMessagingHosts\\${HOST_NAME}`, manifest: firefoxManifest},
    ];
  }
  if (process.platform === 'darwin') {
    return [
      {kind: 'file', browser: 'chromium', path: join(homedir(), 'Library/Application Support/Google/Chrome/NativeMessagingHosts', `${HOST_NAME}.json`)},
      {kind: 'file', browser: 'firefox', path: join(homedir(), 'Library/Application Support/Mozilla/NativeMessagingHosts', `${HOST_NAME}.json`)},
    ];
  }
  return [
    {kind: 'file', browser: 'chromium', path: join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'google-chrome/NativeMessagingHosts', `${HOST_NAME}.json`)},
    {kind: 'file', browser: 'chromium', path: join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'chromium/NativeMessagingHosts', `${HOST_NAME}.json`)},
    {kind: 'file', browser: 'firefox', path: join(homedir(), '.mozilla/native-messaging-hosts', `${HOST_NAME}.json`)},
  ];
}
