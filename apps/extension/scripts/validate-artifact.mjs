import {existsSync, readFileSync} from 'node:fs';
import {resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');
for (const target of ['chromium', 'firefox']) {
  const directory = resolve(root, `dist/${target}`);
  const manifest = JSON.parse(readFileSync(resolve(directory, 'manifest.json'), 'utf8'));
  const permissions = [...manifest.permissions].sort();
  if (JSON.stringify(permissions) !== JSON.stringify(['activeTab', 'nativeMessaging', 'scripting'])) {
    throw new Error(`${target}: unexpected permissions`);
  }
  if ('host_permissions' in manifest || 'content_scripts' in manifest) {
    throw new Error(`${target}: broad host access or static injection is forbidden`);
  }
  for (const entry of ['popup.html', 'popup.js', 'background.js', 'content.js']) {
    if (!existsSync(resolve(directory, entry))) throw new Error(`${target}: missing ${entry}`);
  }
  const content = readFileSync(resolve(directory, 'content.js'), 'utf8');
  if (/\bimport\s*(?:\(|[{'"*])/.test(content)) throw new Error(`${target}: content script is not self-contained`);
  if (/\.requestSubmit\s*\(|\.submit\s*\(/.test(content)) throw new Error(`${target}: content script can submit forms`);
  const background = readFileSync(resolve(directory, 'background.js'), 'utf8');
  if (target === 'firefox' && /\bimport\s*(?:\(|[{\'"*])/.test(background)) {
    throw new Error('firefox: background script is not self-contained');
  }
}
console.log('Extension artifact permissions and entrypoints validated.');
