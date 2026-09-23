import {cpSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');
const shared = resolve(root, 'dist/shared');
for (const [target, manifest] of [['chromium', 'manifest.chromium.json'], ['firefox', 'manifest.firefox.json']]) {
  const destination = resolve(root, `dist/${target}`);
  rmSync(destination, {recursive: true, force: true});
  mkdirSync(destination, {recursive: true});
  cpSync(shared, destination, {recursive: true});
  writeFileSync(resolve(destination, 'manifest.json'), readFileSync(resolve(root, manifest)));
}
console.log('Packaged Chromium and Firefox extension directories.');
