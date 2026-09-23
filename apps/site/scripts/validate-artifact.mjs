import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const dist = join(import.meta.dirname, '..', 'dist');
const indexPath = join(dist, 'index.html');
if (!existsSync(indexPath)) {
  console.error('Missing dist/index.html. Run `pnpm build` first.');
  process.exit(1);
}

const html = readFileSync(indexPath, 'utf8');
const checks = [
  ['built stylesheet', /<link[^>]+href="\.\/assets\/[^"]+\.css"/],
  ['built JavaScript module', /<script[^>]+type="module"[^>]+src="\.\/assets\/[^"]+\.js"/],
  ['no source TypeScript entry', !html.includes('./src/main.ts')],
  ['no external Google Fonts', !html.includes('fonts.googleapis.com') && !html.includes('fonts.gstatic.com')],
];

const failed = checks.filter(([, result]) => (result instanceof RegExp ? !result.test(html) : !result));
if (failed.length > 0) {
  console.error(`Artifact validation failed: ${failed.map(([name]) => name).join(', ')}`);
  process.exit(1);
}

console.log('Artifact validation passed.');
