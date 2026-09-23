import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const rules = (path) => readFileSync(new URL(path, import.meta.url), 'utf8')
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith('#'));

// Policy checks, not a Dockerignore reimplementation or a container build test.
// Keep these exclusions last so a later negation cannot re-include drill data.
test('Docker context ends with exclusions for build caches and retained drills', () => {
  assert.deepEqual(rules('../.dockerignore').slice(-2), [
    '.test-build',
    '**/foliora-s3-drill-*',
  ]);
});

test('Git excludes retained drill evidence independently of Docker', () => {
  assert.deepEqual(rules('../.gitignore').slice(-2), [
    '.test-build/',
    '**/foliora-s3-drill-*/',
  ]);
});
