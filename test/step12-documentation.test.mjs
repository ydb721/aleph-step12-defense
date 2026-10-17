import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const root = path => new URL('../' + path, import.meta.url);

test('README installation commands match declared scripts and local PWA assets', async () => {
  const [readme, packageText, preview] = await Promise.all([
    readFile(root('README.md'), 'utf8'),
    readFile(root('package.json'), 'utf8'),
    readFile(root('scripts/serve-pwa.mjs'), 'utf8'),
  ]);
  const project = JSON.parse(packageText);
  assert.equal(project.engines.node, '>=22');
  for (const command of [
    'operations:test', 'verification:test', 'device:test', 'pwa:test', 'recovery:test',
    'policy:test', 'decider:test', 'detect:test', 'build',
  ]) {
    assert.ok(project.scripts[command], command + ' must exist');
    assert.ok(readme.includes('npm.cmd run ' + command), command + ' must be documented');
  }
  assert.match(readme, /node scripts\/serve-pwa\.mjs/u);
  assert.match(readme, /Ctrl\+C/u);
  assert.match(preview, /operations\.mjs/u);
  assert.match(preview, /operations-manifest\.json/u);
  assert.match(preview, /LOCAL_STATIC_PREVIEW_ONLY/u);
});

test('README distinguishes supplied engine, student implementation, history and unexecuted evidence', async () => {
  const [readme, operationsDoc] = await Promise.all([
    readFile(root('README.md'), 'utf8'),
    readFile(root('docs/OPERATIONS_VERIFICATION.md'), 'utf8'),
  ]);
  assert.match(readme, /ALEPH SDP 엔진\(제공\)/u);
  assert.match(readme, /실제 운영 엔진의 연결.*실측하지 못했다/u);
  assert.match(readme, /사용자 제공 심판 결과 스크린샷/u);
  assert.match(readme, /41종.*임의로 41\/41 성공/u);
  assert.match(readme, /git reset --hard.*사용하지 않는다/u);
  assert.match(operationsDoc, /실제 HTTP 응답이 없는 후보는.*미실행/u);
});
