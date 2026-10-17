import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';

const read = path => readFile(new URL(path, import.meta.url), 'utf8');

test('Release profile retains its intended data-access contract', async () => {
  const [configText, index, memos, notices, restore, devices, manifest] = await Promise.all([
    read('../aleph.config.json'), read('../public/index.html'), read('../api/memos.js'),
    read('../api/notices.js'), read('../api/restore/[id].js'), read('../api/devices.js'),
    read('../public/manifest.webmanifest'),
  ]);
  const config = JSON.parse(configText);

  assert.match(index, /manifest\.webmanifest/u);
  assert.match(devices, /device\.state\s*!==\s*'pending'/u);
  assert.match(devices, /requireDeviceProof/u);
  assert.match(JSON.parse(manifest).name, /^BYTE BACK/u);

  if (config.step === 10) {
    assert.match(index, /fetch\('\/api\/memos'/u);
    assert.match(index, /'\/api\/memos\/' \+ encodeURIComponent\(note\.id\)/u);
    assert.match(index, /'\/api\/restore\/' \+ encodeURIComponent\(id\)/u);
    assert.doesNotMatch(index, /signedFetch\(path/u);
    assert.doesNotMatch(memos, /guardDeviceRequest/u);
    assert.doesNotMatch(notices, /guardDeviceRequest/u);
    assert.doesNotMatch(restore, /guardDeviceRequest/u);
    return;
  }

  assert.equal(config.step, 11);
  assert.match(index, /signedFetch\(path/u);
  assert.match(index, /\/api\/memos\/item\?id=/u);
  assert.match(index, /\/api\/restore\/item\?id=/u);
  assert.match(memos, /guardDeviceRequest/u);
  assert.match(notices, /guardDeviceRequest/u);
  assert.match(restore, /guardDeviceRequest/u);
});
