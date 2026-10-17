import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';

const read = path => readFile(new URL(path, import.meta.url), 'utf8');

test('Release A retains the Step 10 data routes while exposing only device enrollment', async () => {
  const [configText, index, memos, notices, restore, devices, manifest] = await Promise.all([
    read('../aleph.config.json'), read('../public/index.html'), read('../api/memos.js'),
    read('../api/notices.js'), read('../api/restore/[id].js'), read('../api/devices.js'),
    read('../public/manifest.webmanifest'),
  ]);
  const config = JSON.parse(configText);

  assert.equal(config.step, 10);
  assert.match(index, /manifest\.webmanifest/u);
  assert.match(index, /fetch\('\/api\/memos'/u);
  assert.match(index, /'\/api\/memos\/' \+ encodeURIComponent\(note\.id\)/u);
  assert.match(index, /'\/api\/restore\/' \+ encodeURIComponent\(id\)/u);
  assert.doesNotMatch(index, /signedFetch\(path/u);
  assert.doesNotMatch(memos, /guardDeviceRequest/u);
  assert.doesNotMatch(notices, /guardDeviceRequest/u);
  assert.doesNotMatch(restore, /guardDeviceRequest/u);
  assert.match(devices, /device\.state\s*!==\s*'pending'/u);
  assert.match(devices, /requireDeviceProof/u);
  assert.match(JSON.parse(manifest).name, /^BYTE BACK/u);
});
