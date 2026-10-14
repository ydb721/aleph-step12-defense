import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule, createContext } from 'node:vm';
import { resolve, dirname } from 'node:path';
import { TRUSTED_B_BACKUP as trusted } from '../src/recovery/trusted-memo-backup.mjs';

// Authentication and the RPC transport are simulated here. The real API
// handlers and pinned-backup module execute unchanged inside the VM.
async function call({ route = 'api/restore/[id].js', body, responses = [], authorized = true }) {
  const calls = [];
  const context = createContext({
    process: { env: { SUPABASE_URL: 'https://fixture.supabase.co', SUPABASE_SECRET_KEY: 'test-only' } },
    console: { error() {}, info() {} },
    URL,
    fetch: async (url, init) => {
      calls.push({ name: new URL(url).pathname.split('/').at(-1), body: JSON.parse(init.body) });
      const response = responses.shift();
      assert.ok(response, 'unexpected RPC call');
      return { ok: response.status === undefined || response.status === 200,
        json: async () => response.body };
    },
  });
  const cache = new Map();
  async function load(path) {
    if (cache.has(path)) return cache.get(path);
    let module;
    if (path === 'node:module') {
      module = new SyntheticModule(['createRequire'], function () {
        this.setExport('createRequire', () => () => ({}));
      }, { context });
    } else if (path.endsWith('/src/verify-login.mjs')) {
      module = new SyntheticModule(['createLoginVerifier'], function () {
        this.setExport('createLoginVerifier', () => async () => authorized
          ? { kind: 'student', userId: 'fixture-owner' } : null);
      }, { context });
    } else {
      module = new SourceTextModule(await readFile(path, 'utf8'), { context, identifier: path });
    }
    cache.set(path, module);
    await module.link((specifier, parent) => load(specifier.startsWith('node:')
      ? specifier : resolve(dirname(parent.identifier), specifier)));
    return module;
  }
  const module = await load(resolve(route));
  await module.evaluate();
  const result = { headers: {} };
  const res = {
    setHeader(key, value) { result.headers[key] = value; },
    status(code) { result.status = code; return this; },
    json(value) { result.body = JSON.parse(JSON.stringify(value)); return result; },
  };
  await module.namespace.default({
    method: 'POST', headers: { authorization: 'fixture', host: 'fixture.vercel.app' },
    query: { id: trusted.id }, body,
  }, res);
  return { ...result, calls };
}
const preview = (changes = ['title', 'content']) => ({
  id: trusted.id, version: trusted.version, capturedAt: trusted.capturedAt,
  stateVersion: 'a'.repeat(64), verified: true, changedFields: changes,
});

test('tampered target can restore from a verified unchanged backup', async () => {
  const p = preview();
  const result = await call({ body: { expectedVersion: p.version, expectedState: p.stateVersion },
    responses: [{ body: p }, { body: { id: trusted.id, verified: true, restored: true } }] });
  assert.equal(result.status, 200);
  assert.deepEqual(result.calls.map(x => x.name), ['preview_memo_recovery', 'restore_verified_memo']);
  assert.equal(result.calls[1].body.p_expected_version, trusted.version);
});
test('preview has version and changed fields without executing restore', async () => {
  const result = await call({ body: { preview: true }, responses: [{ body: preview() }] });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.changedFields, ['title', 'content']);
  assert.equal(result.calls.length, 1);
});
test('both entry points reject a self-consistent but untrusted backup', async () => {
  for (const route of ['api/restore/[id].js', 'api/restore.js']) {
    const result = await call({ route, body: route.endsWith('/restore.js') ? { id: trusted.id } : {},
      responses: [{ body: { ...preview(), version: 'b'.repeat(64) } }] });
    assert.equal(result.status, 409);
    assert.equal(result.calls.length, 1);
  }
});
test('missing or corrupt backup never calls restore', async () => {
  for (const message of ['backup_not_found', 'backup_hash_mismatch']) {
    const result = await call({ body: {}, responses: [{ status: 409, body: { code: 'P0001', message } }] });
    assert.equal(result.status, 409);
    assert.equal(result.calls.length, 1);
  }
});
test('stale target confirmation is rejected before writing', async () => {
  const result = await call({ body: { expectedState: 'b'.repeat(64) }, responses: [{ body: preview() }] });
  assert.equal(result.body.error, 'TARGET_CHANGED');
  assert.equal(result.calls.length, 1);
});
test('transaction revalidation failure is never reported as restored', async () => {
  const result = await call({ body: {}, responses: [{ body: preview() },
    { status: 409, body: { code: 'P0001', message: 'backup_or_target_changed' } }] });
  assert.equal(result.status, 409);
  assert.equal(result.body.error, 'RECOVERY_STATE_CHANGED');
});
test('malformed or null JSON cannot become an empty restore command', async () => {
  for (const body of ['{broken', 'null', 'false', '[]']) {
    const result = await call({ body });
    assert.equal(result.status, 400);
    assert.equal(result.calls.length, 0);
  }
});
test('invalid authentication never reaches the database', async () => {
  const result = await call({ authorized: false, body: {} });
  assert.equal(result.status, 401);
  assert.equal(result.calls.length, 0);
});
test('RPC programming errors are distinguished from backup rejection', async () => {
  const result = await call({ body: {}, responses: [{ status: 400, body: { code: '22P02' } }] });
  assert.equal(result.status, 502);
  assert.equal(result.body.error, 'RESTORE_DEPENDENCY_ERROR');
});
test('a verified RPC response that did not restore cannot be reported as restored', async () => {
  const result = await call({ body: {}, responses: [{ body: preview() },
    { body: { id: trusted.id, verified: true, restored: false } }] });
  assert.notEqual(result.status, 200);
  assert.notEqual(result.body.restored, true);
});
