import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { SourceTextModule, SyntheticModule, createContext } from 'node:vm';
import { resolve, dirname } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { TRUSTED_B_BACKUP as trusted } from '../src/recovery/trusted-memo-backup.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { restoreItemTarget } from '../src/device-request.mjs';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';

// Authentication and the RPC transport are simulated here. The real API
// handlers and pinned-backup module execute inside the VM. Device admission is
// independently exercised with the real WebAuthn verifier in step11 tests.
const owner = '22222222-2222-4222-8222-222222222222';
const note = { title: 'Recovery fixture', body: 'Original fixture content' };
const sha = value => createHash('sha256').update(value, 'utf8').digest('hex');
const contentSha256 = sha(note.body);
const snapshotSha256 = sha(note.title + '\0' + note.body);

async function call({ route = 'api/restore/[id].js', id = trusted.id, body,
  responses = [], authorized = true, method = 'POST', userId = owner, kind = 'student',
  nonEnumerableHeaders = false }) {
  const calls = [];
  const logs = [];
  const context = createContext({
    process: { env: { SUPABASE_URL: 'https://fixture.supabase.co', SUPABASE_SECRET_KEY: 'test-only' } },
    console: { error() {}, info(message) {
      if (message.startsWith('BYTEBACK_TRACE ')) logs.push(JSON.parse(message.slice(15)));
    } },
    URL,
    fetch: async (url, init) => {
      calls.push({ name: new URL(url).pathname.split('/').at(-1), method: init.method,
        params: Object.fromEntries(new URL(url).searchParams),
        body: init.body === undefined ? null : JSON.parse(init.body) });
      const response = responses.shift();
      assert.ok(response, 'unexpected RPC call');
      return { status: response.status ?? 200,
        ok: response.status === undefined || response.status === 200,
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
    } else if (path === 'node:crypto') {
      module = new SyntheticModule(['createHash', 'randomUUID'], function () {
        this.setExport('createHash', createHash);
        this.setExport('randomUUID', randomUUID);
      }, { context });
    } else if (path === resolve('src/device-gate.mjs')) {
      module = new SyntheticModule(['guardDeviceRequest'], function () {
        this.setExport('guardDeviceRequest', async () => true);
      }, { context });
    } else if (path === resolve('src/device-request.mjs')) {
      module = new SyntheticModule(['readVerifiedRequest', 'restoreItemTarget'], function () {
        this.setExport('readVerifiedRequest', async () => undefined);
        this.setExport('restoreItemTarget', restoreItemTarget);
      }, { context });
    } else if (path === resolve('src/verify-login.mjs')) {
      module = new SyntheticModule(['createLoginVerifier'], function () {
        this.setExport('createLoginVerifier', () => async () => authorized
          ? { kind, userId, ...(kind === 'judge' ? {
            runId: '33333333-3333-4333-8333-333333333333', identity: 'b',
          } : {}) } : null);
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
    end() { return result; },
  };
  const request = { method,
    url: route === 'api/restore/item.js' ? '/api/restore/item?id=' + id : '/api/memos/' + id,
    query: { id }, body };
  Object.defineProperty(request, 'headers', { value: { authorization: 'fixture', host: 'fixture.vercel.app' },
    enumerable: !nonEnumerableHeaders });
  await module.namespace.default(request, res);
  return { ...result, calls, logs };
}
const preview = (changes = ['title', 'content']) => ({
  id: trusted.id, version: trusted.version, capturedAt: trusted.capturedAt,
  stateVersion: 'a'.repeat(64), verified: true, changedFields: changes,
  ownerId: owner, contentSha256, snapshotSha256, backupKind: 'legacy', sealVerified: false,
});
const restored = (p = preview()) => ({
  id: p.id, ...note, ownerId: owner, owner_id: owner,
  contentSha256, content_sha256: contentSha256,
  snapshotSha256, backupVersion: p.version, verified: true, restored: true,
});

test('signed judge JWT preserves sub rather than mapping the B label to a student account', async () => {
  const config = JSON.parse(await readFile(resolve('aleph.config.json'), 'utf8'));
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const keySet = createLocalJWKSet({ keys: [{ ...await exportJWK(publicKey), kid: 'fixture' }] });
  const verify = createLoginVerifier({ config, judgeKeySet: keySet,
    supabaseClient: { auth: { getClaims() { throw new Error('judge must not use student auth'); } } } });
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: config.judgeIssuer, aud: new URL(config.publicAppUrl).hostname,
    sub: randomUUID(), aleph_run: randomUUID(), aleph_role: 'judge', aleph_identity: 'b',
    iat: now, exp: now + 600 };
  const sign = payload => new SignJWT(payload).setProtectedHeader({ alg: 'ES256', kid: 'fixture' })
    .sign(privateKey);
  const identity = await verify('Bearer ' + await sign(claims));
  assert.equal(identity.kind, 'judge');
  assert.equal(identity.userId, claims.sub);
  const second = { ...claims, sub: randomUUID() };
  assert.equal((await verify('Bearer ' + await sign(second))).userId, second.sub);
  for (const patch of [{ aud: 'wrong.vercel.app' }, { aleph_role: 'student' },
    { aleph_identity: 'c' }, { exp: now - 60 }, { sub: 'not-a-uuid' }]) {
    assert.equal(await verify('Bearer ' + await sign({ ...claims, ...patch })), null);
  }
});

test('judge identity is forwarded unchanged to memo ownership and both recovery RPCs', async () => {
  const userId = randomUUID();
  const id = randomUUID();
  const created = await call({ route: 'api/memos.js', method: 'POST', kind: 'judge', userId,
    body: { id, ...note }, responses: [{ body: [{ public_id: id }] }] });
  assert.equal(created.status, 201);
  assert.equal(created.calls[0].body.owner_id, userId);
  const p = { ...preview(), id, ownerId: userId, backupKind: 'on_create', sealVerified: true };
  const result = await call({ id, kind: 'judge', userId, responses: [{ body: p },
    { body: { ...restored(p), ownerId: userId, owner_id: userId } }] });
  assert.equal(result.status, 200);
  assert.ok(result.calls.every(c => c.body.p_actor === userId));
});

test('verified database previews can still be rejected by each API validation gate', async () => {
  const patches = [{ id: randomUUID() }, { version: 'invalid' }, { stateVersion: undefined },
    { ownerId: randomUUID() }, { contentSha256: undefined }, { snapshotSha256: undefined },
    { capturedAt: undefined }, { changedFields: ['body'] }, { changedFields: undefined },
    { capturedAt: trusted.capturedAt.replace('+00:00', 'Z') }, { backupKind: 'on_create', sealVerified: true }];
  for (const patch of patches) {
    const result = await call({ responses: [{ body: { ...preview(), ...patch } }] });
    assert.equal(result.status, 409);
    assert.equal(result.body.error, 'BACKUP_UNVERIFIED');
    assert.equal(result.calls.length, 1);
    assert.ok(result.logs.some(l => l.stage === 'backup_rejected'));
  }
});

test('generic P0001 rejection is BACKUP_UNVERIFIED at either recovery RPC', async () => {
  for (const message of ['backup_hash_mismatch', 'backup_seal_mismatch',
    'expected_versions_required', 'owner_mismatch', 'unexpected_fixture_exception']) {
    for (const duringRestore of [false, true]) {
      const rejection = { status: 400, body: { code: 'P0001', message } };
      const result = await call({ responses: duringRestore ? [{ body: preview() }, rejection] : [rejection] });
      assert.equal(result.status, 409);
      assert.equal(result.body.error, 'BACKUP_UNVERIFIED');
      assert.equal(result.calls.length, duringRestore ? 2 : 1);
      assert.equal(result.logs.find(l => l.stage === 'rpc_rejected').rpc,
        duringRestore ? 'restore_verified_memo' : 'preview_memo_recovery');
    }
  }
});

test('unexpected judge control fields fail before any backup lookup, not as BACKUP_UNVERIFIED', async () => {
  for (const body of [{ id: trusted.id }, { backupVersion: trusted.version },
    { contentSha256 }, { preview: false }]) {
    const result = await call({ body });
    assert.equal(result.status, 400);
    assert.equal(result.body.error, 'INVALID_RESTORE_REQUEST');
    assert.equal(result.calls.length, 0);
  }
});

test('preview shape diagnostics identify the failed field without logging raw values', async () => {
  const cases = [
    ['verified', { verified: false }], ['versionValid', { version: 'PRIVATE_VERSION' }],
    ['stateVersionValid', { stateVersion: undefined }], ['ownerValid', { ownerId: 'PRIVATE_OWNER' }],
    ['contentHashValid', { contentSha256: 'PRIVATE_HASH' }],
    ['snapshotHashValid', { snapshotSha256: undefined }], ['captureValid', { capturedAt: undefined }],
    ['changedFieldsValid', { changedFields: ['PRIVATE_FIELD'] }],
  ];
  for (const [flag, patch] of cases) {
    const result = await call({ responses: [{ body: { ...preview(), ...patch } }] });
    assert.equal(result.status, 409);
    const compared = result.logs.find(l => l.stage === 'backup_compared');
    assert.equal(compared[flag], false);
    assert.equal(compared.structureValid, false);
    assert.ok(!JSON.stringify(result.logs).includes('PRIVATE_'));
  }
});

test('judge create, tamper and restore logs share run, actor and memo references', async () => {
  const id = randomUUID();
  const p = { ...preview(), id, backupKind: 'on_create', sealVerified: true };
  const row = { public_id: id, owner_id: owner, title: note.title, content: note.body };
  const created = await call({ route: 'api/memos.js', method: 'POST', kind: 'judge',
    body: { id, ...note }, responses: [{ body: [row] }] });
  const tampered = await call({ route: 'api/memos/[id].js', method: 'PUT', kind: 'judge', id,
    body: { body: 'Changed fixture' }, responses: [{ body: [{ ...row, content: 'Changed fixture' }] }] });
  const recovered = await call({ kind: 'judge', id, responses: [{ body: p }, { body: restored(p) }] });
  const finals = [created, tampered, recovered].map(r => r.logs.at(-1));
  assert.deepEqual(finals.map(l => l.status), [201, 200, 200]);
  for (const name of ['runRef', 'actorRef', 'memoRef']) {
    assert.ok(finals[0][name]);
    assert.equal(new Set(finals.map(l => l[name])).size, 1);
  }
  assert.equal(new Set(finals.map(l => l.traceId)).size, 3);
  assert.ok(finals.every(l => l.identity === 'b' && l.kind === 'judge'));
  for (const stage of ['authentication', 'rpc_started', 'rpc_finished', 'backup_compared',
    'backup_verified', 'restored_row_compared', 'completed']) {
    assert.ok(recovered.logs.some(l => l.stage === stage), stage);
  }
  const serialized = JSON.stringify([created.logs, tampered.logs, recovered.logs]);
  for (const value of [id, owner, note.body, 'Changed fixture', contentSha256,
    '33333333-3333-4333-8333-333333333333']) assert.ok(!serialized.includes(value));
});

test('tampered target can restore from a verified unchanged backup', async () => {
  const p = preview();
  const result = await call({ body: { expectedVersion: p.version, expectedState: p.stateVersion },
    responses: [{ body: p }, { body: restored(p) }] });
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

test('static restore item preserves Vercel request metadata while delegating to the canonical recovery handler', async () => {
  const result = await call({ route: 'api/restore/item.js', body: { preview: true },
    nonEnumerableHeaders: true, responses: [{ body: preview() }] });
  assert.equal(result.status, 200);
  assert.equal(result.body.verified, true);
  assert.equal(result.calls.length, 1);
  assert.equal(result.calls[0].name, 'preview_memo_recovery');
});
test('missing and corrupt backups have distinct statuses and never call restore', async () => {
  for (const message of ['backup_not_found', 'backup_hash_mismatch', 'backup_seal_mismatch']) {
    const result = await call({ body: {}, responses: [{ status: 409, body: { code: 'P0001', message } }] });
    assert.equal(result.status, message === 'backup_not_found' ? 404 : 409);
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

test('database reread verification failure is a server error without a success payload', async () => {
  const result = await call({ responses: [{ body: preview() },
    { status: 400, body: { code: 'P0001', message: 'restore_verify_failed' } }] });
  assert.equal(result.status, 500);
  assert.equal(result.body.error, 'RESTORE_MISMATCH');
  assert.equal(result.body.restored, undefined);
  assert.equal(result.calls.length, 2);
});

test('404 and 500 require the matching database exception code at either RPC', async () => {
  for (const duringRestore of [false, true]) {
    for (const [message, expected] of [['backup_not_found', 404], ['restore_verify_failed', 500]]) {
      for (const code of ['P0001', '22P02']) {
        const rejection = { status: 400, body: { code, message } };
        const result = await call({ responses: duringRestore ? [{ body: preview() }, rejection] : [rejection] });
        assert.equal(result.status, code === 'P0001' ? expected : 502);
        assert.equal(result.body.restored, undefined);
        assert.equal(result.logs.find(l => l.stage === 'rpc_finished' && l.status === 400).status, 400);
        assert.equal(result.logs.at(-1).status, result.status);
      }
    }
  }
});

test('bodyless judge-style restore binds a fresh snapshot for every change kind', async () => {
  for (const changes of [['title'], ['content'], ['title', 'content'], ['create']]) {
    const id = randomUUID();
    const p = { ...preview(changes), id, backupKind: 'on_create', sealVerified: true,
      version: 'c'.repeat(64) };
    const result = await call({ id, responses: [{ body: p }, { body: restored(p) }] });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.changedFields, changes);
    assert.equal(result.body.id, id);
    assert.equal(result.body.contentSha256, sha(result.body.body));
    assert.equal(result.calls[1].body.p_expected_version, p.version);
    assert.equal(result.calls[1].body.p_expected_state, p.stateVersion);
  }
});

test('another owners or absent snapshot is hidden on both entry points', async () => {
  for (const route of ['api/restore/[id].js', 'api/restore.js']) {
    const result = await call({ route, body: route.endsWith('/restore.js') ? { id: trusted.id } : {},
      responses: [{ status: 400, body: { code: 'P0001', message: 'backup_not_found' } }] });
    assert.equal(result.status, 404);
    assert.deepEqual(result.body, { error: 'MEMO_NOT_FOUND' });
    assert.equal(result.calls.length, 1);
  }
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

test('owner tamper is displayed before restoring the verified backup owner', async () => {
  const result = await call({ body: { preview: true },
    responses: [{ body: preview(['owner_id', 'content']) }] });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.changedFields, ['owner_id', 'content']);
  assert.equal(result.calls.length, 1);
});

test('restore response contains the reread memo owner, body and body hash', async () => {
  const p = preview();
  const result = await call({ body: {}, responses: [{ body: p }, { body: restored(p) }] });
  assert.equal(result.status, 200);
  assert.equal(result.body.ownerId, owner);
  assert.equal(result.body.owner_id, owner);
  assert.equal(result.body.title, note.title);
  assert.equal(result.body.body, note.body);
  assert.equal(result.body.contentSha256, sha(result.body.body));
  assert.equal(result.body.content_sha256, result.body.contentSha256);
  assert.equal(result.body.backupVersion, p.version);
  assert.equal(result.body.capturedAt, p.capturedAt);
  assert.deepEqual(result.body.changedFields, p.changedFields);
});

test('true flags cannot hide a missing or mismatching reread memo', async () => {
  const p = preview();
  for (const patch of [
    { ownerId: '33333333-3333-4333-8333-333333333333' },
    { body: note.body + ' changed' }, { title: note.title + ' changed' },
    { contentSha256: 'b'.repeat(64) }, { content_sha256: 'b'.repeat(64) },
    { backupVersion: 'b'.repeat(64) },
    { body: undefined },
  ]) {
    const result = await call({ body: {},
      responses: [{ body: p }, { body: { ...restored(p), ...patch } }] });
    assert.equal(result.status, 500);
    assert.equal(result.body.error, 'RESTORE_MISMATCH');
  }
});

test('a newly created memo uses its sealed initial snapshot, not the fixed B ID', async () => {
  const id = '44444444-4444-4444-8444-444444444444';
  const p = { ...preview(), id, backupKind: 'on_create', sealVerified: true,
    version: 'c'.repeat(64), capturedAt: '2026-10-14T05:30:00+00:00' };
  const result = await call({ id, body: {}, responses: [{ body: p }, { body: restored(p) }] });
  assert.equal(result.status, 200);
  assert.equal(result.body.id, id);
  assert.equal(result.body.contentSha256, contentSha256);
});

test('an initial snapshot with no valid seal or a different owner never restores', async () => {
  const id = '44444444-4444-4444-8444-444444444444';
  for (const patch of [{ sealVerified: false },
    { ownerId: '33333333-3333-4333-8333-333333333333' }]) {
    const p = { ...preview(), id, backupKind: 'on_create', sealVerified: true,
      version: 'c'.repeat(64), ...patch };
    const result = await call({ id, body: {}, responses: [{ body: p }] });
    assert.equal(result.status, 409);
    assert.equal(result.calls.length, 1);
  }
});

test('successful recovery logs each comparison under one trace without private values', async () => {
  const p = preview();
  const result = await call({ body: {}, responses: [{ body: p }, { body: restored(p) }] });
  assert.equal(new Set(result.logs.map(item => item.traceId)).size, 1);
  assert.equal(result.logs.filter(item => item.stage === 'completed').length, 1);
  const comparison = result.logs.find(item => item.stage === 'restored_row_compared');
  for (const flag of ['idMatches', 'ownerMatches', 'ownerAliasMatches', 'versionMatches',
    'bodyHashMatches', 'snapshotHashMatches', 'hashAliasMatches', 'verified', 'restored']) {
    assert.equal(comparison[flag], true, flag);
  }
  const serialized = JSON.stringify(result.logs);
  for (const privateValue of [owner, trusted.id, note.title, note.body, contentSha256,
    snapshotSha256, trusted.version]) assert.ok(!serialized.includes(privateValue));
});

test('failed hash comparison and early auth rejection always have final status logs', async () => {
  const p = preview();
  const mismatch = await call({ body: {},
    responses: [{ body: p }, { body: { ...restored(p), body: note.body + ' changed' } }] });
  assert.equal(mismatch.logs.find(item => item.stage === 'restored_row_compared').bodyHashMatches, false);
  assert.equal(mismatch.logs.at(-1).status, 500);
  assert.equal(mismatch.logs.at(-1).error, 'RESTORE_MISMATCH');
  const denied = await call({ authorized: false, body: {} });
  assert.equal(denied.logs.at(-1).status, 401);
  assert.equal(denied.logs.at(-1).error, 'AUTH_REQUIRED');
});

test('compatibility route shares the same request trace with the canonical handler', async () => {
  const p = preview();
  const result = await call({ route: 'api/restore.js', body: { id: trusted.id },
    responses: [{ body: p }, { body: restored(p) }] });
  assert.equal(result.status, 200);
  assert.equal(new Set(result.logs.map(item => item.traceId)).size, 1);
  assert.equal(result.logs.filter(item => item.stage === 'received').length, 1);
  assert.equal(result.logs.filter(item => item.stage === 'completed').length, 1);
});

test('memo create, read, update and delete retain their responses while recording outcomes', async () => {
  const row = { public_id: trusted.id, owner_id: owner, title: note.title, content: note.body };
  for (const method of ['POST', 'GET', 'PUT', 'DELETE']) {
    const result = await call({ route: method === 'POST' ? 'api/memos.js' : 'api/memos/[id].js',
      method, body: ['POST', 'PUT'].includes(method) ? note : undefined,
      responses: [{ body: [row] }] });
    assert.equal(result.status, method === 'POST' ? 201 : method === 'DELETE' ? 204 : 200);
    if (method === 'POST') assert.deepEqual(result.body, { id: trusted.id });
    if (['GET', 'PUT'].includes(method)) assert.deepEqual(result.body, { id: trusted.id, ...note });
    assert.equal(result.logs.filter(item => item.stage === 'completed').length, 1);
    assert.equal(result.logs.at(-1).status, result.status);
    const serialized = JSON.stringify(result.logs);
    for (const privateValue of [owner, trusted.id, note.title, note.body]) {
      assert.ok(!serialized.includes(privateValue));
    }
  }
});

test('memo PUT supports a body-only or title-only B tamper without changing owner', async () => {
  const cases = [
    { input: { body: 'Tampered B content' }, patch: { content: 'Tampered B content' },
      returned: { title: note.title, content: 'Tampered B content' } },
    { input: { title: 'Tampered B title' }, patch: { title: 'Tampered B title' },
      returned: { title: 'Tampered B title', content: note.body } },
  ];
  for (const item of cases) {
    const result = await call({ route: 'api/memos/[id].js', method: 'PUT',
      body: item.input, responses: [{ body: [{
        public_id: trusted.id, owner_id: owner, ...item.returned,
      }] }] });
    assert.equal(result.status, 200);
    assert.equal(result.calls.length, 1);
    assert.equal(result.calls[0].method, 'PATCH');
    assert.deepEqual(result.calls[0].body, item.patch);
    assert.deepEqual(result.body, { id: trusted.id,
      title: item.returned.title, body: item.returned.content });
  }
});

// Use letters so UUID case differences cannot disappear in numeric-only fixtures.
const putOwner = 'abcdef01-2345-4678-9abc-def012345678';
for (const [label, userId, returnedOwner] of [
  ['matching lowercase UUIDs', putOwner, putOwner],
  ['an uppercase authenticated UUID', putOwner.toUpperCase(), putOwner],
  ['an uppercase database owner UUID', putOwner, putOwner.toUpperCase()],
]) {
  test('memo PUT accepts ' + label, async () => {
    for (const kind of ['student', 'judge']) {
      const result = await call({ route: 'api/memos/[id].js', method: 'PUT', kind, userId,
        body: { body: note.body }, responses: [{ body: [{
          public_id: trusted.id, owner_id: returnedOwner, title: note.title, content: note.body,
        }] }] });
      assert.equal(result.status, 200);
      assert.deepEqual(result.body, { id: trusted.id, ...note });
      assert.equal(result.calls.length, 1);
      assert.equal(result.calls[0].method, 'PATCH');
      assert.equal(result.calls[0].params.public_id, 'eq.' + trusted.id);
      assert.equal(result.calls[0].params.owner_id, 'eq.' + userId);
      assert.deepEqual(result.calls[0].body, { content: note.body });
    }
  });
}

test('memo PUT rejects different UUIDs and preserves the authenticated owner filter', async () => {
  const userId = putOwner.toUpperCase();
  const otherOwner = 'bbcdef01-2345-4678-9abc-def012345678';
  for (const kind of ['student', 'judge']) {
    for (const [rows, status, error] of [
      [[], 404, 'MEMO_NOT_FOUND'],
      [[{ public_id: trusted.id, owner_id: otherOwner, title: note.title, content: note.body }],
        403, 'OWNER_MISMATCH'],
    ]) {
      const result = await call({ route: 'api/memos/[id].js', method: 'PUT', kind, userId,
        body: { body: note.body }, responses: [{ body: rows }] });
      assert.equal(result.status, status);
      assert.deepEqual(result.body, { error });
      assert.equal(result.calls.length, 1);
      assert.equal(result.calls[0].method, 'PATCH');
      assert.equal(result.calls[0].params.public_id, 'eq.' + trusted.id);
      assert.equal(result.calls[0].params.owner_id, 'eq.' + userId);
      assert.deepEqual(result.calls[0].body, { content: note.body });
    }
  }
});

test('memo PUT rejects unauthenticated requests before any database call', async () => {
  const result = await call({ route: 'api/memos/[id].js', method: 'PUT',
    authorized: false, body: { body: note.body } });
  assert.equal(result.status, 401);
  assert.deepEqual(result.body, { error: 'AUTH_REQUIRED' });
  assert.equal(result.calls.length, 0);
});

test('memo PUT rejects request identity claims before any database call', async () => {
  for (const kind of ['student', 'judge']) {
    for (const field of ['owner_id', 'ownerId', 'userId', 'subjectId', 'role']) {
      const result = await call({ route: 'api/memos/[id].js', method: 'PUT', kind,
        userId: putOwner.toUpperCase(),
        body: { body: note.body, [field]: field === 'role' ? 'admin' : putOwner } });
      assert.equal(result.status, 403);
      assert.deepEqual(result.body, { error: 'IDENTITY_CLAIM_FORBIDDEN' });
      assert.equal(result.calls.length, 0);
    }
  }
});

test('memo partial PUT rejects empty, malformed and owner-claim bodies without DB writes', async () => {
  for (const body of [{}, { title: '  ' }, { body: 123 }, { body: 'ok', owner_id: owner }]) {
    const result = await call({ route: 'api/memos/[id].js', method: 'PUT', body });
    assert.equal(result.status, Object.hasOwn(body, 'owner_id') ? 403 : 400);
    assert.equal(result.calls.length, 0);
  }
});

test('memo authentication and owner rejection still stop without exposing returned memo values', async () => {
  const unauthenticated = await call({ route: 'api/memos/[id].js', method: 'GET', authorized: false });
  assert.equal(unauthenticated.status, 401);
  assert.equal(unauthenticated.calls.length, 0);
  const wrongOwner = await call({ route: 'api/memos/[id].js', method: 'GET', responses: [{ body: [{
    public_id: trusted.id, owner_id: '33333333-3333-4333-8333-333333333333',
    title: note.title, content: note.body,
  }] }] });
  assert.equal(wrongOwner.status, 404);
  assert.equal(wrongOwner.logs.at(-1).error, 'MEMO_NOT_FOUND');
  assert.ok(!JSON.stringify(wrongOwner.logs).includes(note.body));
});
