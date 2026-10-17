import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { createDeviceHandler } from '../api/devices.js';
import restoreItem from '../api/restore/item.js';
import { descriptorBinding, requireDeviceProof, sessionHash } from '../src/device-auth.mjs';
import { RAW_BODY, memoItemTarget, readVerifiedRequest, requestTarget, restoreItemTarget } from '../src/device-request.mjs';
import { createAuthenticator, createMemoryDeviceStore, proofHeader } from './helpers/device-fixture.mjs';

const config = { publicAppUrl: 'https://device-exercise.vercel.app' };
const rpID = new URL(config.publicAppUrl).hostname;
const authorization = 'Bearer exercise.session.signature';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function fixture() {
  const identity = { kind: 'student', userId: randomUUID() };
  const authenticator = createAuthenticator(rpID, config.publicAppUrl);
  const store = createMemoryDeviceStore({ identity, authorization });
  const device = store.addDevice(authenticator.credential);
  return { identity, authorization, authenticator, store, device, config };
}

async function signedRequest(f, { method = 'POST', url = '/api/memos?order=a%20b',
  body = '{ "title": "fixture", "body": "fictional exercise" }', assertion = {} } = {}) {
  const bytes = Buffer.from(body);
  const req = { method, url, headers: {}, body: bytes };
  const binding = descriptorBinding({ method, ...requestTarget(req), bodySha256: hash(bytes) },
    f.identity, f.authorization);
  const nonceId = randomUUID();
  const { challenge } = await f.store.action('challenge', { id: nonceId,
    purpose: 'request', challenge: randomBytes(32).toString('base64url'),
    credentialId: f.device.credentialId, binding });
  const response = f.authenticator.responseAuthentication(challenge, assertion);
  req.headers['x-byteback-proof'] = proofHeader(nonceId, response);
  return { req, nonceId, response, binding };
}

function prove(f, req, overrides = {}) {
  return requireDeviceProof(req, { ...f, ...overrides });
}

function responseObject() {
  return { statusCode: 200, headers: {},
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; } };
}

test('static restore endpoint rejects malformed or additional external query parameters', async () => {
  for (const url of ['/api/restore/item', '/api/restore/item?extra=1',
    `/api/restore/item?id=${randomUUID()}&extra=1`]) {
    const res = responseObject();
    await restoreItem({ method: 'POST', url, headers: {} }, res);
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'INVALID_RESTORE_TARGET');
  }
});

async function api(handler, payload, { method = 'POST', origin = config.publicAppUrl,
  proof, url = '/api/devices' } = {}) {
  const headers = { authorization, ...(origin === null ? {} : { origin }),
    ...(proof ? { 'x-byteback-proof': proof } : {}) };
  const req = { method, url, headers, ...(payload === undefined ? {} : { body: Buffer.from(JSON.stringify(payload)) }) };
  const res = responseObject();
  await handler(req, res);
  return res;
}

test('missing, malformed and oversized device signatures fail closed', async () => {
  const f = fixture();
  await assert.rejects(() => prove(f, { method: 'GET', url: '/api/memos', headers: {} }),
    { status: 403, code: 'DEVICE_SIGNATURE_REQUIRED' });
  for (const value of ['not-valid-json', 'a'.repeat(12001), ['duplicate', 'header']]) {
    await assert.rejects(() => prove(f, { method: 'GET', url: '/api/memos',
      headers: { 'x-byteback-proof': value } }), { status: 403, code: 'DEVICE_INVALID_PROOF' });
  }
  assert.deepEqual(f.store.calls, []);
});

test('real ES256 WebAuthn proof authorizes exact raw request and updates counter once', async () => {
  const f = fixture();
  const { req, nonceId } = await signedRequest(f);
  assert.deepEqual(await prove(f, req), { deviceId: f.device.id, credentialId: f.device.credentialId });
  assert.equal(f.store.devices.get(f.device.id).counter, 1);
  assert.ok(f.store.challenges.get(nonceId).consumedAt);
  assert.equal(typeof req.body, 'string');
  assert.equal(JSON.parse(req.body).title, 'fixture');
  assert.ok(Buffer.isBuffer(req[RAW_BODY]));
});

for (const [name, mutate] of [
  ['raw path', req => { req.url = '/api/memos/other?order=a%20b'; }],
  ['raw query encoding', req => { req.url = '/api/memos?order=a+b'; }],
  ['raw query value', req => { req.url = '/api/memos?order=another'; }],
  ['query presence', req => { req.url = '/api/memos'; }],
  ['HTTP method', req => { req.method = 'PUT'; }],
  ['raw JSON whitespace', req => { req.body = Buffer.from('{"title":"fixture","body":"fictional exercise"}'); }],
  ['body content', req => { req.body = Buffer.from('{"title":"changed","body":"fictional exercise"}'); }],
]) {
  test(`${name} changes are rejected before nonce consumption`, async () => {
    const f = fixture();
    const { req, nonceId } = await signedRequest(f);
    mutate(req);
    await assert.rejects(() => prove(f, req), { code: 'DEVICE_REQUEST_MISMATCH' });
    assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
    assert.ok(!f.store.calls.includes('consume'));
  });
}

test('an empty query marker remains part of the signed request target', async () => {
  const f = fixture();
  const { req } = await signedRequest(f, { url: '/api/memos?' });
  req.url = '/api/memos';
  await assert.rejects(() => prove(f, req), { code: 'DEVICE_REQUEST_MISMATCH' });
});

test('a Vercel dynamic-route query is rejected rather than stripped from the binding', async () => {
  const f = fixture();
  const noteId = randomUUID();
  const { req } = await signedRequest(f, { method: 'PUT', url: `/api/memos/${noteId}` });
  req.url = `/api/memos/[id]?id=${noteId}`;
  await assert.rejects(() => prove(f, req), { code: 'DEVICE_REQUEST_MISMATCH' });
});

test('static memo item routes retain the exact external id query', async () => {
  const noteId = randomUUID();
  assert.deepEqual(memoItemTarget({ url: `/api/memos/item?id=${noteId}` }), { id: noteId, exact: true });
  assert.deepEqual(memoItemTarget({ url: `/api/memos/item?id=${noteId}&extra=1` }), { id: noteId, exact: false });
  assert.deepEqual(memoItemTarget({ url: '/api/memos/item?extra=1' }), { id: '', exact: false });
});

test('static restore item routes retain only the exact external id query', async () => {
  const memoId = randomUUID();
  assert.deepEqual(restoreItemTarget({ url: `/api/restore/item?id=${memoId}` }), { id: memoId, exact: true });
  assert.deepEqual(restoreItemTarget({ url: `/api/restore/item?id=${memoId}&extra=1` }), { id: memoId, exact: false });
  assert.deepEqual(restoreItemTarget({ url: '/api/restore/item?extra=1' }), { id: '', exact: false });
});

for (const [name, body] of [
  ['preview', JSON.stringify({ preview: true })],
  ['restore', JSON.stringify({ expectedVersion: 'a'.repeat(64), expectedState: 'b'.repeat(64) })],
]) {
  test(`a normal signed static restore ${name} succeeds`, async () => {
    const f = fixture();
    const { req } = await signedRequest(f, { url: `/api/restore/item?id=${randomUUID()}`, body });
    assert.deepEqual(await prove(f, req), { deviceId: f.device.id, credentialId: f.device.credentialId });
  });
}

for (const [name, mutate] of [
  ['external query changed', req => { req.url = `/api/restore/item?id=${randomUUID()}`; }],
  ['external query appended', req => { req.url += '&extra=1'; }],
  ['legacy dynamic path substituted', req => { req.url = '/api/restore/' + randomUUID(); }],
  ['one JSON body byte changed', req => { req.body[0] ^= 1; }],
]) {
  test(`static restore preview with ${name} is rejected before nonce consumption`, async () => {
    const f = fixture();
    const { req, nonceId } = await signedRequest(f, {
      url: `/api/restore/item?id=${randomUUID()}`, body: JSON.stringify({ preview: true }),
    });
    mutate(req);
    await assert.rejects(() => prove(f, req), { code: 'DEVICE_REQUEST_MISMATCH' });
    assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
  });
}

test('unsigned static restore preview is rejected', async () => {
  const f = fixture();
  await assert.rejects(() => prove(f, { method: 'POST', url: `/api/restore/item?id=${randomUUID()}`,
    headers: {}, body: Buffer.from(JSON.stringify({ preview: true })) }), { code: 'DEVICE_SIGNATURE_REQUIRED' });
});

test('a static restore nonce cannot be reused', async () => {
  const f = fixture();
  const { req } = await signedRequest(f, {
    url: `/api/restore/item?id=${randomUUID()}`, body: JSON.stringify({ preview: true }),
  });
  await prove(f, req);
  await assert.rejects(() => prove(f, req), { code: 'DEVICE_NONCE_REUSED' });
});

test('a normal signed static memo PUT succeeds', async () => {
  const f = fixture();
  const noteId = randomUUID();
  const { req } = await signedRequest(f, { method: 'PUT', url: `/api/memos/item?id=${noteId}` });
  assert.deepEqual(await prove(f, req), { deviceId: f.device.id, credentialId: f.device.credentialId });
});

for (const [name, mutate] of [
  ['external query changed', req => { req.url = `/api/memos/item?id=${randomUUID()}`; }],
  ['external query appended', req => { req.url += '&extra=1'; }],
  ['legacy path UUID changed', req => { req.url = '/api/memos/' + randomUUID(); }],
  ['one JSON body byte changed', req => { req.body[0] ^= 1; }],
]) {
  test(`static memo PUT with ${name} is rejected before nonce consumption`, async () => {
    const f = fixture();
    const noteId = randomUUID();
    const settings = name === 'legacy path UUID changed'
      ? { method: 'PUT', url: '/api/memos/' + noteId }
      : { method: 'PUT', url: `/api/memos/item?id=${noteId}` };
    const { req, nonceId } = await signedRequest(f, settings);
    mutate(req);
    await assert.rejects(() => prove(f, req), { code: 'DEVICE_REQUEST_MISMATCH' });
    assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
  });
}

test('an unsigned static memo PUT is rejected', async () => {
  const f = fixture();
  await assert.rejects(() => prove(f, { method: 'PUT', url: `/api/memos/item?id=${randomUUID()}`,
    headers: {}, body: Buffer.from('{}') }), { code: 'DEVICE_SIGNATURE_REQUIRED' });
});

test('a static memo PUT nonce cannot be reused', async () => {
  const f = fixture();
  const { req } = await signedRequest(f, { method: 'PUT', url: `/api/memos/item?id=${randomUUID()}` });
  await prove(f, req);
  await assert.rejects(() => prove(f, req), { code: 'DEVICE_NONCE_REUSED' });
});

test('normal signed collection GET, POST and static item DELETE remain authorized', async () => {
  for (const settings of [
    { method: 'GET', url: '/api/memos', body: '' },
    { method: 'POST', url: '/api/memos' },
    { method: 'DELETE', url: `/api/memos/item?id=${randomUUID()}`, body: '' },
  ]) {
    const f = fixture();
    const { req } = await signedRequest(f, settings);
    assert.deepEqual(await prove(f, req), { deviceId: f.device.id, credentialId: f.device.credentialId });
  }
});

for (const [name, mutate] of [
  ['path', req => { req.url = '/api/memos/changed?order=a%20b'; }],
  ['query', req => { req.url = '/api/memos?order=changed'; }],
  ['method', req => { req.method = 'DELETE'; }],
  ['raw body bytes', req => { req[RAW_BODY][0] ^= 1; }],
]) {
  test(`${name} changed during verification is rechecked before consumption`, async () => {
    const f = fixture();
    const { req, nonceId } = await signedRequest(f);
    const action = f.store.action.bind(f.store);
    f.store.action = async (name, payload) => {
      const result = await action(name, payload);
      if (name === 'get_credential') mutate(req);
      return result;
    };
    await assert.rejects(() => prove(f, req), { code: 'DEVICE_REQUEST_MISMATCH' });
    assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
    assert.ok(!f.store.calls.includes('consume'));
  });

  test(`${name} changed while consuming is rejected before the protected handler`, async () => {
    const f = fixture();
    const { req, nonceId } = await signedRequest(f);
    const action = f.store.action.bind(f.store);
    f.store.action = async (name, payload) => {
      const result = await action(name, payload);
      if (name === 'consume') mutate(req);
      return result;
    };
    await assert.rejects(() => prove(f, req), { code: 'DEVICE_REQUEST_MISMATCH' });
    assert.ok(f.store.challenges.get(nonceId).consumedAt);
    assert.equal(f.store.calls.filter(name => name === 'consume').length, 1);
  });
}

test('derived compatibility body may change while the original signed bytes remain intact', async () => {
  const f = fixture();
  const { req } = await signedRequest(f);
  const action = f.store.action.bind(f.store);
  f.store.action = async (name, payload) => {
    const result = await action(name, payload);
    if (name === 'get_credential') req.body = { compatibility: 'derived options' };
    return result;
  };
  assert.deepEqual(await prove(f, req), { deviceId: f.device.id, credentialId: f.device.credentialId });
  assert.deepEqual(req.body, { compatibility: 'derived options' });
});

for (const [name, overrides] of [
  ['another verified user', f => ({ identity: { ...f.identity, userId: randomUUID() } })],
  ['another login session', () => ({ authorization: 'Bearer exercise.other.signature' })],
]) {
  test(`${name} cannot reuse a signed request`, async () => {
    const f = fixture();
    const { req, nonceId } = await signedRequest(f);
    await assert.rejects(() => prove(f, req, overrides(f)), { code: 'DEVICE_REQUEST_MISMATCH' });
    assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
  });
}

test('expired and previously used challenges are rejected', async () => {
  const f = fixture();
  const expired = await signedRequest(f);
  f.store.challenges.get(expired.nonceId).expiresAt = new Date(Date.now() - 1000).toISOString();
  await assert.rejects(() => prove(f, expired.req), { code: 'DEVICE_CHALLENGE_EXPIRED' });
  assert.equal(f.store.challenges.get(expired.nonceId).consumedAt, null);
  const used = await signedRequest(f);
  await prove(f, used.req);
  await assert.rejects(() => prove(f, used.req), { code: 'DEVICE_NONCE_REUSED' });
});

test('concurrent replay has exactly one successful atomic consume in the test store', async () => {
  const f = fixture();
  const { req } = await signedRequest(f);
  const results = await Promise.allSettled([prove(f, req), prove(f, req)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const rejected = results.find(result => result.status === 'rejected');
  assert.equal(rejected.reason.code, 'DEVICE_NONCE_REUSED');
  assert.equal(f.store.devices.get(f.device.id).counter, 1);
});

for (const state of ['pending', 'rejected', 'revoked']) {
  test(`${state} device cannot authorize a protected request`, async () => {
    const f = fixture();
    const { req, nonceId } = await signedRequest(f);
    f.store.devices.get(f.device.id).state = state;
    await assert.rejects(() => prove(f, req), { code: 'DEVICE_NOT_APPROVED' });
    assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
  });
}

test('unregistered credentials cannot authorize a protected request', async () => {
  const f = fixture();
  const { req } = await signedRequest(f);
  f.store.devices.clear();
  await assert.rejects(() => prove(f, req), { code: 'DEVICE_REGISTRATION_REQUIRED' });
});

test('approval is rechecked in atomic consumption after cryptographic verification', async () => {
  const f = fixture();
  const { req, nonceId } = await signedRequest(f);
  f.store.beforeConsume = () => { f.store.devices.get(f.device.id).state = 'revoked'; };
  await assert.rejects(() => prove(f, req), { code: 'DEVICE_NOT_APPROVED' });
  assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
});

for (const [name, assertion] of [
  ['wrong origin', { origin: 'https://another-origin.vercel.app' }],
  ['wrong challenge', { challenge: randomBytes(32).toString('base64url') }],
  ['missing user verification', { uv: false }],
  ['missing user presence', { up: false }],
  ['wrong relying-party ID', { rpID: 'another-origin.vercel.app' }],
  ['wrong ceremony type', { type: 'webauthn.create' }],
  ['synced credential flag', { multiDevice: true }],
  ['backed up credential flag', { multiDevice: true, backedUp: true }],
  ['invalid backup flags', { multiDevice: false, backedUp: true }],
]) {
  test(`${name} in an actual signed assertion is rejected`, async () => {
    const f = fixture();
    const { req, nonceId } = await signedRequest(f, { assertion });
    await assert.rejects(() => prove(f, req), { code: 'DEVICE_SIGNATURE_INVALID' });
    assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
    assert.ok(!f.store.calls.includes('consume'));
  });
}

test('a valid signature by a different private key is rejected', async () => {
  const f = fixture();
  const { req, nonceId } = await signedRequest(f);
  const other = createAuthenticator(rpID, config.publicAppUrl);
  f.store.devices.get(f.device.id).publicKey = other.credential.publicKey;
  await assert.rejects(() => prove(f, req), { code: 'DEVICE_SIGNATURE_INVALID' });
  assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
});

test('counter rollback is rejected and never consumes the request nonce', async () => {
  const f = fixture();
  const { req, nonceId } = await signedRequest(f, { assertion: { counter: 4 } });
  f.store.devices.get(f.device.id).counter = 5;
  await assert.rejects(() => prove(f, req), { code: 'DEVICE_SIGNATURE_INVALID' });
  assert.equal(f.store.challenges.get(nonceId).consumedAt, null);
});

test('counterless authenticators still require distinct nonces', async () => {
  const f = fixture();
  const first = await signedRequest(f, { assertion: { counter: 0 } });
  await prove(f, first.req);
  await assert.rejects(() => prove(f, first.req), { code: 'DEVICE_NONCE_REUSED' });
  await prove(f, (await signedRequest(f, { assertion: { counter: 0 } })).req);
  assert.equal(f.store.devices.get(f.device.id).counter, 0);
});

test('an unavailable store fails closed instead of enabling an environment bypass', async () => {
  const f = fixture();
  const { req } = await signedRequest(f);
  await assert.rejects(() => prove(f, req, { store: {} }), { status: 503, code: 'DEVICE_STORE_UNAVAILABLE' });
});

test('a parsed body object cannot be reserialized as signed raw bytes', async () => {
  await assert.rejects(() => readVerifiedRequest({ method: 'POST', headers: {}, body: { title: 'fixture' } }),
    { status: 503, code: 'RAW_BODY_UNAVAILABLE' });
});

test('Vercel replayed data/end preserves bytes even when readableEnded is already true', async () => {
  const bytes = Buffer.from('{ "title" : "fictional" }');
  const replay = new EventEmitter();
  const req = { method: 'POST', headers: {}, readableEnded: true,
    get body() { throw new Error('The body getter must not be evaluated'); },
    on(name, listener) {
      replay.on(name, listener);
      if (name === 'end') queueMicrotask(() => { replay.emit('data', bytes); replay.emit('end'); });
      return req;
    } };
  assert.deepEqual(await readVerifiedRequest(req), bytes);
  assert.equal(req.body, bytes.toString('utf8'));
  req.body = { compatibility: 'derived body' };
  assert.deepEqual(await readVerifiedRequest(req), bytes);
  assert.deepEqual(req.body, { compatibility: 'derived body' });
  assert.deepEqual({ ...req }[RAW_BODY], bytes);
});

test('GET bodies with framing headers are rejected rather than left unsigned', async () => {
  for (const headers of [{ 'content-length': '3' }, { 'transfer-encoding': 'chunked' }]) {
    await assert.rejects(() => readVerifiedRequest({ method: 'GET', headers }),
      { code: 'DEVICE_BODY_NOT_ALLOWED' });
  }
});

test('device API parses JSON once and retains original request text', async () => {
  const f = fixture();
  const handler = createDeviceHandler({ config, verifyLogin: async () => f.identity, store: f.store });
  for (const raw of ['null', '{broken', 'false', '[]', '""', '"{\\"action\\":\\"registration-options\\"}"']) {
    const req = { method: 'POST', url: '/api/devices', body: Buffer.from(raw),
      headers: { authorization, origin: config.publicAppUrl } };
    const res = responseObject();
    await handler(req, res);
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'DEVICE_INVALID_REQUEST');
    assert.equal(req.body, raw);
  }
  assert.deepEqual(f.store.calls, []);
  const raw = '{ "action" : "registration-options" }';
  const req = { method: 'POST', url: '/api/devices', body: Buffer.from(raw),
    headers: { authorization, origin: config.publicAppUrl } };
  const res = responseObject();
  await handler(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(req.body, raw);
});

test('registration options and actual WebAuthn verification create a pending device only', async () => {
  const f = fixture();
  f.store.devices.clear();
  const handler = createDeviceHandler({ config, verifyLogin: async () => f.identity, store: f.store });
  const options = await api(handler, { action: 'registration-options' });
  assert.equal(options.statusCode, 200);
  assert.equal(options.body.options.authenticatorSelection.userVerification, 'required');
  assert.equal(options.body.options.timeout, 90000);
  const registration = f.authenticator.responseRegistration(options.body.options);
  const verified = await api(handler, { action: 'registration-verify', nonceId: options.body.nonceId, response: registration });
  assert.equal(verified.statusCode, 201);
  assert.equal(verified.body.device.state, 'pending');
  assert.equal(verified.body.device.fingerprint, f.authenticator.credential.publicKeySha256);
  assert.deepEqual(Object.keys(verified.body.device).sort(), ['id', 'credentialId', 'state', 'fingerprint', 'createdAt'].sort());
  const list = await api(handler, undefined, { method: 'GET' });
  assert.deepEqual(list.body.devices, [verified.body.device]);
  const request = await api(handler, { action: 'request-options', credentialId: registration.id,
    method: 'GET', path: '/api/memos', query: '', bodySha256: hash('') });
  assert.equal(request.statusCode, 403);
  assert.equal(request.body.error, 'DEVICE_NOT_APPROVED');
  const decision = await api(handler, { action: 'decision', targetDeviceId: verified.body.device.id,
    decision: 'approved', reason: 'fictional approval exercise' });
  assert.equal(decision.statusCode, 403);
  assert.equal(decision.body.error, 'DEVICE_SIGNATURE_REQUIRED');
  assert.equal([...f.store.devices.values()][0].state, 'pending');
});

for (const [name, overrides, expected] of [
  ['origin mismatch', { origin: 'https://another-origin.vercel.app' }, 'DEVICE_REGISTRATION_INVALID'],
  ['UV missing', { uv: false }, 'DEVICE_REGISTRATION_INVALID'],
  ['backup eligibility', { multiDevice: true }, 'DEVICE_REGISTRATION_UNSUPPORTED'],
  ['cloud backup', { multiDevice: true, backedUp: true }, 'DEVICE_REGISTRATION_UNSUPPORTED'],
]) {
  test(`registration rejects ${name} without consuming the challenge`, async () => {
    const f = fixture();
    f.store.devices.clear();
    const handler = createDeviceHandler({ config, verifyLogin: async () => f.identity, store: f.store });
    const options = await api(handler, { action: 'registration-options' });
    const response = f.authenticator.responseRegistration(options.body.options, overrides);
    const result = await api(handler, { action: 'registration-verify', nonceId: options.body.nonceId, response });
    assert.equal(result.statusCode, 403);
    assert.equal(result.body.error, expected);
    assert.equal(f.store.challenges.get(options.body.nonceId).consumedAt, null);
    assert.equal(f.store.devices.size, 0);
  });
}

test('same-origin checks use fixed configuration and reject cross-origin device writes', async () => {
  const f = fixture();
  const handler = createDeviceHandler({ config, verifyLogin: async () => f.identity, store: f.store });
  const result = await api(handler, { action: 'registration-options' }, { origin: 'https://another-origin.vercel.app' });
  assert.equal(result.statusCode, 403);
  assert.equal(result.body.error, 'ORIGIN_REJECTED');
  assert.deepEqual(f.store.calls, []);
});

test('approved device proof can approve another pending device but not itself', async () => {
  const f = fixture();
  const target = f.store.addDevice(createAuthenticator(rpID, config.publicAppUrl).credential, 'pending');
  const handler = createDeviceHandler({ config, verifyLogin: async () => f.identity, store: f.store });
  const payload = { action: 'decision', targetDeviceId: target.id, decision: 'approved', reason: 'fictional approval exercise' };
  const signed = await signedRequest(f, { url: '/api/devices', body: JSON.stringify(payload) });
  const result = await api(handler, payload, { proof: signed.req.headers['x-byteback-proof'] });
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.device.state, 'approved');
  const self = { ...payload, targetDeviceId: f.device.id };
  const selfSigned = await signedRequest(f, { url: '/api/devices', body: JSON.stringify(self) });
  const denied = await api(handler, self, { proof: selfSigned.req.headers['x-byteback-proof'] });
  assert.equal(denied.statusCode, 403);
  assert.equal(denied.body.error, 'DEVICE_SELF_APPROVAL_FORBIDDEN');
});

test('an uppercase target UUID succeeds after PostgreSQL-style canonicalization', async () => {
  const f = fixture();
  const target = f.store.addDevice(createAuthenticator(rpID, config.publicAppUrl).credential, 'pending');
  const action = f.store.action.bind(f.store);
  let submittedTarget;
  f.store.action = async (name, payload = {}) => {
    if (name !== 'decision') return action(name, payload);
    submittedTarget = payload.targetDeviceId;
    // PostgreSQL uuid input accepts either case and returns its lowercase form.
    return action(name, { ...payload, targetDeviceId: payload.targetDeviceId.toLowerCase() });
  };
  const handler = createDeviceHandler({ config, verifyLogin: async () => f.identity, store: f.store });
  const payload = { action: 'decision', targetDeviceId: target.id.toUpperCase(),
    decision: 'approved', reason: 'fictional uppercase UUID approval' };
  const signed = await signedRequest(f, { url: '/api/devices', body: JSON.stringify(payload) });
  const result = await api(handler, payload, { proof: signed.req.headers['x-byteback-proof'] });
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.device.id, target.id);
  assert.equal(result.body.device.state, 'approved');
  assert.equal(submittedTarget, target.id);
  assert.equal(f.store.devices.get(target.id).state, 'approved');
  assert.ok(f.store.challenges.get(signed.nonceId).consumedAt);
});

test('a signature cannot be transplanted to a different decision body', async () => {
  const f = fixture();
  const target = f.store.addDevice(createAuthenticator(rpID, config.publicAppUrl).credential, 'pending');
  const handler = createDeviceHandler({ config, verifyLogin: async () => f.identity, store: f.store });
  const payload = { action: 'decision', targetDeviceId: target.id, decision: 'approved', reason: 'fictional approval exercise' };
  const signed = await signedRequest(f, { url: '/api/devices', body: JSON.stringify(payload) });
  const result = await api(handler, { ...payload, decision: 'rejected' }, { proof: signed.req.headers['x-byteback-proof'] });
  assert.equal(result.statusCode, 403);
  assert.equal(result.body.error, 'DEVICE_REQUEST_MISMATCH');
  assert.equal(f.store.devices.get(target.id).state, 'pending');
  assert.equal(f.store.challenges.get(signed.nonceId).consumedAt, null);
});

test('session storage binding is the token digest and never the token itself', () => {
  assert.equal(sessionHash(authorization), hash('exercise.session.signature'));
  assert.notEqual(sessionHash(authorization), authorization);
});
