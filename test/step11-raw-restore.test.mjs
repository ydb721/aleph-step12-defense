import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { descriptorBinding, requireDeviceProof } from '../src/device-auth.mjs';
import { RAW_BODY } from '../src/device-request.mjs';
import { createAuthenticator, createMemoryDeviceStore, proofHeader } from './helpers/device-fixture.mjs';

// Exercise the production restore parser and its exact validation block after
// real WebAuthn verification. Only login and the nonce database are test fixtures;
// recovery RPC execution is outside this parser compatibility regression.
const source = await readFile(new URL('../api/restore/[id].js', import.meta.url), 'utf8');
const parserStart = source.indexOf('function readBody(req)');
const parserEnd = source.indexOf('\nfunction rpcHeaders', parserStart);
const validationStart = source.indexOf('  const body = bodyOverride === undefined ? readBody(req) : bodyOverride;');
const validationEnd = source.indexOf('\n  try {', validationStart);
assert.ok(parserStart >= 0 && parserEnd > parserStart && validationStart >= 0 && validationEnd > validationStart);
const validateRestore = runInNewContext(`(function(req) {
  ${source.slice(parserStart, parserEnd)}
  const SHA = /^[0-9a-f]{64}$/u;
  const trace = {};
  const traceRequestShape = () => {};
  const res = { status(status) { return { json(body) { return { status, body }; } }; } };
  const bodyOverride = undefined;
  ${source.slice(validationStart, validationEnd)}
  return { status: 200, validationPassed: true };
})`);

const config = { publicAppUrl: 'https://restore-exercise.vercel.app' };
const rpID = new URL(config.publicAppUrl).hostname;
const authorization = 'Bearer restore.fixture.signature';
for (const [name, raw, expected] of [
  ['absent body', '', 200],
  ['empty object', '{}', 200],
  ['spaced empty object', ' { } ', 200],
  ['literal null', 'null', 400],
  ['malformed JSON', '{broken', 400],
  ['whitespace only', '   ', 400],
  ['JSON empty string', '""', 400],
  ['JSON encoded object string', '"{}"', 400],
  ['JSON encoded null string', '"null"', 400],
  ['literal false', 'false', 400],
  ['JSON array', '[]', 400],
]) {
  test(`real device gate preserves restore handling of ${name}`, async () => {
    const identity = { kind: 'student', userId: randomUUID() };
    const authenticator = createAuthenticator(rpID, config.publicAppUrl);
    const store = createMemoryDeviceStore({ identity, authorization });
    const device = store.addDevice(authenticator.credential);
    const bytes = Buffer.from(raw);
    const nonceId = randomUUID();
    const path = '/api/restore/' + randomUUID();
    const binding = descriptorBinding({ method: 'POST', path, query: '',
      bodySha256: createHash('sha256').update(bytes).digest('hex') }, identity, authorization);
    const { challenge } = await store.action('challenge', { id: nonceId, purpose: 'request',
      challenge: randomBytes(32).toString('base64url'), credentialId: device.credentialId, binding });
    const req = { method: 'POST', url: path, body: bytes,
      headers: { 'x-byteback-proof': proofHeader(nonceId, authenticator.responseAuthentication(challenge)) } };
    await requireDeviceProof(req, { identity, authorization, config, store });
    assert.deepEqual(req[RAW_BODY], bytes);
    assert.equal(req.body, raw.length ? raw : undefined);
    const result = validateRestore(req);
    assert.equal(result.status, expected);
    if (expected === 400) assert.equal(result.body.error, 'INVALID_RESTORE_REQUEST');
    else assert.equal(result.validationPassed, true);
  });
}
