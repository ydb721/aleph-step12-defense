// Isolated integration harness. Run only against the dedicated verification DB.
// No real database credentials, JWTs, authenticator private keys or memo values
// are written to the result. SQL is transported by a local MCP bridge queue.
// Usage: node --experimental-vm-modules scripts/test-device-http-db.mjs --bridge-dir <directory>
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { PassThrough } from 'node:stream';
import { createContext, SourceTextModule, SyntheticModule } from 'node:vm';
import { setTimeout as delay } from 'node:timers/promises';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createDeviceHandler } from '../api/devices.js';
import { createDeviceStore, requestAuthorization, sessionHash } from '../src/device-auth.mjs';
import { guardDeviceRequest } from '../src/device-gate.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createAuthenticator, proofHeader } from '../test/helpers/device-fixture.mjs';

const flag = process.argv.indexOf('--bridge-dir');
if (flag < 0 || !process.argv[flag + 1]) throw new Error('BRIDGE_DIRECTORY_REQUIRED');
if (typeof SourceTextModule !== 'function') throw new Error('EXPERIMENTAL_VM_MODULES_REQUIRED');
const bridgeDirectory = resolve(process.argv[flag + 1]);
await mkdir(bridgeDirectory, { recursive: true });
const resultFile = resolve(bridgeDirectory, 'result.json');
const progressFile = resolve(bridgeDirectory, 'progress.json');
const q = value => "'" + String(value).replaceAll("'", "''") + "'";
const hash = value => createHash('sha256').update(value).digest('hex');
const config = {
  publicAppUrl: 'https://fixture.vercel.app',
  judgeIssuer: 'https://judge-fixture.aleph.tools/defense/judge',
  identityProvider: { issuer: 'https://fixture.supabase.co/auth/v1', audience: 'authenticated',
    jwksUrl: 'https://fixture.supabase.co/auth/v1/.well-known/jwks.json' },
};
const limitations = [
  'Dedicated verification database only; no production or judge evaluation.',
  'Node HTTP and a Vercel body-replay simulation; no deployed Vercel runtime.',
  'PostgREST transport is a SQL adapter; no live Supabase Auth or PostgREST service.',
  'Ephemeral software authenticator exercises real WebAuthn cryptography, not hardware interaction.',
];
const records = [];
const httpRequests = [];
const useStdioBridge = process.argv.includes('--bridge-stdio');
const pendingReplies = new Map();
let protocolSequence = 0;
function writeProtocol(value, callback) {
  // Short ASCII frames survive Windows console soft wrapping without changing SQL.
  const encoded = Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
  const count = Math.ceil(encoded.length / 48);
  const id = ++protocolSequence;
  const frames = Array.from({ length: count }, (_, index) =>
    `BB11|${id}|${index}|${count}|${encoded.slice(index * 48, (index + 1) * 48)}!\n`);
  process.stdout.write(frames.join(''), callback);
}
// Keep protocol replies from being echoed by an interactive verification PTY.
if (useStdioBridge && process.stdin.isTTY) process.stdin.setRawMode(true);
const stdioInterface = useStdioBridge
  ? createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false }) : null;
function bridgeRows(response) {
  if (response.error) {
    const encoded = typeof response.error === 'string' ? response.error : JSON.stringify(response.error);
    const safeCode = /\bDEVICE_[A-Z_]+\b/u.exec(encoded)?.[0];
    throw Object.assign(new Error(safeCode ?? 'FIXTURE_SQL_REJECTED'), { code: safeCode });
  }
  if (!Array.isArray(response.rows)) throw new Error('INVALID_BRIDGE_RESPONSE');
  return response.rows;
}
stdioInterface?.on('line', line => {
  let reply;
  try { reply = JSON.parse(line)?.bridgeReply; } catch { return; }
  if (!reply || typeof reply.id !== 'string') return;
  const pending = pendingReplies.get(reply.id);
  if (!pending) return;
  pendingReplies.delete(reply.id);
  clearTimeout(pending.timer);
  try { pending.resolve(bridgeRows(reply)); } catch (error) { pending.reject(error); }
});
function rejectStdioPending() {
  for (const pending of pendingReplies.values()) {
    clearTimeout(pending.timer);
    pending.reject(new Error('STDIO_BRIDGE_CLOSED'));
  }
  pendingReplies.clear();
}
stdioInterface?.on('close', rejectStdioPending);
stdioInterface?.on('error', rejectStdioPending);
let sequence = 0;
let phase = 'setup';
let httpServer;
let baseUrl;
const nativeFetch = globalThis.fetch;
const previousEnvironment = { SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SECRET_KEY: process.env.SUPABASE_SECRET_KEY };

async function sql(statement) {
  const id = String(++sequence).padStart(5, '0') + '-' + randomUUID();
  if (useStdioBridge) {
    return new Promise((resolveReply, rejectReply) => {
      const timer = setTimeout(() => {
        pendingReplies.delete(id);
        rejectReply(new Error('SQL_BRIDGE_TIMEOUT'));
      }, 120000);
      pendingReplies.set(id, { resolve: resolveReply, reject: rejectReply, timer });
      writeProtocol({ bridgeRequest: { id, sql: statement } }, error => {
        if (!error) return;
        const pending = pendingReplies.get(id);
        if (!pending) return;
        pendingReplies.delete(id);
        clearTimeout(timer);
        pending.reject(new Error('STDIO_BRIDGE_WRITE_FAILED'));
      });
    });
  }
  const requestFile = resolve(bridgeDirectory, id + '.request.json');
  const temporaryFile = requestFile + '.tmp';
  await writeFile(temporaryFile, JSON.stringify({ sql: statement }), { flag: 'wx' });
  await rename(temporaryFile, requestFile);
  const responseFile = resolve(bridgeDirectory, id + '.response.json');
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    try {
      const response = JSON.parse(await readFile(responseFile, 'utf8'));
      return bridgeRows(response);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    await delay(50);
  }
  throw new Error('SQL_BRIDGE_TIMEOUT');
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
}

async function fixtureTransport(input, init = {}) {
  const url = new URL(input);
  if (url.origin !== 'https://fixture.supabase.co') throw new Error('EXTERNAL_FIXTURE_DESTINATION_REJECTED');
  const method = init.method ?? 'GET';
  const payload = init.body === undefined ? null : JSON.parse(init.body);
  if (url.pathname === '/rest/v1/rpc/byteback_device_action') {
    try {
      const rows = await sql(`with api_role as materialized
        (select set_config('role','service_role',true))
        select public.byteback_device_action(${q(payload.p_action)},
        ${q(payload.p_user)}::uuid,${q(payload.p_session_hash)},${q(JSON.stringify(payload.p_payload))}::jsonb) as result from api_role`);
      return jsonResponse(rows[0].result);
    } catch (error) {
      return jsonResponse({ code: 'P0001', message: error.code ?? 'FIXTURE_SQL_ADAPTER_ERROR' }, error.code ? 400 : 503);
    }
  }
  if (url.pathname !== '/rest/v1/memos') return jsonResponse({ error: 'UNKNOWN_FIXTURE_ENDPOINT' }, 503);
  const filters = [];
  for (const field of ['public_id', 'owner_id']) {
    const value = url.searchParams.get(field);
    if (value !== null) {
      if (!/^eq\.[0-9a-f-]{36}$/iu.test(value)) throw new Error('INVALID_FIXTURE_FILTER');
      filters.push(`${field}=${q(value.slice(3))}::uuid`);
    }
  }
  const where = filters.length ? ' where ' + filters.join(' and ') : '';
  const select = url.searchParams.get('select') ?? 'public_id,title,content,owner_id';
  if (!/^[a-z_,]+$/u.test(select)) throw new Error('INVALID_FIXTURE_SELECT');
  let statement;
  if (method === 'GET') {
    statement = `select ${select} from public.s11_http_memos${where} order by created_at,public_id`;
  } else if (method === 'PATCH') {
    const changes = Object.entries(payload).map(([key, value]) => {
      if (!['title', 'content'].includes(key) || typeof value !== 'string') throw new Error('INVALID_FIXTURE_UPDATE');
      return `${key}=${q(value)}`;
    });
    statement = `update public.s11_http_memos set ${changes.join(',')}${where} returning ${select}`;
  } else if (method === 'POST') {
    statement = `insert into public.s11_http_memos(public_id,owner_id,title,content) values
      (${q(payload.public_id)}::uuid,${q(payload.owner_id)}::uuid,${q(payload.title)},${q(payload.content)}) returning ${select}`;
  } else if (method === 'DELETE') {
    statement = `delete from public.s11_http_memos${where} returning ${select}`;
  } else throw new Error('INVALID_FIXTURE_METHOD');
  return jsonResponse(await sql(statement));
}

async function memoModule(verify, entry = 'api/memos.js') {
  const context = createContext({ process: { env: process.env }, URL, Buffer,
    console: { info() {}, error() {} }, fetch: fixtureTransport });
  const cache = new Map();
  async function load(path) {
    if (cache.has(path)) return cache.get(path);
    let module;
    if (path === 'node:module') {
      module = new SyntheticModule(['createRequire'], function () {
        this.setExport('createRequire', () => () => config);
      }, { context });
    } else if (path === 'node:crypto') {
      module = new SyntheticModule(['createHash', 'randomUUID'], function () {
        this.setExport('createHash', createHash); this.setExport('randomUUID', randomUUID);
      }, { context });
    } else if (path === resolve('src/verify-login.mjs')) {
      module = new SyntheticModule(['createLoginVerifier'], function () {
        this.setExport('createLoginVerifier', () => verify);
      }, { context });
    } else if (path === resolve('src/device-gate.mjs')) {
      module = new SyntheticModule(['guardDeviceRequest'], function () {
        this.setExport('guardDeviceRequest', guardDeviceRequest);
      }, { context });
    } else {
      module = new SourceTextModule(await readFile(path, 'utf8'), { context, identifier: path });
    }
    cache.set(path, module);
    await module.link((specifier, parent) => load(specifier.startsWith('node:')
      ? specifier : resolve(dirname(parent.identifier), specifier)));
    return module;
  }
  const module = await load(resolve(entry));
  await module.evaluate();
  return entry === 'api/memos.js' ? module.namespace.handleMemos : module.namespace.default;
}

async function prepareVercelBody(req) {
  if (req.headers['content-type'] === undefined) return;
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks);
  const replay = new PassThrough();
  const originalOn = req.on.bind(req);
  req.read = replay.read.bind(replay);
  req.on = req.addListener = (name, callback) => name === 'data' || name === 'end'
    ? replay.on(name, callback) : originalOn(name, callback);
  replay.end(raw);
  Object.defineProperty(req, 'body', { configurable: true, enumerable: true,
    get() { return raw.length ? JSON.parse(raw.toString('utf8')) : {}; } });
}

async function http(path, { method = 'GET', body, token, proof, origin = config.publicAppUrl } = {}) {
  const started = performance.now();
  const response = await nativeFetch(baseUrl + path, {
    method, headers: { ...(token ? { authorization: 'Bearer ' + token } : {}),
      ...(origin ? { origin } : {}), ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(proof ? { 'x-byteback-proof': proof } : {}) },
    ...(body === undefined ? {} : { body }), redirect: 'error',
  });
  const result = { status: response.status, data: await response.json().catch(() => null),
    durationMs: Math.round((performance.now() - started) * 100) / 100 };
  const pathname = new URL(path, config.publicAppUrl).pathname;
  const pathTemplate = pathname === '/api/devices' ? '/api/devices'
    : pathname === '/api/memos' ? '/api/memos'
      : pathname === '/api/memos/item' ? '/api/memos/item' : '/api/memos/:id';
  httpRequests.push({ method, path: pathTemplate, status: result.status, durationMs: result.durationMs,
    ...(typeof result.data?.error === 'string' && /^[A-Z0-9_]+$/u.test(result.data.error)
      ? { errorCode: result.data.error } : {}) });
  return result;
}

async function main() {
  process.env.SUPABASE_URL = 'https://fixture.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'test-only-placeholder';
  globalThis.fetch = fixtureTransport;
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const keys = createLocalJWKSet({ keys: [{ ...await exportJWK(publicKey), kid: 'isolated-http-test' }] });
  const verify = createLoginVerifier({ config, judgeKeySet: keys,
    supabaseClient: { auth: { async getClaims() { throw new Error('UNEXPECTED_STUDENT_AUTH'); } } } });
  async function tokenFor(subject, label = 'a') {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ iss: config.judgeIssuer, aud: new URL(config.publicAppUrl).hostname,
      sub: subject, aleph_role: 'judge', aleph_identity: label, aleph_run: randomUUID(),
      iat: now, exp: now + 900 }).setProtectedHeader({ alg: 'ES256', kid: 'isolated-http-test' }).sign(privateKey);
  }
  const ownerA = randomUUID();
  const ownerB = randomUUID();
  const tokenA = await tokenFor(ownerA);
  const tokenB = await tokenFor(ownerB, 'b');
  const tokenA2 = await tokenFor(ownerA);
  const noteA = randomUUID();
  const noteA2 = randomUUID();
  const noteB = randomUUID();
  const noteIds = [noteA, noteA2, noteB];
  await sql(`do $fixture_setup$ begin
    create table if not exists public.s11_http_memos (
    public_id uuid primary key, owner_id uuid not null, title text not null,
    content text not null, created_at timestamptz not null default now());
    insert into public.s11_http_memos(public_id,owner_id,title,content) values
    (${q(noteA)}::uuid,${q(ownerA)}::uuid,'Fictional A','Initial fictional memo'),
    (${q(noteA2)}::uuid,${q(ownerA)}::uuid,'Fictional A second','Second fictional memo'),
    (${q(noteB)}::uuid,${q(ownerB)}::uuid,'Fictional B','Other fictional memo');
    end $fixture_setup$;`);
  async function snapshot() {
    const rows = await sql(`select encode(extensions.digest(coalesce(string_agg(
      public_id::text||':'||owner_id::text||':'||title||':'||content,'|' order by public_id),''),
      'sha256'),'hex') as digest,count(*)::int as row_count from public.s11_http_memos
      where public_id in (${noteIds.map(value => q(value) + '::uuid').join(',')})`);
    return { digest: rows[0].digest, rowCount: rows[0].row_count };
  }
  const devicesHandler = createDeviceHandler({ config, verifyLogin: verify });
  const memosHandler = await memoModule(verify);
  const memoItemHandler = await memoModule(verify, 'api/memos/item.js');
  httpServer = createServer(async (req, res) => {
    res.status = function (code) { this.statusCode = code; return this; };
    res.json = function (body) { this.setHeader('content-type', 'application/json'); this.end(JSON.stringify(body)); return this; };
    try {
      await prepareVercelBody(req);
      const pathname = new URL(req.url, 'http://localhost').pathname;
      if (pathname === '/api/devices') return await devicesHandler(req, res);
      if (pathname === '/api/memos') return await memosHandler(req, res);
      if (pathname === '/api/memos/item') return await memoItemHandler(req, res);
      if (/^\/api\/memos\/[0-9a-f-]{36}$/iu.test(pathname)) return await memosHandler(req, res, pathname.split('/').at(-1));
      return res.status(404).json({ error: 'FIXTURE_ROUTE_NOT_FOUND' });
    } catch { if (!res.writableEnded) res.status(500).json({ error: 'FIXTURE_SERVER_ERROR' }); }
  });
  await new Promise(resolveReady => httpServer.listen(0, '127.0.0.1', resolveReady));
  baseUrl = 'http://127.0.0.1:' + httpServer.address().port;
  async function register(token, owner, approve) {
    const authenticator = createAuthenticator(new URL(config.publicAppUrl).hostname, config.publicAppUrl);
    const options = await http('/api/devices', { method: 'POST', token,
      body: JSON.stringify({ action: 'registration-options' }) });
    assert.equal(options.status, 200);
    const response = authenticator.responseRegistration(options.data.options);
    const registered = await http('/api/devices', { method: 'POST', token,
      body: JSON.stringify({ action: 'registration-verify', nonceId: options.data.nonceId, response }) });
    assert.equal(registered.status, 201);
    assert.equal(registered.data.device.state, 'pending');
    assert.deepEqual(Object.keys(registered.data.device).sort(), ['id', 'credentialId', 'state', 'fingerprint', 'createdAt'].sort());
    if (approve) {
      await sql(`select byteback_devices.operator_decide(${q(owner)}::uuid,
        ${q(registered.data.device.id)}::uuid,${q(registered.data.device.fingerprint)},
        'approved','Isolated HTTP verification approval') as result`);
    }
    return { authenticator, device: registered.data.device, token, owner };
  }
  async function signRequest(actor, settings = {}) {
    const { method = 'PUT', path = '/api/memos/item?id=' + noteA, assertion = {} } = settings;
    const body = Object.hasOwn(settings, 'body') ? settings.body
      : JSON.stringify({ body: 'Fictional authorized update' });
    const url = new URL(path, config.publicAppUrl);
    const options = await http('/api/devices', { method: 'POST', token: actor.token,
      body: JSON.stringify({ action: 'request-options', credentialId: actor.device.credentialId,
        method, path: url.pathname, query: url.search, bodySha256: hash(body ?? '') }) });
    assert.equal(options.status, 200);
    const response = actor.authenticator.responseAuthentication(options.data.options, assertion);
    return { nonceId: options.data.nonceId, method, path, body,
      proof: proofHeader(options.data.nonceId, response), token: actor.token };
  }
  async function sendSigned(request, patch = {}) {
    return http(patch.path ?? request.path, { method: request.method, body: request.body,
      proof: request.proof, token: request.token, ...patch });
  }
  async function run(name, operation, expected, changed = false) {
    phase = name;
    const before = await snapshot();
    const response = await operation();
    const after = await snapshot();
    const observed = Array.isArray(response) ? response : [response];
    const statuses = observed.map(value => value.status);
    const wanted = Array.isArray(expected) ? [...expected].sort() : [expected];
    const pass = JSON.stringify([...statuses].sort()) === JSON.stringify(wanted)
      && (before.digest !== after.digest) === changed;
    const record = { name, http: observed.map(value => ({ status: value.status,
      durationMs: value.durationMs,
      ...(typeof value.data?.error === 'string' && /^[A-Z0-9_]+$/u.test(value.data.error)
        ? { errorCode: value.data.error } : {}) })), db: { before, after }, pass };
    records.push(record);
    await writeFile(progressFile, JSON.stringify({ phase, completed: records.length, pass: records.every(value => value.pass) }));
    assert.ok(pass, 'HTTP_DB_CASE_FAILED');
    return response;
  }
  phase = 'register-approved-and-pending-devices';
  const actorA = await register(tokenA, ownerA, true);
  const actorB = await register(tokenB, ownerB, true);
  const pending = await register(tokenA, ownerA, false);
  await run('missing-device-signature', () => http('/api/memos/item?id=' + noteA,
    { method: 'PUT', token: tokenA, body: JSON.stringify({ body: 'Fictional rejected update' }) }), 403);
  const signatureWithoutJwt = await signRequest(actorA);
  // The transport is localhost HTTP, while WebAuthn uses the fixture HTTPS RP.
  // A non-browser request without Origin reaches the existing JWT gate; a
  // mismatching Origin would correctly be rejected by the earlier CSRF gate.
  await run('missing-jwt', () => sendSigned(signatureWithoutJwt, { token: undefined, origin: null }), 401);
  const pathAttack = await signRequest(actorA);
  await run('path-transplant', () => sendSigned(pathAttack, { path: '/api/memos/item?id=' + noteA2 }), 403);
  const bodyAttack = await signRequest(actorA);
  await run('body-transplant', () => sendSigned(bodyAttack,
    { body: JSON.stringify({ body: 'Different fictional rejected update' }) }), 403);
  const queryAttack = await signRequest(actorA, { path: '/api/memos/item?id=' + noteA + '&q=a%20b' });
  await run('raw-query-transplant', () => sendSigned(queryAttack,
    { path: '/api/memos/item?id=' + noteA + '&q=a+b' }), 403);
  const methodAttack = await signRequest(actorA);
  await run('method-transplant', () => sendSigned(methodAttack, { method: 'DELETE', body: undefined }), 403);
  const legitimate = await signRequest(actorA);
  await run('authorized-put', () => sendSigned(legitimate), 200, true);
  const read = await signRequest(actorA, { method: 'GET', body: undefined });
  const readResult = await run('authorized-reread', () => sendSigned(read), 200);
  assert.equal(readResult.data.body, 'Fictional authorized update');
  if (process.argv.includes('--focus-core')) {
    phase = 'complete';
    return { status: 'passed', cases: records.length, records, httpRequests, limitations,
      scope: 'core-after-raw-body-fix' };
  }
  await run('nonce-replay', () => sendSigned(legitimate), 403);
  const foreign = await signRequest(actorB);
  await run('foreign-owner', () => sendSigned(foreign), 404);
  const userAttack = await signRequest(actorA);
  await run('another-verified-user', () => sendSigned(userAttack, { token: tokenB }), 403);
  const sessionAttack = await signRequest(actorA);
  await run('another-verified-session', () => sendSigned(sessionAttack, { token: tokenA2 }), 403);
  for (const [name, assertion] of [
    ['wrong-webauthn-origin', { origin: 'https://other-origin.vercel.app' }],
    ['wrong-webauthn-challenge', { challenge: randomUUID() }],
    ['missing-user-verification', { uv: false }],
    ['wrong-webauthn-rpid', { rpID: 'other-origin.vercel.app' }],
  ]) {
    const signed = await signRequest(actorA, { assertion });
    await run(name, () => sendSigned(signed), 403);
  }
  const expired = await signRequest(actorA);
  await sql(`update byteback_devices.challenges set expires_at=created_at+interval '1 millisecond'
    where id=${q(expired.nonceId)}::uuid`);
  await run('expired-nonce', () => sendSigned(expired), 403);
  await run('pending-request-options', () => http('/api/devices', { method: 'POST', token: tokenA,
    body: JSON.stringify({ action: 'request-options', credentialId: pending.device.credentialId,
      method: 'GET', path: '/api/memos', query: '', bodySha256: hash('') }) }), 403);
  await run('unsigned-self-approval', () => http('/api/devices', { method: 'POST', token: tokenA,
    body: JSON.stringify({ action: 'decision', targetDeviceId: pending.device.id,
      decision: 'approved', reason: 'Isolated unsigned approval rejection' }) }), 403);
  const concurrent = await signRequest(actorA, { method: 'GET', body: undefined });
  await run('concurrent-nonce-replay', () => Promise.all([sendSigned(concurrent), sendSigned(concurrent)]), [200, 403]);
  const revoked = await signRequest(actorA);
  await sql(`select byteback_devices.operator_decide(${q(ownerA)}::uuid,
    ${q(actorA.device.id)}::uuid,${q(actorA.device.fingerprint)},
    'revoked','Isolated HTTP verification revocation') as result`);
  await run('revoked-device-with-earlier-signature', () => sendSigned(revoked), 403);
  await run('revoked-device-new-options', () => http('/api/devices', { method: 'POST', token: tokenA,
    body: JSON.stringify({ action: 'request-options', credentialId: actorA.device.credentialId,
      method: 'GET', path: '/api/memos', query: '', bodySha256: hash('') }) }), 403);
  // Confirm the production RPC adapter kept only a token digest in its binding.
  const identity = await verify('Bearer ' + tokenB);
  assert.ok(identity && requestAuthorization({ headers: { authorization: 'Bearer ' + tokenB } }));
  const db = createDeviceStore({ identity, authorization: 'Bearer ' + tokenB, config });
  assert.ok(Array.isArray((await db.action('list')).devices));
  assert.equal(sessionHash('Bearer ' + tokenB), hash(tokenB));
  phase = 'complete';
  return { status: 'passed', cases: records.length, records, httpRequests, limitations };
}

let result;
try {
  result = await main();
} catch {
  result = { status: 'failed', phase, cases: records.length, records, httpRequests, limitations,
    error: 'HTTP_DB_VERIFICATION_FAILED' };
  process.exitCode = 1;
} finally {
  if (httpServer) await new Promise(resolveClosed => httpServer.close(resolveClosed));
  stdioInterface?.close();
  if (useStdioBridge && process.stdin.isTTY) process.stdin.setRawMode(false);
  if (useStdioBridge) process.stdin.pause();
  globalThis.fetch = nativeFetch;
  for (const [name, value] of Object.entries(previousEnvironment)) {
    if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
}
await writeFile(resultFile, JSON.stringify(result, null, 2));
const summary = { status: result.status, cases: result.cases,
  ...(result.status === 'failed' ? { phase } : {}), resultFile };
if (useStdioBridge) writeProtocol(summary); else console.log(JSON.stringify(summary));
