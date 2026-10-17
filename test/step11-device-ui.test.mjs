import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';

const ORIGIN = 'https://device-ui.example.test';
const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
const inlineSource = html.match(/<script\s+type="module">([\s\S]*?)<\/script>/u)?.[1];
const deviceSource = await readFile(new URL('../public/device.mjs', import.meta.url), 'utf8');
const MEMO_ID = '11111111-1111-4111-8111-111111111111';
const VERSION = 'a'.repeat(64);
const STATE_VERSION = 'b'.repeat(64);

function eventTarget(initial = {}) {
  const listeners = new Map();
  return {
    ...initial,
    addEventListener(type, callback) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(callback);
    },
    dispatchEvent(event) {
      for (const callback of listeners.get(event.type) ?? []) callback(event);
      return true;
    },
    async emit(type, fields = {}) {
      const event = { type, preventDefault() {}, ...fields };
      await Promise.all([...(listeners.get(type) ?? [])].map(callback => callback(event)));
    },
  };
}

function element(tagName = 'div') {
  const node = eventTarget({ tagName, value: '', hidden: false, disabled: false, children: [] });
  const attributes = new Map();
  let text = '';
  Object.defineProperty(node, 'textContent', {
    get() { return text + node.children.map(child => child.textContent).join(''); },
    set(value) { text = String(value); node.children = []; },
  });
  node.append = (...children) => node.children.push(...children);
  node.replaceChildren = (...children) => { text = ''; node.children = children; };
  node.setAttribute = (name, value) => attributes.set(name, value);
  node.getAttribute = name => attributes.get(name);
  node.reset = () => {};
  node.scrollIntoView = () => {};
  node.requestSubmit = () => node.emit('submit');
  return node;
}

function descendants(node) {
  return node.children.flatMap(child => [child, ...descendants(child)]);
}

function button(node, text) {
  const found = descendants(node).find(child => child.tagName === 'button' && child.textContent === text);
  assert.ok(found, 'expected button: ' + text);
  return found;
}

function publicDevice(id = 'first', state = 'approved') {
  return {
    id, credentialId: 'public-credential-' + id, state,
    fingerprint: 'public-fingerprint-' + id, createdAt: '2026-10-15T00:00:00.000Z',
  };
}

// The real browser modules run in a context with synthetic DOM, HTTP and WebAuthn.
// Node imports, filesystem writers, browser storage and Cache Storage are absent or
// forbidden. Passing these tests does not verify real browser ceremonies or a judge.
async function page({ authenticated = true, devices = [publicDevice()], supported = true,
  initialNotes = [{ id: MEMO_ID, title: 'fixture protected memo', body: '' }] } = {}) {
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/gu)].map(([, id]) => ['#' + id, element()]));
  const get = id => nodes.get('#' + id);
  get('memo-editor').reset = () => { get('memo-title').value = ''; get('memo-body').value = ''; };
  const document = eventTarget({
    visibilityState: 'visible', querySelector: selector => nodes.get(selector), createElement: element,
  });
  let forbiddenAccesses = 0;
  const forbidden = new Proxy({}, {
    get() { ++forbiddenAccesses; throw new Error('persistent storage is forbidden'); },
    set() { ++forbiddenAccesses; throw new Error('persistent storage is forbidden'); },
  });
  Object.defineProperty(document, 'cookie', {
    get() { ++forbiddenAccesses; throw new Error('client cookie access is forbidden'); },
    set() { ++forbiddenAccesses; throw new Error('client cookie writes are forbidden'); },
  });
  const navigator = { onLine: true, userActivation: { isActive: true } };
  const window = eventTarget({
    document, navigator, location: { origin: ORIGIN }, isSecureContext: supported,
    ...(supported ? { PublicKeyCredential: class {} } : {}),
    localStorage: forbidden, sessionStorage: forbidden, indexedDB: forbidden, caches: forbidden,
    showSaveFilePicker() { ++forbiddenAccesses; throw new Error('file writes are forbidden'); },
  });
  const intervals = new Map();
  let timerId = 0;
  const requests = [];
  const assertions = [];
  const registrations = [];
  const notes = initialNotes.map(note => ({ ...note }));
  let serverDevices = devices.map(device => ({ ...device }));
  let nextAssertion;
  let nextResponse;
  let pendingMemo;
  let releaseMemo;
  let memoStarted;
  let pendingDevices;
  let releaseDevices;
  let activePrompts = 0;
  let maxPrompts = 0;
  let nonce = 0;
  let invalidList = false;

  const fetch = async (path, options = {}) => {
    const method = options.method ?? 'GET';
    const input = options.body === undefined ? undefined : JSON.parse(options.body);
    requests.push({ path, method, input, options });
    if (path === '/api/auth') {
      if (method === 'POST') authenticated = input.action === 'login';
      return Response.json({ authenticated, email: 'fixture@example.test' });
    }
    if (path === '/api/devices' && method === 'GET') {
      if (pendingDevices) {
        pendingDevices = false;
        return new Promise(resolve => { releaseDevices = () => resolve(Response.json({ devices: serverDevices })); });
      }
      return Response.json(invalidList ? { devices: [{ id: 'malformed' }] } : { devices: serverDevices });
    }
    if (path === '/api/devices' && input?.action === 'registration-options') {
      return Response.json({ nonceId: 'registration-' + ++nonce, options: { challenge: 'registration-options' } });
    }
    if (path === '/api/devices' && input?.action === 'registration-verify') {
      const device = publicDevice('new', 'pending');
      serverDevices.push(device);
      return Response.json({ device }, { status: 201 });
    }
    if (path === '/api/devices' && input?.action === 'request-options') {
      return Response.json({ nonceId: 'request-' + ++nonce, options: { challenge: 'request-options-' + nonce } });
    }
    const proof = new Headers(options.headers).get('X-Byteback-Proof');
    assert.ok(proof, 'all protected HTTP calls must carry the proof header');
    if (nextResponse) {
      const response = nextResponse;
      nextResponse = undefined;
      return response;
    }
    if (path === '/api/devices' && input?.action === 'decision') {
      const target = serverDevices.find(device => device.id === input.targetDeviceId);
      assert.ok(target);
      target.state = input.decision;
      return Response.json({ device: target });
    }
    if (path.startsWith('/api/memos') && method === 'GET') {
      if (pendingMemo) {
        pendingMemo = false;
        return new Promise(resolve => {
          releaseMemo = () => resolve(Response.json(notes));
          memoStarted?.();
        });
      }
      return Response.json(notes);
    }
    if (new URL(path, ORIGIN).pathname === '/api/memos' && method === 'POST') {
      notes.push({ id: MEMO_ID, title: input.title, body: input.body });
      return Response.json({ id: MEMO_ID }, { status: 201 });
    }
    if (path === '/api/memos/item?id=' + MEMO_ID && method === 'PUT') {
      Object.assign(notes[0], input);
      return Response.json({ id: MEMO_ID });
    }
    if (path === '/api/memos/item?id=' + MEMO_ID && method === 'DELETE') {
      notes.splice(0, 1);
      return new Response(null, { status: 204 });
    }
    if (path === '/api/notices/' + MEMO_ID) {
      return Response.json({ id: MEMO_ID, title: 'virtual protected notice', body: '' });
    }
    if (path === '/api/notices') return Response.json({ error: 'INVALID_NOTICE_ID' }, { status: 400 });
    if (path === '/api/restore/item?id=' + MEMO_ID || path === '/api/restore') {
      return Response.json(input.preview ? {
        id: MEMO_ID, verified: true, version: VERSION, stateVersion: STATE_VERSION,
        changedFields: ['title'], capturedAt: '2026-10-15T00:00:00.000Z',
      } : { id: MEMO_ID, restored: true, verified: true });
    }
    throw new Error('unexpected synthetic HTTP call: ' + method + ' ' + path);
  };
  const context = vm.createContext({
    window, document, navigator, fetch, URL, Headers, Response, TextEncoder, crypto: webcrypto,
    CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options?.detail; } },
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    setInterval(callback, milliseconds) { const id = ++timerId; intervals.set(id, { callback, milliseconds }); return id; },
    clearInterval(id) { intervals.delete(id); },
    localStorage: forbidden, sessionStorage: forbidden, indexedDB: forbidden, caches: forbidden,
  });
  const library = new vm.SyntheticModule(['startRegistration', 'startAuthentication'], function () {
    this.setExport('startRegistration', async options => {
      registrations.push(options);
      return { id: 'virtual-registration', response: {} };
    });
    this.setExport('startAuthentication', async options => {
      assertions.push(options);
      ++activePrompts;
      maxPrompts = Math.max(maxPrompts, activePrompts);
      const operation = nextAssertion;
      nextAssertion = undefined;
      try { return operation ? await operation() : { id: 'virtual-assertion', response: {} }; }
      finally { --activePrompts; }
    });
  }, { context });
  const deviceModule = new vm.SourceTextModule(deviceSource, { context, identifier: 'public/device.mjs' });
  await deviceModule.link(specifier => {
    assert.equal(specifier, '/vendor/simplewebauthn-browser.js');
    return library;
  });
  const application = new vm.SourceTextModule(inlineSource, { context, identifier: 'public/index.html' });
  await application.link(specifier => {
    assert.equal(specifier, '/device.mjs');
    return deviceModule;
  });
  await application.evaluate({ timeout: 1000 });
  const flush = () => new Promise(resolve => setImmediate(resolve));
  return {
    get, document, window, navigator, requests, assertions, registrations, intervals,
    device: deviceModule.namespace, flush,
    storageAccesses: () => forbiddenAccesses, maxPrompts: () => maxPrompts,
    setState(id, state) { serverDevices.find(device => device.id === id).state = state; },
    setMalformedList() { invalidList = true; },
    setNextResponse(response) { nextResponse = response; },
    setNextAssertion(operation) { nextAssertion = operation; },
    deferNextMemo() { pendingMemo = true; return new Promise(resolve => { memoStarted = resolve; }); },
    releaseMemo() { assert.ok(releaseMemo); releaseMemo(); },
    deferNextDevices() { pendingDevices = true; },
    releaseDevices() { assert.ok(releaseDevices); releaseDevices(); },
    async poll() {
      for (const { callback, milliseconds } of intervals.values()) { assert.equal(milliseconds, 30_000); callback(); }
      await flush();
    },
    protectedRequests: () => requests.filter(request => new Headers(request.options.headers).has('X-Byteback-Proof')),
  };
}

test('server approval alone never exposes memos; a user click obtains a fresh assertion and signs the GET', async () => {
  const active = await page();
  assert.equal(active.protectedRequests().length, 0);
  assert.equal(active.get('memo-editor').hidden, true);
  assert.doesNotMatch(active.get('notes').textContent, /fixture protected/u);
  await active.get('device-connect').emit('click');
  assert.equal(active.assertions.length, 1);
  assert.equal(active.protectedRequests().length, 1);
  assert.equal(active.get('memo-editor').hidden, false);
  assert.match(active.get('notes').textContent, /fixture protected memo/u);
  const request = active.protectedRequests()[0];
  const proof = JSON.parse(Buffer.from(new Headers(request.options.headers).get('X-Byteback-Proof'), 'base64url').toString('utf8'));
  assert.match(proof.nonceId, /^request-/u);
  assert.equal(proof.assertion.id, 'virtual-assertion');
  assert.deepEqual(JSON.parse(JSON.stringify(active.assertions[0])), { optionsJSON: { challenge: 'request-options-1' } });
  assert.ok(active.requests.every(request => request.options.cache === 'no-store'));
  assert.ok(active.requests.every(request => request.options.credentials === 'same-origin'));
  assert.equal(active.storageAccesses(), 0);

  for (const state of ['pending', 'rejected', 'revoked']) {
    const denied = await page({ devices: [publicDevice('first', state)] });
    assert.equal(denied.get('device-connect').disabled, true);
    await denied.get('device-connect').emit('click');
    await assert.rejects(denied.device.signedFetch('/api/memos'));
    assert.equal(denied.assertions.length, 0);
    assert.equal(denied.protectedRequests().length, 0);
    assert.equal(denied.storageAccesses(), 0);
  }
});

test('a signed empty memo response visibly confirms successful retrieval and zero results', async () => {
  const active = await page({ initialNotes: [] });
  await active.get('device-connect').emit('click');
  assert.equal(active.assertions.length, 1);
  assert.equal(active.protectedRequests().length, 1);
  assert.equal(active.get('memo-feedback').textContent, '메모 조회 성공 · 0건');
  assert.equal(active.get('notes').textContent, '등록된 가상 메모가 없습니다.');
  assert.equal(active.get('memo-editor').hidden, false);
});

test('request challenge binds the exact method, path, query and UTF-8 body bytes sent to HTTP', async () => {
  const active = await page();
  const body = JSON.stringify({ title: '가상 제목', body: 'line one\nline two' });
  await active.device.signedFetch('/api/memos?view=%EA%B0%80%EC%83%81&n=1', {
    method: 'POST', body, headers: { 'Content-Type': 'application/json' },
  });
  const challenge = active.requests.find(request => request.input?.action === 'request-options');
  assert.deepEqual(challenge.input, {
    action: 'request-options', credentialId: 'public-credential-first', method: 'POST',
    path: '/api/memos', query: '?view=%EA%B0%80%EC%83%81&n=1',
    bodySha256: createHash('sha256').update(body, 'utf8').digest('hex'),
  });
  const target = active.protectedRequests()[0];
  assert.equal(target.options.body, body);
  assert.equal(target.method, 'POST');
  assert.equal(target.options.redirect, 'error');
  assert.equal(new Headers(target.options.headers).get('Content-Type'), 'application/json');
  await assert.rejects(active.device.signedFetch('https://external.example.test/api/memos'));
  await assert.rejects(active.device.signedFetch('/api/auth'));
  await assert.rejects(active.device.signedFetch('/api/memos', { method: 'POST', body: {} }));
  assert.equal(active.storageAccesses(), 0);
});

test('registration stays pending, clears prior protected data and never claims approval', async () => {
  const active = await page();
  await active.get('device-connect').emit('click');
  await active.get('device-register').emit('click');
  assert.equal(active.registrations.length, 1);
  assert.equal(active.registrations[0].optionsJSON.challenge, 'registration-options');
  const verification = active.requests.find(request => request.input?.action === 'registration-verify');
  assert.equal(verification.input.response.id, 'virtual-registration');
  assert.match(verification.input.nonceId, /^registration-/u);
  assert.equal(active.get('device-approval-status').textContent, '승인 대기');
  assert.equal(active.get('device-connect').disabled, true);
  assert.match(active.get('device-feedback').textContent, /최초 승인은 관리자/u);
  assert.equal(active.get('memo-editor').hidden, true);
  assert.doesNotMatch(active.get('notes').textContent, /fixture protected/u);
  assert.equal(active.protectedRequests().length, 1, 'registration never sends an unapproved memo request');
  assert.equal(active.storageAccesses(), 0);
});

test('protected notice and compatibility restore routes receive request-bound proofs and preserve server denials', async () => {
  const active = await page();
  const notice = await active.device.signedFetch('/api/notices/' + MEMO_ID);
  assert.equal(notice.status, 200);
  const invalidNotice = await active.device.signedFetch('/api/notices');
  assert.equal(invalidNotice.status, 400, 'the client preserves the server denial for a missing notice ID');
  assert.equal((await invalidNotice.json()).error, 'INVALID_NOTICE_ID');
  const body = JSON.stringify({ id: MEMO_ID, preview: true });
  const restore = await active.device.signedFetch('/api/restore', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
  });
  assert.equal(restore.status, 200);
  assert.deepEqual(active.protectedRequests().map(request => request.path), [
    '/api/notices/' + MEMO_ID, '/api/notices', '/api/restore',
  ]);
  const challenge = active.requests.find(request => request.input?.action === 'request-options'
    && request.input.path === '/api/restore');
  assert.equal(challenge.input.bodySha256, createHash('sha256').update(body).digest('hex'));
  await assert.rejects(active.device.signedFetch('/api/notices/' + MEMO_ID + '/extra'));
});

test('device decisions use signed requests and self-revocation immediately clears protected DOM', async () => {
  const active = await page({ devices: [publicDevice(), publicDevice('other', 'pending')] });
  active.get('device-select').value = 'first';
  await active.get('device-select').emit('change');
  await active.get('device-connect').emit('click');
  const pendingCard = active.get('device-list').children.find(card => card.textContent.includes('public-fingerprint-other'));
  const reason = pendingCard.children.find(child => child.tagName === 'input');
  assert.equal(reason.required, true);
  assert.equal(reason.minLength, 3);
  assert.equal(reason.maxLength, 240);
  const count = active.requests.length;
  await button(pendingCard, '이 기기 승인').emit('click');
  assert.equal(active.requests.length, count, 'an empty decision reason never opens WebAuthn or sends HTTP');
  assert.match(active.get('device-feedback').textContent, /3~240/u);
  reason.value = 'x'.repeat(241);
  await button(pendingCard, '이 기기 승인').emit('click');
  assert.equal(active.requests.length, count, 'an overlong decision reason is rejected before signing');
  reason.value = '  virtual approval  ';
  await button(pendingCard, '이 기기 승인').emit('click');
  const decision = active.protectedRequests().find(request => request.input?.action === 'decision');
  assert.deepEqual(decision.input, {
    action: 'decision', targetDeviceId: 'other', decision: 'approved', reason: 'virtual approval',
  });
  const ownCard = active.get('device-list').children.find(card => card.textContent.includes('public-fingerprint-first'));
  ownCard.children.find(child => child.tagName === 'input').value = 'virtual revocation';
  await button(ownCard, '이 기기 승인 취소').emit('click');
  assert.equal(active.get('memo-editor').hidden, true);
  assert.equal(active.get('recovery-confirmation').hidden, true);
  assert.doesNotMatch(active.get('notes').textContent, /fixture protected/u);
  assert.equal(active.get('device-connect').disabled, true);
  assert.doesNotMatch(active.get('device-approval-status').textContent, /연결됨/u);
  assert.equal(active.storageAccesses(), 0);
});

test('the 30-second status poll clears memos and the recovery plan when approval is revoked', async () => {
  const active = await page();
  await active.get('device-connect').emit('click');
  active.get('recovery-id').value = MEMO_ID;
  await active.get('recovery-preview-form').emit('submit');
  assert.equal(active.get('recovery-confirmation').hidden, false);
  active.setState('first', 'revoked');
  await active.poll();
  assert.equal(active.get('memo-editor').hidden, true);
  assert.equal(active.get('recovery-panel').hidden, true);
  assert.equal(active.get('recovery-confirmation').hidden, true);
  assert.equal(active.get('recovery-id').value, '');
  assert.equal(active.get('recovery-details').textContent, '');
  assert.doesNotMatch(active.get('notes').textContent, /fixture protected/u);
  const count = active.requests.length;
  await active.get('recovery-apply').emit('click');
  assert.equal(active.requests.length, count, 'the cleared recovery plan cannot issue a request');
});

test('a rejected device decision restores its button and does not retain protected data or show success', async () => {
  const active = await page({ devices: [publicDevice(), publicDevice('other', 'pending')] });
  active.get('device-select').value = 'first';
  await active.get('device-select').emit('change');
  await active.get('device-connect').emit('click');
  const card = active.get('device-list').children.find(item => item.textContent.includes('public-fingerprint-other'));
  card.children.find(child => child.tagName === 'input').value = 'virtual reason';
  const decision = button(card, '이 기기 거부');
  active.setNextResponse(Response.json({ error: 'INVALID_DEVICE_DECISION' }, { status: 400 }));
  await decision.emit('click');
  assert.equal(decision.disabled, false);
  assert.equal(active.get('memo-editor').hidden, true);
  assert.doesNotMatch(active.get('notes').textContent, /fixture protected/u);
  assert.equal(active.get('device-feedback').textContent, 'INVALID_DEVICE_DECISION');
  assert.doesNotMatch(active.get('device-approval-status').textContent, /연결됨/u);
});

test('401 and DEVICE_403 responses clear protected UI without displaying connection success', async () => {
  for (const status of [401, 403]) {
    const active = await page();
    await active.get('device-connect').emit('click');
    active.setNextResponse(Response.json({ error: 'DEVICE_NOT_APPROVED' }, { status }));
    await assert.rejects(active.device.signedFetch('/api/memos'));
    assert.equal(active.get('memo-editor').hidden, true);
    assert.doesNotMatch(active.get('notes').textContent, /fixture protected/u);
    assert.doesNotMatch(active.get('device-approval-status').textContent, /연결됨/u);
  }
});

test('a request-binding rejection retains its server error instead of claiming the device state changed', async () => {
  const active = await page();
  active.setNextResponse(Response.json({ error: 'DEVICE_REQUEST_MISMATCH' }, { status: 403 }));
  await active.get('device-connect').emit('click');
  assert.equal(active.get('memo-editor').hidden, true);
  assert.equal(active.get('device-feedback').textContent, 'DEVICE_REQUEST_MISMATCH');
  assert.match(active.get('device-approval-status').textContent, /기기 연결 필요/u);
  assert.doesNotMatch(active.get('device-feedback').textContent, /기기 상태가 바뀌었습니다/u);
});

test('cancelled ceremonies and missing user gestures fail closed and can be retried by a fresh click', async () => {
  const active = await page();
  await active.get('device-connect').emit('click');
  active.setNextAssertion(async () => { const error = new Error('cancelled'); error.name = 'NotAllowedError'; throw error; });
  await active.get('device-connect').emit('click');
  assert.equal(active.get('memo-editor').hidden, true);
  assert.doesNotMatch(active.get('device-approval-status').textContent, /연결됨/u);
  assert.match(active.get('device-feedback').textContent, /취소/u);
  active.navigator.userActivation.isActive = false;
  const count = active.requests.length;
  await assert.rejects(active.device.signedFetch('/api/memos'), /사용자 확인/u);
  assert.equal(active.requests.length, count, 'missing gesture sends neither challenge nor protected request');
  active.navigator.userActivation.isActive = true;
  await active.get('device-connect').emit('click');
  assert.equal(active.get('memo-editor').hidden, false);
  assert.equal(active.storageAccesses(), 0);
});

test('concurrent protected operations serialize authenticator prompts and issue distinct challenges', async () => {
  const active = await page();
  let release;
  let started;
  const promptStarted = new Promise(resolve => { started = resolve; });
  active.setNextAssertion(() => new Promise(resolve => { release = resolve; started(); }));
  const first = active.device.signedFetch('/api/memos');
  const second = active.device.signedFetch('/api/memos');
  await promptStarted;
  assert.equal(active.assertions.length, 1);
  assert.equal(active.maxPrompts(), 1);
  release({ id: 'deferred-virtual-assertion', response: {} });
  await Promise.all([first, second]);
  assert.equal(active.assertions.length, 2);
  assert.equal(active.maxPrompts(), 1);
  const proofs = active.protectedRequests().map(request => JSON.parse(Buffer.from(
    new Headers(request.options.headers).get('X-Byteback-Proof'), 'base64url').toString('utf8')));
  assert.notEqual(proofs[0].nonceId, proofs[1].nonceId);
});

test('offline and logout clear UI, stop polling and ignore a late protected HTTP response', async () => {
  for (const transition of ['offline', 'logout']) {
    const active = await page();
    const pending = active.deferNextMemo();
    const loading = active.get('device-connect').emit('click');
    await pending;
    if (transition === 'offline') {
      active.navigator.onLine = false;
      await active.window.emit('offline');
    } else await active.get('logout-btn').emit('click');
    active.releaseMemo();
    await loading;
    assert.equal(active.get('memo-editor').hidden, true);
    assert.equal(active.get('recovery-panel').hidden, true);
    assert.doesNotMatch(active.get('notes').textContent, /fixture protected/u);
    assert.equal(active.intervals.size, 0);
    assert.equal(active.storageAccesses(), 0);
  }
});

test('status requests are deduplicated and cannot resurrect state after logout', async () => {
  const active = await page();
  active.deferNextDevices();
  const first = active.device.refreshDevices();
  const second = active.device.refreshDevices();
  await active.poll();
  assert.equal(active.requests.filter(request => request.path === '/api/devices' && request.method === 'GET').length, 2);
  await active.get('logout-btn').emit('click');
  active.releaseDevices();
  await Promise.all([first, second]);
  assert.equal(active.get('device-controls').hidden, true);
  assert.equal(active.get('memo-editor').hidden, true);
  assert.equal(active.intervals.size, 0);
});

test('malformed device status and unsupported WebAuthn never expose protected data', async () => {
  const active = await page();
  await active.get('device-connect').emit('click');
  active.setMalformedList();
  await active.device.refreshDevices();
  assert.equal(active.get('memo-editor').hidden, true);
  assert.equal(active.get('device-connect').disabled, true);
  assert.doesNotMatch(active.get('device-approval-status').textContent, /연결됨/u);
  const unsupported = await page({ supported: false });
  await unsupported.get('device-connect').emit('click');
  assert.equal(unsupported.protectedRequests().length, 0);
  assert.equal(unsupported.assertions.length, 0);
  assert.equal(unsupported.get('memo-editor').hidden, true);
  assert.equal(unsupported.storageAccesses(), 0);
});

test('memo editing, deletion and restore retain click-based signing and require an explicit reread', async () => {
  const active = await page();
  await active.get('device-connect').emit('click');
  let card = active.get('notes').children[0];
  await button(card, '수정').emit('click');
  const editForm = card.children.find(child => child.tagName === 'form');
  assert.equal(editForm.hidden, false);
  editForm.children[0].children[0].value = 'fixture edited';
  await editForm.emit('submit');
  assert.equal(active.protectedRequests().find(request => request.method === 'PUT').path,
    '/api/memos/item?id=' + MEMO_ID);
  assert.equal(active.get('memo-editor').hidden, true);
  assert.doesNotMatch(active.get('notes').textContent, /fixture protected memo/u);
  assert.equal(active.requests.filter(request => request.path === '/api/memos' && request.method === 'GET').length, 1);
  await active.get('device-connect').emit('click');
  assert.match(active.get('notes').textContent, /fixture edited/u);
  active.get('recovery-id').value = MEMO_ID;
  await active.get('recovery-preview-form').emit('submit');
  await active.get('recovery-apply').emit('click');
  assert.deepEqual(active.protectedRequests().filter(request => request.path === '/api/restore/item?id=' + MEMO_ID).map(request => request.input), [
    { preview: true }, { expectedVersion: VERSION, expectedState: STATE_VERSION },
  ]);
  assert.equal(active.get('recovery-confirmation').hidden, true);
  assert.equal(active.get('memo-editor').hidden, true);
  await active.get('device-connect').emit('click');
  card = active.get('notes').children[0];
  await button(card, '삭제').emit('click');
  assert.equal(active.protectedRequests().filter(request => request.method === 'DELETE').length, 0);
  await button(card, '기기 확인 후 삭제').emit('click');
  assert.equal(active.protectedRequests().filter(request => request.method === 'DELETE').length, 1);
  assert.equal(active.protectedRequests().find(request => request.method === 'DELETE').path,
    '/api/memos/item?id=' + MEMO_ID);
  assert.equal(active.get('memo-editor').hidden, true);
  assert.equal(active.storageAccesses(), 0);
});
