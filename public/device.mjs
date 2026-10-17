import { startRegistration, startAuthentication } from '/vendor/simplewebauthn-browser.js';

const approvalStatus = document.querySelector('#device-approval-status');
const controls = document.querySelector('#device-controls');
const selector = document.querySelector('#device-select');
const registerButton = document.querySelector('#device-register');
const refreshButton = document.querySelector('#device-refresh');
const connectButton = document.querySelector('#device-connect');
const feedback = document.querySelector('#device-feedback');
const deviceList = document.querySelector('#device-list');
const supported = window.isSecureContext && typeof window.PublicKeyCredential === 'function';
const stateLabels = { pending: '승인 대기', approved: '승인됨', rejected: '거부됨', revoked: '승인 취소됨' };

// Only public credential identifiers and the last server status live in memory.
// WebAuthn keeps the signing key in the authenticator; it never enters this module.
let signedIn = false;
let devices = [];
let selectedId = '';
let statusKnown = false;
let connected = false;
let generation = 0;
let pollTimer = null;
let refreshInFlight = null;
let promptQueue = Promise.resolve();
let promptCount = 0;

function selectedDevice() {
  return devices.find(device => device.id === selectedId);
}

export function hasApprovedDevice() {
  return signedIn && statusKnown && selectedDevice()?.state === 'approved';
}

function invalidate(message = '승인 기기로 다시 연결하세요.') {
  connected = false;
  window.dispatchEvent(new CustomEvent('byteback:device-invalidated', { detail: { message } }));
}

function render() {
  controls.hidden = !signedIn;
  const selected = selectedDevice();
  approvalStatus.textContent = !signedIn ? '기기 승인 미확인 · 로그인 필요'
    : !supported ? '이 환경에서는 기기 인증을 사용할 수 없습니다.'
    : !statusKnown ? '기기 승인 미확인'
    : !selected ? '등록된 기기를 선택하거나 새 기기를 등록하세요.'
    : selected.state !== 'approved' ? stateLabels[selected.state]
    : connected ? '승인 기기로 연결됨' : '서버 승인 확인 · 기기 연결 필요';
  registerButton.disabled = !signedIn || !supported || promptCount > 0;
  refreshButton.disabled = !signedIn || Boolean(refreshInFlight);
  selector.disabled = !signedIn || promptCount > 0;
  connectButton.disabled = !hasApprovedDevice() || !supported || promptCount > 0;
  connectButton.textContent = connected ? '메모 새로 읽기' : '승인 기기로 연결';
}

function deviceError(data, fallback) {
  const error = new Error(data?.error || fallback);
  error.code = data?.code || data?.error || '';
  return error;
}

function checkDenied(response, data) {
  const code = data?.code || data?.error || '';
  // A request-binding rejection is not proof that the server changed this
  // device's approval. Keep the approved status observable so its precise
  // error is not replaced by a misleading connection-state message.
  if (response.status === 401 || ['DEVICE_NOT_APPROVED', 'DEVICE_REGISTRATION_UNSUPPORTED',
    'DEVICE_COUNTER_CHANGED'].includes(code)) {
    statusKnown = false;
    invalidate('기기 승인 또는 로그인을 다시 확인하세요.');
    render();
  }
}

async function deviceRequest(input) {
  const response = await fetch('/api/devices', {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
  });
  const data = await response.json().catch(() => null);
  checkDenied(response, data);
  if (!response.ok) throw deviceError(data, '기기 요청 실패 (' + response.status + ')');
  return data;
}

function requireGesture() {
  if (navigator.userActivation && navigator.userActivation.isActive !== true) {
    throw new Error('사용자 확인이 필요합니다. 승인 기기로 연결 또는 원하는 작업 버튼을 다시 누르세요.');
  }
}

function withAuthenticator(operation) {
  requireGesture();
  ++promptCount;
  render();
  const operationGeneration = generation;
  const run = promptQueue.then(async () => {
    if (!signedIn || operationGeneration !== generation) throw new Error('로그인 상태를 다시 확인하세요.');
    requireGesture();
    return operation(operationGeneration);
  });
  promptQueue = run.catch(() => undefined);
  return run.finally(() => { --promptCount; render(); });
}

function assertCurrent(operationGeneration, credentialId) {
  if (operationGeneration !== generation || !hasApprovedDevice()
      || selectedDevice()?.credentialId !== credentialId || navigator.onLine === false) {
    throw new Error('기기 상태가 바뀌었습니다. 승인 기기로 다시 연결하세요.');
  }
}

function toBase64url(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

export async function signedFetch(path, init = {}) {
  if (!hasApprovedDevice()) throw new Error('서버에서 승인된 기기를 선택한 뒤 연결하세요.');
  if (!supported || navigator.onLine === false) throw new Error('온라인의 WebAuthn 지원 환경에서 기기를 확인하세요.');
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin || url.hash
      || !(/^\/api\/(?:memos(?:\/[^/]+)?|notices(?:\/[^/]+)?|restore(?:\/[^/]+)?|devices)$/u.test(url.pathname))) {
    throw new Error('기기 서명을 사용할 수 없는 경로입니다.');
  }
  const method = (init.method || 'GET').toUpperCase();
  // The caller serializes JSON once. Hash and send exactly these UTF-8 bytes.
  const body = init.body;
  if (body !== undefined && typeof body !== 'string') throw new Error('서명할 본문은 문자열이어야 합니다.');
  const credentialId = selectedDevice().credentialId;
  try {
    return await withAuthenticator(async operationGeneration => {
      assertCurrent(operationGeneration, credentialId);
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body ?? ''));
      const bodySha256 = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
      const challenge = await deviceRequest({
        action: 'request-options', credentialId, method, path: url.pathname, query: url.search, bodySha256,
      });
      assertCurrent(operationGeneration, credentialId);
      requireGesture();
      const assertion = await startAuthentication({ optionsJSON: challenge.options });
      assertCurrent(operationGeneration, credentialId);
      const headers = new Headers(init.headers);
      headers.set('X-Byteback-Proof', toBase64url({ nonceId: challenge.nonceId, assertion }));
      const response = await fetch(url.pathname + url.search, {
        ...init, method, headers, ...(body === undefined ? {} : { body }),
        credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      });
      const data = response.ok ? null : await response.clone().json().catch(() => null);
      checkDenied(response, data);
      assertCurrent(operationGeneration, credentialId);
      if (response.ok) {
        connected = true;
        feedback.textContent = '';
        render();
      } else {
        feedback.textContent = data?.code || data?.error || '요청이 거부되었습니다.';
        invalidate('요청이 거부되었습니다. 승인 기기로 다시 연결하세요.');
        render();
      }
      return response;
    });
  } catch (error) {
    invalidate('기기 확인에 실패했습니다. 승인 기기로 다시 연결하세요.');
    feedback.textContent = error?.name === 'NotAllowedError'
      ? '기기 확인이 취소되었거나 허용되지 않았습니다. 작업 버튼을 다시 누르세요.' : error.message;
    render();
    throw error;
  }
}

function renderDevices() {
  const empty = document.createElement('option');
  empty.value = '';
  empty.textContent = '기기 선택';
  selector.replaceChildren(empty, ...devices.map(device => {
    const option = document.createElement('option');
    option.value = device.id;
    option.textContent = `${device.fingerprint} · ${stateLabels[device.state]}`;
    return option;
  }));
  selector.value = selectedId;
  deviceList.replaceChildren(...devices.map(device => {
    const item = document.createElement('li');
    const label = document.createElement('strong');
    label.textContent = `${device.fingerprint} · ${stateLabels[device.state]}`;
    const metadata = document.createElement('p');
    metadata.textContent = '등록 시각: ' + device.createdAt;
    item.append(label, metadata);
    if (hasApprovedDevice() && ['pending', 'approved'].includes(device.state)) {
      const reason = document.createElement('input');
      reason.type = 'text';
      reason.minLength = 3;
      reason.maxLength = 240;
      reason.required = true;
      reason.placeholder = '승인·거부·취소 사유 (필수, 3~240자)';
      reason.setAttribute('aria-label', device.fingerprint + ' 결정 사유');
      item.append(reason);
      const decisions = device.state === 'pending' ? ['approved', 'rejected'] : ['revoked'];
      for (const decision of decisions) {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = { approved: '이 기기 승인', rejected: '이 기기 거부', revoked: '이 기기 승인 취소' }[decision];
        button.addEventListener('click', async () => {
          const decisionReason = reason.value.trim();
          if (decisionReason.length < 3 || reason.value.length > 240) {
            feedback.textContent = '결정 사유를 3~240자로 입력하세요.';
            return;
          }
          button.disabled = true;
          try {
            const response = await signedFetch('/api/devices', {
              method: 'POST', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ action: 'decision', targetDeviceId: device.id, decision, reason: decisionReason }),
            });
            const result = await response.json().catch(() => null);
            if (!response.ok) throw deviceError(result, '기기 결정 요청이 거부되었습니다.');
            if (device.id === selectedId && decision === 'revoked') {
              ++generation;
              statusKnown = false;
              invalidate('현재 기기의 승인을 취소했습니다.');
            }
            await refreshDevices();
            feedback.textContent = statusKnown ? '서버 기기 상태를 다시 확인했습니다.'
              : '결정 요청 후 현재 기기 상태를 확인하지 못했습니다. 다시 확인하세요.';
          } catch (error) { feedback.textContent = error.message; }
          finally { button.disabled = false; }
        });
        item.append(button);
      }
    }
    return item;
  }));
  render();
}

export function clearDeviceState() {
  ++generation;
  signedIn = false;
  devices = [];
  selectedId = '';
  statusKnown = false;
  clearInterval(pollTimer);
  pollTimer = null;
  refreshInFlight = null;
  feedback.textContent = '';
  invalidate('로그인 후 승인 기기로 연결하세요.');
  renderDevices();
}

export async function refreshDevices() {
  if (!signedIn) {
    signedIn = true;
    ++generation;
  }
  if (refreshInFlight) return refreshInFlight;
  const refreshGeneration = generation;
  const previousSelected = selectedDevice();
  const run = (async () => {
    try {
      const response = await fetch('/api/devices', { credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
      const result = await response.json().catch(() => null);
      if (refreshGeneration !== generation || !signedIn) return false;
      checkDenied(response, result);
      if (!response.ok) throw deviceError(result, '기기 목록을 확인할 수 없습니다.');
      if (!Array.isArray(result?.devices) || result.devices.some(device =>
        typeof device.id !== 'string' || typeof device.credentialId !== 'string'
        || !Object.hasOwn(stateLabels, device.state) || typeof device.fingerprint !== 'string'
        || typeof device.createdAt !== 'string')) throw new Error('기기 목록 응답을 확인할 수 없습니다.');
      devices = result.devices.map(({ id, credentialId, state, fingerprint, createdAt }) => ({ id, credentialId, state, fingerprint, createdAt }));
      statusKnown = true;
      if (!selectedId && devices.length === 1) selectedId = devices[0].id;
      const selected = selectedDevice();
      if (previousSelected && (selected?.state !== previousSelected.state || selected?.credentialId !== previousSelected.credentialId)) {
        ++generation;
        invalidate('선택 기기의 승인 상태가 바뀌었습니다. 승인 기기로 다시 연결하세요.');
      }
      if (!hasApprovedDevice()) invalidate('서버에서 승인된 기기로 연결해야 메모를 볼 수 있습니다.');
      renderDevices();
      return hasApprovedDevice();
    } catch (error) {
      if (refreshGeneration === generation && signedIn) {
        statusKnown = false;
        invalidate('기기 상태를 확인할 수 없어 보호 자료를 지웠습니다.');
        feedback.textContent = error.message;
        render();
      }
      return false;
    }
  })();
  refreshInFlight = run;
  render();
  if (!pollTimer) pollTimer = setInterval(() => {
    if (signedIn && navigator.onLine !== false && document.visibilityState !== 'hidden') void refreshDevices();
  }, 30_000);
  try { return await run; }
  finally {
    if (refreshInFlight === run) refreshInFlight = null;
    render();
  }
}

selector.addEventListener('change', () => {
  selectedId = selector.value;
  ++generation;
  feedback.textContent = '';
  invalidate('선택한 승인 기기로 다시 연결하세요.');
  renderDevices();
});
refreshButton.addEventListener('click', () => void refreshDevices());
registerButton.addEventListener('click', async () => {
  feedback.textContent = '';
  invalidate('새 기기 등록을 확인합니다.');
  try {
    await withAuthenticator(async operationGeneration => {
      const challenge = await deviceRequest({ action: 'registration-options' });
      if (operationGeneration !== generation || !signedIn) throw new Error('로그인 상태가 바뀌었습니다.');
      requireGesture();
      const response = await startRegistration({ optionsJSON: challenge.options });
      if (operationGeneration !== generation || !signedIn) throw new Error('로그인 상태가 바뀌었습니다.');
      const result = await deviceRequest({ action: 'registration-verify', nonceId: challenge.nonceId, response });
      if (operationGeneration !== generation || !signedIn) throw new Error('로그인 상태가 바뀌었습니다.');
      if (result?.device?.state !== 'pending') throw new Error('기기 승인 대기 상태를 확인할 수 없습니다.');
      selectedId = result.device.id;
      invalidate('새 기기는 승인 대기 중입니다.');
    });
    await refreshDevices();
    feedback.textContent = '기기 등록 완료 · 승인 대기 중입니다. 최초 승인은 관리자의 별도 승인이 필요합니다. 이후에는 승인된 기기에서 승인할 수 있습니다.';
  } catch (error) {
    connected = false;
    feedback.textContent = error?.name === 'NotAllowedError' ? '기기 등록이 취소되었거나 허용되지 않았습니다.' : error.message;
    render();
  }
});
window.addEventListener('offline', clearDeviceState);
document.addEventListener('visibilitychange', () => {
  if (signedIn && document.visibilityState === 'visible' && navigator.onLine !== false) void refreshDevices();
});
render();
