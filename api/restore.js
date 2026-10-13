import { createRequire } from 'node:module';
import { createLoginVerifier } from '../src/verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const changedFieldNames = new Set(['title', 'content', 'create']);

let verifier;
function getVerifier() {
  if (!verifier) verifier = createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return verifier;
}

function readBody(req) {
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return null; }
  }
  return req.body ?? null;
}

function bearerOrCookie(req) {
  if (req.headers.authorization) return req.headers.authorization;
  const cookie = String(req.headers.cookie || '').split(';').map((part) => part.trim())
    .find((part) => part.startsWith('__Host-byteback-access='));
  if (!cookie) return undefined;
  try { return 'Bearer ' + decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1)); }
  catch { return undefined; }
}

function rpcHeaders() {
  const key = process.env.SUPABASE_SECRET_KEY;
  return { apikey: key, Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' };
}

async function rpc(name, body) {
  const response = await fetch(new URL('/rest/v1/rpc/' + name, process.env.SUPABASE_URL), {
    method: 'POST',
    headers: rpcHeaders(),
    body: JSON.stringify(body),
    redirect: 'error',
  });
  let data;
  try { data = await response.json(); } catch { data = null; }

  if (!response.ok) {
    const code = typeof data?.code === 'string' ? data.code : '';
    if (code === '42883' || code === 'PGRST202') {
      return { status: 503, body: { error: 'RESTORE_NOT_READY' } };
    }
    return { status: 409, body: { error: 'BACKUP_UNVERIFIED' } };
  }
  return { status: 200, body: data };
}

function validPreview(value, memoId) {
  return value
    && typeof value === 'object'
    && value.id === memoId
    && value.verified === true
    && sha256Pattern.test(value.version ?? '')
    && sha256Pattern.test(value.stateVersion ?? '')
    && typeof value.capturedAt === 'string'
    && Array.isArray(value.changedFields)
    && value.changedFields.every((field) => changedFieldNames.has(field));
}

async function previewRestore(actorId, memoId) {
  const result = await rpc('preview_memo_recovery', {
    p_actor: actorId,
    p_public_id: memoId,
  });
  if (result.status !== 200) return result;
  if (!validPreview(result.body, memoId)) {
    return { status: 409, body: { error: 'BACKUP_UNVERIFIED' } };
  }
  return { status: 200, body: result.body };
}

async function restoreMemo(actorId, memoId, expectedVersion, expectedState) {
  // 1차 읽기: 검증된 사본 버전과 현재 대상 상태 버전을 확인한다.
  const preview = await previewRestore(actorId, memoId);
  if (preview.status !== 200) return preview;

  if (expectedVersion !== undefined && expectedVersion !== preview.body.version) {
    return { status: 409, body: { error: 'BACKUP_CHANGED' } };
  }
  if (expectedState !== undefined && expectedState !== preview.body.stateVersion) {
    return { status: 409, body: { error: 'TARGET_CHANGED' } };
  }

  // 실제 복원 RPC는 트랜잭션 잠금 뒤 사본과 대상을 다시 읽어
  // 위 version/stateVersion과 같은 경우에만 한 건을 복원한다.
  const result = await rpc('restore_verified_memo', {
    p_actor: actorId,
    p_public_id: memoId,
    p_expected_version: preview.body.version,
    p_expected_state: preview.body.stateVersion,
  });
  if (result.status !== 200) return result;
  if (!result.body || result.body.id !== memoId || result.body.verified !== true) {
    return { status: 409, body: { error: 'RESTORE_MISMATCH' } };
  }

  return { status: 200, body: { id: memoId, restored: true, verified: true } };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }
  if (!req.headers.authorization && req.headers.origin
      && req.headers.origin !== 'https://' + req.headers.host) {
    return res.status(403).json({ error: 'ORIGIN_REJECTED' });
  }

  let verifyLogin;
  try { verifyLogin = getVerifier(); }
  catch { return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' }); }

  const identity = await verifyLogin(bearerOrCookie(req));
  if (!identity) return res.status(401).json({ error: 'AUTH_REQUIRED' });

  const body = readBody(req);
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || typeof body.id !== 'string' || !uuidPattern.test(body.id)) {
    return res.status(400).json({ error: 'INVALID_RESTORE_REQUEST' });
  }

  const allowedKeys = new Set(['id', 'preview', 'expectedVersion', 'expectedState']);
  if (Object.keys(body).some((key) => !allowedKeys.has(key))
      || (body.preview !== undefined && body.preview !== true)
      || (body.expectedVersion !== undefined && !sha256Pattern.test(body.expectedVersion))
      || (body.expectedState !== undefined && !sha256Pattern.test(body.expectedState))
      || (body.preview === true
        && (body.expectedVersion !== undefined || body.expectedState !== undefined))) {
    return res.status(400).json({ error: 'INVALID_RESTORE_REQUEST' });
  }

  const memoId = body.id.toLowerCase();

  try {
    if (body.preview === true) {
      const preview = await previewRestore(identity.userId, memoId);
      return res.status(preview.status).json(preview.body);
    }
    const result = await restoreMemo(
      identity.userId,
      memoId,
      body.expectedVersion,
      body.expectedState,
    );
    return res.status(result.status).json(result.body);
  } catch {
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}
