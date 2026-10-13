import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { createLoginVerifier } from '../../src/verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../../aleph.config.json');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA = /^[0-9a-f]{64}$/u;
const CHANGED = new Set(['title', 'content', 'create']);

let verifier;

function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    });
  }
  return verifier;
}

function authHeader(req) {
  if (req.headers.authorization) return req.headers.authorization;
  const cookie = String(req.headers.cookie || '')
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('__Host-byteback-access='));
  if (!cookie) return undefined;
  try {
    return 'Bearer ' + decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1));
  } catch {
    return undefined;
  }
}

function readBody(req) {
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return null; }
  }
  return req.body ?? null;
}

function rpcHeaders() {
  const key = process.env.SUPABASE_SECRET_KEY;
  return {
    apikey: key,
    Authorization: 'Bearer ' + key,
    'Content-Type': 'application/json',
  };
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
    && SHA.test(value.version ?? '')
    && SHA.test(value.stateVersion ?? '')
    && typeof value.capturedAt === 'string'
    && Array.isArray(value.changedFields)
    && value.changedFields.every((field) => CHANGED.has(field));
}

function planSha256(preview) {
  return createHash('sha256').update(JSON.stringify({
    id: preview.id,
    version: preview.version,
    stateVersion: preview.stateVersion,
    capturedAt: preview.capturedAt,
    changedFields: preview.changedFields,
  })).digest('hex');
}

async function loadPreview(actorId, memoId) {
  const result = await rpc('preview_memo_recovery', {
    p_actor: actorId,
    p_public_id: memoId,
  });
  if (result.status !== 200) return result;
  if (!validPreview(result.body, memoId)) {
    return { status: 409, body: { error: 'BACKUP_UNVERIFIED' } };
  }

  return {
    status: 200,
    body: {
      id: memoId,
      verified: true,
      version: result.body.version,
      stateVersion: result.body.stateVersion,
      capturedAt: result.body.capturedAt,
      changedFields: result.body.changedFields,
      planSha256: planSha256(result.body),
    },
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('CDN-Cache-Control', 'no-store');
  res.setHeader('Vercel-CDN-Cache-Control', 'no-store');

  if (!['GET', 'POST'].includes(req.method)) {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  const routeId = Array.isArray(req.query?.id) ? null : req.query?.id;
  if (typeof routeId !== 'string' || !UUID.test(routeId)) {
    return res.status(400).json({ error: 'INVALID_RESTORE_ID' });
  }
  const memoId = routeId.toLowerCase();

  if (req.method === 'POST' && !req.headers.authorization && req.headers.origin
      && req.headers.origin !== 'https://' + req.headers.host) {
    return res.status(403).json({ error: 'ORIGIN_REJECTED' });
  }

  let verifyLogin;
  try { verifyLogin = getVerifier(); }
  catch { return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' }); }

  const identity = await verifyLogin(authHeader(req));
  if (!identity) return res.status(401).json({ error: 'AUTH_REQUIRED' });

  try {
    // GET은 읽기 전용 미리보기다. 복구할 버전·현재 상태·바뀔 항목과 확인 해시만 반환한다.
    if (req.method === 'GET') {
      const preview = await loadPreview(identity.userId, memoId);
      return res.status(preview.status).json(preview.body);
    }

    // POST는 GET에서 확인한 planSha256 하나만 받는다.
    const body = readBody(req);
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).sort().join(',') !== 'planSha256'
        || !SHA.test(body.planSha256 ?? '')) {
      return res.status(400).json({ error: 'PLAN_CONFIRMATION_REQUIRED' });
    }

    // 실제 쓰기 직전에 백업과 현재 대상 상태를 다시 읽어 새 plan을 만든다.
    const reread = await loadPreview(identity.userId, memoId);
    if (reread.status !== 200) return res.status(reread.status).json(reread.body);
    if (reread.body.planSha256 !== body.planSha256) {
      return res.status(409).json({ error: 'BACKUP_OR_TARGET_CHANGED' });
    }

    // DB 함수가 트랜잭션 잠금 뒤 백업/대상 상태를 다시 읽고 version/stateVersion을 대조한다.
    const restored = await rpc('restore_verified_memo', {
      p_actor: identity.userId,
      p_public_id: memoId,
      p_expected_version: reread.body.version,
      p_expected_state: reread.body.stateVersion,
    });
    if (restored.status !== 200) return res.status(restored.status).json(restored.body);
    if (!restored.body || restored.body.id !== memoId || restored.body.verified !== true) {
      return res.status(409).json({ error: 'RESTORE_MISMATCH' });
    }

    return res.status(200).json({
      id: memoId,
      restored: true,
      verified: true,
    });
  } catch {
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}
