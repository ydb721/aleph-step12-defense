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

async function previewRestore(actorId, memoId) {
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
    },
  };
}

async function restoreMemo(actorId, memoId, expectedVersion, expectedState) {
  // 실행 직전 1차 재조회: 검증된 사본과 현재 대상 상태를 다시 읽습니다.
  const preview = await previewRestore(actorId, memoId);
  if (preview.status !== 200) return preview;

  if (expectedVersion !== undefined && expectedVersion !== preview.body.version) {
    return { status: 409, body: { error: 'BACKUP_CHANGED' } };
  }
  if (expectedState !== undefined && expectedState !== preview.body.stateVersion) {
    return { status: 409, body: { error: 'TARGET_CHANGED' } };
  }

  // DB 트랜잭션 안에서 사본/대상을 잠근 뒤 다시 읽어
  // 위 version/stateVersion과 같을 때만 복원합니다.
  const restored = await rpc('restore_verified_memo', {
    p_actor: actorId,
    p_public_id: memoId,
    p_expected_version: preview.body.version,
    p_expected_state: preview.body.stateVersion,
  });

  if (restored.status !== 200) return restored;
  if (!restored.body || restored.body.id !== memoId || restored.body.verified !== true) {
    return { status: 409, body: { error: 'RESTORE_MISMATCH' } };
  }

  return {
    status: 200,
    body: {
      id: memoId,
      verified: true,
      restored: true,
    },
  };
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('CDN-Cache-Control', 'no-store');
  res.setHeader('Vercel-CDN-Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
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

  if (!req.headers.authorization && req.headers.origin
      && req.headers.origin !== 'https://' + req.headers.host) {
    return res.status(403).json({ error: 'ORIGIN_REJECTED' });
  }

  let verifyLogin;
  try { verifyLogin = getVerifier(); }
  catch { return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' }); }

  const identity = await verifyLogin(authHeader(req));
  if (!identity) return res.status(401).json({ error: 'AUTH_REQUIRED' });

  const body = readBody(req);
  if (body != null) {
    if (typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).some((key) => !['preview', 'expectedVersion', 'expectedState'].includes(key))
        || (body.preview !== undefined && body.preview !== true)
        || (body.expectedVersion !== undefined && !SHA.test(body.expectedVersion))
        || (body.expectedState !== undefined && !SHA.test(body.expectedState))
        || (body.preview === true
          && (body.expectedVersion !== undefined || body.expectedState !== undefined))) {
      return res.status(400).json({ error: 'INVALID_RESTORE_REQUEST' });
    }
  }

  try {
    if (body?.preview === true) {
      const preview = await previewRestore(identity.userId, memoId);
      return res.status(preview.status).json(preview.body);
    }

    const result = await restoreMemo(
      identity.userId,
      memoId,
      body?.expectedVersion,
      body?.expectedState,
    );
    return res.status(result.status).json(result.body);
  } catch {
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}
