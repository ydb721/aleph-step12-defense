import { createRequire } from 'node:module';
import { createLoginVerifier } from '../src/verify-login.mjs';

const require = createRequire(import.meta.url);
const config = require('../aleph.config.json');
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

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
  try {
    return 'Bearer ' + decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1));
  } catch {
    return undefined;
  }
}

async function callRestore(actorId, memoId) {
  const url = new URL('/rest/v1/rpc/restore_memo_from_backup', process.env.SUPABASE_URL);
  const key = process.env.SUPABASE_SECRET_KEY;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      apikey: key,
      Authorization: 'Bearer ' + key,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      p_actor: actorId,
      p_public_id: memoId,
    }),
  });

  let data;
  try { data = await response.json(); } catch { data = null; }

  if (response.ok) return { data };

  const message = typeof data?.message === 'string' ? data.message : '';
  if (message.includes('backup_not_found')) return { status: 404, error: 'BACKUP_NOT_FOUND' };
  if (message.includes('backup_owner_mismatch')) return { status: 403, error: 'BACKUP_OWNER_MISMATCH' };
  if (message.includes('backup_hash_mismatch')) return { status: 409, error: 'BACKUP_HASH_MISMATCH' };
  if (message.includes('restore_verify_failed')) return { status: 502, error: 'RESTORE_VERIFY_FAILED' };

  return {
    status: 502,
    error: 'RESTORE_FAILED',
    upstreamStatus: response.status,
    upstreamCode: typeof data?.code === 'string' ? data.code : null,
  };
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
      || Object.keys(body).sort().join(',') !== 'id'
      || typeof body.id !== 'string' || !uuidPattern.test(body.id)) {
    return res.status(400).json({ error: 'INVALID_RESTORE_REQUEST' });
  }

  try {
    const result = await callRestore(identity.userId, body.id);
    if (result.error) {
      return res.status(result.status).json({
        error: result.error,
        ...(result.upstreamStatus ? { upstreamStatus: result.upstreamStatus } : {}),
        ...(result.upstreamCode ? { upstreamCode: result.upstreamCode } : {}),
      });
    }

    const value = result.data;
    if (!value || value.restored !== true || value.id !== body.id
        || value.ownerMatches !== true || value.contentHashMatches !== true) {
      return res.status(502).json({ error: 'RESTORE_VERIFY_FAILED' });
    }

    return res.status(200).json(value);
  } catch {
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}
