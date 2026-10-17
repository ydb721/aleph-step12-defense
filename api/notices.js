import { createRequire } from 'node:module';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { guardDeviceRequest } from '../src/device-gate.mjs';

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

function hasIdentityClaim(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && ['owner_id', 'ownerId', 'userId', 'subjectId', 'role', 'instructor']
      .some((name) => Object.hasOwn(value, name));
}

async function restRequest(table, method, params, payload) {
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  const url = new URL('/rest/v1/' + table, base);
  Object.entries(params).forEach(([name, value]) => url.searchParams.set(name, value));
  const headers = {
    apikey: key,
    Authorization: 'Bearer ' + key,
    'Content-Type': 'application/json',
  };
  if (method !== 'GET') headers.Prefer = 'return=representation';

  const response = await fetch(url, {
    method,
    headers,
    ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
  });
  let data;
  try { data = await response.json(); } catch { data = null; }
  return { ok: response.ok, status: response.status, data };
}

async function verifiedInstructor(userId) {
  const grant = await restRequest('vault_instructors', 'GET', {
    select: 'user_id',
    user_id: 'eq.' + userId,
    limit: '1',
  });
  if (!grant.ok || !Array.isArray(grant.data) || grant.data.length !== 1) return false;
  return typeof grant.data[0].user_id === 'string'
    && grant.data[0].user_id.toLowerCase() === userId.toLowerCase();
}

function noticeFields(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || hasIdentityClaim(value)
      || Object.keys(value).some((key) => !['title', 'body'].includes(key))
      || typeof value.title !== 'string' || typeof value.body !== 'string') return null;
  const title = value.title.trim();
  if (!title || title.length > 120 || value.body.length > 4000) return null;
  return { title, content: value.body };
}

export async function handleNotices(req, res, noticeId = null) {
  res.setHeader('Cache-Control', 'no-store');

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' });
  }

  let verifyLogin;
  try { verifyLogin = getVerifier(); }
  catch { return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' }); }

  const bearer = req.headers.authorization;
  const cookie = String(req.headers.cookie || '').split(';').map((part) => part.trim())
    .find((part) => part.startsWith('__Host-byteback-access='));
  let authHeader = bearer;
  if (!authHeader && cookie) {
    try { authHeader = 'Bearer ' + decodeURIComponent(cookie.slice(cookie.indexOf('=') + 1)); }
    catch { authHeader = undefined; }
  }

  if (!bearer && ['PUT'].includes(req.method)
      && req.headers.origin && req.headers.origin !== 'https://' + req.headers.host) {
    return res.status(403).json({ error: 'ORIGIN_REJECTED' });
  }

  const identity = await verifyLogin(authHeader);
  if (!identity) return res.status(401).json({ error: 'AUTH_REQUIRED' });
  if (!(await guardDeviceRequest(req, res, identity, authHeader, config))) return;

  if (typeof noticeId !== 'string' || !uuidPattern.test(noticeId)) {
    return res.status(400).json({ error: 'INVALID_NOTICE_ID' });
  }
  if (!['GET', 'PUT'].includes(req.method)) {
    res.setHeader('Allow', 'GET, PUT');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  // Request-body role claims never grant instructor access.
  if (hasIdentityClaim(readBody(req))) {
    return res.status(403).json({ error: 'IDENTITY_CLAIM_FORBIDDEN' });
  }

  // Fail closed unless the verified login identity is stored as an instructor.
  if (!(await verifiedInstructor(identity.userId))) {
    return res.status(403).json({ error: 'INSTRUCTOR_REQUIRED' });
  }

  if (req.method === 'GET') {
    const result = await restRequest('vault_notices', 'GET', {
      select: 'public_id,title,content',
      public_id: 'eq.' + noticeId,
      limit: '1',
    });
    if (!result.ok) return res.status(502).json({ error: 'DATA_REQUEST_FAILED' });
    if (!Array.isArray(result.data) || result.data.length !== 1) {
      return res.status(404).json({ error: 'NOTICE_NOT_FOUND' });
    }
    const row = result.data[0];
    return res.status(200).json({ id: row.public_id, title: row.title, body: row.content ?? '' });
  }

  const fields = noticeFields(readBody(req));
  if (!fields) return res.status(400).json({ error: 'INVALID_NOTICE' });
  const result = await restRequest('vault_notices', 'PATCH', {
    select: 'public_id,title,content',
    public_id: 'eq.' + noticeId,
  }, fields);
  if (!result.ok) return res.status(502).json({ error: 'DATA_REQUEST_FAILED' });
  if (!Array.isArray(result.data) || result.data.length !== 1) {
    return res.status(404).json({ error: 'NOTICE_NOT_FOUND' });
  }
  const row = result.data[0];
  return res.status(200).json({ id: row.public_id, title: row.title, body: row.content ?? '' });
}

export default async function handler(req, res) {
  return handleNotices(req, res, null);
}
