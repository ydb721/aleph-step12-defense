import { createHash } from 'node:crypto';
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

// 복원 사본의 "내용"은 제목 + NUL 구분자 + 본문 전체로 고정합니다.
// 제목만 변조돼도 같은 내용으로 취급하지 않기 위해 둘을 함께 SHA-256 합니다.
export function memoContentSha256(title, content) {
  return createHash('sha256')
    .update(String(title), 'utf8')
    .update('\0')
    .update(String(content), 'utf8')
    .digest('hex');
}

function headers(extra = {}) {
  const key = process.env.SUPABASE_SECRET_KEY;
  return {
    apikey: key,
    Authorization: 'Bearer ' + key,
    'Content-Type': 'application/json',
    ...extra,
  };
}

function tableUrl(name) {
  return new URL('/rest/v1/' + name, process.env.SUPABASE_URL);
}

async function readRows(url) {
  const response = await fetch(url, { method: 'GET', headers: headers(), redirect: 'error' });
  let data;
  try { data = await response.json(); } catch { data = null; }
  if (!response.ok || !Array.isArray(data)) throw new Error('upstream_read_failed');
  return data;
}

function validBackup(row, id, ownerId) {
  return row && row.public_id === id && row.owner_id === ownerId
    && typeof row.title === 'string' && typeof row.content === 'string'
    && typeof row.content_sha256 === 'string'
    && /^[0-9a-f]{64}$/u.test(row.content_sha256)
    && memoContentSha256(row.title, row.content) === row.content_sha256;
}

async function restoreOne(actorId, memoId) {
  // 1) 복원 실행 직전에 비공개 사본을 다시 읽고 ID·소유자·제목+본문 해시를 검증합니다.
  const backupUrl = tableUrl('memo_restore_backups');
  backupUrl.searchParams.set('select', 'public_id,owner_id,title,content,content_sha256');
  backupUrl.searchParams.set('public_id', 'eq.' + memoId);
  backupUrl.searchParams.set('owner_id', 'eq.' + actorId);
  backupUrl.searchParams.set('limit', '2');
  const backups = await readRows(backupUrl);

  if (backups.length === 0) return { status: 404, body: { error: 'BACKUP_NOT_FOUND' } };
  if (backups.length !== 1 || !validBackup(backups[0], memoId, actorId)) {
    return { status: 409, body: { error: 'BACKUP_UNVERIFIED' } };
  }
  const backup = backups[0];

  // 2) 현재 메모를 ID로 읽어 다른 소유자의 같은 ID를 절대 덮어쓰지 않습니다.
  const currentUrl = tableUrl('memos');
  currentUrl.searchParams.set('select', 'public_id,owner_id,title,content');
  currentUrl.searchParams.set('public_id', 'eq.' + memoId);
  currentUrl.searchParams.set('limit', '2');
  const currentRows = await readRows(currentUrl);
  if (currentRows.length > 1) return { status: 409, body: { error: 'RESTORE_CONFLICT' } };

  const current = currentRows[0] ?? null;
  if (current && current.owner_id !== actorId) {
    return { status: 404, body: { error: 'BACKUP_NOT_FOUND' } };
  }

  const beforeHash = current ? memoContentSha256(current.title, current.content ?? '') : null;
  const alreadyMatches = current
    && current.public_id === backup.public_id
    && current.owner_id === backup.owner_id
    && beforeHash === backup.content_sha256;

  // 3) 지정한 한 건만 복원합니다. 있으면 소유자까지 조건으로 수정하고, 없으면 같은 ID로 다시 만듭니다.
  if (!alreadyMatches) {
    const writeUrl = tableUrl('memos');
    let response;
    if (current) {
      writeUrl.searchParams.set('public_id', 'eq.' + memoId);
      writeUrl.searchParams.set('owner_id', 'eq.' + actorId);
      response = await fetch(writeUrl, {
        method: 'PATCH',
        headers: headers({ Prefer: 'return=representation' }),
        body: JSON.stringify({ title: backup.title, content: backup.content }),
        redirect: 'error',
      });
    } else {
      response = await fetch(writeUrl, {
        method: 'POST',
        headers: headers({ Prefer: 'return=representation' }),
        body: JSON.stringify({
          public_id: backup.public_id,
          owner_id: backup.owner_id,
          title: backup.title,
          content: backup.content,
        }),
        redirect: 'error',
      });
    }

    let written;
    try { written = await response.json(); } catch { written = null; }
    if (!response.ok || !Array.isArray(written) || written.length !== 1) {
      return { status: 502, body: { error: 'RESTORE_WRITE_FAILED' } };
    }
  }

  // 4) 쓴 뒤 DB에서 다시 읽어 ID·소유자·제목+본문 해시가 사본과 정확히 같은지 확인합니다.
  const checkUrl = tableUrl('memos');
  checkUrl.searchParams.set('select', 'public_id,owner_id,title,content');
  checkUrl.searchParams.set('public_id', 'eq.' + memoId);
  checkUrl.searchParams.set('owner_id', 'eq.' + actorId);
  checkUrl.searchParams.set('limit', '2');
  const afterRows = await readRows(checkUrl);
  const after = afterRows.length === 1 ? afterRows[0] : null;
  const afterHash = after ? memoContentSha256(after.title, after.content ?? '') : null;

  if (!after || after.public_id !== backup.public_id || after.owner_id !== backup.owner_id
      || afterHash !== backup.content_sha256) {
    return { status: 500, body: { error: 'RESTORE_MISMATCH' } };
  }

  // 기존 감사 이력을 지우지 않고 복원 성공 기록 한 줄만 덧붙입니다.
  const auditUrl = tableUrl('memo_restore_audit');
  const audit = await fetch(auditUrl, {
    method: 'POST',
    headers: headers({ Prefer: 'return=minimal' }),
    body: JSON.stringify({
      actor_id: actorId,
      memo_public_id: memoId,
      backup_sha256: backup.content_sha256,
      action: 'memo_restore',
    }),
    redirect: 'error',
  });
  if (!audit.ok) return { status: 502, body: { error: 'RESTORE_AUDIT_FAILED' } };

  return {
    status: 200,
    body: {
      id: backup.public_id,
      restored: true,
      contentSha256: backup.content_sha256,
    },
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
    const result = await restoreOne(identity.userId, body.id.toLowerCase());
    return res.status(result.status).json(result.body);
  } catch {
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}
