import { isTrustedMemoBackupPreview, TRUSTED_B_BACKUP } from '../../src/recovery/trusted-memo-backup.mjs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { createLoginVerifier } from '../../src/verify-login.mjs';
import { createRequestTrace, traceRequestShape } from '../../src/request-trace.mjs';

const require = createRequire(import.meta.url);
const config = require('../../aleph.config.json');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA = /^[0-9a-f]{64}$/u;
const CHANGED = new Set(['title', 'content', 'owner_id', 'create']);

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
    try { return JSON.parse(req.body) ?? false; } catch { return false; }
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

async function rpc(name, body, trace) {
  trace('rpc_started', { rpc: name });
  const response = await fetch(new URL('/rest/v1/rpc/' + name, process.env.SUPABASE_URL), {
    method: 'POST',
    headers: rpcHeaders(),
    body: JSON.stringify(body),
    redirect: 'error',
  });

  let data;
  try { data = await response.json(); } catch { data = null; }
  trace('rpc_finished', { rpc: name, status: response.status ?? (response.ok ? 200 : 502) });

  if (!response.ok) {
    const code = typeof data?.code === 'string' ? data.code : '';
    if (code === '42883' || code === 'PGRST202') {
      return { status: 503, body: { error: 'RESTORE_NOT_READY' } };
    }
    const message = typeof data?.message === 'string' ? data.message : '';
    const known = new Set(['backup_not_found', 'backup_hash_mismatch', 'backup_seal_mismatch', 'owner_mismatch',
      'expected_versions_required', 'backup_or_target_changed', 'restore_verify_failed']);
    trace('rpc_rejected', { rpc: name, code, reason: known.has(message) ? message : 'other' });
    if (message === 'backup_or_target_changed') {
      return { status: 409, body: { error: 'RECOVERY_STATE_CHANGED' } };
    }
    if (code !== 'P0001') {
      trace('rpc_dependency_failed', { rpc: name, code });
      return { status: 502, body: { error: 'RESTORE_DEPENDENCY_ERROR' } };
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
    && UUID.test(value.ownerId ?? '')
    && SHA.test(value.contentSha256 ?? '')
    && SHA.test(value.snapshotSha256 ?? '')
    && typeof value.capturedAt === 'string'
    && Array.isArray(value.changedFields)
    && value.changedFields.every((field) => CHANGED.has(field));
}

async function previewRestore(actorId, memoId, trace) {
  const result = await rpc('preview_memo_recovery', {
    p_actor: actorId,
    p_public_id: memoId,
  }, trace);

  if (result.status !== 200) return result;
  const comparison = {
    structureValid: Boolean(validPreview(result.body, memoId)),
    idMatches: result.body?.id === memoId,
    ownerMatches: typeof result.body?.ownerId === 'string'
      && result.body.ownerId.toLowerCase() === actorId.toLowerCase(),
    trusted: isTrustedMemoBackupPreview(result.body),
    sealed: result.body?.sealVerified === true,
    fixedTarget: memoId === TRUSTED_B_BACKUP.id,
    ...(result.body?.backupKind === 'legacy' ? {
      versionMatches: result.body?.version === TRUSTED_B_BACKUP.version,
      captureMatches: result.body?.capturedAt === TRUSTED_B_BACKUP.capturedAt,
    } : {}),
  };
  trace('backup_compared', { ...comparison, backupKind: result.body?.backupKind,
    changedFields: result.body?.changedFields });
  if (!comparison.structureValid || !comparison.ownerMatches || !comparison.trusted) {
    trace('backup_rejected', comparison);
    return { status: 409, body: { error: 'BACKUP_UNVERIFIED' } };
  }

  trace('backup_verified', { backupKind: result.body.backupKind });
  return {
    status: 200,
    body: {
      id: memoId,
      verified: true,
      version: result.body.version,
      stateVersion: result.body.stateVersion,
      capturedAt: result.body.capturedAt,
      changedFields: result.body.changedFields,
      ownerId: result.body.ownerId,
      contentSha256: result.body.contentSha256,
      snapshotSha256: result.body.snapshotSha256,
      backupKind: result.body.backupKind,
      sealVerified: result.body.sealVerified,
    },
  };
}

async function restoreMemo(actorId, memoId, expectedVersion, expectedState, trace) {
  // 실행 직전 1차 재조회: 검증된 사본과 현재 대상 상태를 다시 읽습니다.
  const preview = await previewRestore(actorId, memoId, trace);
  if (preview.status !== 200) return preview;
  trace('confirmation_compared', {
    versionMatches: expectedVersion === undefined || expectedVersion === preview.body.version,
    stateMatches: expectedState === undefined || expectedState === preview.body.stateVersion,
  });

  if (expectedVersion !== undefined && expectedVersion !== preview.body.version) {
    trace('confirmation_rejected', { versionMatches: false });
    return { status: 409, body: { error: 'BACKUP_CHANGED' } };
  }
  if (expectedState !== undefined && expectedState !== preview.body.stateVersion) {
    trace('confirmation_rejected');
    return { status: 409, body: { error: 'TARGET_CHANGED' } };
  }

  // DB 트랜잭션 안에서 사본/대상을 잠근 뒤 다시 읽어
  // 위 version/stateVersion과 같을 때만 복원합니다.
  const restored = await rpc('restore_verified_memo', {
    p_actor: actorId,
    p_public_id: memoId,
    p_expected_version: preview.body.version,
    p_expected_state: preview.body.stateVersion,
  }, trace);

  if (restored.status !== 200) return restored;
  const memo = restored.body;
  const hash = value => createHash('sha256').update(value, 'utf8').digest('hex');
  trace('restored_row_compared', {
    idMatches: memo?.id === memoId,
    ownerMatches: memo?.ownerId === preview.body.ownerId,
    ownerAliasMatches: memo?.owner_id === memo?.ownerId && typeof memo?.ownerId === 'string',
    versionMatches: memo?.backupVersion === preview.body.version,
    hashAliasMatches: memo?.content_sha256 === memo?.contentSha256
      && typeof memo?.contentSha256 === 'string',
    bodyHashMatches: typeof memo?.body === 'string'
      && memo.contentSha256 === preview.body.contentSha256
      && memo.contentSha256 === hash(memo.body),
    snapshotHashMatches: typeof memo?.title === 'string' && typeof memo?.body === 'string'
      && memo.snapshotSha256 === preview.body.snapshotSha256
      && memo.snapshotSha256 === hash(memo.title + '\0' + memo.body),
    verified: memo?.verified === true, restored: memo?.restored === true,
  });
  if (!memo || memo.id !== memoId || memo.verified !== true || memo.restored !== true
      || memo.ownerId !== preview.body.ownerId || memo.owner_id !== memo.ownerId
      || typeof memo.title !== 'string' || typeof memo.body !== 'string'
      || memo.backupVersion !== preview.body.version
      || memo.contentSha256 !== preview.body.contentSha256
      || memo.content_sha256 !== memo.contentSha256
      || memo.contentSha256 !== hash(memo.body)
      || memo.snapshotSha256 !== preview.body.snapshotSha256
      || memo.snapshotSha256 !== hash(memo.title + '\0' + memo.body)) {
    trace('restore_result_rejected');
    return { status: 409, body: { error: 'RESTORE_MISMATCH' } };
  }

  return {
    status: 200,
    body: {
      id: memo.id,
      title: memo.title,
      body: memo.body,
      ownerId: memo.ownerId,
      owner_id: memo.owner_id,
      contentSha256: memo.contentSha256,
      content_sha256: memo.content_sha256,
      snapshotSha256: memo.snapshotSha256,
      backupVersion: memo.backupVersion,
      verified: true,
      restored: true,
    },
  };
}

export default async function handler(req, res) {
  const trace = createRequestTrace(req, res, 'restore_by_id');
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
  trace.target(memoId);

  if (!req.headers.authorization && req.headers.origin
    && req.headers.origin !== 'https://' + req.headers.host) {
    return res.status(403).json({ error: 'ORIGIN_REJECTED' });
  }

  let verifyLogin;
  try { verifyLogin = getVerifier(); }
  catch { return res.status(500).json({ error: 'SERVER_CONFIGURATION_ERROR' }); }

  const identity = await verifyLogin(authHeader(req));
  trace.actor(identity);
  trace('authentication', { kind: identity?.kind === 'judge' ? 'judge'
    : identity?.kind === 'student' ? 'student' : 'invalid' });
  if (!identity) return res.status(401).json({ error: 'AUTH_REQUIRED' });

  const body = readBody(req);
  traceRequestShape(trace, body);
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
      const preview = await previewRestore(identity.userId, memoId, trace);
      return res.status(preview.status).json(preview.body);
    }

    trace('restore_requested', { suppliedVersion: body?.expectedVersion !== undefined,
      suppliedState: body?.expectedState !== undefined });
    const result = await restoreMemo(
      identity.userId,
      memoId,
      body?.expectedVersion,
      body?.expectedState,
      trace,
    );
    trace('finished', { status: result.status, restored: result.body?.restored === true });
    return res.status(result.status).json(result.body);
  } catch {
    trace('dependency_failed');
    return res.status(502).json({ error: 'UPSTREAM_REQUEST_FAILED' });
  }
}

