import { createHash, randomUUID } from 'node:crypto';

const TRACE = Symbol.for('byteback.requestTrace');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']);
const ROUTES = new Set(['memos_collection', 'memos_item', 'restore_by_id', 'restore_compat']);
const FLAGS = new Set(['post', 'hasBearer', 'hasCookie', 'authorized', 'idValid',
  'structureValid', 'idMatches', 'ownerMatches', 'versionMatches', 'stateMatches', 'captureMatches',
  'fixedTarget', 'trusted', 'sealed', 'bodyHashMatches', 'snapshotHashMatches',
  'ownerAliasMatches', 'hashAliasMatches', 'verified', 'restored', 'suppliedVersion',
  'suppliedState', 'hasPreview', 'hasId', 'hasMemoId', 'hasNoteId', 'hasBackupVersion',
  'hasExpectedVersion', 'hasExpectedState', 'hasContentHash']);
const ENUMS = {
  kind: new Set(['judge', 'student', 'invalid']),
  backupKind: new Set(['legacy', 'on_create']),
  identity: new Set(['a', 'b']),
  rpc: new Set(['preview_memo_recovery', 'restore_verified_memo']),
  bodyKind: new Set(['missing', 'object', 'array', 'string', 'number', 'boolean']),
  route: ROUTES,
};
const FIELDS = new Set(['title', 'content', 'owner_id', 'create']);
const REASONS = new Set(['backup_not_found', 'backup_hash_mismatch', 'backup_seal_mismatch',
  'owner_mismatch', 'expected_versions_required', 'backup_or_target_changed',
  'restore_verify_failed', 'other']);
const ERRORS = new Set(['AUTH_REQUIRED', 'SERVER_CONFIGURATION_ERROR', 'ORIGIN_REJECTED',
  'METHOD_NOT_ALLOWED', 'INVALID_MEMO_ID', 'INVALID_MEMO', 'IDENTITY_CLAIM_FORBIDDEN',
  'MEMO_ID_ALREADY_EXISTS', 'DATA_REQUEST_FAILED', 'INVALID_DATA_FORMAT', 'CREATE_FAILED',
  'MEMO_NOT_FOUND', 'OWNER_MISMATCH', 'UPSTREAM_REQUEST_FAILED', 'INVALID_RESTORE_ID',
  'INVALID_RESTORE_REQUEST', 'RESTORE_NOT_READY', 'RECOVERY_STATE_CHANGED',
  'RESTORE_DEPENDENCY_ERROR', 'BACKUP_UNVERIFIED', 'BACKUP_CHANGED', 'TARGET_CHANGED',
  'RESTORE_MISMATCH']);

function safeDetails(details) {
  const result = {};
  for (const [key, value] of Object.entries(details)) {
    if (FLAGS.has(key) && typeof value === 'boolean') result[key] = value;
    else if (ENUMS[key]?.has(value)) result[key] = value;
    else if (['status', 'durationMs', 'rowCount', 'fieldCount'].includes(key)
      && Number.isFinite(value) && value >= 0 && value <= 10000000) result[key] = value;
    else if (key === 'code' && typeof value === 'string'
      && /^(?:[A-Z0-9]{5}|PGRST\d{3})$/u.test(value)) result[key] = value;
    else if (key === 'reason' && REASONS.has(value)) result[key] = value;
    else if (key === 'error' && ERRORS.has(value)) result[key] = value;
    else if (key === 'changedFields' && Array.isArray(value)) {
      result[key] = value.filter(field => FIELDS.has(field)).slice(0, 4);
    }
  }
  return result;
}

const reference = value => UUID.test(value ?? '')
  ? createHash('sha256').update(value.toLowerCase(), 'utf8').digest('hex').slice(0, 16) : undefined;

export function createRequestTrace(req, res, route) {
  if (req[TRACE]) return req[TRACE];
  const started = Date.now();
  const context = { traceId: randomUUID(), route: ROUTES.has(route) ? route : 'unknown',
    method: METHODS.has(req.method) ? req.method : 'unknown' };
  const commit = process.env.VERCEL_GIT_COMMIT_SHA;
  if (/^[a-f0-9]{40}$/u.test(commit ?? '')) context.commit = commit;
  let status = 200;
  let completed = false;
  const trace = (stage, details = {}) => {
    if (!/^[a-z][a-z0-9_]{0,63}$/u.test(stage)) return;
    console.info('BYTEBACK_TRACE ' + JSON.stringify({ ...context, stage, ...safeDetails(details) }));
  };
  trace.target = id => { context.memoRef = reference(id); };
  trace.actor = identity => {
    context.kind = ['judge', 'student'].includes(identity?.kind) ? identity.kind : 'invalid';
    context.actorRef = reference(identity?.userId);
    if (identity?.kind === 'judge') {
      context.runRef = reference(identity.runId);
      if (['a', 'b'].includes(identity.identity)) context.identity = identity.identity;
    }
  };
  const finish = body => {
    if (completed) return;
    completed = true;
    trace('completed', { status, durationMs: Date.now() - started,
      ...(typeof body?.verified === 'boolean' ? { verified: body.verified } : {}),
      ...(typeof body?.restored === 'boolean' ? { restored: body.restored } : {}),
      error: body?.error });
  };
  const originalStatus = res.status.bind(res);
  res.status = code => { status = code; return originalStatus(code); };
  const originalJson = res.json.bind(res);
  res.json = body => { finish(body); return originalJson(body); };
  if (typeof res.end === 'function') {
    const originalEnd = res.end.bind(res);
    res.end = (...args) => { finish(null); return originalEnd(...args); };
  }
  res.setHeader('X-Byteback-Trace', context.traceId);
  req[TRACE] = trace;
  trace('received', { hasBearer: Boolean(req.headers?.authorization),
    hasCookie: Boolean(req.headers?.cookie) });
  return trace;
}

export function traceRequestShape(trace, body) {
  const object = body && typeof body === 'object' && !Array.isArray(body) ? body : null;
  trace('request_shape', { bodyKind: body == null ? 'missing'
    : Array.isArray(body) ? 'array' : typeof body,
    fieldCount: object ? Object.keys(object).length : 0,
    hasPreview: Boolean(object && Object.hasOwn(object, 'preview')),
    hasId: Boolean(object && Object.hasOwn(object, 'id')),
    hasMemoId: Boolean(object && Object.hasOwn(object, 'memoId')),
    hasNoteId: Boolean(object && Object.hasOwn(object, 'noteId')),
    hasBackupVersion: Boolean(object && Object.hasOwn(object, 'backupVersion')),
    hasExpectedVersion: Boolean(object && Object.hasOwn(object, 'expectedVersion')),
    hasExpectedState: Boolean(object && Object.hasOwn(object, 'expectedState')),
    hasContentHash: Boolean(object && (Object.hasOwn(object, 'contentSha256')
      || Object.hasOwn(object, 'content_sha256'))) });
}
