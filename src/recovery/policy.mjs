import { createHash, randomUUID } from 'node:crypto';
import { lstat, readFile, realpath, rename, unlink, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve, sep } from 'node:path';

const HEX64 = /^[a-f0-9]{64}$/u;
const ID = /^[a-z][a-z0-9_:-]{0,63}$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

export const TRUSTED_POLICY_SHA256 = 'a28720a1eac019a429c4923ff6dfbced56c931233a53e99196c1e728bf515ac5';
export const RECOVERY_INCIDENT_AT = '2026-10-13T00:00:00.000Z';

export const sha256 = (value) => {
  const canonical = typeof value === 'string' ? value.replace(/\r\n/gu, '\n') : value;
  return createHash('sha256').update(canonical).digest('hex');
};
const fail = (code) => { throw new Error(code); };

function checkedTime(value) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) fail('INVALID_BACKUP_TIME');
  const n = Date.parse(value);
  if (!Number.isFinite(n) || new Date(n).toISOString() !== value) fail('INVALID_BACKUP_TIME');
  return n;
}

function checkedPolicy(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'ownerOnly,rules,version'
      || typeof value.version !== 'string' || !ID.test(value.version)
      || typeof value.ownerOnly !== 'boolean'
      || !Array.isArray(value.rules) || value.rules.length > 20
      || value.rules.some((rule) => typeof rule !== 'string' || !ID.test(rule))
      || new Set(value.rules).size !== value.rules.length) {
    fail('INVALID_POLICY_STRUCTURE');
  }
  return structuredClone(value);
}

export function verifyPolicyBackup(raw, expectedSha256, incidentAt) {
  if (typeof raw !== 'string' || raw.length > 65536
      || typeof expectedSha256 !== 'string' || !HEX64.test(expectedSha256)
      || sha256(raw) !== expectedSha256) {
    fail('UNVERIFIED_POLICY_BACKUP');
  }

  let backup;
  try { backup = JSON.parse(raw); } catch { fail('INVALID_POLICY_BACKUP'); }

  if (!backup || Object.keys(backup).sort().join(',') !==
      'capturedAt,policy,schema,serviceId,verifiedAt'
      || backup.schema !== 'aleph.recovery.policy-backup.v1'
      || backup.serviceId !== 'notes') {
    fail('INVALID_POLICY_BACKUP');
  }

  const capturedAt = checkedTime(backup.capturedAt);
  const verifiedAt = checkedTime(backup.verifiedAt);
  const incident = checkedTime(incidentAt);
  if (capturedAt > verifiedAt || verifiedAt >= incident) fail('NOT_VERIFIED_BEFORE_INCIDENT');

  return {
    ...backup,
    policy: checkedPolicy(backup.policy),
    sha256: expectedSha256,
  };
}

function checkedCurrent(current) {
  if (!current || typeof current !== 'object' || Array.isArray(current)
      || current.schema !== 'aleph.recovery.test-policy.v1'
      || !current.services || typeof current.services !== 'object' || Array.isArray(current.services)
      || !Object.hasOwn(current.services, 'notes')
      || !Array.isArray(current.audit)) {
    fail('INVALID_TEST_POLICY');
  }
  checkedPolicy(current.services.notes);
  return structuredClone(current);
}

export function previewPolicyRestore({ current, backupRaw, trustedSha256, incidentAt }) {
  const state = checkedCurrent(current);
  const backup = verifyPolicyBackup(backupRaw, trustedSha256, incidentAt);
  const before = checkedPolicy(state.services.notes);
  const after = backup.policy;

  const changes = Object.keys(after)
    .filter((key) => JSON.stringify(before[key]) !== JSON.stringify(after[key]))
    .map((key) => ({
      path: 'services.notes.' + key,
      before: before[key],
      after: after[key],
    }));

  const currentSha256 = sha256(JSON.stringify(state));
  const planSha256 = sha256(JSON.stringify({
    currentSha256,
    backupSha256: backup.sha256,
    targetService: backup.serviceId,
    targetPolicy: after,
  }));

  return {
    schema: 'aleph.recovery.policy-preview.v1',
    serviceId: backup.serviceId,
    currentVersion: before.version,
    restoreVersion: after.version,
    backupSha256: backup.sha256,
    currentSha256,
    planSha256,
    changedPaths: changes.map((item) => item.path),
    changes,
  };
}

export function restoreTestPolicy({
  current, backupRaw, trustedSha256, incidentAt, confirmedPlanSha256,
}) {
  const preview = previewPolicyRestore({ current, backupRaw, trustedSha256, incidentAt });
  if (!HEX64.test(confirmedPlanSha256 ?? '') || confirmedPlanSha256 !== preview.planSha256) {
    fail('POLICY_PLAN_CONFIRMATION_REQUIRED');
  }

  const restored = checkedCurrent(current);
  restored.services.notes = verifyPolicyBackup(
    backupRaw, trustedSha256, incidentAt,
  ).policy;

  return { preview, restored };
}

async function safeRegularFile(path) {
  let meta;
  try { meta = await lstat(path); } catch { fail('UNVERIFIED_POLICY_BACKUP'); }
  if (!meta.isFile() || meta.isSymbolicLink()) fail('UNSAFE_POLICY_FILE');
  return readFile(path, 'utf8');
}

async function rereadVerifiedBackup(path, trustedSha256, incidentAt) {
  const raw = await safeRegularFile(path);
  verifyPolicyBackup(raw, trustedSha256, incidentAt);
  return raw;
}

function assertRecoveryPaths(currentPath, backupPath) {
  if (basename(currentPath) !== 'test-policy.json' || basename(backupPath) !== 'safe-policy.json') {
    fail('TEST_POLICY_PATH_REQUIRED');
  }
  if (resolve(dirname(currentPath)) !== resolve(dirname(backupPath))) {
    fail('TEST_POLICY_PATH_REQUIRED');
  }
}

export async function recoverTestPolicyFile({
  currentPath,
  backupPath,
  trustedSha256,
  incidentAt,
  confirm = null,
}) {
  assertRecoveryPaths(currentPath, backupPath);

  const currentRaw = await safeRegularFile(currentPath);
  const backupRaw = await rereadVerifiedBackup(backupPath, trustedSha256, incidentAt);

  let current;
  try { current = JSON.parse(currentRaw); } catch { fail('INVALID_TEST_POLICY'); }

  const preview = previewPolicyRestore({ current, backupRaw, trustedSha256, incidentAt });
  if (confirm == null) return { preview, applied: false };

  // 미리보기 뒤 적용 시 사본을 디스크에서 다시 읽어 재검증합니다.
  const rereadBackup = await rereadVerifiedBackup(backupPath, trustedSha256, incidentAt);
  if (rereadBackup !== backupRaw) fail('UNVERIFIED_POLICY_BACKUP');

  const { restored } = restoreTestPolicy({
    current,
    backupRaw: rereadBackup,
    trustedSha256,
    incidentAt,
    confirmedPlanSha256: confirm,
  });

  // 실제 쓰기 직전 현재 시험 정책이 바뀌지 않았는지도 확인합니다.
  if (sha256(await safeRegularFile(currentPath)) !== sha256(currentRaw)) {
    fail('POLICY_CHANGED_DURING_RESTORE');
  }

  const dir = await realpath(dirname(currentPath));
  const temp = join(dir, '.test-policy-' + randomUUID() + '.tmp');
  try {
    await writeFile(temp, JSON.stringify(restored, null, 2) + '\n', {
      flag: 'wx',
      mode: 0o600,
    });

    // 원자적 교체 직전에 사본을 다시 한 번 읽어 검증합니다.
    const finalBackup = await rereadVerifiedBackup(backupPath, trustedSha256, incidentAt);
    if (finalBackup !== rereadBackup) fail('UNVERIFIED_POLICY_BACKUP');

    if (sha256(await safeRegularFile(currentPath)) !== sha256(currentRaw)) {
      fail('POLICY_CHANGED_DURING_RESTORE');
    }

    await rename(temp, currentPath);
  } finally {
    await unlink(temp).catch((error) => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }

  return { preview, applied: true };
}
