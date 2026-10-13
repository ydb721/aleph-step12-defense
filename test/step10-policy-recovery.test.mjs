import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  RECOVERY_INCIDENT_AT,
  TRUSTED_POLICY_SHA256,
  previewPolicyRestore,
  recoverTestPolicyFile,
  restoreTestPolicy,
  verifyPolicyBackup,
} from '../src/recovery/policy.mjs';

const safeRaw = `{
  "schema": "aleph.recovery.policy-backup.v1",
  "serviceId": "notes",
  "capturedAt": "2026-10-12T00:00:00.000Z",
  "verifiedAt": "2026-10-12T00:05:00.000Z",
  "policy": {
    "version": "stage9_verified",
    "ownerOnly": true,
    "rules": [
      "device_registered",
      "step_up_required",
      "resource_scope",
      "burst_read_revocation"
    ]
  }
}
`;
const compromised = () => ({
  schema: 'aleph.recovery.test-policy.v1',
  services: {
    notes: { version: 'unsafe_v2', ownerOnly: false, rules: [] },
    otherService: { version: 'unchanged', ownerOnly: true, rules: ['keep_existing'] },
  },
  audit: [{ id: 'historic', kind: 'preserve' }],
});

test('검증된 사본으로 복원할 버전과 변경 범위를 미리 보여줌', () => {
  const current = compromised();
  const preview = previewPolicyRestore({
    current,
    backupRaw: safeRaw,
    trustedSha256: TRUSTED_POLICY_SHA256,
    incidentAt: RECOVERY_INCIDENT_AT,
  });
  assert.equal(preview.currentVersion, 'unsafe_v2');
  assert.equal(preview.restoreVersion, 'stage9_verified');
  assert.deepEqual(preview.changedPaths, [
    'services.notes.version',
    'services.notes.ownerOnly',
    'services.notes.rules',
  ]);

  const { restored } = restoreTestPolicy({
    current,
    backupRaw: safeRaw,
    trustedSha256: TRUSTED_POLICY_SHA256,
    incidentAt: RECOVERY_INCIDENT_AT,
    confirmedPlanSha256: preview.planSha256,
  });
  assert.equal(restored.services.notes.ownerOnly, true);
  assert.deepEqual(restored.services.otherService, current.services.otherService);
  assert.deepEqual(restored.audit, current.audit);
});

test('사본 지문이 틀리거나 침해 전 검증이 아니면 복원을 거부', () => {
  assert.throws(() => verifyPolicyBackup(
    safeRaw, '0'.repeat(64), RECOVERY_INCIDENT_AT,
  ), /UNVERIFIED_POLICY_BACKUP/);

  assert.throws(() => verifyPolicyBackup(
    safeRaw, TRUSTED_POLICY_SHA256, '2026-10-12T00:04:00.000Z',
  ), /NOT_VERIFIED_BEFORE_INCIDENT/);
});

test('미리보기 후 사본이 변조되거나 삭제되면 적용 전 중단하고 시험 정책은 그대로 보존', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-recovery-lab-'));
  const currentPath = join(dir, 'test-policy.json');
  const backupPath = join(dir, 'safe-policy.json');

  try {
    const original = compromised();
    await writeFile(currentPath, JSON.stringify(original, null, 2) + '\n');
    await writeFile(backupPath, safeRaw);

    const first = await recoverTestPolicyFile({
      currentPath,
      backupPath,
      trustedSha256: TRUSTED_POLICY_SHA256,
      incidentAt: RECOVERY_INCIDENT_AT,
    });

    await writeFile(backupPath, safeRaw.replace('stage9_verified', 'fake_version'));
    await assert.rejects(
      recoverTestPolicyFile({
        currentPath,
        backupPath,
        trustedSha256: TRUSTED_POLICY_SHA256,
        incidentAt: RECOVERY_INCIDENT_AT,
        confirm: first.preview.planSha256,
      }),
      /UNVERIFIED_POLICY_BACKUP/,
    );
    assert.deepEqual(JSON.parse(await readFile(currentPath, 'utf8')), original);

    await writeFile(backupPath, safeRaw);
    await unlink(backupPath);
    await assert.rejects(
      recoverTestPolicyFile({
        currentPath,
        backupPath,
        trustedSha256: TRUSTED_POLICY_SHA256,
        incidentAt: RECOVERY_INCIDENT_AT,
        confirm: first.preview.planSha256,
      }),
      /UNVERIFIED_POLICY_BACKUP/,
    );
    assert.deepEqual(JSON.parse(await readFile(currentPath, 'utf8')), original);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('정상 사본은 시험 정책 한 구역만 복원하고 다른 서비스와 감사 이력을 보존', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-recovery-lab-'));
  const currentPath = join(dir, 'test-policy.json');
  const backupPath = join(dir, 'safe-policy.json');

  try {
    const original = compromised();
    await writeFile(currentPath, JSON.stringify(original, null, 2) + '\n');
    await writeFile(backupPath, safeRaw);

    const first = await recoverTestPolicyFile({
      currentPath,
      backupPath,
      trustedSha256: TRUSTED_POLICY_SHA256,
      incidentAt: RECOVERY_INCIDENT_AT,
    });

    const done = await recoverTestPolicyFile({
      currentPath,
      backupPath,
      trustedSha256: TRUSTED_POLICY_SHA256,
      incidentAt: RECOVERY_INCIDENT_AT,
      confirm: first.preview.planSha256,
    });
    assert.equal(done.applied, true);

    const after = JSON.parse(await readFile(currentPath, 'utf8'));
    assert.equal(after.services.notes.version, 'stage9_verified');
    assert.equal(after.services.notes.ownerOnly, true);
    assert.deepEqual(after.services.otherService, original.services.otherService);
    assert.deepEqual(after.audit, original.audit);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
