import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  RECOVERY_INCIDENT_AT,
  TRUSTED_POLICY_SHA256,
  previewPolicyRestore,
  verifyPolicyBackup,
} from '../src/recovery/policy.mjs';

const root = resolve(import.meta.dirname, '..');
const backupPath = resolve(root, 'policy', 'safe-policy.json');
const currentPath = resolve(root, 'policy', 'test-policy.json');

try {
  const [backupRaw, currentRaw] = await Promise.all([
    readFile(backupPath, 'utf8'),
    readFile(currentPath, 'utf8'),
  ]);

  verifyPolicyBackup(backupRaw, TRUSTED_POLICY_SHA256, RECOVERY_INCIDENT_AT);
  const current = JSON.parse(currentRaw);
  const preview = previewPolicyRestore({
    current,
    backupRaw,
    trustedSha256: TRUSTED_POLICY_SHA256,
    incidentAt: RECOVERY_INCIDENT_AT,
  });

  process.stdout.write([
    '사본 검증: 통과',
    '복원할 버전: ' + preview.restoreVersion,
    '현재 시험 정책 버전: ' + preview.currentVersion,
    '변경 범위: ' + (preview.changedPaths.length ? preview.changedPaths.join(', ') : '없음'),
    '계획 확인값: ' + preview.planSha256,
    '실제 운영 정책은 수정하지 않습니다.',
    '',
  ].join('\n'));
} catch (error) {
  process.stderr.write('정책 비교 중단: ' + (error?.message || 'POLICY_DIFF_FAILED') + '\n');
  process.exitCode = 1;
}
