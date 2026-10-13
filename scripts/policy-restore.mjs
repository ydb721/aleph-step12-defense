import { resolve } from 'node:path';
import {
  RECOVERY_INCIDENT_AT,
  TRUSTED_POLICY_SHA256,
  recoverTestPolicyFile,
} from '../src/recovery/policy.mjs';

const root = resolve(import.meta.dirname, '..');
const currentPath = resolve(root, 'policy', 'test-policy.json');
const backupPath = resolve(root, 'policy', 'safe-policy.json');
const apply = process.argv.includes('--apply');
const confirm = process.argv.find((arg) => arg.startsWith('--confirm='))?.slice('--confirm='.length) ?? null;

try {
  const result = await recoverTestPolicyFile({
    currentPath,
    backupPath,
    trustedSha256: TRUSTED_POLICY_SHA256,
    incidentAt: RECOVERY_INCIDENT_AT,
    confirm: apply ? confirm : null,
  });

  const p = result.preview;
  process.stdout.write([
    '사본 검증: 통과',
    '복원할 버전: ' + p.restoreVersion,
    '현재 시험 정책 버전: ' + p.currentVersion,
    '변경 범위: ' + (p.changedPaths.length ? p.changedPaths.join(', ') : '없음'),
    '계획 확인값: ' + p.planSha256,
    result.applied
      ? '시험 정책 복원 완료. 실제 운영 정책과 감사 이력은 건드리지 않았습니다.'
      : '미리보기만 수행했습니다. 아직 아무것도 바꾸지 않았습니다.',
    !apply && p.changedPaths.length
      ? '실행: npm.cmd run policy:restore -- --apply --confirm=' + p.planSha256
      : '',
    '',
  ].filter(Boolean).join('\n') + '\n');
} catch (error) {
  process.stderr.write('정책 복원 중단: ' + (error?.message || 'POLICY_RECOVERY_FAILED') + '\n');
  process.exitCode = 1;
}
