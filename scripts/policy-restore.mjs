import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { comparePolicy, loadVerifiedPolicy, printPolicyDiff, root } from './policy-lib.mjs';

const AUDIT_LOG = 'policy/restore-audit.log';
const apply = process.argv.includes('--apply');
const confirm = process.argv.find((arg) => arg.startsWith('--confirm='))?.slice('--confirm='.length);

function restoreContent(item) {
  if (!item.policyKeys) return item.baseline;

  const baselineJson = JSON.parse(item.baseline);
  let currentJson = {};
  const currentPath = join(root, item.path);
  if (existsSync(currentPath)) {
    try {
      currentJson = JSON.parse(readFileSync(currentPath, 'utf8'));
    } catch {
      currentJson = {};
    }
  }

  const merged = { ...currentJson };
  for (const key of item.policyKeys) merged[key] = baselineJson[key];
  return `${JSON.stringify(merged, null, 2)}\n`;
}

function currentFingerprint(item) {
  const path = join(root, item.path);
  if (!existsSync(path)) return 'missing';
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function changeSetId(policy, changed) {
  const payload = [
    policy.manifest.verifiedCommit,
    ...changed.map((item) => [item.path, currentFingerprint(item), item.changedKeys ?? null]),
  ];
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex').slice(0, 12);
}

try {
  const policy = loadVerifiedPolicy();
  const results = comparePolicy(policy);
  const changed = printPolicyDiff(policy, results);

  if (!changed.length) {
    process.stdout.write('되돌릴 정책 항목이 없습니다. 아무것도 바꾸지 않았습니다.\n');
  } else {
    const id = changeSetId(policy, changed);

    if (!apply) {
      process.stdout.write(`\n확인 번호: ${id}\n`);
      process.stdout.write('위 변경 범위만 검증 사본으로 되돌릴 수 있습니다. 아직 아무것도 바꾸지 않았습니다.\n');
      process.stdout.write(`실행: npm.cmd run policy:restore -- --apply --confirm=${id}\n`);
    } else if (confirm !== id) {
      throw new Error(`확인 번호가 맞지 않습니다(현재 ${id}). 미리보기를 다시 실행해 주세요.`);
    } else {
      const auditRows = [];

      for (const item of changed) {
        const target = join(root, item.path);
        const before = currentFingerprint(item);
        const restored = restoreContent(item);

        mkdirSync(dirname(target), { recursive: true });
        writeFileSync(target, restored, 'utf8');

        auditRows.push({
          path: item.path,
          before,
          after: createHash('sha256').update(restored).digest('hex'),
          keys: item.changedKeys ?? null,
        });
      }

      appendFileSync(join(root, AUDIT_LOG), `${JSON.stringify({
        at: new Date().toISOString(),
        action: 'policy_restore',
        verifiedCommit: policy.manifest.verifiedCommit,
        changeSet: id,
        files: auditRows,
      })}\n`, 'utf8');

      process.stdout.write(`\n${changed.length}개 정책 파일/항목을 검증 사본으로 되돌렸습니다.\n`);
      process.stdout.write(`${AUDIT_LOG}에는 기존 기록을 지우지 않고 복원 기록을 덧붙였습니다.\n`);
    }
  }
} catch (error) {
  process.stderr.write(`정책 복원 중단: ${error.message}\n`);
  process.exitCode = 1;
}
