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

function verifiedPolicyFingerprint(policy) {
  return createHash('sha256').update(JSON.stringify([
    policy.manifest.verifiedCommit,
    ...policy.entries.map((entry) => [entry.path, entry.blob, entry.policyKeys ?? null]),
  ])).digest('hex');
}

function changeSetId(policy, changed) {
  const payload = [
    policy.manifest.verifiedCommit,
    ...changed.map((item) => [item.path, currentFingerprint(item), item.changedKeys ?? null]),
  ];
  return createHash('sha256').update(JSON.stringify(payload)).digest('hex').slice(0, 12);
}

function rereadAndVerify(expectedFingerprint) {
  // 복원 실행 때마다 디스크의 사본 목록을 다시 읽고 Git의 검증 커밋/파일 지문을 재검증합니다.
  // 사본이 사라졌거나 한 항목이라도 바뀌면 loadVerifiedPolicy()가 예외를 내고 쓰기 전에 중단됩니다.
  const fresh = loadVerifiedPolicy();
  if (verifiedPolicyFingerprint(fresh) !== expectedFingerprint) {
    throw new Error('검증된 정책 사본이 미리보기 뒤 변경되었습니다.');
  }
  return fresh;
}

try {
  // 1) 미리보기용 첫 읽기/검증.
  const policy = loadVerifiedPolicy();
  const policyFingerprint = verifiedPolicyFingerprint(policy);
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
    } else {
      // 2) 적용 요청을 받으면 사본을 디스크에서 다시 읽어 독립적으로 재검증합니다.
      const reread = rereadAndVerify(policyFingerprint);
      const rereadResults = comparePolicy(reread);
      const rereadChanged = rereadResults.filter((item) => item.status !== 'same');
      const rereadId = changeSetId(reread, rereadChanged);

      if (confirm !== id || confirm !== rereadId) {
        throw new Error(`확인 번호가 맞지 않습니다(현재 ${rereadId}). 미리보기를 다시 실행해 주세요.`);
      }

      // 3) 실제 쓰기 직전 한 번 더 사본을 다시 읽어 검증합니다.
      const finalPolicy = rereadAndVerify(policyFingerprint);
      const finalResults = comparePolicy(finalPolicy);
      const finalChanged = finalResults.filter((item) => item.status !== 'same');
      const finalId = changeSetId(finalPolicy, finalChanged);
      if (confirm !== finalId) {
        throw new Error('정책 또는 검증 사본이 복원 직전에 변경되었습니다.');
      }

      // 모든 대상의 복원 내용과 현재 지문을 먼저 준비하고, 하나라도 바뀌면 쓰기 전에 전부 중단합니다.
      const staged = finalChanged.map((item) => ({
        item,
        target: join(root, item.path),
        before: currentFingerprint(item),
        restored: restoreContent(item),
      }));
      if (staged.some(({ item, before }) => currentFingerprint(item) !== before)) {
        throw new Error('정책이 복원 준비 중 변경되었습니다.');
      }

      const auditRows = [];
      for (const { item, target, before, restored } of staged) {
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
        verifiedCommit: finalPolicy.manifest.verifiedCommit,
        changeSet: finalId,
        files: auditRows,
      })}\n`, 'utf8');

      process.stdout.write(`\n${finalChanged.length}개 정책 파일/항목을 검증 사본으로 되돌렸습니다.\n`);
      process.stdout.write(`${AUDIT_LOG}에는 기존 기록을 지우지 않고 복원 기록을 덧붙였습니다.\n`);
    }
  }
} catch (error) {
  process.stderr.write(`정책 복원 중단: ${error.message}\n`);
  process.exitCode = 1;
}
