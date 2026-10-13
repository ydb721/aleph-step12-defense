import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const root = resolve(import.meta.dirname, '..');
export const MANIFEST = 'policy/verified-policy.json';

const SHA = /^[0-9a-f]{40}$/u;
const KEY = /^[A-Za-z][A-Za-z0-9_]{0,63}$/u;

const gitRaw = (...args) => execFileSync('git', ['-C', root, ...args], {
  encoding: 'utf8',
  timeout: 10000,
  maxBuffer: 8 * 1024 * 1024,
  windowsHide: true,
  stdio: ['ignore', 'pipe', 'ignore'],
});

export const git = (...args) => gitRaw(...args).trim();

const stop = (message) => { throw new Error(message); };
const normalizeText = (value) => value.replace(/\r\n/gu, '\n');

function policySubset(json, keys) {
  return JSON.stringify(Object.fromEntries(keys.map((key) => [key, json[key] ?? null])));
}

export function loadVerifiedPolicy() {
  const manifestPath = join(root, MANIFEST);
  if (!existsSync(manifestPath)) stop(`검증된 정책 사본 목록(${MANIFEST})이 없습니다.`);

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    stop(`${MANIFEST}를 읽을 수 없습니다.`);
  }

  if (manifest?.schema !== 'aleph.policy.verified.v1'
      || !SHA.test(manifest.verifiedCommit ?? '')
      || !manifest.files || typeof manifest.files !== 'object') {
    stop(`${MANIFEST}의 형식이 맞지 않습니다.`);
  }

  try {
    git('cat-file', '-e', `${manifest.verifiedCommit}^{commit}`);
  } catch {
    stop(`사본 커밋 ${manifest.verifiedCommit.slice(0, 12)}을 이 저장소에서 찾을 수 없습니다.`);
  }

  const entries = Object.entries(manifest.files).map(([path, spec]) => {
    const blob = spec?.blob;
    const policyKeys = spec?.policyKeys ?? null;

    if (!SHA.test(blob ?? '') || path.includes('..') || path.startsWith('/')
        || (policyKeys !== null && (!Array.isArray(policyKeys) || !policyKeys.length
          || !policyKeys.every((key) => KEY.test(key)) || !path.endsWith('.json')))) {
      stop(`${MANIFEST}의 파일 항목 형식이 맞지 않습니다: ${path}`);
    }

    let actualBlob;
    let baseline;
    try {
      actualBlob = git('rev-parse', `${manifest.verifiedCommit}:${path}`);
      baseline = gitRaw('show', `${manifest.verifiedCommit}:${path}`);
    } catch {
      stop(`사본 커밋에 ${path}가 없습니다.`);
    }

    if (actualBlob !== blob) {
      stop(`사본 검증 실패: ${path}의 Git 지문이 목록과 다릅니다.`);
    }

    return { path, blob, policyKeys, baseline };
  });

  if (!entries.length) stop('검증된 정책 파일 목록이 비어 있습니다.');
  return { manifest, entries };
}

export function comparePolicy(policy) {
  return policy.entries.map((entry) => {
    const currentPath = join(root, entry.path);
    if (!existsSync(currentPath)) return { ...entry, status: 'missing', changedKeys: null };

    const currentText = readFileSync(currentPath, 'utf8');

    if (entry.policyKeys) {
      let currentJson;
      let baselineJson;
      try {
        currentJson = JSON.parse(currentText);
        baselineJson = JSON.parse(entry.baseline);
      } catch {
        return { ...entry, status: 'changed', changedKeys: ['JSON_PARSE_ERROR'] };
      }

      const changedKeys = entry.policyKeys.filter((key) =>
        JSON.stringify(currentJson[key] ?? null) !== JSON.stringify(baselineJson[key] ?? null));

      return {
        ...entry,
        status: changedKeys.length ? 'changed' : 'same',
        changedKeys,
      };
    }

    const same = normalizeText(currentText) === normalizeText(entry.baseline);
    return { ...entry, status: same ? 'same' : 'changed', changedKeys: null };
  });
}

export function printPolicyDiff(policy, results) {
  const lines = [
    `복원 기준: ${policy.manifest.label}`,
    `검증 커밋: ${policy.manifest.verifiedCommit}`,
    `사본 검증: 통과 (${policy.entries.length}개 파일의 Git 지문 일치)`,
    '',
    '현재 시험 정책과의 차이:',
  ];

  for (const item of results) {
    if (item.status === 'same') {
      lines.push(`  같음    ${item.path}`);
    } else if (item.status === 'missing') {
      lines.push(`  삭제됨  ${item.path}`);
    } else if (item.changedKeys?.length) {
      lines.push(`  변경됨  ${item.path} (정책 항목: ${item.changedKeys.join(', ')})`);
    } else {
      lines.push(`  변경됨  ${item.path}`);
    }
  }

  const changed = results.filter((item) => item.status !== 'same');
  lines.push('', changed.length
    ? `요약: ${changed.length}개 정책 파일/항목이 검증 사본과 다릅니다.`
    : '요약: 검증 사본과 정책 차이가 없습니다.');
  lines.push('이 명령은 읽기 전용이며 실제 정책을 수정하지 않습니다.');

  process.stdout.write(`${lines.join('\n')}\n`);
  return changed;
}
