import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

export const root = resolve(import.meta.dirname, '..');
export const MANIFEST = 'policy/verified-policy.json';

const SHA = /^[0-9a-f]{40}$/u;
const KEY = /^[A-Za-z][A-Za-z0-9_]{0,63}$/u;

const TRUSTED_VERIFIED_COMMIT = '847972a71c0f469c330f58b67ea1dbc3893cfec3';
const TRUSTED_FILES = {
  'src/decider.mjs': { blob: 'df9bcb24741a83ed4a66e41cae952b46e79be4f5' },
  'src/detect.mjs': { blob: '721e79eceed50790a392c33d69e5d60f6133a107' },
  'src/verify-login.mjs': { blob: '784ec5af7067e01c6b7f83cf423db0b8c63d9e09' },
  'src/resource-ids.mjs': { blob: '4dc0b160f92cdb7eff898da6d1cd0eba7259922e' },
  'api/memos.js': { blob: '3a5b9ddca731c96db99d794e0674e3f9dc00e996' },
  'api/notices.js': { blob: '99ff277f3c4104c177d3632e49d878c8e464945a' },
  'aleph.config.json': {
    blob: '109911e22c9bcc5431ba2c0b3fc2befbde4a076f',
    policyKeys: ['identityProvider', 'allowedRoutes', 'originalApiUrl'],
  },
  'vercel.json': { blob: 'c9946daa21a070d4809cd24711e59d59f0a5f995' },
};

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

function sameTrustedFiles(files) {
  if (!files || typeof files !== 'object' || Array.isArray(files)) return false;
  const actualPaths = Object.keys(files).sort();
  const trustedPaths = Object.keys(TRUSTED_FILES).sort();
  if (JSON.stringify(actualPaths) !== JSON.stringify(trustedPaths)) return false;

  return trustedPaths.every((path) => {
    const actual = files[path];
    const trusted = TRUSTED_FILES[path];
    if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
    if (actual.blob !== trusted.blob) return false;
    return JSON.stringify(actual.policyKeys ?? null) === JSON.stringify(trusted.policyKeys ?? null);
  });
}

export function assertTrustedPolicyManifest(manifest) {
  if (manifest?.verifiedCommit !== TRUSTED_VERIFIED_COMMIT || !sameTrustedFiles(manifest?.files)) {
    stop('검증된 정책 사본 목록이 신뢰한 9단계 저장점과 다릅니다.');
  }
  return true;
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

  // 사본 목록 자체도 신뢰한 9단계 저장점과 정확히 일치해야 합니다.
  // 파일 목록/지문/검증 커밋이 하나라도 바뀌면 복원 전에 중단합니다.
  assertTrustedPolicyManifest(manifest);

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
