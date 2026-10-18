import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  changedFilesFromCommitResponse,
  localCommitFromGitMetadata,
  sameChangedFiles,
  sameSourceText,
} from './bundle-changes.mjs';

const root = resolve(import.meta.dirname, '..');
const DEFAULT_NOTES = Object.freeze({
  explanation: 'No local bundle notes were supplied. The bundle distinguishes actual public GET observations from not_run checks and does not claim execution of the official 41 attacks.',
  blockedAt: 'Official 41-attack identifiers and execution evidence were not supplied; unexecuted checks remain not_run.',
});
const bundleNotes = () => {
  try { return JSON.parse(readFileSync(join(root, 'bundle-notes.json'), 'utf8')); }
  catch (error) {
    // bundle-notes.json is intentionally gitignored and absent from a clean
    // judge checkout. A supplied file may refine this text, but is optional.
    if (error?.code === 'ENOENT') return DEFAULT_NOTES;
    throw error;
  }
};
const fail = (message) => { throw new Error(message); };
const secretPattern = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|\bsb_secret_[A-Za-z0-9_-]{12,}|\bsk-[A-Za-z0-9_-]{20,}|\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu;
const repository = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)\/([A-Za-z0-9._-]{1,100})\/?$/iu;
const normalizedRepo = value => {
  const match = typeof value === 'string' && value.length <= 250 && repository.exec(value);
  if (!match) fail('GitHub HTTPS 저장소 주소를 origin으로 등록해 주세요.');
  const repo = match[2].toLowerCase().replace(/\.git$/u, '');
  if (repo === '.' || repo === '..' || repo === '.git' || repo.endsWith('.git')) {
    fail('GitHub HTTPS 저장소 주소를 origin으로 등록해 주세요.');
  }
  return `https://github.com/${match[1].toLowerCase()}/${repo}`;
};
const sameJson = (left, right) => {
  if (left === right) return true;
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object') return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length
      && left.every((item, index) => sameJson(item, right[index]));
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index]
    && sameJson(left[key], right[key]));
};
const fetchPublic = async (url, label) => {
  let response;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try { response = await fetch(url, { method: 'GET', signal: controller.signal, headers: { Accept: 'application/vnd.github+json' } }); }
  catch { fail(`${label} 공개 HTTPS GET에 실패했습니다.`); }
  finally { clearTimeout(timeout); }
  if (!response?.ok) fail(`${label} 공개 HTTPS GET이 HTTP ${response?.status ?? 'network'}로 실패했습니다.`);
  return response;
};
const fetchJson = async (url, label) => {
  const response = await fetchPublic(url, label);
  try { return { body: await response.json(), link: response.headers.get('link') ?? '' }; }
  catch { fail(`${label} 응답 JSON 형식이 올바르지 않습니다.`); }
};
const fetchText = async (url, label) => {
  const response = await fetchPublic(url, label);
  try { return await response.text(); }
  catch { fail(`${label} 응답 본문을 읽을 수 없습니다.`); }
};
const verifyCommittedSource = async (owner, repo, commit, relativePath) => {
  const encodedPath = relativePath.split('/').map(encodeURIComponent).join('/');
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${encodedPath}`;
  const committed = await fetchText(url, `GitHub raw ${relativePath}`);
  const local = readFileSync(join(root, ...relativePath.split('/')), 'utf8');
  if (!sameSourceText(local, committed)) fail(`${relativePath}가 검증된 커밋과 일치하지 않습니다.`);
};
const githubFiles = async (owner, repo, commit) => {
  const files = [];
  let expectedParents = null;
  for (let page = 1; page <= 100; page += 1) {
    const url = `https://api.github.com/repos/${owner}/${repo}/commits/${commit}?per_page=100&page=${page}`;
    const { body, link } = await fetchJson(url, 'GitHub Commit API');
    if (body?.sha?.toLowerCase() !== commit) fail('GitHub Commit API SHA가 로컬 HEAD와 다릅니다.');
    if (!Array.isArray(body.parents)) fail('GitHub Commit API 부모 커밋 형식이 올바르지 않습니다.');
    const parents = body.parents.map(parent => parent?.sha?.toLowerCase());
    if (parents.some(parent => !/^[a-f0-9]{40}$/u.test(parent))) fail('GitHub Commit API 부모 SHA 형식이 올바르지 않습니다.');
    if (expectedParents && !sameJson(expectedParents, parents)) fail('GitHub Commit API 페이지의 부모 정보가 일치하지 않습니다.');
    expectedParents = parents;
    if (!Array.isArray(body.files)) fail('GitHub Commit API의 변경 파일 목록이 누락되었습니다.');
    files.push(...body.files);
    if (!/\brel="next"/u.test(link)) return { parents, changedFiles: changedFilesFromCommitResponse({ files }) };
  }
  fail('GitHub Commit API 변경 파일 페이지 수가 제한을 초과했습니다.');
};
const githubCompareFiles = async (owner, repo, base, head) => {
  const url = `https://api.github.com/repos/${owner}/${repo}/compare/${base}...${head}?per_page=100`;
  const { body, link } = await fetchJson(url, 'GitHub Compare API');
  if (/\brel="next"/u.test(link) || !Array.isArray(body?.files)) {
    fail('GitHub Compare API의 first-parent 변경 파일 목록이 불완전합니다.');
  }
  return changedFilesFromCommitResponse({ files: body.files });
};

try {
  // This bundle records only the checked-out commit. Uncommitted working-tree
  // files are intentionally neither read as submission evidence nor reported clean.
  const commit = localCommitFromGitMetadata(root);
  const localConfig = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
  const repoUrl = normalizedRepo(localConfig.repoUrl);
  const [, owner, repo] = new URL(repoUrl).pathname.split('/');
  const { parents, changedFiles } = await githubFiles(owner, repo, commit);
  const configUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${commit}/aleph.config.json`;
  const { body: config } = await fetchJson(configUrl, 'GitHub raw aleph.config.json');
  if (!sameJson(localConfig, config)) fail('로컬 aleph.config.json과 커밋 설정이 일치하지 않습니다.');
  await Promise.all([
    'scripts/bundle.mjs',
    'scripts/bundle-changes.mjs',
    'src/decider.mjs',
    'src/attack-check.mjs',
  ].map(relativePath => verifyCommittedSource(owner, repo, commit, relativePath)));
  if (parents.length > 1) {
    const firstParentFiles = await githubCompareFiles(owner, repo, parents[0], commit);
    if (!sameChangedFiles(changedFiles, firstParentFiles)) {
      fail('병합 커밋의 변경 파일이 first-parent 기준과 일치하지 않습니다.');
    }
  }
  const notes = bundleNotes();
  if (!Number.isInteger(config.step) || config.step < 1 || config.step > 12) fail('aleph.config.json의 step을 확인해 주세요.');
  if (config.step >= 3 && (!config.identityProvider || typeof config.identityProvider !== 'object'
      || ['issuer', 'audience', 'jwksUrl'].some((key) => typeof config.identityProvider[key] !== 'string'
        || !config.identityProvider[key].trim()))) {
    fail('3단계부터 aleph.config.json의 identityProvider에 발급자·대상·공개키 주소가 필요합니다. 3단계 제작 2를 다시 확인해 주세요.');
  }
  if (config.step >= 5 && (typeof config.originalApiUrl !== 'string'
      || !config.originalApiUrl.startsWith('https://'))) {
    fail('5단계부터 aleph.config.json의 originalApiUrl에 원본 자료 API의 HTTPS 주소가 필요합니다. 5단계 제작 2를 다시 확인해 주세요.');
  }
  if (config.step >= 3 && (!Array.isArray(config.allowedRoutes) || !config.allowedRoutes.length)) {
    fail('3단계부터 aleph.config.json의 allowedRoutes에 자료 API 경로가 필요합니다. 3단계 제작 3을 다시 확인해 주세요.');
  }
  const deciderUrl = pathToFileURL(join(root, 'src', 'decider.mjs'));
  const { RULE_IDS } = await import(deciderUrl.href);
  if (!Array.isArray(RULE_IDS)) fail('src/decider.mjs의 RULE_IDS는 규칙 이름 배열이어야 합니다.');
  const policyRules = [...RULE_IDS];
  if (policyRules.length > 80 || policyRules.some(item => typeof item !== 'string'
      || !/^[a-z][a-z0-9_.-]{0,79}$/iu.test(item)) || new Set(policyRules).size !== policyRules.length) {
    fail('src/decider.mjs의 RULE_IDS 이름과 중복을 확인해 주세요.');
  }
  if (typeof notes.explanation !== 'string' || notes.explanation.trim().length < 10) {
    fail('제공한 bundle-notes.json의 explanation을 확인해 주세요.');
  }
  const checkerUrl = pathToFileURL(join(root, 'src', 'attack-check.mjs'));
  const { runAttackChecks } = await import(checkerUrl.href);
  if (typeof runAttackChecks !== 'function') fail('src/attack-check.mjs가 runAttackChecks를 내보내야 합니다.');
  const attackAttempts = await runAttackChecks(config);
  if (!Array.isArray(attackAttempts) || !attackAttempts.length || attackAttempts.length > 20) {
    fail('직접 실행한 공격 점검 결과 1~20개가 필요합니다.');
  }
  for (const attempt of attackAttempts) {
    if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt)
        || Object.keys(attempt).sort().join(',') !== 'attackId,expected,observed'
        || typeof attempt.attackId !== 'string' || !/^[a-z0-9][a-z0-9_.-]{0,79}$/iu.test(attempt.attackId)
        || typeof attempt.expected !== 'string' || !attempt.expected.trim() || attempt.expected.length > 300
        || typeof attempt.observed !== 'string' || !attempt.observed.trim() || attempt.observed.length > 300) {
      fail('공격 점검 결과에는 attackId·expected·observed만 넣어 주세요.');
    }
  }
  if (new Set(attackAttempts.map(item => item.attackId)).size !== attackAttempts.length) {
    fail('공격 점검 ID가 중복되었습니다.');
  }
  const bundle = {
    schema: 'aleph.defense.submission.v2', step: config.step, commit, repoUrl,
    changedFiles, policyRules,
    attackAttempts, explanation: notes.explanation.trim(), blockedAt: notes.blockedAt ?? null,
    identityProvider: config.identityProvider ?? null, allowedRoutes: config.allowedRoutes ?? [],
    originalApiUrl: config.originalApiUrl ?? null, restoreRoute: config.restoreRoute ?? null,
  };
  if (secretPattern.test(JSON.stringify(bundle))) fail('제출 묶음에 비밀값 또는 연락처로 보이는 내용이 있습니다.');
  mkdirSync(join(root, 'artifacts'), { recursive: true });
  const output = join(root, 'artifacts', 'submission.json');
  writeFileSync(output, `${JSON.stringify(bundle, null, 2)}\n`, { encoding: 'utf8', flag: 'w' });
  process.stdout.write(`제출 묶음 JSON 생성: ${output}\n단계 ${bundle.step} · 커밋 ${commit.slice(0, 12)} · 바뀐 파일 ${changedFiles.length}개 · 규칙 ${policyRules.length}개 · 직접 점검 ${attackAttempts.length}개\n`);
} catch (error) {
  process.stderr.write(`제출 묶음 생성 중 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}
