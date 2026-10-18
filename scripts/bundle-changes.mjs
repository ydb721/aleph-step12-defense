import { existsSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const SHA = /^[a-f0-9]{40}$/iu;
const REF = /^refs\/[A-Za-z0-9._/-]+$/u;
const text = path => readFileSync(path, 'utf8').trim();
const fail = message => { throw new Error(message); };

function gitDirectories(root) {
  const dotGit = join(root, '.git');
  if (!existsSync(dotGit)) fail('.git 메타데이터에 접근할 수 없습니다.');
  let gitDir = dotGit;
  if (!statSync(dotGit).isDirectory()) {
    const pointer = /^gitdir:\s*(.+)$/mu.exec(text(dotGit));
    if (!pointer) fail('Git worktree 경로를 확인할 수 없습니다.');
    gitDir = resolve(root, pointer[1]);
  }
  if (!existsSync(gitDir)) fail('Git worktree 경로를 확인할 수 없습니다.');
  const commonDirFile = join(gitDir, 'commondir');
  return { gitDir, commonDir: existsSync(commonDirFile) ? resolve(gitDir, text(commonDirFile)) : gitDir };
}

function shaFromRef({ gitDir, commonDir }, ref) {
  if (!REF.test(ref) || ref.split('/').includes('..')) fail('Git HEAD 참조 형식이 올바르지 않습니다.');
  for (const directory of [gitDir, commonDir]) {
    const loose = join(directory, ref);
    if (existsSync(loose)) return text(loose);
    const packed = join(directory, 'packed-refs');
    if (!existsSync(packed)) continue;
    const line = text(packed).split(/\r?\n/u).find(entry => entry
      && !entry.startsWith('#') && !entry.startsWith('^') && entry.endsWith(` ${ref}`));
    if (line) return line.slice(0, line.indexOf(' '));
  }
  fail('Git HEAD 참조를 찾을 수 없습니다.');
}

export function localCommitFromGitMetadata(root) {
  const directories = gitDirectories(root);
  const head = text(join(directories.gitDir, 'HEAD'));
  const sha = head.startsWith('ref: ') ? shaFromRef(directories, head.slice(5)) : head;
  if (!SHA.test(sha)) fail('Git HEAD SHA 형식이 올바르지 않습니다.');
  return sha.toLowerCase();
}

export function changedFilesFromCommitResponse(commit) {
  if (!commit || typeof commit !== 'object' || Array.isArray(commit)
      || !Array.isArray(commit.files) || !commit.files.length) {
    fail('GitHub Commit API의 변경 파일 목록이 없습니다.');
  }
  const files = commit.files.map(item => item?.filename);
  if (files.some(file => typeof file !== 'string' || !file || file.length > 4096)
      || new Set(files).size !== files.length) {
    fail('GitHub Commit API의 변경 파일 목록 형식이 올바르지 않습니다.');
  }
  return [...files].sort();
}

export function sameChangedFiles(left, right) {
  return left.length === right.length && left.every((file, index) => file === right[index]);
}
