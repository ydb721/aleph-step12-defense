import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { test } from 'node:test';
import {
  changedFilesFromCommitResponse,
  localCommitFromGitMetadata,
  sameChangedFiles,
  sameSourceText,
} from '../scripts/bundle-changes.mjs';

const SHA = 'a'.repeat(40);
const tempRoot = () => mkdtempSync(join(tmpdir(), 'bundle-gitless-'));
const file = (path, value) => {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, value, 'utf8');
};

test('gitless bundle resolves ordinary, detached, packed-ref, and worktree HEAD metadata', () => {
  const root = tempRoot();
  try {
    const ordinary = join(root, 'ordinary');
    file(join(ordinary, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    file(join(ordinary, '.git', 'refs', 'heads', 'main'), `${SHA}\n`);
    assert.equal(localCommitFromGitMetadata(ordinary), SHA);

    const detached = join(root, 'detached');
    file(join(detached, '.git', 'HEAD'), `${SHA.toUpperCase()}\n`);
    assert.equal(localCommitFromGitMetadata(detached), SHA);

    const packed = join(root, 'packed');
    file(join(packed, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    file(join(packed, '.git', 'packed-refs'), `# pack-refs with: peeled\n${SHA} refs/heads/main\n`);
    assert.equal(localCommitFromGitMetadata(packed), SHA);

    const worktree = join(root, 'worktree');
    const gitDir = join(root, 'metadata', 'worktrees', 'current');
    const common = join(root, 'metadata');
    file(join(worktree, '.git'), `gitdir: ${relative(worktree, gitDir)}\n`);
    file(join(gitDir, 'HEAD'), 'ref: refs/heads/experiment\n');
    file(join(gitDir, 'commondir'), `${relative(gitDir, common)}\n`);
    file(join(common, 'refs', 'heads', 'experiment'), `${SHA}\n`);
    assert.equal(localCommitFromGitMetadata(worktree), SHA);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('gitless bundle fails closed for missing metadata and malformed commit files', () => {
  const root = tempRoot();
  try {
    assert.throws(() => localCommitFromGitMetadata(root), /\.git 메타데이터/u);
    const missingHead = join(root, 'missing-head');
    mkdirSync(join(missingHead, '.git'), { recursive: true });
    assert.throws(() => localCommitFromGitMetadata(missingHead));
    file(join(root, '.git'), 'not a git worktree pointer\n');
    assert.throws(() => localCommitFromGitMetadata(root), /Git worktree/u);
    assert.throws(() => changedFilesFromCommitResponse({ files: [] }), /변경 파일/u);
    assert.throws(() => changedFilesFromCommitResponse({ files: [{ filename: 'a' }, { filename: 'a' }] }), /형식/u);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('gitless bundle keeps a sorted, exact first-parent file comparison', () => {
  const fromCommit = changedFilesFromCommitResponse({ files: [{ filename: 'b.mjs' }, { filename: 'a.mjs' }] });
  assert.deepEqual(fromCommit, ['a.mjs', 'b.mjs']);
  assert.equal(sameChangedFiles(fromCommit, ['a.mjs', 'b.mjs']), true);
  assert.equal(sameChangedFiles(fromCommit, ['b.mjs', 'a.mjs']), false);
});

test('committed source comparison permits Windows line endings but rejects code changes', () => {
  assert.equal(sameSourceText('export const value = 1;\r\n', 'export const value = 1;\n'), true);
  assert.equal(sameSourceText('export const value = 2;\n', 'export const value = 1;\n'), false);
  assert.equal(sameSourceText(null, 'export const value = 1;\n'), false);
});
