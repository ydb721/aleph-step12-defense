import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { changedFilesForCommit } from '../scripts/bundle-changes.mjs';

test('submission records root, ordinary and merged changes against the first parent', () => {
  const root = mkdtempSync(join(tmpdir(), 'bundle-changes-'));
  const git = (...args) => execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
  try {
    git('init', '-b', 'main');
    git('config', 'user.name', 'Fixture');
    git('config', 'user.email', 'fixture@invalid.test');
    writeFileSync(join(root, 'baseline.txt'), 'baseline');
    git('add', '.'); git('commit', '-m', 'root');
    assert.deepEqual(changedFilesForCommit(git, git('rev-parse', 'HEAD')), ['baseline.txt']);
    git('checkout', '-b', 'recovery');
    writeFileSync(join(root, 'recovery.txt'), 'recovery');
    git('add', '.'); git('commit', '-m', 'recovery');
    assert.deepEqual(changedFilesForCommit(git, git('rev-parse', 'HEAD')), ['recovery.txt']);
    git('checkout', 'main');
    writeFileSync(join(root, 'other.txt'), 'other work');
    git('add', '.'); git('commit', '-m', 'other work');
    git('merge', '--no-ff', 'recovery', '-m', 'merge recovery');
    assert.deepEqual(changedFilesForCommit(git, git('rev-parse', 'HEAD')), ['recovery.txt']);
    assert.equal(git('show', 'HEAD:other.txt'), 'other work');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
