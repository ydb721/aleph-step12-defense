import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { assertTrustedPolicyManifest } from '../scripts/policy-lib.mjs';

const manifestPath = resolve(import.meta.dirname, '..', 'policy', 'verified-policy.json');
const clean = () => JSON.parse(readFileSync(manifestPath, 'utf8'));

test('10단계 정책 사본 목록은 고정한 9단계 저장점과 일치함', () => {
  assert.equal(assertTrustedPolicyManifest(clean()), true);
});

test('검증 커밋이 바뀐 사본 목록은 복원 전에 거부', () => {
  const changed = clean();
  changed.verifiedCommit = '0'.repeat(40);
  assert.throws(() => assertTrustedPolicyManifest(changed), /신뢰한 9단계 저장점/);
});

test('파일이 빠지거나 지문이 바뀐 사본 목록은 복원 전에 거부', () => {
  const missing = clean();
  delete missing.files['api/memos.js'];
  assert.throws(() => assertTrustedPolicyManifest(missing), /신뢰한 9단계 저장점/);

  const changed = clean();
  changed.files['src/decider.mjs'].blob = 'f'.repeat(40);
  assert.throws(() => assertTrustedPolicyManifest(changed), /신뢰한 9단계 저장점/);
});
