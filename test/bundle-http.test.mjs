import assert from 'node:assert/strict';
import test from 'node:test';
import { fetchPublic } from '../scripts/bundle-http.mjs';

const withFetch = async (replacement, callback) => {
  const original = globalThis.fetch;
  globalThis.fetch = replacement;
  try { await callback(); } finally { globalThis.fetch = original; }
};

test('GitHub public GET sends an explicit valid User-Agent and accepts HTTP 200', async () => {
  await withFetch(async (_url, init) => {
    assert.equal(init.method, 'GET');
    assert.equal(init.headers.Accept, 'application/vnd.github+json');
    assert.equal(init.headers['User-Agent'], 'BYTE-BACK-step12-bundle');
    return new Response('{}', { status: 200 });
  }, async () => {
    const response = await fetchPublic('https://api.github.com/repos/example/repo/commits/abc', 'GitHub Commit API');
    assert.equal(response.status, 200);
  });
});

test('GitHub public GET distinguishes primary rate limit HTTP 403', async () => {
  await withFetch(async () => new Response('{}', {
    status: 403,
    headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1792309999' },
  }), async () => {
    await assert.rejects(fetchPublic('https://api.github.com/', 'GitHub Commit API'),
      /HTTP 403; type=primary_rate_limit; remaining=0; reset=1792309999; retryAfter=unknown/u);
  });
});

test('GitHub public GET keeps an unexplained HTTP 403 distinct', async () => {
  await withFetch(async () => new Response('{}', { status: 403 }), async () => {
    await assert.rejects(fetchPublic('https://api.github.com/', 'GitHub Commit API'),
      /HTTP 403; type=access_forbidden; remaining=unknown; reset=unknown; retryAfter=unknown/u);
  });
});

test('GitHub public GET reports HTTP 429 retry metadata without retrying', async () => {
  let calls = 0;
  await withFetch(async () => {
    calls += 1;
    return new Response('{}', { status: 429, headers: { 'retry-after': '60' } });
  }, async () => {
    await assert.rejects(fetchPublic('https://api.github.com/', 'GitHub Commit API'),
      /HTTP 429; type=retry_later; remaining=unknown; reset=unknown; retryAfter=60/u);
    assert.equal(calls, 1);
  });
});

test('GitHub public GET fails closed on a network error', async () => {
  await withFetch(async () => { throw new TypeError('private network detail'); }, async () => {
    await assert.rejects(fetchPublic('https://api.github.com/', 'GitHub Commit API'),
      { message: 'GitHub Commit API 공개 HTTPS GET에 실패했습니다.' });
  });
});
