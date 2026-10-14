// Run manually after signing into the learning app as test account B.
// This uses the existing HttpOnly session; no password/token is requested or logged.
export async function runRecoveryCheck() {
  const check = (value, label) => { if (!value) throw new Error(label); };
  const sha = async value => [...new Uint8Array(await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(value)))].map(byte => byte.toString(16).padStart(2, '0')).join('');
  const request = async (method, path, body, expected, credentials = 'same-origin') => {
    const response = await fetch(path, { method, credentials, cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const data = response.status === 204 ? null : await response.json();
    check(response.status === expected, method + ' ' + path + ': HTTP ' + response.status
      + (data?.error ? ' ' + data.error : ''));
    return data;
  };
  const metadata = await request('GET', '/aleph.json', undefined, 200);
  check(metadata.step >= 10 && metadata.restoreRoute === '/api/restore/:id',
    '10단계 복구 경로가 배포되지 않았음');
  const title = 'R10 recovery check ' + Date.now();
  const body = 'UTF-8 test fixture: 한글 🧪';
  let id;
  let finished = false;
  try {
    const created = await request('POST', '/api/memos', { title, body }, 201);
    id = created.id;
    check(/^[0-9a-f-]{36}$/u.test(id), '생성 ID 오류');
    const route = metadata.restoreRoute.replace(':id', id);
    const original = await request('GET', '/api/memos/' + id, undefined, 200);
    check(original.title === title && original.body === body, '생성된 메모 불일치');
    const expectedHash = await sha(body);
    await request('POST', route, {}, 401, 'omit');
    await request('PUT', '/api/memos/' + id,
      { title: title + ' changed', body: body + ' changed' }, 200);
    const plan = await request('POST', route, { preview: true }, 200);
    check(plan.verified === true && plan.contentSha256 === expectedHash, '최초 사본 해시 오류');
    console.table([{ phase: '변조 복원 전', version: plan.version,
      changedFields: plan.changedFields.join(', ') }]);
    const restored = await request('POST', route,
      { expectedVersion: plan.version, expectedState: plan.stateVersion }, 200);
    const matches = result => result.id === id && result.title === title && result.body === body
      && result.ownerId === plan.ownerId && result.owner_id === plan.ownerId
      && result.contentSha256 === expectedHash && result.content_sha256 === expectedHash;
    check(matches(restored), '변조 복원 응답의 ID·소유자·본문·해시 불일치');
    const reread = await request('GET', '/api/memos/' + id, undefined, 200);
    check(reread.title === title && reread.body === body, '변조 복원 후 DB 조회 불일치');
    await request('DELETE', '/api/memos/' + id, undefined, 204);
    await request('GET', '/api/memos/' + id, undefined, 404);
    const deletedPlan = await request('POST', route, { preview: true }, 200);
    console.table([{ phase: '삭제 복원 전', version: deletedPlan.version,
      changedFields: deletedPlan.changedFields.join(', ') }]);
    // Also exercise the judge-style POST without confirmation fields.
    const recovered = await request('POST', route, {}, 200);
    check(matches(recovered), '삭제 복원 응답 불일치');
    const recreated = await request('GET', '/api/memos/' + id, undefined, 200);
    check(recreated.title === title && recreated.body === body, '삭제 복원 후 DB 조회 불일치');
    finished = true;
    console.table({ initialSnapshot: true, tamperRestore: true, deletedRestore: true,
      ownerAndBodyHashMatch: true, unauthenticatedRestoreDenied: true });
    return { passed: true, contentHashMatches: true };
  } finally {
    if (id) {
      const cleanup = await fetch('/api/memos/' + id, { method: 'DELETE', credentials: 'same-origin' });
      if (![204, 404].includes(cleanup.status)) {
        throw new Error('시험 메모 정리 실패: HTTP ' + cleanup.status);
      }
    }
    if (!finished) console.info('복구 확인 미완료. 통과로 기록하지 않음.');
  }
}
