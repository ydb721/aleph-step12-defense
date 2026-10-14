import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequestTrace, traceRequestShape } from '../src/request-trace.mjs';

test('request trace redacts extra details and preserves status, JSON and end behavior', () => {
  const logs = [];
  const originalInfo = console.info;
  console.info = message => logs.push(JSON.parse(message.slice(15)));
  try {
    const headers = {};
    const res = { status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; this.end(); return this; },
      end() { this.ended = true; return this; },
      setHeader(key, value) { headers[key] = value; } };
    const req = { method: 'POST', headers: { authorization: 'SECRET_TOKEN', cookie: 'PRIVATE_COOKIE' } };
    const trace = createRequestTrace(req, res, 'memos_item');
    trace.target('44444444-4444-4444-8444-444444444444');
    trace.actor({ kind: 'judge', identity: 'b', userId: '22222222-2222-4222-8222-222222222222',
      runId: '33333333-3333-4333-8333-333333333333' });
    trace('comparison', { body: 'SECRET_BODY', token: 'SECRET_TOKEN', ownerId: 'PRIVATE_OWNER',
      backupKind: 'on_create', bodyHashMatches: false,
      reason: 'SECRET_REASON', code: 'SECRET_CODE', changedFields: ['content', 'SECRET_FIELD'] });
    traceRequestShape(trace, { memoId: 'PRIVATE_MEMO_ID', password: 'SECRET_PASSWORD' });
    const body = { error: 'MEMO_NOT_FOUND' };
    assert.equal(res.status(404).json(body), res);
    assert.equal(res.body, body);
    assert.equal(res.ended, true);
    assert.equal(logs.filter(item => item.stage === 'completed').length, 1);
    assert.equal(logs.at(-1).status, 404);
    assert.equal(logs.at(-1).kind, 'judge');
    assert.equal(logs.find(item => item.stage === 'comparison').backupKind, 'on_create');
    assert.equal(logs.find(item => item.stage === 'request_shape').hasMemoId, true);
    assert.match(headers['X-Byteback-Trace'], /^[0-9a-f-]{36}$/u);
    const serialized = JSON.stringify(logs);
    for (const value of ['SECRET', 'PRIVATE', '22222222-2222-4222-8222-222222222222',
      '33333333-3333-4333-8333-333333333333', '44444444-4444-4444-8444-444444444444']) {
      assert.ok(!serialized.includes(value));
    }
  } finally { console.info = originalInfo; }
});
