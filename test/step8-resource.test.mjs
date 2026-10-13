import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { decide } from '../src/decider.mjs';

function request(overrides = {}) {
  return {
    schema: 'aleph.decision.v1',
    requestId: randomUUID(),
    classId: 'class_fixture',
    projectId: 'project_fixture',
    subjectId: 'learner_fixture',
    deviceId: 'aaaaaaaaaaaaaaaa',
    service: 'notes',
    method: 'GET',
    path: '/notes/demo',
    route: 'GET /notes/:id',
    queryLength: 0,
    querySha256: createHash('sha256').update('').digest('hex'),
    at: new Date().toISOString(),
    policyRevision: 1,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [],
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 },
    ...overrides,
  };
}

test('8단계 자원 구역 판정', async () => {
  const ownMemo = await decide(request());
  assert.equal(ownMemo.decision, 'allow');
  assert.equal(ownMemo.reasonCode, 'approved');

  const otherUserMemo = await decide(request({
    requestId: randomUUID(),
    subjectId: 'other_fixture',
  }));
  assert.equal(otherUserMemo.decision, 'deny');
  assert.equal(otherUserMemo.reasonCode, 'resource_not_allowed');

  const noticeId = '11111111-1111-4111-8111-111111111111';
  const studentNoticeUpdate = await decide(request({
    requestId: randomUUID(),
    service: 'notices',
    method: 'PUT',
    path: '/notices/' + noticeId,
    route: 'PUT /notices/:id',
  }));
  assert.equal(studentNoticeUpdate.decision, 'deny');
  assert.equal(studentNoticeUpdate.reasonCode, 'resource_not_allowed');
});

test('기능 경로와 쿼리 선택은 자원으로 허용하지 않음', async () => {
  const exportPath = await decide(request({
    requestId: randomUUID(),
    path: '/notes/export',
  }));
  assert.equal(exportPath.decision, 'deny');
  assert.equal(exportPath.reasonCode, 'resource_not_allowed');

  const queryFeature = await decide(request({
    requestId: randomUUID(),
    queryLength: 11,
  }));
  assert.equal(queryFeature.decision, 'deny');
  assert.equal(queryFeature.reasonCode, 'resource_not_allowed');
});
