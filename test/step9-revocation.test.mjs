import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect, proposeRevocation } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);

function reads(count, subject = 'learner_fixture') {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(START + index * 2000).toISOString(),
    method: 'GET',
    identity: { sub: subject },
  }));
}

test('의심 사건은 확인된 기기 한 개에만 회수 제안', () => {
  const detection = detect(reads(121));
  assert.deepEqual(detection, {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    subject: 'learner_fixture',
  });

  assert.deepEqual(proposeRevocation(detection, {
    subjectId: 'learner_fixture',
    deviceId: 'aaaaaaaaaaaaaaaa',
  }), {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    target: {
      subjectId: 'learner_fixture',
      deviceId: 'aaaaaaaaaaaaaaaa',
    },
  });

  assert.equal(proposeRevocation(detection, {
    subjectId: 'other_fixture',
    deviceId: 'aaaaaaaaaaaaaaaa',
  }), null);

  assert.equal(proposeRevocation(detection, {
    subjectId: 'learner_fixture',
    deviceId: 'invalid-device',
  }), null);
});

test('정상 사건은 회수 제안을 내지 않음', () => {
  const detection = detect(reads(30));
  assert.deepEqual(detection, { action: 'observe' });
  assert.equal(proposeRevocation(detection, {
    subjectId: 'learner_fixture',
    deviceId: 'aaaaaaaaaaaaaaaa',
  }), null);
});
