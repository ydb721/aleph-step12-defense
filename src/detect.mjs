// 9단계 탐지 입력은 docs/DETECT_EVENTS.md의 가상 사건 계약만 신뢰합니다.
// 메모 내용, 토큰, 실명이나 계약에 없는 브라우저 값은 읽거나 보존하지 않습니다.

// This is an implementation summary, not evidence of a live engine event.
// The operations room reads it during the public build so the displayed
// threshold cannot drift from the detector below.
export const DETECTION_CONTRACT = Object.freeze({
  windowSeconds: 10 * 60,
  readLimit: 120,
  method: 'GET',
  action: 'propose_revocation',
  reasonCode: 'burst_read',
});

const WINDOW_MS = DETECTION_CONTRACT.windowSeconds * 1000;
const READ_LIMIT = DETECTION_CONTRACT.readLimit;

function validSubject(value) {
  return typeof value === 'string'
    && /^[A-Za-z0-9_-]{1,128}$/u.test(value);
}

function validUtcIso(value) {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed)
    && new Date(parsed).toISOString() === value;
}

export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  return events.flatMap((event) => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) return [];
    if (!validUtcIso(event.at)) return [];
    if (typeof event.method !== 'string' || !event.method) return [];
    if (!event.identity || typeof event.identity !== 'object'
        || Array.isArray(event.identity) || !validSubject(event.identity.sub)) {
      return [];
    }

    return [{
      at: event.at,
      method: event.method,
      subject: event.identity.sub,
    }];
  });
}

function burstReadSubject(events) {
  const readsBySubject = new Map();

  for (const event of events) {
    if (event.method !== 'GET') continue;
    const list = readsBySubject.get(event.subject) ?? [];
    list.push(Date.parse(event.at));
    readsBySubject.set(event.subject, list);
  }

  for (const [subject, times] of readsBySubject) {
    times.sort((a, b) => a - b);
    let start = 0;

    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] >= WINDOW_MS) start += 1;
      if (end - start + 1 > READ_LIMIT) return subject;
    }
  }

  return null;
}

export function detect(events) {
  const safeEvents = readDetectionEvents(events);
  const subject = burstReadSubject(safeEvents);

  if (subject) {
    return {
      action: 'propose_revocation',
      reasonCode: 'burst_read',
      subject,
    };
  }

  return { action: 'observe' };
}

const DEVICE_ID = /^[0-9a-f]{16}$/u;

export function proposeRevocation(detection, verified) {
  if (!detection || typeof detection !== 'object'
      || detection.action !== 'propose_revocation'
      || detection.reasonCode !== 'burst_read'
      || !validSubject(detection.subject)) {
    return null;
  }

  if (!verified || typeof verified !== 'object' || Array.isArray(verified)
      || Object.keys(verified).sort().join(',') !== 'deviceId,subjectId') {
    return null;
  }

  if (verified.subjectId !== detection.subject
      || !DEVICE_ID.test(verified.deviceId)) {
    return null;
  }

  return {
    action: 'propose_revocation',
    reasonCode: 'burst_read',
    target: {
      subjectId: verified.subjectId,
      deviceId: verified.deviceId,
    },
  };
}
