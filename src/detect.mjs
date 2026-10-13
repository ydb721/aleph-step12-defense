// 9단계 탐지 입력은 docs/DETECT_EVENTS.md의 가상 사건 계약만 신뢰합니다.
// 메모 내용, 토큰, 실명이나 계약에 없는 브라우저 값은 읽거나 보존하지 않습니다.

const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;

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
