// 9단계 탐지 입력은 docs/DETECT_EVENTS.md의 가상 사건 계약만 신뢰합니다.
// 메모 내용, 토큰, 실명이나 계약에 없는 브라우저 값은 읽거나 보존하지 않습니다.

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

// 제작 1에서는 입력 정리만 구현합니다.
// 탐지 규칙과 회수 제안은 다음 제작 단계에서 추가합니다.
export function detect(events) {
  readDetectionEvents(events);
  return { action: 'observe' };
}
