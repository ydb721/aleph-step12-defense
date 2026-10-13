// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

const SIGNAL_SOURCES = new Set(['none', 'judge_fixture']);

function inspectEngineContext(request) {
  const signals = request?.signals;
  const source = signals && SIGNAL_SOURCES.has(signals.source) ? signals.source : null;

  return {
    source,
    region: source && typeof signals.region === 'string' ? signals.region : null,
    network: source && typeof signals.network === 'string' ? signals.network : null,
    hour: source && Number.isInteger(signals.hour) ? signals.hour : null,
    recentEvents: Array.isArray(request?.recentEvents) ? request.recentEvents : null,
  };
}

export async function decide(request) {
  // 7단계 입력 준비: 계약에 있는 signals/recentEvents만 읽고,
  // 누락되거나 출처가 불명확한 값을 임의의 정상값으로 채우지 않습니다.
  inspectEngineContext(request);

  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [RULE_IDS[0]],
  };
}
