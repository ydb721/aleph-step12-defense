// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

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

function needsStepUp(context) {
  if (context.source !== 'judge_fixture') return false;

  const unusualTime = Number.isInteger(context.hour)
    && (context.hour < 6 || context.hour >= 23);
  const unfamiliarNetwork = context.network === 'unusual';
  const burstReadSignal = Array.isArray(context.recentEvents)
    && context.recentEvents.some((event) => event?.kind === 'risk_signal'
      && Number.isInteger(event.count) && event.count >= 20
      && Number.isInteger(event.ageSeconds) && event.ageSeconds <= 300);

  // 지역 하나만으로 판단하지 않고 여러 이상 신호가 동시에 있을 때만 추가 확인합니다.
  return unusualTime && unfamiliarNetwork && burstReadSignal;
}

export async function decide(request) {
  // 계약에 있는 signals/recentEvents만 읽고,
  // 누락되거나 출처가 불명확한 값을 임의의 정상값으로 채우지 않습니다.
  const context = inspectEngineContext(request);

  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  if (needsStepUp(context)) {
    const stepUp = request?.stepUp;
    const recentlyVerified = stepUp?.verified === true
      && Number.isInteger(stepUp.authAgeSeconds)
      && stepUp.authAgeSeconds >= 0
      && stepUp.authAgeSeconds <= 900;

    if (!recentlyVerified) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'step_up',
        reasonCode: 'step_up_required',
        ruleIds: [RULE_IDS[1]],
      };
    }
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [RULE_IDS[0]],
  };
}
