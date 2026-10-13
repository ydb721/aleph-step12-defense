// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.

const STARTER_RESOURCE_BINDINGS = Object.freeze([
  {
    classId: 'class_fixture',
    projectId: 'project_fixture',
    subjectId: 'learner_fixture',
    ownerSubjectId: 'learner_fixture',
    deviceId: 'aaaaaaaaaaaaaaaa',
    service: 'notes',
    path: '/notes/demo',
    resourceId: 'notes:demo',
    permissions: ['GET', 'PUT'],
  },
]);

export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_scope',
]);

const SIGNAL_SOURCES = new Set(['none', 'judge_fixture']);

function loadResourceBindings() {
  const raw = typeof process !== 'undefined'
    ? process.env.ALEPH_RESOURCE_BINDINGS
    : undefined;

  if (!raw) return STARTER_RESOURCE_BINDINGS;

  try {
    const entries = JSON.parse(raw);
    return Array.isArray(entries) ? entries : [];
  } catch {
    return [];
  }
}

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

function expectedResource(request) {
  if (request.queryLength !== 0) return null;
  if (!['GET', 'PUT'].includes(request.method)) return null;
  if (typeof request.path !== 'string' || /[%?#\\]/u.test(request.path)) return null;

  const family = request.service === 'notes'
    ? 'notes'
    : request.service === 'notices'
      ? 'notices'
      : null;
  if (!family) return null;

  const prefix = `/${family}/`;
  if (!request.path.startsWith(prefix)) return null;

  const id = request.path.slice(prefix.length);
  if (!id || id.includes('/')) return null;

  // 기존 7단계 연습 자원 demo와 실제 UUID 자원만 받습니다.
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
  if (id !== 'demo' && !uuid.test(id)) return null;

  const expectedRoute = `${request.method} /${family}/:id`;
  if (request.route !== expectedRoute) return null;

  return {
    family,
    id,
    resourceId: `${family}:${id}`,
  };
}

function resourceAllowed(request, bindings = loadResourceBindings()) {
  if (request.schema !== 'aleph.decision.v1') return false;

  const requiredText = ['classId', 'projectId', 'subjectId'];
  if (!requiredText.every((key) => typeof request[key] === 'string'
      && request[key].length > 0 && request[key].length <= 256)) {
    return false;
  }

  if (!/^[a-f0-9]{16}$/u.test(request.deviceId ?? '')) return false;

  const resource = expectedResource(request);
  if (!resource) return false;

  // The current decision contract has no verified role/instructor field.
  // Therefore notice writes are never authorized by the decider.
  if (resource.family === 'notices' && request.method !== 'GET') return false;

  return bindings.some((entry) => entry
    && entry.classId === request.classId
    && entry.projectId === request.projectId
    && entry.subjectId === request.subjectId
    && entry.deviceId === request.deviceId
    && entry.service === request.service
    && entry.path === request.path
    && entry.resourceId === resource.resourceId
    && Array.isArray(entry.permissions)
    && entry.permissions.includes(request.method)
    && (resource.family !== 'notes' || entry.ownerSubjectId === request.subjectId));
}

function response(request, decision, reasonCode, ruleId) {
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  };
}

export async function decide(request) {
  // 계약에 있는 signals/recentEvents만 읽고,
  // 누락되거나 출처가 불명확한 값을 임의의 정상값으로 채우지 않습니다.
  const context = inspectEngineContext(request);

  if (request.deviceRegistered !== true) {
    return response(request, 'deny', 'device_not_registered', 'device_registered');
  }

  if (needsStepUp(context)) {
    const stepUp = request?.stepUp;
    const recentlyVerified = stepUp?.verified === true
      && Number.isInteger(stepUp.authAgeSeconds)
      && stepUp.authAgeSeconds >= 0
      && stepUp.authAgeSeconds <= 900;

    if (!recentlyVerified) {
      return response(request, 'step_up', 'step_up_required', 'step_up_required');
    }
  }

  if (resourceAllowed(request)) {
    return response(request, 'allow', 'approved', 'resource_scope');
  }

  // 알 수 없는 경로, 다른 사람 메모, 권한 없는 공지 수정은 모두 기본 거부합니다.
  return response(request, 'deny', 'resource_not_allowed', 'resource_scope');
}
