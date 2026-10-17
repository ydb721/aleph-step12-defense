// The operations room is a read-only view. It never creates a server record,
// executes recovery, or treats a local fixture as an operational result.

export const STATUS = Object.freeze({
  operationalObserved: '운영 API 실측',
  deploymentObserved: '현재 배포 API 실측',
  judgeConfirmed: '심판 판정 확인',
  localTest: '로컬 테스트',
  virtualPractice: '가상 입력 연습',
  notRun: '미실행',
  notConnected: '미연동',
  verificationFailed: '검증 실패',
  implementation: '구현 기준',
});

const DEVICE_STATES = new Set(['pending', 'approved', 'rejected', 'revoked']);
const SHA = /^[a-f0-9]{40}$/iu;
const SAFE_ERROR_CODES = new Set([
  'AUTH_REQUIRED', 'DEVICE_NOT_APPROVED', 'DEVICE_REGISTRATION_REQUIRED',
  'DEVICE_SIGNATURE_REQUIRED', 'DEVICE_REQUEST_MISMATCH', 'DEVICE_NONCE_REUSED',
  'BACKUP_UNVERIFIED', 'NOT_FOUND', 'METHOD_NOT_ALLOWED',
]);
const SAFE_REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/u;
const SAFE_SERVER_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;

export const VERIFICATION_CASES = Object.freeze([
  { step: 3, testId: 'unauthenticated_memo_list', purpose: '무인증 메모 목록 차단', kind: 'prohibited', environment: 'operational', method: 'GET', path: '/api/memos', expectedStatuses: [401, 403], expectedErrorCodes: [], source: 'src/attack-check.mjs', limitation: '운영에서 자동 실행하지 않음' },
  { step: 4, testId: 'foreign_memo_scope', purpose: '다른 소유자 메모 범위 차단', kind: 'prohibited', environment: 'isolation', method: 'GET', path: '/api/memos/:id', expectedStatuses: [403, 404], expectedErrorCodes: [], source: 'api/memos.js owner filter', limitation: '대상 소유자·ID를 화면에 기록하지 않음' },
  { step: 5, testId: 'allowed_route_scope', purpose: '허용 API 경로 범위 확인', kind: 'prohibited', environment: 'local', method: 'GET', path: '/api/:unlisted', expectedStatuses: [], expectedErrorCodes: [], source: 'aleph.config.json allowedRoutes', limitation: '공식 HTTP 시험 정의 미확인' },
  { step: 10, testId: 'verified_restore_preview', purpose: '검증된 사본 복원 미리보기', kind: 'normal', environment: 'isolation', method: 'POST', path: '/api/restore/:id', expectedStatuses: [200], expectedErrorCodes: [], source: 'api/restore/[id].js', limitation: '복원 실행 없이 미리보기만 별도 승인 후 수행' },
  { step: 10, testId: 'restore_owner_or_backup_rejection', purpose: '소유자·백업 검증 실패 차단', kind: 'prohibited', environment: 'isolation', method: 'POST', path: '/api/restore/:id', expectedStatuses: [403, 404], expectedErrorCodes: ['BACKUP_UNVERIFIED'], source: 'api/restore/[id].js', limitation: '운영에서 상태 변경 시험 금지' },
  { step: 11, testId: 'approved_signed_memo_list', purpose: '승인 기기의 서명된 메모 조회', kind: 'normal', environment: 'operational', method: 'GET', path: '/api/memos', expectedStatuses: [200], expectedErrorCodes: [], source: 'public/index.html signedFetch', limitation: '응답 본문을 기록하지 않음' },
  { step: 11, testId: 'unapproved_device_rejected', purpose: '미등록·미승인 기기 차단', kind: 'prohibited', environment: 'isolation', method: 'GET', path: '/api/memos', expectedStatuses: [403], expectedErrorCodes: ['DEVICE_NOT_APPROVED', 'DEVICE_REGISTRATION_REQUIRED'], source: 'src/device-auth.mjs', limitation: '기기 상태 변경은 별도 승인 필요' },
  { step: 11, testId: 'unsigned_protected_request', purpose: '서명 없는 보호 요청 차단', kind: 'prohibited', environment: 'isolation', method: 'GET', path: '/api/memos', expectedStatuses: [403], expectedErrorCodes: ['DEVICE_SIGNATURE_REQUIRED'], source: 'docs/DEVICE_REQUEST.md', limitation: '격리 환경에서만 명시적으로 실행' },
  { step: 11, testId: 'bound_path_or_query_rejected', purpose: '서명 후 경로·쿼리 변조 차단', kind: 'prohibited', environment: 'isolation', method: 'PUT', path: '/api/memos/:id', expectedStatuses: [403], expectedErrorCodes: ['DEVICE_REQUEST_MISMATCH'], source: 'docs/DEVICE_REQUEST.md', limitation: '새 assertion을 쓰는 격리 시험 필요' },
  { step: 11, testId: 'bound_body_rejected', purpose: '서명 후 본문 변조 차단', kind: 'prohibited', environment: 'isolation', method: 'PUT', path: '/api/memos/:id', expectedStatuses: [403], expectedErrorCodes: ['DEVICE_REQUEST_MISMATCH'], source: 'docs/DEVICE_REQUEST.md', limitation: '새 assertion을 쓰는 격리 시험 필요' },
  { step: 11, testId: 'nonce_reuse_rejected', purpose: 'nonce 재사용 차단', kind: 'prohibited', environment: 'isolation', method: 'GET', path: '/api/memos', expectedStatuses: [403], expectedErrorCodes: ['DEVICE_NONCE_REUSED'], source: 'docs/DEVICE_REQUEST.md', limitation: '첫 정상 요청과 재사용 요청을 구분 기록' },
]);

function safeErrorCode(value) {
  return typeof value === 'string' && SAFE_ERROR_CODES.has(value) ? value : null;
}

function safeRequestId(value) {
  return typeof value === 'string' && SAFE_REQUEST_ID.test(value) ? value : null;
}

function safeServerTime(value) {
  return typeof value === 'string' && SAFE_SERVER_TIME.test(value) ? value : null;
}

export function compareVerification(caseDefinition, response) {
  if (!caseDefinition || !Number.isInteger(response?.httpStatus)) {
    return { state: 'not_run', passed: false };
  }
  if (response.httpStatus >= 500) return { state: 'verification_failed', passed: false };
  const statusMatches = caseDefinition.expectedStatuses.includes(response.httpStatus);
  const expectedCodes = caseDefinition.expectedErrorCodes;
  const errorMatches = expectedCodes.length === 0
    ? response.errorCode === null : expectedCodes.includes(response.errorCode);
  return statusMatches && errorMatches
    ? { state: 'passed', passed: true } : { state: 'failed', passed: false };
}

export function recordVerification(caseDefinition, response, { clientCaseId, executedAt, confirmedAt } = {}) {
  if (!caseDefinition || !VERIFICATION_CASES.includes(caseDefinition)) {
    throw new TypeError('UNKNOWN_VERIFICATION_CASE');
  }
  if (!Number.isInteger(response?.httpStatus)) throw new TypeError('HTTP_RESPONSE_REQUIRED');
  if (typeof clientCaseId !== 'string' || !/^case-[1-9][0-9]*$/u.test(clientCaseId)) {
    throw new TypeError('INVALID_CLIENT_CASE_ID');
  }
  const compared = compareVerification(caseDefinition, {
    httpStatus: response.httpStatus,
    errorCode: safeErrorCode(response.errorCode),
  });
  return Object.freeze({
    step: caseDefinition.step,
    testId: caseDefinition.testId,
    purpose: caseDefinition.purpose,
    kind: caseDefinition.kind,
    environment: response.environment === 'isolation' || response.environment === 'local'
      ? response.environment : caseDefinition.environment,
    method: caseDefinition.method,
    path: caseDefinition.path,
    expected: { statuses: [...caseDefinition.expectedStatuses], errorCodes: [...caseDefinition.expectedErrorCodes] },
    actualHttpStatus: response.httpStatus,
    actualErrorCode: safeErrorCode(response.errorCode),
    serverRequestId: safeRequestId(response.serverRequestId),
    serverObservedAt: safeServerTime(response.serverObservedAt),
    clientCaseId,
    executedAt: safeServerTime(executedAt),
    confirmedAt: safeServerTime(confirmedAt),
    source: typeof response.source === 'string' ? response.source : 'browser_observation',
    executionState: compared.state,
    passed: compared.passed,
    evidence: caseDefinition.source,
    limitation: caseDefinition.limitation,
  });
}

export function summarizeDevices(payload) {
  if (!payload || !Array.isArray(payload.devices)
      || payload.devices.some(device => !device || !DEVICE_STATES.has(device.state))) {
    throw new TypeError('INVALID_DEVICE_SUMMARY');
  }
  const states = Object.fromEntries([...DEVICE_STATES].map(state => [state, 0]));
  for (const device of payload.devices) ++states[device.state];
  // Deliberately return counts only: no credential IDs, fingerprints, or dates.
  return { total: payload.devices.length, states };
}

export function operationFailure(httpStatus = null) {
  return {
    status: STATUS.verificationFailed,
    httpStatus: Number.isInteger(httpStatus) ? httpStatus : null,
    requestId: null,
  };
}

export function protectedReadObservation({ httpStatus, checkedAt, origin, configuredOrigin }) {
  const operational = typeof origin === 'string' && origin === configuredOrigin;
  return {
    status: operational ? STATUS.operationalObserved : STATUS.deploymentObserved,
    httpStatus: Number.isInteger(httpStatus) ? httpStatus : null,
    checkedAt: typeof checkedAt === 'string' ? checkedAt : null,
    requestId: null,
  };
}

export function validateManifest(value) {
  const implementation = value?.implementation;
  if (!value || value.schema !== 'byteback.operations-room.v1'
      || !Array.isArray(implementation?.decider?.ruleIds)
      || implementation.decider.ruleIds.some(rule => typeof rule !== 'string')
      || !Array.isArray(implementation?.decider?.outcomes)
      || !Number.isInteger(implementation?.detection?.windowSeconds)
      || !Number.isInteger(implementation?.detection?.readLimit)
      || typeof implementation?.recovery?.memoRoute !== 'string'
      || !Number.isInteger(value?.attackCatalog?.expectedCount)
      || value.attackCatalog.officialIdentifiersAvailable !== false
      || !Array.isArray(value.attackCatalog.executions)
      || value.attackCatalog.executions.length !== 0) {
    throw new TypeError('INVALID_OPERATIONS_MANIFEST');
  }
  return value;
}

function element(tag, text = '') {
  const node = document.createElement(tag);
  node.textContent = text;
  return node;
}

function card(title, status, details = []) {
  const item = element('li');
  item.className = 'operations-card';
  const heading = element('strong', title);
  const badge = element('span', status);
  badge.className = 'operations-status';
  const body = element('p', details.filter(Boolean).join(' · '));
  item.append(heading, badge, body);
  return item;
}

function timestamp(value) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return '확인 시각 없음';
  return '브라우저 확인 시각: ' + value;
}

function configuredOrigin(manifest) {
  return typeof manifest?.deployment?.publicOrigin === 'string'
    ? manifest.deployment.publicOrigin : '';
}

export function createOperationsRoom(root) {
  const refresh = root.querySelector('#operations-refresh');
  const status = root.querySelector('#operations-feedback');
  const list = root.querySelector('#operations-list');
  const verificationSummary = root.querySelector('#verification-summary');
  const verificationTable = root.querySelector('#verification-table-body');
  let allowed = false;
  let manifest = null;
  let protectedRead = null;
  let snapshot = null;
  let manifestLoad = null;
  let caseSequence = 0;
  let verificationRecords = [];

  const renderVerification = () => {
    const byTestId = new Map(verificationRecords.map(record => [record.testId, record]));
    const rows = VERIFICATION_CASES.map(definition => {
      const record = byTestId.get(definition.testId);
      const row = element('tr');
      const cells = record
        ? [
          definition.step + ' · ' + definition.testId,
          definition.kind + ' · ' + definition.purpose,
          record.environment + ' · ' + record.method + ' ' + record.path,
          record.expected.statuses.join('/') + (record.expected.errorCodes.length ? ' · ' + record.expected.errorCodes.join('/') : ''),
          'HTTP ' + record.actualHttpStatus + (record.actualErrorCode ? ' · ' + record.actualErrorCode : ''),
          (record.serverRequestId ?? '서버 제공 요청 ID 없음') + ' · 서버 시각 ' + (record.serverObservedAt ?? '없음') + ' · 클라이언트 실행 ' + (record.executedAt ?? '없음') + ' · 확인 ' + (record.confirmedAt ?? '없음'),
          record.source + ' · ' + record.executionState + ' · clientCaseId ' + record.clientCaseId,
          record.evidence + ' · ' + record.limitation,
        ]
        : [
          definition.step + ' · ' + definition.testId,
          definition.kind + ' · ' + definition.purpose,
          definition.environment + ' · ' + definition.method + ' ' + definition.path,
          definition.expectedStatuses.join('/') + (definition.expectedErrorCodes.length ? ' · ' + definition.expectedErrorCodes.join('/') : ''),
          '미실행',
          '서버 제공 요청 ID 없음 · 시각 없음',
          '미실행',
          definition.source + ' · ' + definition.limitation,
        ];
      row.append(...cells.map(value => element('td', value)));
      return row;
    });
    verificationTable.replaceChildren(...rows);
    const passed = verificationRecords.filter(record => record.passed).length;
    verificationSummary.textContent = '실제 HTTP 응답 기록 ' + verificationRecords.length + '건 · 통과 ' + passed
      + '건 · 미실행 후보 ' + (VERIFICATION_CASES.length - verificationRecords.length) + '건. 미실행은 통과에 포함하지 않습니다.';
  };

  const addVerification = (definition, response) => {
    const now = new Date().toISOString();
    const record = recordVerification(definition, response, {
      clientCaseId: 'case-' + (++caseSequence), executedAt: response.executedAt ?? now, confirmedAt: now,
    });
    verificationRecords = [...verificationRecords.filter(value => value.testId !== record.testId), record];
    renderVerification();
  };

  const render = () => {
    if (!allowed) {
      root.hidden = true;
      list.replaceChildren();
      status.textContent = '';
      verificationTable.replaceChildren();
      verificationSummary.textContent = '';
      return;
    }
    root.hidden = false;
    renderVerification();
    if (!manifest) {
      list.replaceChildren(card('작전실 구현 정보', STATUS.notConnected,
        ['공개 구현 요약을 읽는 중입니다. 실제 API 결과는 아직 조회하지 않았습니다.']));
      return;
    }

    const decider = manifest.implementation.decider;
    const detection = manifest.implementation.detection;
    const recovery = manifest.implementation.recovery;
    const judge = manifest.judgeRecord;
    const attacks = manifest.attackCatalog;
    const entries = [
      card('판정기 규칙', STATUS.implementation, [
        '선언 규칙 ' + decider.ruleIds.length + '개: ' + decider.ruleIds.join(', '),
        '가능 결과: ' + decider.outcomes.join(' / '),
        '실제 SDP 엔진 응답 기록은 ' + STATUS.notConnected,
      ]),
      card('탐지', STATUS.notConnected, [
        '동일 주체의 ' + detection.method + '가 ' + (detection.windowSeconds / 60)
          + '분에 ' + detection.readLimit + '건 초과 시 ' + detection.action,
        '운영 탐지 로그 출처 없음',
      ]),
      card('회수', STATUS.notRun, [
        'propose_revocation은 제안이며 실제 회수 API 실행이 아닙니다.',
        '이 화면은 기기 상태를 읽을 수만 있습니다.',
      ]),
      card('복구', STATUS.notRun, [
        '메모 경로: ' + recovery.memoRoute,
        '검증 정책 버전: ' + (recovery.policyVersion ?? '확인 불가'),
        '작전실 조회는 미리보기·복원을 실행하지 않습니다.',
      ]),
      card('심판 기록', judge?.status === 'user_reported' ? STATUS.judgeConfirmed : STATUS.notConnected, [
        judge?.status === 'user_reported'
          ? '사용자 제공 스크린샷 기록: ' + judge.step + '단계 ' + judge.score + '/100 · '
            + String(judge.commit).slice(0, 12)
          : '심판 결과 출처 없음',
        '심판 응답 API 실측이 아닙니다.',
      ]),
      card('공식 공격 목록', STATUS.notConnected, [
        '요구 수: ' + attacks.expectedCount + '종',
        '공식 식별자와 실행 기록이 없어 0/' + attacks.expectedCount + ' 성공으로도 표시하지 않습니다.',
      ]),
    ];

    if (protectedRead) {
      entries.unshift(card('보호 자료 접근 확인', protectedRead.status, [
        protectedRead.httpStatus == null ? 'HTTP 상태 미제공' : 'HTTP ' + protectedRead.httpStatus,
        timestamp(protectedRead.checkedAt),
        '서버 제공 요청 ID 없음',
      ]));
    }

    if (snapshot?.aleph) {
      entries.push(card('배포 식별', snapshot.aleph.status, snapshot.aleph.details));
    }
    if (snapshot?.devices) {
      entries.push(card('기기 상태', snapshot.devices.status, snapshot.devices.details));
    }
    list.replaceChildren(...entries);
  };

  const loadManifest = async () => {
    if (manifestLoad) return manifestLoad;
    manifestLoad = (async () => {
      try {
        const response = await fetch('/operations-manifest.json', {
          credentials: 'omit', cache: 'no-store', redirect: 'error',
        });
        const payload = await response.json().catch(() => null);
        if (!response.ok) throw new Error('HTTP_' + response.status);
        manifest = validateManifest(payload);
      } catch {
        status.textContent = '작전실 구현 요약을 검증하지 못했습니다.';
      } finally {
        manifestLoad = null;
        render();
      }
    })();
    return manifestLoad;
  };

  const refreshSnapshot = async () => {
    if (!allowed || !manifest || refresh.disabled) return;
    refresh.disabled = true;
    status.textContent = '사용자 요청으로 현재 상태를 확인하는 중입니다.';
    const checkedAt = new Date().toISOString();
    const [aleph, devices] = await Promise.allSettled([
      fetch('/aleph.json', { credentials: 'omit', cache: 'no-store', redirect: 'error' }),
      fetch('/api/devices', { credentials: 'same-origin', cache: 'no-store', redirect: 'error' }),
    ]);
    snapshot = {};

    if (aleph.status === 'fulfilled' && aleph.value.ok) {
      const payload = await aleph.value.json().catch(() => null);
      if (Number.isInteger(payload?.step) && SHA.test(payload?.commit ?? '')) {
        snapshot.aleph = {
          status: window.location.origin === configuredOrigin(manifest)
            ? STATUS.operationalObserved : STATUS.deploymentObserved,
          details: ['step ' + payload.step, '커밋 ' + payload.commit.slice(0, 12), timestamp(checkedAt), '서버 제공 요청 ID 없음'],
        };
      } else snapshot.aleph = { ...operationFailure(aleph.value.status), details: ['응답 형식 검증 실패', timestamp(checkedAt)] };
    } else {
      const httpStatus = aleph.status === 'fulfilled' ? aleph.value.status : null;
      snapshot.aleph = { ...operationFailure(httpStatus), details: [httpStatus == null ? '요청 실패' : 'HTTP ' + httpStatus, timestamp(checkedAt)] };
    }

    if (devices.status === 'fulfilled' && devices.value.ok) {
      const payload = await devices.value.json().catch(() => null);
      try {
        const summary = summarizeDevices(payload);
        snapshot.devices = {
          status: window.location.origin === configuredOrigin(manifest)
            ? STATUS.operationalObserved : STATUS.deploymentObserved,
          details: ['총 ' + summary.total + '개', '승인 ' + summary.states.approved,
            '대기 ' + summary.states.pending, '거부 ' + summary.states.rejected,
            '취소 ' + summary.states.revoked, timestamp(checkedAt), '서버 제공 요청 ID 없음'],
        };
      } catch {
        snapshot.devices = { ...operationFailure(devices.value.status), details: ['응답 형식 검증 실패', timestamp(checkedAt)] };
      }
    } else {
      const httpStatus = devices.status === 'fulfilled' ? devices.value.status : null;
      snapshot.devices = { ...operationFailure(httpStatus), details: [httpStatus == null ? '요청 실패' : 'HTTP ' + httpStatus, timestamp(checkedAt)] };
    }
    status.textContent = '수동 확인 결과입니다. 자동 반복 조회는 하지 않습니다.';
    refresh.disabled = false;
    render();
  };

  refresh.addEventListener('click', () => void refreshSnapshot());
  return {
    allow(detail = {}) {
      allowed = true;
      protectedRead = protectedReadObservation({
        httpStatus: detail.httpStatus,
        checkedAt: detail.checkedAt,
        origin: window.location.origin,
        configuredOrigin: configuredOrigin(manifest),
      });
      render();
      void loadManifest().then(() => {
        if (allowed) {
          protectedRead = protectedReadObservation({
            httpStatus: detail.httpStatus, checkedAt: detail.checkedAt,
            origin: window.location.origin, configuredOrigin: configuredOrigin(manifest),
          });
          render();
          if (Number.isInteger(detail.httpStatus)) {
            addVerification(VERIFICATION_CASES.find(value => value.testId === 'approved_signed_memo_list'), {
              httpStatus: detail.httpStatus,
              errorCode: null,
              serverRequestId: detail.serverRequestId,
              serverObservedAt: detail.serverObservedAt,
              executedAt: detail.checkedAt,
              environment: window.location.origin === configuredOrigin(manifest) ? 'operational' : 'isolation',
              source: 'approved_signed_fetch',
            });
          }
        }
      });
    },
    clear() {
      allowed = false;
      protectedRead = null;
      snapshot = null;
      verificationRecords = [];
      caseSequence = 0;
      refresh.disabled = false;
      render();
    },
  };
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const root = document.querySelector('#operations-room');
  if (root) {
    const room = createOperationsRoom(root);
    window.addEventListener('byteback:operations-access', event => room.allow(event.detail));
    window.addEventListener('byteback:operations-hidden', () => room.clear());
    window.addEventListener('byteback:device-invalidated', () => room.clear());
  }
}
