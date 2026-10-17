# 11단계 기기 요청 계약 (구현 계약, 운영 미적용)

공식 `docs/DECIDER_REQUEST.md`는 판정기의 18개 입력·5개 출력 계약이며 이 문서와 별개다. 제공된 자료에는 WebAuthn 또는 HTTP 서명 헤더 형식이 없었다. 아래 계약은 이 자료실의 구현이며 실제 심판·반 엔진과의 호환성은 미확인이다. 판정기 입력이나 `RULE_IDS`를 추가하지 않는다.

## 신뢰 경계

- 기존 로그인 검증이 결정한 사용자 UUID와 세션 토큰의 SHA-256에 기기를 묶는다. 클라이언트의 사용자·역할·승인 주장은 사용하지 않는다. 토큰 원문은 DB에 저장하지 않는다.
- WebAuthn 검증은 고정 버전 `@simplewebauthn/server` 14.0.3, 브라우저 처리는 `@simplewebauthn/browser` 14.0.0을 사용한다. 브라우저 번들과 라이선스는 빌드 시 로컬 패키지에서 복사한다. 자체 바이너리 파서나 서명 검증기를 만들지 않는다.
- RP ID와 origin은 서버의 `publicAppUrl`에서만 결정한다. 요청의 Host·Origin을 신뢰 기준으로 채택하지 않는다. 사용자 존재 및 사용자 확인(UP/UV)을 요구하고 동기화 가능한 `multiDevice` 또는 백업된 credential은 거부한다.
- `attestationType: none`이므로 제조사·인증장치의 하드웨어 비추출성이나 PWA 설치 사실을 증명하지 않는다. 보장하는 것은 승인된 공개키에 대응하는 유효한 WebAuthn 서명이다. 실제 개인키는 인증장치가 관리하며 앱은 읽거나 저장하지 않는다.

## 등록과 승인

모든 `/api/devices` 요청은 기존 사용자 인증이 필요하다. 쿠키를 사용하는 POST는 설정된 origin과 일치해야 한다. 응답은 `Cache-Control: no-store`다.

1. `GET /api/devices`: 본인 기기의 식별자·상태·공개키 지문을 조회한다. 공개키 원문·카운터·다른 사용자 기기는 응답하지 않는다.
2. `POST /api/devices`, `{"action":"registration-options"}`: 해당 사용자·세션에 묶인 등록 challenge를 발급한다.
3. `{"action":"registration-verify","nonceId":"…","response":WebAuthn등록응답}`: 라이브러리로 challenge·origin·RP ID·UP/UV를 검증한 뒤 **pending**으로 등록한다. 처음 등록한 기기도 자동 승인하지 않는다.
4. 이미 승인된 본인 기기에서 아래 요청 서명 절차로 `{"action":"decision","targetDeviceId":"…","decision":"approved|rejected|revoked","reason":"3~240자 사유"}`를 전송한다. 자기 승인은 금지하며 자기 회수는 허용한다.
5. 첫 기기는 HTTP 승인 경로를 사용할 수 없다. 별도 권한을 가진 운영자가 사용자의 신원을 독립 확인하고 전체 공개키 지문을 대조한 후 비공개 `operator_decide`를 실행한다. 구체적인 순서는 [운영 적용 준비](DEVICE_ROLLOUT.md)를 따른다.

미등록은 행이 없는 상태다. 저장 상태는 pending·approved·rejected·revoked를 구분한다. pending에서 approved/rejected, approved에서 revoked로만 이동한다. 거부·회수된 키를 다시 승인하지 않는다. 등록·결정·회수·성공한 요청 증명을 별도 추가 전용 감사 표에 기록하며 기존 메모 감사 표는 변경하지 않는다. 사유 원문 대신 해시를 기록한다.

## 요청 서명

메모 목록·단건 조회·생성·수정·삭제, 보호 공지, 복원 미리보기·실행 및 기기 승인 결정은 각각 별도의 증명이 필요하다. 로그인과 기기 등록/상태 조회는 보호 자료를 노출하지 않는다.

1. 브라우저가 **실제로 보낼 문자열**을 UTF-8로 해시한다. 본문 없는 요청의 해시는 빈 바이트열의 SHA-256이다.
2. `POST /api/devices`에 `action: "request-options"`, `credentialId`, `method`, `path`, `query`, `bodySha256`을 보낸다. `query`는 없으면 빈 문자열, 있으면 `?`부터 시작하는 원문이다. 쿼리 순서·인코딩도 바뀌면 다른 요청이다.
3. 서버는 본인 승인 기기만 허용하고 임의 challenge를 생성한다. DB에 인증된 사용자·세션 해시·credential·메서드·경로·쿼리·본문 해시와 challenge를 묶는다. DB가 발급 시각부터 **90초 만료**를 설정한다. 브라우저가 만료 시각을 정할 수 없다.
4. 인증장치가 challenge에 서명한다. 실제 요청에는 `X-Byteback-Proof: base64url(UTF-8 JSON({nonceId, assertion}))`를 포함한다. assertion은 라이브러리의 인증 응답이다. JWT/HttpOnly 세션도 별도로 필요하다. proof를 URL에 넣지 않는다.
5. 서버는 **수신한 원시 본문 바이트**를 읽고 메서드·`req.url` 경로/쿼리·본문 SHA-256을 계산한다. 파싱된 객체를 JSON으로 재직렬화하여 대체하지 않는다. 원시 바이트를 얻지 못하면 거부한다.
6. 저장된 바인딩과 실제 요청을 비교하고 라이브러리로 공개키·challenge·origin·RP ID·UP/UV·카운터를 검증한다. 서명 검증 직후 실제 요청 정보를 다시 계산한다.
7. DB가 기기·nonce를 잠그고 현재 승인·소유자·세션·바인딩·만료·일회성·기존 카운터를 재검증한다. nonce 소비와 카운터 갱신은 하나의 트랜잭션이다. 같은 nonce의 병렬 소비는 하나만 성공한다.
8. DB 반환 이후 실제 요청을 다시 비교한 뒤 기존 API의 입력·소유권·백업·권한 검사를 수행한다. 증명이 유효해도 기존 정책을 우회하지 않는다.

nonce는 업무 요청 전에 소비하므로 뒤의 입력·소유권·업무 DB 검사가 실패해도 재시도에는 새 증명이 필요하다. 기기 회수는 이후 nonce 소비를 차단한다. 이미 소비를 마친 진행 중 업무 요청을 회수 트랜잭션과 원자적으로 취소하는 구조는 아니다.

## 실패와 운영 한계

| 조건 | HTTP·오류 | 보호 자료 접근/업무 쓰기 |
|---|---|---|
| 사용자 인증 없음/실패 | 401 `AUTH_REQUIRED` | 차단 |
| 서명 없음 | 403 `DEVICE_SIGNATURE_REQUIRED` | 차단 |
| 경로·쿼리·메서드·본문 바인딩 불일치 | 403 `DEVICE_REQUEST_MISMATCH` | 차단 |
| WebAuthn 서명·origin·challenge·UV 실패 | 403 `DEVICE_SIGNATURE_INVALID` | 차단 |
| 미등록/타인 credential | 403 `DEVICE_REGISTRATION_REQUIRED` 또는 `DEVICE_NOT_APPROVED` | 차단 |
| 대기·거부·회수 상태 | 403 `DEVICE_NOT_APPROVED` | 차단 |
| 만료/재사용/카운터 경쟁 | 403 `DEVICE_CHALLENGE_EXPIRED` / `DEVICE_NONCE_REUSED` / `DEVICE_COUNTER_CHANGED` | 차단 |
| DB·설정·원시 본문 사용 불가 | 503, 상황별 `DEVICE_*`/`RAW_BODY_*` | 허용으로 전환하지 않음 |

보호 API의 최종 원시 본문 실패는 공통 gate에서 503 `DEVICE_VERIFICATION_UNAVAILABLE`로 제한한다. 기존 400/404/409/500 업무 응답은 기기 검사를 통과한 뒤에도 발생할 수 있다. 기존 복원 RPC 커밋 후 API의 추가 검사가 실패해도 해당 커밋을 되돌릴 수 없는 한계는 유지된다.

승인 대기·승인 완료 기기의 합계는 사용자당 10개, 유효 nonce는 사용자당 30개로 제한한다. 거부·회수된 기기는 이력과 감사를 보존하되 활성 기기 한도에서는 제외한다. 따라서 모든 기기를 회수했어도 새 기기를 승인 대기로 등록하고 독립 운영자 확인을 다시 받을 수 있다. 회수된 키를 재승인하거나 첫 기기를 자동 승인하지는 않는다. 격리 PostgreSQL의 `test/step11-device-quota.sql` 27개 검사에서 활성 한도, 회수·거부 후 등록, 이력 보존, nonce/CAS와 소유자 잠금을 확인했다. 만료 challenge 보관·등록 스팸에 대한 별도 운영 정리/제한은 추후 검토 대상이다. 등록된 기기가 없는 환경에서 이 후보를 배포하면 보호 API가 즉시 잠긴다. 검사 우회 환경변수나 심판 토큰 예외는 없다.

브라우저 저장소에 개인키·토큰·증명·승인 플래그를 기록하지 않는다. 기기 선택은 메모리에만 유지한다. 서버 승인 목록만으로 메모를 표시하지 않으며, 사용자 동작으로 유효하게 서명한 조회가 성공해야 표시한다. 회수 감지·401/기기 403·로그아웃·오프라인 전환 시 자료를 숨긴다. 상태 새로고침은 30초 및 창 활성화 시 수행하므로 이미 표시한 화면에서 회수를 인지하는 데 지연이 있을 수 있다. 모든 보호 API는 매 요청의 DB 승인 검증을 거친다.

Vercel의 원시 본문 재생은 공식 Node 런타임 구현을 근거로 지원했다. 실제 Vercel 배포에서의 원시 경로·본문 전달, 실제 브라우저·인증장치, 운영 Supabase, 실제 심판 JWT/기기 프로토콜은 아직 검증하지 않았다.

## 시험 재실행

`npm.cmd run device:test`는 시험 인증장치·메모리 저장소·가상 화면을 사용하며 운영 DB에 연결하지 않는다. 원시 본문은 문자열 그대로 기존 API에 전달한다. 빈 바이트는 본문 없음으로 유지하고 JSON `null`·문자열·잘못된 JSON을 빈 복원 명령으로 바꾸지 않는 회귀를 포함한다. `npm.cmd run pwa:test`는 캐시 경계를 모의 실행하고 실제 브라우저 번들을 로딩한다.

`scripts/test-device-http-db.mjs`는 별도 실제 HTTP·DB 검증용 도구다. 독립 시험 DB에 신규 SQL이 이미 적용되어 있어야 한다. DB 비밀번호를 받지 않고 `--bridge-dir`의 SQL 요청/응답 파일 또는 `--bridge-stdio`의 프레임을 MCP 중계자가 전달하는 구조이므로 이 스크립트만 실행하면 DB 시험이 완료되는 것은 아니다. 중계자는 반드시 의도한 격리 project/branch/database를 고정하고 운영 DB로 전달하지 않는다. 가상 데이터와 시험 키만 사용하며 결과에는 경로 형식·상태·시간·데이터 지문만 기록한다. 실제 PostgREST 서비스·실제 인증장치·운영 쿠키·심판 토큰을 검증하는 도구는 아니다.
