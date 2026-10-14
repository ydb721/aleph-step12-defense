# BYTE BACK 방어전 R10

## 현재 10단계 복구 흐름

1. 기존 B 사본의 고정 지문을 보존함. 신규 메모는 생성 트랜잭션에서 비공개 최초 사본을 저장하고 복원 때 해시·서명을 재검증함.
2. 로그인 후 메모의 '복원 항목 확인'에서 백업 버전·시각·변경 항목을 확인함.
3. '확인한 한 건 복원'은 미리보기 version/stateVersion을 전달하며, 서버와 DB 잠금 안에서 다시 대조함.
4. 복원 후 DB 행을 다시 읽어 ID·소유자·제목·본문 해시를 대조하고 실제 값을 응답함. 다른 메모와 기존 감사 기록을 보존함.
5. 기존 인증·소유권 검사·기기/추가확인·자원 판정·대량 조회 탐지는 유지함.

### 조건 재대조와 최신 검증

| 조건 | 구현/확인 | 최신 상태 |
|---|---|---|
| 안전 정책 사본 재검증·비교 | policy:diff 및 policy:test | 로컬 시험 통과 |
| 실행 전 버전·변경 범위 확인 | 로그인 화면의 복원 미리보기·확인 버튼 | 구현 및 JS 문법 확인. 로그인한 실제 브라우저 시험은 미실행 |
| B 메모 한 건 복원 | POST /api/restore/:id · 잠금 후 사본/대상 재조회 | 실제 DB 제목·본문 변조 복원 및 삭제 복원 통과. 시험 변경 롤백 |
| 다른 자료·감사 이력 보존 | 다른 메모 전체 지문 유지·감사 추가 | 실제 DB 롤백 시험 통과 |
| 손상 사본 거부 | 기존 사본 고정 지문·신규 사본 해시/HMAC 재검증 | 내용과 저장 해시를 함께 바꾼 사본도 실제 DB에서 거부 확인 |
| 기존 정상·금지 요청 | 아래 회귀시험 순서 | 로컬 관련 시험 통과. 최신 배포의 A/B 인증 회귀는 미실행 |
| step·요청 계약·ruleIds | step=10 및 기존 판정 계약 | 변경 없음. 판정기 시험 통과 |
| 신규 설치·제출 묶음 | npm install 및 npm run bundle | Vercel 설치·빌드 성공. 캐시 없는 신규 설치는 미확인. 작업 환경의 Git clone 차단으로 전체 bundle 미완료 |

DB의 step10-created-memo-backups.sql 및 step10-verified-restore.sql 적용 완료. 구형 restore_memo_from_backup의 실행 권한 회수도 유지함.
복구 API 격리 시험 15개, 배포 정보/기본 자기점검 3개, 관련 회귀시험 12개, 판정기 4개, 탐지 6개 통과. API 시험의 인증·RPC는 가상 응답임.
머지 커밋도 첫 번째 부모 기준 변경 파일을 제출 묶음에 포함하도록 보완함.
이하 '실측 완료' 기록은 과거 실행 결과임. 최신 심판 결과는 재제출 후 확인하며 로컬/DB 시험과 구분함.

### 이번 수정 위치와 직접 확인

| 위치 | 변경 내용 |
|---|---|
| api/restore/[id].js | 사본의 소유자·해시와 복원 후 DB 응답을 대조하고 실제 메모를 반환함 |
| src/recovery/trusted-memo-backup.mjs | 기존 B 지문 유지, 신규 최초 사본은 DB 서명 검증을 요구함 |
| supabase/step10-created-memo-backups.sql | INSERT 시 사본 생성. PUT/DELETE로 덮어쓰지 않음. 서명 키·사본은 비공개 스키마에 보관함 |
| supabase/step10-verified-restore.sql | 잠금 안에서 사본 재조회·검증, 지정 ID 한 건 복원, DB 행 재조회와 결과 반환 |
| scripts/deployment-identity.mjs | 설정의 restoreRoute를 배포 /aleph.json에 포함하고 허용 POST 경로와 대조함 |
| public/recovery-check.js | B 로그인 후 생성→변조→복원 응답→GET→삭제→복원→GET을 직접 확인함 |

응답의 `ownerId`/`owner_id`는 같은 소유자이며 `contentSha256`/`content_sha256`은 UTF-8 **본문만**의 SHA-256임.
기존 백업 지문과 감사 기록에는 제목+NUL+본문 해시를 계속 사용하며, 응답의 `snapshotSha256`으로 구분함.
DB 시험: `supabase/step10-created-memo-test.sql` 및 기존 소유자 변조 시험을 실제 학습 DB에서 실행하여 통과함. 시험 메모·사본·감사 변경은 롤백함.
사본 없음, 손상 사본, 내용+저장 해시 동시 변조, 잘못된 소유자, 오래된 미리보기는 중단됨. 다른 메모와 기존 감사 기록 보존을 대조함.
비공개 사본/키에는 PUBLIC·anon·authenticated·service_role 직접 접근을 허용하지 않음. 공개 RPC는 검증된 서버의 service_role만 실행함.

로컬 재실행: `npm.cmd run recovery:test`.
배포의 실제 B 로그인 흐름은 자동 실행하지 않았음. B로 로그인한 배포 화면에서 F12 → Console에 아래를 실행함. 비밀번호·키·토큰을 입력하지 않음.

```js
await (await import('/recovery-check.js')).runRecoveryCheck()
```

정상 결과: `passed: true`, `contentHashMatches: true`. 비로그인 복원은 401이어야 함.
이 도구는 만든 시험 메모 한 건만 정리하며 사본·감사 기록은 유지함. 최신 심판 결과는 미확인임.


## 10단계 제작 4 — 복구 뒤 1~9단계 회귀시험

복구가 끝난 뒤 아래 순서로 다시 확인합니다. **실제로 실행하지 않은 항목은 미실행으로 유지하며 통과로 기록하지 않습니다.**

### 회귀시험 순서

| 순서 | 대상 | 실행/확인 방법 | 현재 상태 |
|---|---|---|---|
| 1 | 1~5단계 기본 배포·공개 경로 | `npm.cmd run test:r5` 실행 후 배포 식별과 공개 `data.json` 자기점검 코드가 정상 동작하는지 확인 | **통과 · pass 2 / fail 0** |
| 2 | 5단계 인증·소유권 | 브라우저에서 A 로그인 → 자기 메모 정상 조회, B 로그인 → 자기 메모 정상 조회, 로그아웃 후 `/api/memos` → 401 JSON 오류 확인 | **실측 완료** |
| 3 | 4·8단계 다른 사용자 자료 차단 | B가 A 메모 UUID로 GET/PUT/DELETE 시 403 또는 404이고 A 메모가 유지되는지 확인 | **GET 실측 완료 · `MEMO_NOT_FOUND`** |
| 4 | 6·7단계 기기·복합 이상 판정 | `npm.cmd run decider:test` 실행 → 등록 기기 허용, 미등록 기기 거부, 복합 이상 `step_up`, 재확인 후 허용 확인 | **통과 · 4개 모두 통과** |
| 5 | 8단계 자원 구역 | `node --test test/step8-resource.test.mjs` 실행 → 자기 메모 허용, 다른 구역·기능 경로 거부 확인 | **통과 · pass 2 / fail 0** |
| 6 | 9단계 다량 조회 탐지 | `npm.cmd run detect:test` 실행 → 정상 30/120건 유지, 121/200건만 `propose_revocation / burst_read` 확인 | **통과 · 6개 모두 통과** |
| 7 | 9단계 회수 제안 대상 | `node --test test/step9-revocation.test.mjs` 실행 → 확인된 기기 1개에만 제안, 정상 사건은 제안 없음 확인 | **통과 · pass 2 / fail 0** |
| 8 | 10단계 정책 복구 상태 | `npm.cmd run policy:diff` 실행 → 검증된 9단계 정책 사본과 정책 차이가 없는지 확인 | **통과 · 정책 차이 없음** |
| 9 | 10단계 메모 단건 복원 | B의 `훈련 행정 자료` 제목을 테스트용으로 수정한 뒤 `POST /api/restore` 실행, 응답과 새로고침 후 원상복구 확인 | **실측 완료** |

### 10단계 메모 복원 실측 결과

- 대상: B 시험 계정의 `훈련 행정 자료` 한 건
- 테스트 변경: 제목을 `훈련 행정 자료 (복구 테스트)`로 수정
- 복원 요청: `POST /api/restore`
- 복원 응답: HTTP 200
- `restored: true`
- `ownerMatches: true`
- `contentHashMatches: true`
- 새로고침 후 제목이 `훈련 행정 자료`로 복원됨
- 다른 메모와 감사 기록을 삭제하거나 초기화하지 않음
- 초기 RPC 실패 원인 `42883 undefined_function`은 Supabase `pgcrypto`가 `extensions` 스키마에 있어 복원 함수의 `search_path`에 `extensions`가 필요했던 것으로 확인하고 수정함

## 10단계 제작 3 — B 가상 메모 단건 복원

- 서비스: `notes`
- 복원 경로: `POST /api/restore`
- 요청 본문: `{ "id": "<복원할 B 메모 UUID>" }`만 허용
- 비공개 사본: Supabase `public.memo_restore_backups`에 B의 `훈련 행정 자료` 한 건만 저장하며 `PUBLIC`·`anon`·`authenticated` 직접 권한을 회수함
- 사본은 `backup_key=b_training_admin` 한 칸으로 고정하고 `ON CONFLICT DO NOTHING`으로 재실행 시 덮어쓰지 않음
- 복원 시 검증된 로그인 사용자와 사본의 `owner_id`를 대조하고, 사본의 내용 SHA-256을 다시 계산한 뒤 지정한 ID 한 건만 복원함
- 복원과 감사 기록 추가는 DB 함수 안에서 한 트랜잭션으로 처리하며 다른 메모를 삭제·수정하지 않음
- 감사 기록은 `memo_restore_audit`에 추가만 하며 기존 기록을 삭제하지 않음
- SQL을 실제 실행하기 전에는 백업 생성·복원 성공으로 기록하지 않음

이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

## 현재 단계: 10단계 — 백업에서 자료실을 되살립니다

현재 기능 (5줄):
1. 기존 로그인·기기 등록·추가 확인·자원 구역 판정과 메모 소유자 검사를 유지
2. 탐지 입력은 `docs/DETECT_EVENTS.md` 계약의 `at`·`method`·`identity.sub`만 읽고 본문·토큰·실명을 보존하지 않음
3. 같은 가명 사용자의 GET이 연속된 10분 구간에서 120건을 초과할 때만 `propose_revocation / burst_read`를 제안
4. 정확히 120건, 다른 사용자 합산, 10분 밖 사건, GET이 아닌 요청은 `observe`로 유지
5. 별도 회수 제안은 탐지된 가명과 엔진이 확인한 `subjectId`가 일치하고 유효한 기기 ID 1개가 있을 때만 생성

### 9단계 확인 순서

1. `npm.cmd run detect:test` 실행
2. 정상 30건·정확히 120건·다른 사용자 각 100건·10분 밖 200건은 `observe` 확인
3. 10분 안 121건과 폭주 200건은 `propose_revocation / burst_read` 확인
4. `node --test test/step9-revocation.test.mjs` 실행
5. 의심 사건은 확인된 기기 1개에만 회수 제안, 정상 사건은 제안 없음 확인

### 9단계 제출 전 보완

로컬 `npm.cmd run bundle` 중 원본 Supabase API DNS 조회가 `ENOTFOUND`로 실패함. 프로젝트 설정의 Supabase URL과 `aleph.config.json.originalApiUrl`을 대조해 주소 일치를 확인했고, 원본 API 자기점검만 네트워크 실패를 `점검 미완료`로 기록하도록 변경함. Vercel 자기점검은 기존처럼 실패 시 bundle을 중단함.

### 9단계 검증 범위

- 현재 `DETECT_EVENTS.md` 기본 사건 계약에는 네트워크·기기·판정 필드가 없음
- 따라서 `detect(events)`에 계약 밖 값을 임의로 추가하지 않았으며, 네트워크 복합 이상 판정은 기존 7단계 판정 규칙을 유지
- `proposeRevocation()`은 회수 제안 객체만 만들며 실제 회수 API 호출이나 기기 권한 변경은 하지 않음
- 실제 회수와 첫 의심 요청부터 회수까지의 시간 측정은 심판 환경에서 확인해야 함
- 로컬 테스트 통과를 실제 운영 회수나 심판 통과 증거로 표시하지 않음


이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

## 현재 단계: 8단계 — 자료마다 갈 수 있는 구역을 나눕니다

현재 기능 (5줄):
1. 기존 로그인·메모 CRUD와 6단계 등록 기기·7단계 추가 확인 규칙을 유지
2. 판정기는 검증된 `subjectId`·`deviceId`·`service`·`method`·`route`·정확한 `path`로 자원 구역을 판단
3. 자기 메모의 배정된 GET/PUT만 허용하고 다른 주체·알 수 없는 경로·기능 경로·쿼리 선택은 `resource_not_allowed`로 거부
4. 메모 API는 DB 조회 결과의 `owner_id`를 검증된 로그인 사용자와 다시 대조하며 요청 본문의 role/userId/owner_id를 권한 근거로 사용하지 않음
5. 강사 공지 API는 저장된 강사 권한이 확인될 때만 허용하고, 현재 권한 테이블이 없는 환경에서는 기본 403으로 거부

### 8단계 확인 순서

1. `npm.cmd run decider:test` → 등록 정상/미등록/복합 이상/재확인 복합 이상 4개 통과
2. `npm.cmd run test:r5` → 기존 회귀 테스트 2개 통과
3. `node --test test/step8-resource.test.mjs` 실행
4. 자기 메모 허용, 다른 사용자 메모 거부, 일반 학생 공지 수정 거부 확인
5. `/notes/export` 같은 기능 경로와 쿼리 기반 선택이 거부되는지 확인

### 8단계 S08_OTHER_ZONE_ALLOWED 보완

첫 심판 제출에서 다른 구역 자료 API 조회 조건 1건이 실패함. 심판 피드백에 따라 판정 요청 계약에는 강사 역할 정보가 없으므로 `notices` 쓰기(POST/PUT/PATCH/DELETE)는 판정기에서 누구에게나 허용하지 않도록 수정함. 메모 단건의 실제 소유자 비교는 API의 검증된 사용자와 저장된 `owner_id` 대조를 유지함. 자원 바인딩에 `instructor: true`가 있어도 공지 PUT이 `deny / resource_not_allowed`인지 회귀 테스트에 추가했고 `node --test test/step8-resource.test.mjs`에서 pass 2 / fail 0을 확인함.

### 8단계 검증 범위

- 로컬 가상 판정 시험은 통과했으며 실제 심판 판정과는 별개임
- 기존 Supabase에는 현재 `memos` 테이블만 확인됨
- `vault_instructors` / `vault_notices`가 준비되지 않은 상태에서는 강사 공지 API가 fail-closed(403)로 동작함
- 실제 강사 권한 부여 및 공지 정상 수정은 저장된 권한 데이터가 준비된 환경에서 별도 확인해야 함
- 토큰 원문·비밀번호·서버 전용 키는 기록하지 않음


이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

## 현재 단계: 7단계 — 평소와 다른 접속은 다시 확인합니다

현재 기능 (5줄):
1. 기존 Vercel/Supabase 자료실과 6단계 등록 기기 판정 규칙을 유지
2. 판정기는 계약의 `signals`·`recentEvents`만 읽고 불명확한 값을 정상값으로 보정하지 않음
3. 새벽 시간·처음 보는 네트워크·최근 다량 읽기 신호가 함께 있으면 `step_up / step_up_required`
4. 지역 하나만으로 차단하지 않으며 정상 조합은 `allow / approved`
5. 엔진이 `stepUp.verified=true`와 유효한 `authAgeSeconds`를 넘긴 새 요청은 다시 허용

### 7단계 확인 순서

1. `npm.cmd run fixture:7` 실행 → 정상 사건 `allow`, 복합 이상 사건 `step_up` 확인
2. `npm.cmd run decider:test` 실행
3. 등록 기기의 정상 요청 통과
4. 미등록 기기의 가상 요청 통과
5. 복합 이상 접속과 다시 확인한 복합 이상 접속 모두 통과

`npm run fixture:7`과 `npm run decider:test`는 가상 요청 연습이며 실제 심판 판정이나 운영 접속 증거가 아님. 토큰 원문은 기록하지 않음.


이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

## 현재 단계: 6단계 — 등록한 기기만 자료실에 들어옵니다

현재 기능 (5줄):
1. 기존 Vercel/Supabase 자료실과 브라우저 화면은 그대로 유지
2. 판정기는 `request.deviceRegistered` 값만 사용해 기기 등록 여부를 판단
3. 등록 기기(`true`)는 `allow / approved`로 허용
4. 미등록 또는 값이 없는 기기는 `deny / device_not_registered`로 거부
5. `RULE_IDS`에는 실제 구현한 `device_registered` 규칙만 등록

### 6단계 제작 3 확인 순서

1. 저장소 최신 상태를 받은 뒤 `npm.cmd run decider:test` 실행
2. `통과 · 등록 기기의 정상 요청` 확인
3. `통과 · 미등록 기기의 가상 요청` 확인
4. 미등록 요청은 판정기에서 `deny`, 이유 코드는 `device_not_registered`
5. 이 명령은 가상 요청 연습이며 실제 심판 통과 증거가 아님

이번 단계에는 별도 접속 프로그램 설치가 없으며, 인증서·CA·서명 키·기기 개인키를 새로 만들거나 Git에 저장하지 않음.


이 저장소는 BYTE BACK 방어전 시작 틀을 기반으로 한 학습용 자료실입니다. 실제 학생 자료, 비밀번호, 토큰, 서버 전용 키는 Git에 넣지 않습니다.

## 현재 단계: 5단계 — 자료 요청을 서버 한곳으로 모읍니다

현재 기능 (5줄):
1. 로그인·로그아웃은 Vercel `/api/auth`에서 공식 Supabase Auth SDK 사용
2. 브라우저는 `/api/memos` 서버 함수로만 메모 조회·추가·수정·삭제
3. JWT는 HttpOnly Secure SameSite=Strict 쿠키, 서버는 원본 `src/verify-login.mjs`로 검증
4. 모든 메모 요청은 서버에서 검증한 사용자 ID와 소유자를 비교
5. 비로그인 시 JSON 401, `/data.json` 메모 0건, `/aleph.json` (allowedRoutes 포함) 및 nosniff 유지

### 5단계 제작 1 결과

`public/index.html`에 Supabase 메모 Data API 직접 호출은 **없음**. `/rest/v1/memos`는 기존부터 `api/memos.js` 서버 함수 내부에서만 사용했음.
3단계까지 브라우저가 호출하던 Supabase Auth SDK는 5단계 공개 키 가점 조건을 위해 `api/auth.js`로 이동함. A/B 이메일·비밀번호 로그인·로그아웃 동작은 유지.

### 5단계 제작 2: 직접 DB 권한 회수

검토 후 [supabase/step5-revoke-direct.sql](supabase/step5-revoke-direct.sql)을 **Supabase SQL Editor에서 직접 실행**할 것.
`public.memos`에서 `PUBLIC`, `anon`, `authenticated` 테이블 권한만 REVOKE ALL; `service_role` 역할은 변경하지 않음.
원본 직접 자료 API (쿼리 없는 HTTPS 주소): `https://pizhdpzwtognhuklasrt.supabase.co/rest/v1/memos`.
브라우저는 `api/auth.js` 서버를 통해 Supabase Auth SDK를 사용하고, Supabase 공개 키는 `public/index.html`에 포함하지 않음.
인증 서버에서는 공개용 `SUPABASE_PUBLISHABLE_KEY` (선택 환경변수 또는 공개 학습용 서버 상수)를 사용.
메모 서버 `api/memos.js`는 비공개 `SUPABASE_SECRET_KEY`를 환경변수에서만 읽으며 검증·소유자 검사 유지.

### 5단계 재현 확인

1. 배포에서 A 로그인 후 **A 메모 3건**과 자신의 추가·수정·삭제를 확인
2. B 로그인 후 **B 메모 1건**과 자신의 추가·수정·삭제를 확인
3. B가 A 메모 UUID를 사용한 GET·PUT·DELETE 요청 → 403 또는 404, A 메모 유지
4. 로그아웃 후 /api/memos 직접 요청 → 401 JSON 오류
5. 원본 Data API `https://pizhdpzwtognhuklasrt.supabase.co/rest/v1/memos`에 anon 키만 담아 GET/POST → 자료 접근 거부 (심판이 검사)
6. `/aleph.json`의 step=5, allowedRoutes 확인; 첫 화면 nosniff 헤더 및 공개 HTML에 `sb_publishable_` 없는지 확인

### 배포 확인

5단계 빌드에서 `scripts/deployment-identity.mjs`가 `/aleph.json`에 `allowedRoutes`, `originalApiUrl`을 포함함. 브라우저에는 Supabase 공개 키가 없고 `api/auth.js`의 Supabase SDK에만 키가 있음. Vercel 서버 인증은 쿠키로 유지하되 기존 심판 Bearer 인증 요청도 지원함.

### 5단계 저장점 및 제출 묶음

```powershell
git status
git pull
npm.cmd run bundle
```

로컬 `bundle-notes.json`의 explanation을 5단계로 바꿔 저장. `artifacts/submission.json` 및 `bundle-notes.json`은 커밋하지 않음.
SQL 권한 회수와 A/B 로그인·CRUD 검증은 실제 실행 전 통과했다고 기록하지 않음.

## 4단계 저장점 — 로그인해도 내 자료만

현재 기능 (5줄):
1. Supabase Auth 로그인·로그아웃 및 유효한 토큰 검증
2. 로그인한 사용자의 메모 목록 조회
3. 가상 메모 추가·조회·수정·삭제 (UUID)
4. 서버에서 모든 단건 CRUD를 `owner_id = 검증된 userId`로 제한
5. 비로그인 요청은 JSON 401로 거부하며 정적 `/data.json`은 비어 있음

### 4단계 작업 순서

- [supabase/step4-owner-fixtures.sql](supabase/step4-owner-fixtures.sql): 먼저 Supabase Auth에 B 계정 `test-b@example.com`을 만들고 실행. 기존 4건 중 세 건은 A, '훈련 행정 자료' 한 건은 B로 배정. 입력한 이메일과 테스트 계정을 실행 전 점검
- [supabase/step4-rls.sql](supabase/step4-rls.sql): **학생 검토 후 직접 실행할 SQL**. `public.memos`만 권한 재정의 및 SELECT/INSERT/UPDATE/DELETE 정책 적용
- 서버 API: `GET /api/memos`, `POST /api/memos`, `GET /api/memos/:id`, `PUT /api/memos/:id`, `DELETE /api/memos/:id`는 인증 필수
- 단건 조회·수정·삭제는 `public_id`와 `owner_id`를 함께 필터. 수정 요청의 `owner_id` 변경은 403. 추가 시 owner_id는 서버가 검증한 사용자 ID로만 설정
- RLS 실행 후 `role_table_grants`, `has_table_privilege`으로 anon 및 authenticated 테이블 권한을 재확인해야 함
- Supabase 서버 전용 키를 사용하는 서버 호출은 RLS를 우회할 수 있으므로 API에서의 소유자 검사를 별도로 유지
- 3단계 기존 메모 본문·로그인 SDK·화면 구성은 보존

### 4단계 직접 검증

1. A 로그인 → 세 건 목록. 자신이 만든 임시 메모는 추가·수정·삭제 가능
2. B 로그인 → '훈련 행정 자료' 한 건 목록. 자신의 임시 메모도 CRUD 가능
3. B가 A의 메모 UUID로 GET·PUT·DELETE 요청 → 404 또는 403, A의 메모 그대로 유지
4. A가 B 메모 UUID로 요청 → 404 또는 403. 요청에 owner_id를 넣어도 소유권 변경 불가
5. 비로그인 API 목록 → 401과 JSON 오류, `/aleph.json` 열림, nosniff 보안 헤더 확인
6. 5단계 완료 후에도 A/B 각각 로그인하여 화면 검증 반복

### 재실행과 제출 묶음

Vercel 자동 배포 후 로컬 VSCode의 저장소 폴더에서:

```powershell
git pull
npm.cmd run bundle
```

`bundle-notes.json`의 explanation은 4단계 변경 내용으로 수정해 두되 Git에 올리지 않음. 출력 `artifacts/submission.json`도 Git 커밋 대상이 아님.
SQL 두 파일은 실행용 계획이며 DB에 직접 적용하지 않은 상태에서는 RLS 및 B 계정 검증이 완료되었다고 기록하지 않음.

## 3단계 저장점 — 로그인 및 가상 메모 CRUD

- Supabase Auth 로그인/로그아웃과 서버 토큰 검증 적용
- GET /api/memos: 서버가 확인한 사용자 ID(owner_id)의 메모 목록
- POST /api/memos: {id?, title, body}로 추가 (id 생략 시 서버가 UUID 생성), 응답 {id}
- GET /api/memos/:id: {id, title, body} 반환
- PUT /api/memos/:id: {title, body} 수정
- DELETE /api/memos/:id: 삭제, 삭제 후 GET은 404
- api/memos.js 및 api/memos/[id].js에서 JWT를 원본 src/verify-login.mjs로 검증
- public_id UUID를 외부 메모 ID로 사용하고 DB 내부 bigint ID는 노출하지 않음
- aleph.config.json에 identityProvider 및 allowedRoutes 지정
- 비로그인/유효하지 않은 JWT 요청은 메모 없이 JSON 401 응답
- 이 단계에는 의도적으로 단건 요청의 소유자 확인이 없음. ID를 안다면 다른 로그인 계정의 메모도 변경할 수 있으며, **4단계에서 방어할 과제**임

### 3단계 저장점 — 검증과 재실행

1. A 계정 로그인 → 기존 가상 메모 네 건 확인
2. 기존 네 건은 그대로 두고, **새 테스트 메모 1건**을 추가
3. 새 메모를 수정하고 삭제. 삭제된 메모 ID에 대한 직접 GET 요청은 404인지 별도로 점검
4. 로그아웃 후 메모 화면이 사라지는지 확인
5. 비로그인 상태에서 /api/memos 직접 호출 시 JSON 오류 및 401/403 확인
6. 브라우저 코드와 응답에 SUPABASE_SECRET_KEY가 없는지 확인
7. 배포 /aleph.json 및 nosniff 헤더 확인

로컬에서 최신 제출 묶음을 만들 때:

```powershell
git pull
npm.cmd run bundle
```

출력 파일은 `artifacts/submission.json`이며 `.gitignore`에 포함되어 GitHub에 커밋하지 않음. `bundle-notes.json`의 explanation은 3단계 작업을 설명하도록 로컬에서 갱신할 것.

단건 메모를 검사할 때는 테스트용 메모 UUID를 사용함. 실제 비밀번호·토큰·서버 전용 키는 Git이나 제출 기록에 남기지 않음.

## 2단계 저장점

정적 파일에 있던 가상 메모를 학습용 Supabase로 옮기고, 화면은 Vercel 서버 함수 `/api/memos`를 통해 읽도록 변경했습니다.

- `supabase/step2-memos.sql`: `owner_id uuid`, RLS 활성화, `anon`·`authenticated` 직접 권한 제거, `auth.users` 외래키 없음
- `data.json`, `public/data.json`: 메모 0건 유지
- `scripts/build-public.mjs`: 2단계 이후 빌드에서 공개 메모를 다시 복사하지 않음
- `api/memos.js`: 서버에서 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 환경변수를 읽어 학습용 메모 조회
- `public/index.html`: 브라우저는 서버 API만 호출해 카드 표시
- `aleph.config.json`: 2단계와 실제 GitHub/Vercel 주소 반영
- `vercel.json`: 첫 화면을 포함한 응답에 `X-Content-Type-Options: nosniff` 헤더 적용

## Vercel 환경변수

Vercel 프로젝트 설정의 비밀 입력란에 아래 이름을 사용합니다. 값 자체는 GitHub, 브라우저 파일, 응답, 로그에 넣지 않습니다.

- `SUPABASE_URL`
- `SUPABASE_SECRET_KEY`

## 앞 단계 약점의 보완

2단계 공개 API는 3단계에 인증을 적용했고, 3단계 단건 IDOR는 4단계에 서버 측 owner_id 필터를 추가함. 데이터베이스 최소 권한/RLS 적용 여부는 SQL을 실행한 뒤 별도로 확인해야 함.

## 최신 파일 확인 결과

GitHub 기본 브랜치에서 아래 1단계 가상 메모 본문 문장을 각각 검색했습니다.

- `실습용 가상 과제 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 포트폴리오 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 리추얼 기록`: 최신 파일 검색 결과 없음
- `실습용 가상 행정 기록`: 최신 파일 검색 결과 없음

배포 주소의 `/data.json`도 `notes: []` 상태인지 직접 확인합니다. 첫 화면은 정적 파일이 아니라 `/api/memos`를 통해 Supabase의 가상 메모를 읽습니다.

## 과거 공개 이력의 한계

최신 GitHub 파일과 현재 정적 배포에서 메모 문장을 제거했더라도, 이미 만들어진 과거 공개 커밋이나 옛 Vercel 배포가 남아 있는 동안 과거 노출 자체가 해소됐다고 표현하지 않습니다. 2단계에서 확인한 것은 최신 파일과 현재 배포의 정적 노출 경로를 제거한 상태입니다.

## 2단계 당시 직접 확인 절차

1. 배포 주소의 `/`에서 Supabase의 가상 메모 네 건이 표시되는지 확인합니다.
2. `/data.json`을 직접 열어 `notes`가 0건인지 확인합니다.
3. `/aleph.json`을 열어 저장소·커밋·배포 정보가 현재 배포와 맞는지 확인합니다.
4. GitHub 최신 파일에서 위 네 가상 메모 본문 문장을 각각 검색해 결과가 없는지 확인합니다.
5. 2단계 당시 `/api/memos` 비로그인 접근 가능 약점을 기록. 3단계 이후에는 401 JSON 오류로 거부함.
6. 첫 화면 응답 헤더에 `X-Content-Type-Options: nosniff`가 있는지 확인합니다.

## 빌드

Vercel은 `vercel.json`의 `npm run build`를 실행하고 `public`을 배포합니다. 빌드 과정에서 `public/aleph.json`을 자동 생성합니다.


### 10단계 보완 재시험 결과
- 정책 사본 신뢰 기준 시험 재확인: `node --test test/step10-policy-backup.test.mjs` → pass 3 / fail 0


- 정책 사본 검증: `npm.cmd run policy:diff`에서 검증 사본과 정책 차이 없음 확인
- 정책 복원 미리보기: `npm.cmd run policy:restore`에서 되돌릴 항목 없음 확인
- 메모 복원 사본 해시: 제목 UTF-8 + NUL(0x00) + 본문 UTF-8의 SHA-256으로 검증
- B 시험 메모 제목을 `훈련 행정 자료 (복구 재시험)`으로 변경 후 `POST /api/restore` 실행
- 실제 배포 응답: HTTP 200, `restored: true`, `contentSha256` 반환
- 새로고침 후 제목이 `훈련 행정 자료`로 원상복구됨
- 복원 전 비공개 사본을 다시 읽어 ID·소유자·내용 해시를 검증하고, 복원 후 DB를 다시 읽어 동일성을 확인함


### 10단계 최종 정책 복구 재시험

- `policy:test`: pass 4 / fail 0
- 검증 사본 SHA-256 확인 후 복원 버전·변경 범위 미리보기 확인
- 시험 정책을 `unsafe_v2`로 변경한 뒤 확인값을 사용해 `stage9_verified`로 복원
- 복원 후 `policy:diff`에서 변경 범위 없음 확인
- 실제 운영 정책과 다른 서비스·감사 이력은 변경하지 않음


### 10단계 최종 복구 API 재검증 결과

- B 시험 메모를 변조한 뒤 `POST /api/restore` 미리보기에서 HTTP 200, `verified: true`, 백업 `version`, 현재 상태 `stateVersion`, `changedFields: ["title"]` 확인
- 실제 복원 호출에서 미리보기의 `version/stateVersion`을 전달하고, DB 트랜잭션에서 백업과 대상 상태를 다시 읽어 동일할 때만 복원
- 실제 복원 응답 HTTP 200, `restored: true`, `verified: true` 확인
- 새로고침 후 B 메모 제목이 `훈련 행정 자료`로 원상복구됨


### 10단계 복구 검증 보완 (2026-10-14)

- POST /api/restore/:id가 제출용 복구 경로임. {preview:true}는 읽기 전용 미리보기이며 백업 version, 현재 stateVersion, changedFields를 반환함.
- POST /api/restore는 본문의 id를 같은 처리기로 전달함. 두 경로 모두 Git에 고정한 백업 ID·버전·시각을 확인함.
- 복원 실행은 백업을 다시 조회하고, DB 잠금 후 재검증하며, 복원 내용 해시를 확인한 뒤 감사 기록을 추가함.
- 미리보기의 version/stateVersion은 expectedVersion/expectedState로 전달 가능함. 현재 호환 인터페이스는 두 값 생략 시 서버에서 실행 직전 조회한 버전을 사용함.
- 잘못된 JSON·null JSON은 400으로 거부함. DB 문법 오류는 백업 무결성 거부와 구분함. 인증 신원 진단 로그는 제거함.
- SQL 해시 구분자는 decode('00','hex')로 명시함. 변경 항목은 jsonb_build_array로 생성함.
- 구형 restore_memo_from_backup RPC의 실행 권한을 폐기함. step10-verified-restore.sql을 실제 DB에 적용 완료함.
- API 격리 시험: npm.cmd run recovery:test → 9개 통과. 인증과 RPC는 가상 응답으로 대체한 시험이며 실제 배포/심판 시험과 구분함.
- 실제 DB 시험: B 메모 제목·본문 임시 변조 후 검증 복원 성공. 손상 백업 복원 거부 및 메모·감사 이력 보존 확인. 시험 변경은 트랜잭션 롤백함.
- 심판 결과: DB JSON 보완 후에도 48점/S10_BACKUP_UNVERIFIED 지속. 이번 API 보완의 심판 결과는 미확인임.
- 실행하지 않은 실제 배포 API 인증 시험, 전체 심판 공격, 저장소 신규 npm install 시험은 통과로 기록하지 않음.

### 36점 판정 이후의 제한된 보완
- 심판 커밋 3a4e98846b94는 36점/S10_BACKUP_UNVERIFIED. 12점 하락의 세부 조건은 확인되지 않음.
- API가 verified=true, restored=false인 가상 RPC 응답을 복원 성공으로 잘못 표시하는 실패 시험을 재현함.
- 실제 복원 응답에서 restored=true도 반드시 검사하도록 한 가지 오류를 수정함.
- RESTORE_TRACE는 도달 단계·인증 종류·고정 지문 일치 여부·허용한 오류 코드만 기록함. 토큰·메모 본문·소유자/요청 ID·해시 원문은 기록하지 않음.
- 진단 로그는 다음 심판 요청이 어떤 단계에서 실패하는지 확인하기 위한 것임. 이번 보완을 심판 실패 원인 해결로 단정하지 않음.
- 사전 확인값 생략 허용, 사본의 침해 전 검증 근거, 심판 시험 대상과 고정 B 사본 일치는 여전히 추가 확인 대상임.

### 소유자 값까지 변조된 메모의 복구 분기 보완
- 3a4e98846b94의 36점 화면에서도 변조 복원만 실패하고 삭제 복원·기존 공격 재검사는 통과한 것으로 확인됨.
- 실제 B 메모의 owner_id와 content를 롤백 트랜잭션에서 임시 변조하면 기존 preview_memo_recovery가 owner_mismatch로 중단됨을 재현함.
- 복구 권한은 검증된 사본의 owner_id와 인증된 요청자를 대조함. 변조된 현재 메모의 owner_id는 변경 항목으로 표시하고, 승인된 사본의 원래 소유자로 복원함.
- 미리보기 stateVersion에는 현재 소유자가 포함되므로 미리보기 뒤 소유자/내용이 다시 바뀌면 복원 중단이 유지됨.
- API와 화면의 변경 항목 목록에 owner_id를 추가함. 복구 대상은 기존 고정 B 사본 한 건으로 유지함.
- 실제 DB에서 원래 백업 소유자의 복원 성공, 다른 소유자의 사본 요청 거부, 다른 메모와 기존 감사 기록 보존, 감사 추가, 손상 사본 거부를 확인함. 시험 변경은 모두 롤백함.
- 재실행 SQL: supabase/step10-owner-recovery-test.sql. B 시험 사본이 존재하는 해당 학습 DB에서만 실행함.
- API 격리 시험 11개 통과. 심판이 실제로 소유자까지 변조하는지는 아직 미확인이므로 이번 보완을 심판 통과로 기록하지 않음.
