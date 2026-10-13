# BYTE BACK 방어전 R9

## 10단계 제작 4 — 복구 뒤 1~9단계 회귀시험

복구가 끝난 뒤 아래 순서로 다시 확인합니다. **실제로 실행하지 않은 항목은 미실행으로 유지하며 통과로 기록하지 않습니다.**

### 회귀시험 순서

| 순서 | 대상 | 실행/확인 방법 | 현재 상태 |
|---|---|---|---|
| 1 | 1~5단계 기본 배포·공개 경로 | `npm.cmd run test:r5` 실행 후 배포 식별과 공개 `data.json` 자기점검 코드가 정상 동작하는지 확인 | 미실행 |
| 2 | 5단계 인증·소유권 | 브라우저에서 A 로그인 → 자기 메모 정상 조회, B 로그인 → 자기 메모 정상 조회, 로그아웃 후 `/api/memos` → 401 JSON 오류 확인 | 미실행 |
| 3 | 4·8단계 다른 사용자 자료 차단 | B가 A 메모 UUID로 GET/PUT/DELETE 시 403 또는 404이고 A 메모가 유지되는지 확인 | 미실행 |
| 4 | 6·7단계 기기·복합 이상 판정 | `npm.cmd run decider:test` 실행 → 등록 기기 허용, 미등록 기기 거부, 복합 이상 `step_up`, 재확인 후 허용 확인 | 미실행 |
| 5 | 8단계 자원 구역 | `node --test test/step8-resource.test.mjs` 실행 → 자기 메모 허용, 다른 구역·기능 경로 거부 확인 | 미실행 |
| 6 | 9단계 다량 조회 탐지 | `npm.cmd run detect:test` 실행 → 정상 30/120건 유지, 121/200건만 `propose_revocation / burst_read` 확인 | 미실행 |
| 7 | 9단계 회수 제안 대상 | `node --test test/step9-revocation.test.mjs` 실행 → 확인된 기기 1개에만 제안, 정상 사건은 제안 없음 확인 | 미실행 |
| 8 | 10단계 정책 복구 상태 | `npm.cmd run policy:diff` 실행 → 검증된 9단계 정책 사본과 정책 차이가 없는지 확인 | 미실행 |
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

## 현재 단계: 9단계 — 도플갱어를 찾고 권한을 거둡니다

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
