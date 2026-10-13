// 8단계 자원 구역 식별자.
// 요청 계약에 새 필드를 만들지 않고, 서버/판정기가 같은 규칙으로 자원을 구분할 때 사용합니다.
export const RESOURCE_KIND = Object.freeze({
  MEMO: 'memo',
  INSTRUCTOR_NOTICE: 'instructor_notice',
});

function cleanId(id) {
  if (typeof id !== 'string') return null;
  const value = id.trim();
  return value && !value.includes('/') ? value : null;
}

export function memoResourceId(id) {
  const value = cleanId(id);
  return value ? `${RESOURCE_KIND.MEMO}:${value}` : null;
}

export function instructorNoticeResourceId(id) {
  const value = cleanId(id);
  return value ? `${RESOURCE_KIND.INSTRUCTOR_NOTICE}:${value}` : null;
}
