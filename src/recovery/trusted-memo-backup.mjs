// The nonsecret digest of the independently recorded B exercise backup.
// This value is pinned in Git, outside the mutable Supabase backup row.
// It covers the snapshot ID, owner, title, content, stored content hash,
// source commit and capture time (see preview_memo_recovery SQL).
// Pinning detects later changes; it is not evidence of verification before
// any historical incident that preceded this commit.
export const TRUSTED_B_BACKUP = Object.freeze({
  id: 'a4d2a3cc-33be-481b-b479-a0bcd5f07bfb',
  version: 'db42e80d61e1344d50f03517281f76927518a87c81cab1a402339985792f5b87',
  capturedAt: '2026-10-13T07:28:40.913811+00:00',
  sourceCommit: '847972a71c0f469c330f58b67ea1dbc3893cfec3',
});

export function isTrustedMemoBackupPreview(preview) {
  return Boolean(
    preview
    && typeof preview === 'object'
    && preview.id === TRUSTED_B_BACKUP.id
    && preview.version === TRUSTED_B_BACKUP.version
    && preview.capturedAt === TRUSTED_B_BACKUP.capturedAt
    && preview.verified === true
  );
}
