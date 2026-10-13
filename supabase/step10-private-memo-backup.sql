-- BYTE BACK 10단계 제작 3
-- 9단계 통과 직후의 B 가상 메모 한 건만 비공개 백업으로 고정합니다.
-- 메모 본문은 Git에 넣지 않고, 이 SQL을 학생의 Supabase SQL Editor에서 실행할 때 DB 내부에서만 복사합니다.
-- 같은 backup_key가 이미 있으면 절대 덮어쓰지 않습니다.

create extension if not exists pgcrypto;

create table if not exists public.memo_restore_backups (
  backup_key text primary key check (backup_key = 'b_training_admin'),
  public_id uuid unique not null,
  owner_id uuid not null,
  title text not null,
  content text not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  source_commit text not null check (source_commit ~ '^[0-9a-f]{40}$'),
  backed_up_at timestamptz not null default now()
);

create table if not exists public.memo_restore_audit (
  audit_id uuid primary key default gen_random_uuid(),
  restored_at timestamptz not null default now(),
  actor_id uuid not null,
  memo_public_id uuid not null,
  backup_sha256 text not null check (backup_sha256 ~ '^[0-9a-f]{64}$'),
  action text not null check (action = 'memo_restore')
);

alter table public.memo_restore_backups enable row level security;
alter table public.memo_restore_audit enable row level security;

revoke all on table public.memo_restore_backups from public, anon, authenticated;
revoke all on table public.memo_restore_audit from public, anon, authenticated;

do $$
declare
  b_user uuid;
  candidates integer;
begin
  select id into b_user
  from auth.users
  where email = 'test-b@example.com';

  if b_user is null then
    raise exception 'B 테스트 계정을 찾을 수 없습니다.';
  end if;

  select count(*) into candidates
  from public.memos
  where owner_id = b_user
    and title = '훈련 행정 자료';

  if candidates <> 1 then
    raise exception 'B 복원 대상은 정확히 한 건이어야 합니다. 현재 %건', candidates;
  end if;

  insert into public.memo_restore_backups (
    backup_key,
    public_id,
    owner_id,
    title,
    content,
    content_sha256,
    source_commit
  )
  select
    'b_training_admin',
    public_id,
    owner_id,
    title,
    coalesce(content, ''),
    encode(digest(coalesce(content, ''), 'sha256'), 'hex'),
    '847972a71c0f469c330f58b67ea1dbc3893cfec3'
  from public.memos
  where owner_id = b_user
    and title = '훈련 행정 자료'
  on conflict (backup_key) do nothing;
end $$;

create or replace function public.restore_memo_from_backup(
  p_actor uuid,
  p_public_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  b public.memo_restore_backups%rowtype;
  restored_hash text;
begin
  select *
  into b
  from public.memo_restore_backups
  where public_id = p_public_id;

  if not found then
    raise exception using errcode = 'P0001', message = 'backup_not_found';
  end if;

  if b.owner_id <> p_actor then
    raise exception using errcode = 'P0001', message = 'backup_owner_mismatch';
  end if;

  if encode(digest(coalesce(b.content, ''), 'sha256'), 'hex') <> b.content_sha256 then
    raise exception using errcode = 'P0001', message = 'backup_hash_mismatch';
  end if;

  update public.memos
  set owner_id = b.owner_id,
      title = b.title,
      content = b.content
  where public_id = b.public_id;

  if not found then
    insert into public.memos (public_id, owner_id, title, content)
    values (b.public_id, b.owner_id, b.title, b.content);
  end if;

  select encode(digest(coalesce(content, ''), 'sha256'), 'hex')
  into restored_hash
  from public.memos
  where public_id = b.public_id
    and owner_id = b.owner_id;

  if restored_hash is distinct from b.content_sha256 then
    raise exception using errcode = 'P0001', message = 'restore_verify_failed';
  end if;

  insert into public.memo_restore_audit (
    actor_id,
    memo_public_id,
    backup_sha256,
    action
  )
  values (
    p_actor,
    b.public_id,
    b.content_sha256,
    'memo_restore'
  );

  return jsonb_build_object(
    'restored', true,
    'id', b.public_id,
    'ownerMatches', true,
    'contentHashMatches', true
  );
end;
$$;

revoke all on function public.restore_memo_from_backup(uuid, uuid) from public, anon, authenticated;
grant execute on function public.restore_memo_from_backup(uuid, uuid) to service_role;

-- 확인용: 본문은 출력하지 않습니다.
select
  backup_key,
  public_id,
  owner_id,
  content_sha256,
  source_commit,
  backed_up_at
from public.memo_restore_backups;
