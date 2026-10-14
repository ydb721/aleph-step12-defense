-- Install before step10-verified-restore.sql. No existing memo is copied here.
-- Future INSERTs capture the initial memo atomically; PUT/DELETE never update it.
-- The signing key is generated inside Postgres and never leaves this schema.
create schema if not exists byteback_recovery;
revoke all on schema byteback_recovery from public, anon, authenticated, service_role;

create table if not exists byteback_recovery.signing_key (
  singleton boolean primary key check (singleton),
  secret bytea not null check (octet_length(secret) = 32)
);
insert into byteback_recovery.signing_key(singleton, secret)
values (true, extensions.gen_random_bytes(32)) on conflict do nothing;

create table if not exists byteback_recovery.initial_memo_backups (
  public_id uuid primary key,
  owner_id uuid not null,
  title text not null,
  content text not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  backed_up_at timestamptz not null,
  seal bytea not null check (octet_length(seal) = 32)
);
alter table byteback_recovery.signing_key enable row level security;
alter table byteback_recovery.initial_memo_backups enable row level security;
revoke all on all tables in schema byteback_recovery
from public, anon, authenticated, service_role;

create or replace function byteback_recovery.capture_initial_memo()
returns trigger language plpgsql security definer
set search_path = pg_catalog
set timezone = 'UTC'
as $$
declare
  previous_owner uuid;
  previous_title text;
  previous_content text;
  captured timestamptz := clock_timestamp();
  content_hash text;
  manifest bytea;
  signing_secret bytea;
begin
  -- Preserve older unowned public fixtures; authenticated creates always have an owner.
  if new.owner_id is null then return new; end if;
  select owner_id, title, content into previous_owner, previous_title, previous_content
  from public.memo_restore_backups where public_id = new.public_id;
  if not found then
    select owner_id, title, content into previous_owner, previous_title, previous_content
    from byteback_recovery.initial_memo_backups where public_id = new.public_id;
  end if;
  if found then
    -- A verified restoration may recreate this ID. A new create cannot replace its snapshot.
    if previous_owner is distinct from new.owner_id
       or previous_title is distinct from new.title
       or previous_content is distinct from coalesce(new.content, '') then
      raise exception using errcode = 'P0001', message = 'memo_id_reserved';
    end if;
    return new;
  end if;
  content_hash := encode(extensions.digest(convert_to(new.title, 'UTF8')
    || decode('00', 'hex') || convert_to(coalesce(new.content, ''), 'UTF8'), 'sha256'), 'hex');
  manifest := convert_to(jsonb_build_array(new.public_id, new.owner_id, new.title,
    coalesce(new.content, ''), content_hash, 'on_create', captured)::text, 'UTF8');
  select secret into strict signing_secret from byteback_recovery.signing_key where singleton;
  insert into byteback_recovery.initial_memo_backups
    (public_id, owner_id, title, content, content_sha256, backed_up_at, seal)
  values (new.public_id, new.owner_id, new.title, coalesce(new.content, ''), content_hash,
    captured, extensions.hmac(manifest, signing_secret, 'sha256'));
  return new;
end;
$$;
revoke all on function byteback_recovery.capture_initial_memo()
from public, anon, authenticated, service_role;

drop trigger if exists byteback_capture_initial_memo on public.memos;
create trigger byteback_capture_initial_memo
after insert on public.memos for each row
execute function byteback_recovery.capture_initial_memo();

create or replace function byteback_recovery.verified_snapshot(p_actor uuid, p_public_id uuid)
returns jsonb language plpgsql security definer
set search_path = pg_catalog
set timezone = 'UTC'
as $$
declare
  legacy public.memo_restore_backups%rowtype;
  initial byteback_recovery.initial_memo_backups%rowtype;
  content_hash text;
  manifest bytea;
  backup_version text;
  signing_secret bytea;
begin
  select * into legacy from public.memo_restore_backups where public_id = p_public_id;
  if found then
    if legacy.owner_id is distinct from p_actor then
      raise exception using errcode = 'P0001', message = 'backup_not_found';
    end if;
    content_hash := encode(extensions.digest(convert_to(legacy.title, 'UTF8')
      || decode('00', 'hex') || convert_to(coalesce(legacy.content, ''), 'UTF8'), 'sha256'), 'hex');
    if content_hash is distinct from legacy.content_sha256 then
      raise exception using errcode = 'P0001', message = 'backup_hash_mismatch';
    end if;
    manifest := convert_to(jsonb_build_array(legacy.public_id, legacy.owner_id,
      legacy.title, legacy.content, legacy.content_sha256,
      legacy.source_commit, legacy.backed_up_at)::text, 'UTF8');
    backup_version := encode(extensions.digest(manifest, 'sha256'), 'hex');
    -- Keep the existing independently recorded B snapshot anchor unchanged.
    if backup_version <> 'db42e80d61e1344d50f03517281f76927518a87c81cab1a402339985792f5b87' then
      raise exception using errcode = 'P0001', message = 'backup_seal_mismatch';
    end if;
    return jsonb_build_object('id', legacy.public_id, 'ownerId', legacy.owner_id,
      'title', legacy.title, 'body', legacy.content, 'snapshotSha256', content_hash,
      'contentSha256', encode(extensions.digest(convert_to(legacy.content, 'UTF8'), 'sha256'), 'hex'),
      'version', backup_version, 'capturedAt', legacy.backed_up_at,
      'backupKind', 'legacy', 'sealVerified', false);
  end if;
  select * into initial from byteback_recovery.initial_memo_backups
  where public_id = p_public_id and owner_id = p_actor;
  if not found then
    raise exception using errcode = 'P0001', message = 'backup_not_found';
  end if;
  content_hash := encode(extensions.digest(convert_to(initial.title, 'UTF8')
    || decode('00', 'hex') || convert_to(initial.content, 'UTF8'), 'sha256'), 'hex');
  if content_hash is distinct from initial.content_sha256 then
    raise exception using errcode = 'P0001', message = 'backup_hash_mismatch';
  end if;
  manifest := convert_to(jsonb_build_array(initial.public_id, initial.owner_id,
    initial.title, initial.content, initial.content_sha256,
    'on_create', initial.backed_up_at)::text, 'UTF8');
  select secret into strict signing_secret from byteback_recovery.signing_key where singleton;
  if extensions.hmac(manifest, signing_secret, 'sha256') is distinct from initial.seal then
    raise exception using errcode = 'P0001', message = 'backup_seal_mismatch';
  end if;
  backup_version := encode(extensions.digest(manifest, 'sha256'), 'hex');
  return jsonb_build_object('id', initial.public_id, 'ownerId', initial.owner_id,
    'title', initial.title, 'body', initial.content, 'snapshotSha256', content_hash,
    'contentSha256', encode(extensions.digest(convert_to(initial.content, 'UTF8'), 'sha256'), 'hex'),
    'version', backup_version, 'capturedAt', initial.backed_up_at,
    'backupKind', 'on_create', 'sealVerified', true);
end;
$$;
revoke all on function byteback_recovery.verified_snapshot(uuid, uuid)
from public, anon, authenticated, service_role;
