-- Install step10-created-memo-backups.sql first. Only this test memo service changes.
-- Reread and verify the snapshot, lock snapshot/target, restore one ID, then reread it.
create or replace function public.preview_memo_recovery(p_actor uuid, p_public_id uuid)
returns jsonb language plpgsql security definer
set search_path = pg_catalog
set timezone = 'UTC'
as $$
declare
  b jsonb;
  m public.memos%rowtype;
  changes jsonb := '[]'::jsonb;
  state_version text;
begin
  b := byteback_recovery.verified_snapshot(p_actor, p_public_id);
  select * into m from public.memos where public_id = p_public_id;
  if not found then
    changes := jsonb_build_array('create');
    state_version := encode(extensions.digest(
      convert_to('missing:' || p_public_id::text, 'UTF8'), 'sha256'), 'hex');
  else
    -- The verified snapshot owns the authorization decision; the target may be tampered.
    if m.owner_id is distinct from (b->>'ownerId')::uuid then
      changes := changes || jsonb_build_array('owner_id');
    end if;
    if m.title is distinct from b->>'title' then
      changes := changes || jsonb_build_array('title');
    end if;
    if coalesce(m.content, '') is distinct from b->>'body' then
      changes := changes || jsonb_build_array('content');
    end if;
    state_version := encode(extensions.digest(convert_to(jsonb_build_array(
      m.public_id, m.owner_id, m.title, coalesce(m.content, ''))::text, 'UTF8'), 'sha256'), 'hex');
  end if;
  return jsonb_build_object('id', p_public_id, 'verified', true,
    'version', b->>'version', 'stateVersion', state_version,
    'capturedAt', b->>'capturedAt', 'changedFields', changes,
    'ownerId', b->>'ownerId', 'contentSha256', b->>'contentSha256',
    'snapshotSha256', b->>'snapshotSha256', 'backupKind', b->>'backupKind',
    'sealVerified', (b->>'sealVerified')::boolean);
end;
$$;

create or replace function public.restore_verified_memo(
  p_actor uuid, p_public_id uuid, p_expected_version text, p_expected_state text
)
returns jsonb language plpgsql security definer
set search_path = pg_catalog
set timezone = 'UTC'
as $$
declare
  preview jsonb;
  b jsonb;
  restored public.memos%rowtype;
  restored_hash text;
  body_hash text;
begin
  if p_expected_version is null or p_expected_version !~ '^[0-9a-f]{64}$'
     or p_expected_state is null or p_expected_state !~ '^[0-9a-f]{64}$' then
    raise exception using errcode = 'P0001', message = 'expected_versions_required';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(p_public_id::text, 0));
  perform 1 from public.memo_restore_backups where public_id = p_public_id for update;
  perform 1 from byteback_recovery.initial_memo_backups where public_id = p_public_id for update;
  perform 1 from public.memos where public_id = p_public_id for update;
  -- These calls physically reread and rehash the snapshot inside the locked transaction.
  preview := public.preview_memo_recovery(p_actor, p_public_id);
  if preview->>'version' is distinct from p_expected_version
     or preview->>'stateVersion' is distinct from p_expected_state then
    raise exception using errcode = 'P0001', message = 'backup_or_target_changed';
  end if;
  b := byteback_recovery.verified_snapshot(p_actor, p_public_id);
  update public.memos set owner_id = (b->>'ownerId')::uuid,
    title = b->>'title', content = b->>'body' where public_id = p_public_id;
  if not found then
    insert into public.memos(public_id, owner_id, title, content)
    values (p_public_id, (b->>'ownerId')::uuid, b->>'title', b->>'body');
  end if;
  -- Read the persisted row, not the input snapshot or a success flag.
  select * into restored from public.memos where public_id = p_public_id;
  if not found or restored.public_id is distinct from (b->>'id')::uuid
     or restored.owner_id is distinct from (b->>'ownerId')::uuid then
    raise exception using errcode = 'P0001', message = 'restore_verify_failed';
  end if;
  restored_hash := encode(extensions.digest(convert_to(restored.title, 'UTF8')
    || decode('00', 'hex') || convert_to(coalesce(restored.content, ''), 'UTF8'), 'sha256'), 'hex');
  body_hash := encode(extensions.digest(
    convert_to(coalesce(restored.content, ''), 'UTF8'), 'sha256'), 'hex');
  if restored_hash is distinct from b->>'snapshotSha256'
     or body_hash is distinct from b->>'contentSha256' then
    raise exception using errcode = 'P0001', message = 'restore_verify_failed';
  end if;
  insert into public.memo_restore_audit(actor_id, memo_public_id, backup_sha256, action)
  values (p_actor, restored.public_id, restored_hash, 'memo_restore');
  return jsonb_build_object('id', restored.public_id, 'title', restored.title,
    'body', coalesce(restored.content, ''),
    'ownerId', restored.owner_id, 'owner_id', restored.owner_id,
    'contentSha256', body_hash, 'content_sha256', body_hash,
    'snapshotSha256', restored_hash, 'backupVersion', b->>'version',
    'verified', true, 'restored', true);
end;
$$;
revoke all on function public.preview_memo_recovery(uuid, uuid)
from public, anon, authenticated;
revoke all on function public.restore_verified_memo(uuid, uuid, text, text)
from public, anon, authenticated;
grant execute on function public.preview_memo_recovery(uuid, uuid) to service_role;
grant execute on function public.restore_verified_memo(uuid, uuid, text, text) to service_role;
do $retire$
begin
  if to_regprocedure('public.restore_memo_from_backup(uuid,uuid)') is not null then
    execute 'revoke all on function public.restore_memo_from_backup(uuid,uuid) from public, anon, authenticated, service_role';
  end if;
end $retire$;
notify pgrst, 'reload schema';
