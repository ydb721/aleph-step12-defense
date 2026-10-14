-- BYTE BACK 10단계 S10_BACKUP_UNVERIFIED 보완
-- 미리보기에서 사본/현재 상태 버전을 만들고,
-- 실제 복원 트랜잭션에서 두 행을 잠근 뒤 다시 읽어 같은 버전일 때만 복원합니다.

create or replace function public.preview_memo_recovery(
  p_actor uuid,
  p_public_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  b public.memo_restore_backups%rowtype;
  m public.memos%rowtype;
  changes jsonb := '[]'::jsonb;
  backup_version text;
  state_version text;
  actual_backup_hash text;
begin
  select * into b
  from public.memo_restore_backups
  where public_id = p_public_id
    and owner_id = p_actor;

  if not found then
    raise exception using errcode = 'P0001', message = 'backup_not_found';
  end if;

  actual_backup_hash := encode(
    extensions.digest(
      convert_to(b.title, 'UTF8')
      || decode('00', 'hex')
      || convert_to(coalesce(b.content, ''), 'UTF8'),
      'sha256'
    ),
    'hex'
  );

  if actual_backup_hash is distinct from b.content_sha256 then
    raise exception using errcode = 'P0001', message = 'backup_hash_mismatch';
  end if;

  backup_version := encode(
    extensions.digest(
      convert_to(
        jsonb_build_array(
          b.public_id, b.owner_id, b.title, b.content,
          b.content_sha256, b.source_commit, b.backed_up_at
        )::text,
        'UTF8'
      ),
      'sha256'
    ),
    'hex'
  );

  select * into m
  from public.memos
  where public_id = p_public_id;

  if not found then
    changes := jsonb_build_array('create');
    state_version := encode(
      extensions.digest(convert_to('missing:' || p_public_id::text, 'UTF8'), 'sha256'),
      'hex'
    );
  else
    if m.owner_id is distinct from p_actor then
      raise exception using errcode = 'P0001', message = 'owner_mismatch';
    end if;

    if m.title is distinct from b.title then
      changes := changes || jsonb_build_array('title');
    end if;
    if coalesce(m.content, '') is distinct from coalesce(b.content, '') then
      changes := changes || jsonb_build_array('content');
    end if;

    state_version := encode(
      extensions.digest(
        convert_to(
          jsonb_build_array(m.public_id, m.owner_id, m.title, coalesce(m.content, ''))::text,
          'UTF8'
        ),
        'sha256'
      ),
      'hex'
    );
  end if;

  return jsonb_build_object(
    'id', p_public_id,
    'verified', true,
    'version', backup_version,
    'stateVersion', state_version,
    'capturedAt', b.backed_up_at,
    'changedFields', changes
  );
end;
$$;

create or replace function public.restore_verified_memo(
  p_actor uuid,
  p_public_id uuid,
  p_expected_version text,
  p_expected_state text
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, extensions
as $$
declare
  preview jsonb;
  b public.memo_restore_backups%rowtype;
  restored_hash text;
begin
  if p_expected_version is null
     or p_expected_version !~ '^[0-9a-f]{64}$'
     or p_expected_state is null
     or p_expected_state !~ '^[0-9a-f]{64}$' then
    raise exception using errcode = 'P0001', message = 'expected_versions_required';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_public_id::text, 0));

  perform 1
  from public.memo_restore_backups
  where public_id = p_public_id
  for update;

  perform 1
  from public.memos
  where public_id = p_public_id
  for update;

  preview := public.preview_memo_recovery(p_actor, p_public_id);

  if preview->>'version' is distinct from p_expected_version
     or preview->>'stateVersion' is distinct from p_expected_state then
    raise exception using errcode = 'P0001', message = 'backup_or_target_changed';
  end if;

  select * into b
  from public.memo_restore_backups
  where public_id = p_public_id
    and owner_id = p_actor;

  if not found then
    raise exception using errcode = 'P0001', message = 'backup_not_found';
  end if;

  update public.memos
  set title = b.title,
      content = b.content
  where public_id = b.public_id
    and owner_id = b.owner_id;

  if not found then
    insert into public.memos (public_id, owner_id, title, content)
    values (b.public_id, b.owner_id, b.title, b.content);
  end if;

  select encode(
    extensions.digest(
      convert_to(title, 'UTF8')
      || decode('00', 'hex')
      || convert_to(coalesce(content, ''), 'UTF8'),
      'sha256'
    ),
    'hex'
  )
  into restored_hash
  from public.memos
  where public_id = b.public_id
    and owner_id = b.owner_id;

  if restored_hash is distinct from b.content_sha256 then
    raise exception using errcode = 'P0001', message = 'restore_verify_failed';
  end if;

  insert into public.memo_restore_audit (
    actor_id, memo_public_id, backup_sha256, action
  )
  values (
    p_actor, b.public_id, b.content_sha256, 'memo_restore'
  );

  return jsonb_build_object(
    'id', b.public_id,
    'verified', true,
    'restored', true
  );
end;
$$;

revoke all on function public.preview_memo_recovery(uuid, uuid)
from public, anon, authenticated;

revoke all on function public.restore_verified_memo(uuid, uuid, text, text)
from public, anon, authenticated;

grant execute on function public.preview_memo_recovery(uuid, uuid)
to service_role;

grant execute on function public.restore_verified_memo(uuid, uuid, text, text)
to service_role;

notify pgrst, 'reload schema';


-- Retire the obsolete RPC so it cannot bypass verified recovery.
do $retire$
begin
  if to_regprocedure('public.restore_memo_from_backup(uuid,uuid)') is not null then
    execute 'revoke all on function public.restore_memo_from_backup(uuid,uuid) from public, anon, authenticated, service_role';
  end if;
end $retire$;
