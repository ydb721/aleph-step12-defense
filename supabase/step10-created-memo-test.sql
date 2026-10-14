-- Learning DB only. All fixture memo/snapshot/audit changes are rolled back.
begin;
do $test$
declare
  actor uuid;
  wrong_actor uuid := gen_random_uuid();
  target uuid := gen_random_uuid();
  p jsonb;
  original_preview jsonb;
  result jsonb;
  before_memos text;
  before_audit text;
  before_audit_ids uuid[];
  before_audit_count bigint;
  before_initial_count bigint;
  snapshot_before text;
  error_message text;
  original_title text := 'Recovery fixture';
  original_body text := 'Original UTF-8 fixture: 한글 🧪';
begin
  select owner_id into strict actor from public.memo_restore_backups;
  select md5(coalesce(jsonb_agg(to_jsonb(m) order by m.public_id)::text,''))
    into before_memos from public.memos m;
  select md5(coalesce(jsonb_agg(to_jsonb(a) order by a.audit_id)::text,'')),
    array_agg(a.audit_id),count(*)
    into before_audit,before_audit_ids,before_audit_count from public.memo_restore_audit a;
  select count(*) into before_initial_count from byteback_recovery.initial_memo_backups;

  insert into public.memos(public_id,owner_id,title,content)
  values(target,actor,original_title,original_body);
  if (select count(*) from byteback_recovery.initial_memo_backups)<>before_initial_count+1 then
    raise exception 'initial_snapshot_not_created';
  end if;
  original_preview := public.preview_memo_recovery(actor,target);
  if original_preview->>'backupKind'<>'on_create'
     or original_preview->>'sealVerified'<>'true'
     or original_preview->>'contentSha256'<>encode(extensions.digest(convert_to(original_body,'UTF8'),'sha256'),'hex') then
    raise exception 'initial_snapshot_not_verified';
  end if;
  select md5(to_jsonb(b)::text) into snapshot_before
    from byteback_recovery.initial_memo_backups b where public_id=target;

  update public.memos set title='Tampered fixture',content='Changed fixture' where public_id=target;
  p := public.preview_memo_recovery(actor,target);
  if p->>'version'<>original_preview->>'version'
     or not (p->'changedFields' ? 'title') or not (p->'changedFields' ? 'content') then
    raise exception 'tamper_overwrote_snapshot';
  end if;
  result := public.restore_verified_memo(actor,target,p->>'version',p->>'stateVersion');
  if result->>'id'<>target::text or result->>'ownerId'<>actor::text
     or result->>'owner_id'<>actor::text or result->>'title'<>original_title
     or result->>'body'<>original_body
     or result->>'contentSha256'<>original_preview->>'contentSha256'
     or result->>'content_sha256'<>result->>'contentSha256'
     or result->>'snapshotSha256'<>original_preview->>'snapshotSha256' then
    raise exception 'restore_response_mismatch';
  end if;
  if not exists(select 1 from public.memos where public_id=target
    and owner_id=actor and title=original_title and content=original_body) then
    raise exception 'persisted_restore_mismatch';
  end if;

  -- A preview is invalidated if the current memo changes before execution.
  p := public.preview_memo_recovery(actor,target);
  begin
    update public.memos set content='Concurrent fixture' where public_id=target;
    perform public.restore_verified_memo(actor,target,p->>'version',p->>'stateVersion');
    raise exception 'stale_preview_accepted';
  exception when sqlstate 'P0001' then
    get stacked diagnostics error_message=message_text;
    if error_message<>'backup_or_target_changed' then raise; end if;
  end;

  -- Wrong users and missing snapshots stop without a restoration or audit append.
  begin
    perform public.restore_verified_memo(wrong_actor,target,p->>'version',p->>'stateVersion');
    raise exception 'wrong_owner_accepted';
  exception when sqlstate 'P0001' then
    get stacked diagnostics error_message=message_text;
    if error_message<>'backup_not_found' then raise; end if;
  end;
  begin
    perform public.restore_verified_memo(actor,gen_random_uuid(),p->>'version',p->>'stateVersion');
    raise exception 'missing_backup_accepted';
  exception when sqlstate 'P0001' then
    get stacked diagnostics error_message=message_text;
    if error_message<>'backup_not_found' then raise; end if;
  end;

  delete from public.memos where public_id=target;
  if exists(select 1 from public.memos where public_id=target) then raise exception 'delete_failed'; end if;
  begin
    insert into public.memos(public_id,owner_id,title,content)
    values(target,wrong_actor,'Reused fixture','Reused fixture');
    raise exception 'snapshot_id_reassigned';
  exception when sqlstate 'P0001' then
    get stacked diagnostics error_message=message_text;
    if error_message<>'memo_id_reserved' then raise; end if;
  end;
  p := public.preview_memo_recovery(actor,target);
  if p->'changedFields'<>jsonb_build_array('create') then raise exception 'missing_target_not_detected'; end if;
  result := public.restore_verified_memo(actor,target,p->>'version',p->>'stateVersion');
  if result->>'body'<>original_body or result->>'ownerId'<>actor::text
     or result->>'contentSha256'<>original_preview->>'contentSha256' then
    raise exception 'deleted_restore_mismatch';
  end if;
  if snapshot_before is distinct from (select md5(to_jsonb(b)::text)
    from byteback_recovery.initial_memo_backups b where public_id=target) then
    raise exception 'snapshot_changed_by_update_delete_restore';
  end if;

  p := public.preview_memo_recovery(actor,target);
  begin
    update byteback_recovery.initial_memo_backups set content='Damaged fixture' where public_id=target;
    perform public.restore_verified_memo(actor,target,p->>'version',p->>'stateVersion');
    raise exception 'corrupt_snapshot_accepted';
  exception when sqlstate 'P0001' then
    get stacked diagnostics error_message=message_text;
    if error_message<>'backup_hash_mismatch' then raise; end if;
  end;
  -- Recalculating the stored checksum cannot forge the separately sealed snapshot.
  begin
    update byteback_recovery.initial_memo_backups
    set content='Self-consistent damaged fixture', content_sha256=encode(extensions.digest(
      convert_to(original_title,'UTF8')||decode('00','hex')
        ||convert_to('Self-consistent damaged fixture','UTF8'),'sha256'),'hex')
    where public_id=target;
    perform public.restore_verified_memo(actor,target,p->>'version',p->>'stateVersion');
    raise exception 'self_consistent_corrupt_snapshot_accepted';
  exception when sqlstate 'P0001' then
    get stacked diagnostics error_message=message_text;
    if error_message<>'backup_seal_mismatch' then raise; end if;
  end;

  if before_memos is distinct from (select md5(coalesce(jsonb_agg(to_jsonb(m)
    order by m.public_id)::text,'')) from public.memos m where public_id<>target) then
    raise exception 'other_memos_changed';
  end if;
  if (select count(*) from public.memo_restore_audit)<>before_audit_count+2
     or before_audit is distinct from (select md5(coalesce(jsonb_agg(to_jsonb(a)
       order by a.audit_id)::text,'')) from public.memo_restore_audit a where audit_id=any(before_audit_ids)) then
    raise exception 'audit_not_preserved';
  end if;
  if has_schema_privilege('anon','byteback_recovery','USAGE')
     or has_schema_privilege('authenticated','byteback_recovery','USAGE')
     or has_schema_privilege('service_role','byteback_recovery','USAGE')
     or has_function_privilege('authenticated','public.restore_verified_memo(uuid,uuid,text,text)','EXECUTE')
     or has_function_privilege('anon','public.restore_verified_memo(uuid,uuid,text,text)','EXECUTE') then
    raise exception 'private_recovery_exposed';
  end if;
end $test$;
select 'PASS: on-create snapshot; tamper restore response and DB row; deleted restore; immutable snapshot; stale preview denied; wrong owner denied; missing/corrupt/self-consistent corrupt snapshots denied; other memos and audit preserved; private grants' as result;
rollback;
