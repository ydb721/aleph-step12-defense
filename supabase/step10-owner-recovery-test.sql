-- B fixture only. All memo/backup/audit test changes are rolled back.
begin;
do $test$
declare
  b public.memo_restore_backups%rowtype;
  other_owner uuid;
  p jsonb;
  other_memos text;
  previous_audit text;
  previous_audit_count bigint;
  previous_audit_ids uuid[];
  message text;
begin
  select * into strict b from public.memo_restore_backups
  where public_id='a4d2a3cc-33be-481b-b479-a0bcd5f07bfb';
  select owner_id into other_owner from public.memos where owner_id<>b.owner_id limit 1;
  if other_owner is null then raise exception 'missing_second_fixture_owner'; end if;
  select md5(coalesce(jsonb_agg(to_jsonb(m) order by m.public_id)::text,''))
    into other_memos from public.memos m where public_id<>b.public_id;
  select md5(coalesce(jsonb_agg(to_jsonb(a) order by a.audit_id)::text,'')),count(*),array_agg(a.audit_id)
    into previous_audit,previous_audit_count,previous_audit_ids from public.memo_restore_audit a;
  update public.memos set owner_id=other_owner,content=coalesce(content,'')||' [recovery fixture]'
    where public_id=b.public_id;
  -- Current ownership never grants permission over someone else's backup.
  begin
    perform public.preview_memo_recovery(other_owner,b.public_id);
    raise exception 'wrong_owner_authorized';
  exception when sqlstate 'P0001' then
    get stacked diagnostics message=message_text;
    if message<>'backup_not_found' then raise; end if;
  end;
  p:=public.preview_memo_recovery(b.owner_id,b.public_id);
  if not (p->'changedFields' ? 'owner_id') or not (p->'changedFields' ? 'content')
     or p->>'version'<>'db42e80d61e1344d50f03517281f76927518a87c81cab1a402339985792f5b87' then
    raise exception 'owner_change_or_trust_not_detected';
  end if;
  perform public.restore_verified_memo(b.owner_id,b.public_id,p->>'version',p->>'stateVersion');
  if not exists(select 1 from public.memos where public_id=b.public_id
    and owner_id=b.owner_id and title=b.title and content=b.content) then
    raise exception 'restored_fields_mismatch';
  end if;
  if other_memos is distinct from
    (select md5(coalesce(jsonb_agg(to_jsonb(m) order by m.public_id)::text,''))
     from public.memos m where public_id<>b.public_id) then
    raise exception 'other_memos_changed';
  end if;
  if (select count(*) from public.memo_restore_audit)<>previous_audit_count+1 then
    raise exception 'audit_append_failed';
  end if;
  if previous_audit is distinct from
    (select md5(coalesce(jsonb_agg(to_jsonb(a) order by a.audit_id)::text,''))
     from public.memo_restore_audit a where audit_id=any(previous_audit_ids)) then
    raise exception 'existing_audit_changed';
  end if;
  p:=public.preview_memo_recovery(b.owner_id,b.public_id);
  begin
    update public.memo_restore_backups set content=content||' [damaged fixture]' where public_id=b.public_id;
    begin
      perform public.restore_verified_memo(b.owner_id,b.public_id,p->>'version',p->>'stateVersion');
      raise exception 'damaged_backup_restored';
    exception when sqlstate 'P0001' then
      get stacked diagnostics message=message_text;
      if message<>'backup_hash_mismatch' then raise; end if;
    end;
    raise exception using errcode='Z0001',message='revert_fixture';
  exception when sqlstate 'Z0001' then null;
  end;
end $test$;
select 'PASS: tampered owner restored for original backup owner, wrong owner denied, content restored, other memos preserved, audit appended, damaged backup rejected' as result;
rollback;
