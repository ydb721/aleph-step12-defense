-- ISOLATED TEST DATABASE ONLY. Never run against production Supabase.
-- Requires step11-device-auth.sql and the isolated test administrator's ability
-- to SET LOCAL ROLE postgres/service_role. Uses synthetic public-key bytes only;
-- this verifies SQL behavior, not a WebAuthn ceremony or a judge decision.
-- One DO statement works with a prepared-statement-only SQL bridge.
-- A deliberate exception rolls every fixture row back in a subtransaction.
-- Existing credentials/challenges/audit rows are compared before and afterward.
-- This does not claim sequence-number, session-state or external-effect rollback.
-- No credential, owner UUID, session digest or key material is printed.
-- Success completes 27 assertions; any failed assertion aborts the statement.

do $device_quota_regression$
declare
  fixture_owner uuid;
  fixture_owners uuid[] := array[]::uuid[];
  original_credential_ids uuid[];
  original_challenge_ids uuid[];
  original_audit_ids uuid[];
  registration_nonce uuid;
  request_nonce uuid;
  token_hash text := repeat('a', 64);
  nonce_value text;
  key_hash text := encode(extensions.digest(decode('AQIDBA==', 'base64'), 'sha256'), 'hex');
  new_credential text;
  request_credential text;
  request_counter bigint;
  request_binding jsonb;
  seed_state text;
  seeded_ids uuid[];
  target byteback_devices.credentials%rowtype;
  result jsonb;
  owner_lock bigint;
  checks integer := 0;
  credentials_before text;
  challenges_before text;
  audit_before text;
  fingerprint_after text;
  stage text := 'baseline';
begin
  set local role postgres;
  select array_agg(x.id), encode(extensions.digest(convert_to(coalesce(jsonb_agg(to_jsonb(x) order by x.id)::text, '[]'), 'UTF8'), 'sha256'), 'hex')
    into original_credential_ids, credentials_before from byteback_devices.credentials x;
  select array_agg(x.id), encode(extensions.digest(convert_to(coalesce(jsonb_agg(to_jsonb(x) order by x.id)::text, '[]'), 'UTF8'), 'sha256'), 'hex')
    into original_challenge_ids, challenges_before from byteback_devices.challenges x;
  select array_agg(x.id), encode(extensions.digest(convert_to(coalesce(jsonb_agg(to_jsonb(x) order by x.id)::text, '[]'), 'UTF8'), 'sha256'), 'hex')
    into original_audit_ids, audit_before from byteback_devices.audit x;

  begin
    foreach seed_state in array array['revoked', 'approved', 'pending'] loop
      stage := 'fixture_' || seed_state;
      set local role postgres;
      fixture_owner := gen_random_uuid();
      fixture_owners := array_append(fixture_owners, fixture_owner);
      registration_nonce := gen_random_uuid();
      nonce_value := translate(rtrim(encode(extensions.gen_random_bytes(32), 'base64'), '='), '+/', '-_');
      new_credential := translate(rtrim(encode(convert_to(fixture_owner::text || ':new', 'UTF8'), 'base64'), '='), '+/', '-_');
      insert into byteback_devices.credentials
        (owner_id, credential_id, public_key, counter, transports, device_type, backed_up, state, public_key_sha256)
      select fixture_owner,
        translate(rtrim(encode(convert_to(fixture_owner::text || ':' || n::text, 'UTF8'), 'base64'), '='), '+/', '-_'),
        'AQIDBA', 0, '[]'::jsonb, 'singleDevice', false, seed_state, key_hash
      from generate_series(1, 10) n;
      select array_agg(id order by id) into seeded_ids from byteback_devices.credentials where owner_id = fixture_owner;
      if cardinality(seeded_ids) <> 10 then raise exception 'ASSERT_QUOTA_FIXTURE_COUNT'; end if;
      checks := checks + 1;

      set local role service_role;
      result := public.byteback_device_action('challenge', fixture_owner, token_hash, jsonb_build_object(
        'id', registration_nonce, 'challenge', nonce_value, 'purpose', 'registration',
        'credentialId', null, 'binding', '{}'::jsonb));

      if seed_state = 'revoked' then
        stage := 'ten_revoked_allow_registration';
        result := public.byteback_device_action('register', fixture_owner, token_hash, jsonb_build_object(
          'nonceId', registration_nonce, 'credentialId', new_credential, 'publicKey', 'AQIDBA',
          'counter', 0, 'transports', '[]'::jsonb, 'deviceType', 'singleDevice', 'backedUp', false));
        set local role postgres;
        if result->'device'->>'state' <> 'pending'
           or (select count(*) from byteback_devices.credentials where owner_id = fixture_owner) <> 11
           or (select count(*) from byteback_devices.credentials where owner_id = fixture_owner and state = 'revoked') <> 10
           or (select count(*) from byteback_devices.credentials where owner_id = fixture_owner and state in ('pending', 'approved')) <> 1 then
          raise exception 'ASSERT_REVOKED_HISTORY_BLOCKED_RECOVERY';
        end if;
        checks := checks + 1;
      else
        stage := 'ten_' || seed_state || '_enforce_limit';
        begin
          result := public.byteback_device_action('register', fixture_owner, token_hash, jsonb_build_object(
            'nonceId', registration_nonce, 'credentialId', new_credential, 'publicKey', 'AQIDBA',
            'counter', 0, 'transports', '[]'::jsonb, 'deviceType', 'singleDevice', 'backedUp', false));
          raise exception 'ASSERT_ACTIVE_LIMIT_NOT_ENFORCED';
        exception when others then
          if sqlerrm <> 'DEVICE_LIMIT_REACHED' then raise; end if;
        end;
        checks := checks + 1;
        set local role postgres;
        if (select count(*) from byteback_devices.credentials where owner_id = fixture_owner) <> 10
           or (select consumed_at from byteback_devices.challenges where id = registration_nonce) is not null then
          raise exception 'ASSERT_LIMIT_FAILURE_CHANGED_STATE';
        end if;
        checks := checks + 1;

        stage := 'release_' || seed_state || '_slot';
        select * into strict target from byteback_devices.credentials where id = seeded_ids[1];
        result := byteback_devices.operator_decide(fixture_owner, target.id, key_hash,
          case when seed_state = 'approved' then 'revoked' else 'rejected' end,
          'isolated synthetic quota regression');
        set local role service_role;
        result := public.byteback_device_action('register', fixture_owner, token_hash, jsonb_build_object(
          'nonceId', registration_nonce, 'credentialId', new_credential, 'publicKey', 'AQIDBA',
          'counter', 0, 'transports', '[]'::jsonb, 'deviceType', 'singleDevice', 'backedUp', false));
        set local role postgres;
        if result->'device'->>'state' <> 'pending'
           or (select count(*) from byteback_devices.credentials where owner_id = fixture_owner) <> 11
           or (select count(*) from byteback_devices.credentials where owner_id = fixture_owner and state in ('pending', 'approved')) <> 10
           or (select count(*) from byteback_devices.credentials where owner_id = fixture_owner
               and state = case when seed_state = 'approved' then 'revoked' else 'rejected' end) <> 1 then
          raise exception 'ASSERT_RELEASED_SLOT_DID_NOT_ALLOW_REGISTRATION';
        end if;
        checks := checks + 1;
      end if;

      stage := 'history_and_audit_' || seed_state;
      set local role postgres;
      if (select count(*) from byteback_devices.credentials where id = any(seeded_ids) and owner_id = fixture_owner) <> 10 then
        raise exception 'ASSERT_EXISTING_DEVICE_HISTORY_REMOVED';
      end if;
      checks := checks + 1;
      if (select count(*) from byteback_devices.audit where owner_id = fixture_owner and action = 'registration_requested') <> 1
         or (select count(*) from byteback_devices.audit where owner_id = fixture_owner)
            <> (case when seed_state = 'revoked' then 1 else 2 end) then
        raise exception 'ASSERT_QUOTA_AUDIT_NOT_APPENDED';
      end if;
      checks := checks + 1;

      -- Observe the exact 64-bit owner transaction lock taken by the RPC.
      owner_lock := hashtextextended('byteback-device:' || fixture_owner::text, 11);
      if not exists (select 1 from pg_catalog.pg_locks
          where locktype = 'advisory' and pid = pg_backend_pid() and granted
            and mode = 'ExclusiveLock' and objsubid = 1
            and classid = ((owner_lock >> 32) & 4294967295)::oid
            and objid = (owner_lock & 4294967295)::oid) then
        raise exception 'ASSERT_OWNER_TRANSACTION_LOCK_MISSING';
      end if;
      checks := checks + 1;

      if seed_state = 'approved' then
        stage := 'counter_cas';
        select credential_id, counter into strict request_credential, request_counter
          from byteback_devices.credentials where owner_id = fixture_owner and state = 'approved' order by id limit 1;
        request_nonce := gen_random_uuid();
        nonce_value := translate(rtrim(encode(extensions.gen_random_bytes(32), 'base64'), '='), '+/', '-_');
        request_binding := jsonb_build_object('method', 'GET', 'path', '/api/memos', 'query', '',
          'bodySha256', repeat('b', 64), 'userId', fixture_owner::text, 'sessionHash', token_hash);
        set local role service_role;
        result := public.byteback_device_action('challenge', fixture_owner, token_hash, jsonb_build_object(
          'id', request_nonce, 'challenge', nonce_value, 'purpose', 'request',
          'credentialId', request_credential, 'binding', request_binding));
        begin
          result := public.byteback_device_action('consume', fixture_owner, token_hash, jsonb_build_object(
            'nonceId', request_nonce, 'credentialId', request_credential,
            'expectedCounter', request_counter + 1, 'newCounter', request_counter + 2, 'binding', request_binding));
          raise exception 'ASSERT_COUNTER_CAS_ACCEPTED_STALE_EXPECTATION';
        exception when others then
          if sqlerrm <> 'DEVICE_COUNTER_CHANGED' then raise; end if;
        end;
        checks := checks + 1;
        set local role postgres;
        if (select counter from byteback_devices.credentials where owner_id = fixture_owner and credential_id = request_credential) <> request_counter
           or (select consumed_at from byteback_devices.challenges where id = request_nonce) is not null then
          raise exception 'ASSERT_FAILED_CAS_CHANGED_COUNTER_OR_NONCE';
        end if;
        checks := checks + 1;
        set local role service_role;
        result := public.byteback_device_action('consume', fixture_owner, token_hash, jsonb_build_object(
          'nonceId', request_nonce, 'credentialId', request_credential,
          'expectedCounter', request_counter, 'newCounter', request_counter + 1, 'binding', request_binding));
        set local role postgres;
        if (result->'device'->>'counter')::bigint <> request_counter + 1
           or (select counter from byteback_devices.credentials where owner_id = fixture_owner and credential_id = request_credential) <> request_counter + 1
           or (select consumed_at from byteback_devices.challenges where id = request_nonce) is null then
          raise exception 'ASSERT_SUCCESSFUL_CAS_NOT_ATOMIC';
        end if;
        checks := checks + 1;
        set local role service_role;
        begin
          result := public.byteback_device_action('consume', fixture_owner, token_hash, jsonb_build_object(
            'nonceId', request_nonce, 'credentialId', request_credential,
            'expectedCounter', request_counter, 'newCounter', request_counter + 1, 'binding', request_binding));
          raise exception 'ASSERT_REQUEST_NONCE_REPLAY_ACCEPTED';
        exception when others then
          if sqlerrm <> 'DEVICE_NONCE_REUSED' then raise; end if;
        end;
        checks := checks + 1;
        set local role postgres;
        if (select count(*) from byteback_devices.audit where owner_id = fixture_owner and action = 'request_verified') <> 1 then
          raise exception 'ASSERT_CAS_AUDIT_DUPLICATED';
        end if;
        checks := checks + 1;
      end if;
    end loop;
    stage := 'fixture_rollback';
    raise exception using errcode = 'P7702', message = 'SYNTHETIC_QUOTA_FIXTURES_ROLLBACK';
  exception when sqlstate 'P7702' then null;
  end;

  stage := 'original_rows_preserved';
  set local role postgres;
  select encode(extensions.digest(convert_to(coalesce(jsonb_agg(to_jsonb(x) order by x.id)::text, '[]'), 'UTF8'), 'sha256'), 'hex')
    into fingerprint_after from byteback_devices.credentials x where x.id = any(original_credential_ids);
  if fingerprint_after is distinct from credentials_before
     or exists(select 1 from byteback_devices.credentials where owner_id = any(fixture_owners)) then
    raise exception 'ASSERT_ORIGINAL_CREDENTIALS_CHANGED_OR_FIXTURES_PERSISTED';
  end if;
  checks := checks + 1;
  select encode(extensions.digest(convert_to(coalesce(jsonb_agg(to_jsonb(x) order by x.id)::text, '[]'), 'UTF8'), 'sha256'), 'hex')
    into fingerprint_after from byteback_devices.challenges x where x.id = any(original_challenge_ids);
  if fingerprint_after is distinct from challenges_before
     or exists(select 1 from byteback_devices.challenges where owner_id = any(fixture_owners)) then
    raise exception 'ASSERT_ORIGINAL_CHALLENGES_CHANGED_OR_FIXTURES_PERSISTED';
  end if;
  checks := checks + 1;
  select encode(extensions.digest(convert_to(coalesce(jsonb_agg(to_jsonb(x) order by x.id)::text, '[]'), 'UTF8'), 'sha256'), 'hex')
    into fingerprint_after from byteback_devices.audit x where x.id = any(original_audit_ids);
  if fingerprint_after is distinct from audit_before
     or exists(select 1 from byteback_devices.audit where owner_id = any(fixture_owners)) then
    raise exception 'ASSERT_ORIGINAL_AUDIT_CHANGED_OR_FIXTURES_PERSISTED';
  end if;
  checks := checks + 1;
  if checks <> 27 then raise exception 'ASSERT_QUOTA_CHECK_COUNT'; end if;
  raise notice 'DEVICE_QUOTA_REGRESSION: 27 assertions passed; fixture rows rolled back.';
exception when others then
  raise exception 'DEVICE_QUOTA_REGRESSION_FAILED at %: %', stage, sqlerrm;
end $device_quota_regression$;