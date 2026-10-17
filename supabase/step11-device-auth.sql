-- Step 11 / production 2: prepare only; this file is not applied automatically.
-- Apply manually as postgres in the intended Supabase SQL Editor after review.
-- Existing memo tables, data, policies and previous SQL are unchanged.
-- The API must verify the user's JWT and WebAuthn proof before calling this RPC.
-- p_session_hash is SHA-256 of the verified session token, never the token itself.
-- No first device is automatically approved. Only the private postgres operator
-- function below can explicitly approve the first pending device by fingerprint.

begin;

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists byteback_devices authorization postgres;
alter schema byteback_devices owner to postgres;
revoke all on schema byteback_devices from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema byteback_devices
  revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role postgres in schema byteback_devices
  revoke execute on functions from public, anon, authenticated, service_role;

create table if not exists byteback_devices.credentials (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  credential_id text not null unique
    check (credential_id ~ '^[A-Za-z0-9_-]+$' and length(credential_id) between 1 and 2048 and length(credential_id) % 4 <> 1),
  public_key text not null
    check (public_key ~ '^[A-Za-z0-9_-]+$' and length(public_key) between 1 and 8192 and length(public_key) % 4 <> 1),
  counter bigint not null check (counter between 0 and 4294967295),
  transports jsonb not null default '[]'::jsonb
    check (jsonb_typeof(transports) = 'array' and jsonb_array_length(transports) <= 10),
  device_type text not null check (device_type = 'singleDevice'),
  backed_up boolean not null check (backed_up = false),
  state text not null default 'pending'
    check (state in ('pending', 'approved', 'rejected', 'revoked')),
  public_key_sha256 text not null check (public_key_sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default clock_timestamp(),
  updated_at timestamptz not null default clock_timestamp()
);
create index if not exists byteback_device_owner_state
  on byteback_devices.credentials (owner_id, state);

create table if not exists byteback_devices.challenges (
  id uuid primary key,
  owner_id uuid not null,
  session_hash text not null check (session_hash ~ '^[0-9a-f]{64}$'),
  purpose text not null check (purpose in ('registration', 'request')),
  challenge text not null unique
    check (challenge ~ '^[A-Za-z0-9_-]{43,128}$' and length(challenge) % 4 <> 1),
  credential_id text,
  binding jsonb not null check (jsonb_typeof(binding) = 'object'),
  created_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  check ((purpose = 'registration' and credential_id is null)
      or (purpose = 'request' and credential_id is not null)),
  check (expires_at > created_at)
);
create index if not exists byteback_challenge_owner_live
  on byteback_devices.challenges (owner_id, expires_at) where consumed_at is null;

-- No tokens, raw sessions, signatures, request bindings, memo bodies or raw reasons
-- are stored in audit. A reason is represented only by its SHA-256 digest.
create table if not exists byteback_devices.audit (
  id uuid primary key default gen_random_uuid(),
  occurred_at timestamptz not null default clock_timestamp(),
  owner_id uuid not null,
  actor_device_id uuid,
  target_device_id uuid not null,
  action text not null check (action in (
    'registration_requested', 'request_verified', 'device_approved',
    'device_rejected', 'device_revoked', 'operator_approved',
    'operator_rejected', 'operator_revoked')),
  public_key_sha256 text not null check (public_key_sha256 ~ '^[0-9a-f]{64}$'),
  reason_sha256 text check (reason_sha256 ~ '^[0-9a-f]{64}$')
);
create index if not exists byteback_device_audit_owner_time
  on byteback_devices.audit (owner_id, occurred_at);

alter table byteback_devices.credentials enable row level security;
alter table byteback_devices.challenges enable row level security;
alter table byteback_devices.audit enable row level security;
-- No client policies: all access goes through the server-only, checked function.
revoke all on all tables in schema byteback_devices
  from public, anon, authenticated, service_role;
revoke all on all sequences in schema byteback_devices
  from public, anon, authenticated, service_role;

create or replace function byteback_devices.block_audit_mutation()
returns trigger language plpgsql set search_path = pg_catalog as $$
begin
  raise exception using errcode = 'P0001', message = 'DEVICE_AUDIT_APPEND_ONLY';
end;
$$;
revoke all on function byteback_devices.block_audit_mutation()
  from public, anon, authenticated, service_role;
drop trigger if exists byteback_device_audit_append_only on byteback_devices.audit;
create trigger byteback_device_audit_append_only
  before update or delete or truncate on byteback_devices.audit
  for each statement execute function byteback_devices.block_audit_mutation();

create or replace function byteback_devices.credential_json(
  p_device byteback_devices.credentials
) returns jsonb language sql stable strict
set search_path = pg_catalog as $$
  select jsonb_build_object(
    'id', p_device.id, 'ownerId', p_device.owner_id,
    'credentialId', p_device.credential_id, 'publicKey', p_device.public_key,
    'counter', p_device.counter, 'transports', p_device.transports,
    'deviceType', p_device.device_type, 'backedUp', p_device.backed_up,
    'state', p_device.state, 'publicKeySha256', p_device.public_key_sha256,
    'createdAt', p_device.created_at, 'updatedAt', p_device.updated_at);
$$;
revoke all on function byteback_devices.credential_json(byteback_devices.credentials)
  from public, anon, authenticated, service_role;

create or replace function byteback_devices.challenge_json(
  p_challenge byteback_devices.challenges
) returns jsonb language sql stable strict
set search_path = pg_catalog as $$
  select jsonb_build_object(
    'id', p_challenge.id, 'ownerId', p_challenge.owner_id,
    'sessionHash', p_challenge.session_hash, 'purpose', p_challenge.purpose,
    'challenge', p_challenge.challenge, 'credentialId', p_challenge.credential_id,
    'binding', p_challenge.binding, 'expiresAt', p_challenge.expires_at,
    'consumedAt', p_challenge.consumed_at);
$$;
revoke all on function byteback_devices.challenge_json(byteback_devices.challenges)
  from public, anon, authenticated, service_role;

create or replace function public.byteback_device_action(
  p_action text,
  p_user uuid,
  p_session_hash text,
  p_payload jsonb default '{}'::jsonb
) returns jsonb language plpgsql security definer
set search_path = pg_catalog
set timezone = 'UTC'
as $$
declare
  d byteback_devices.credentials%rowtype;
  actor byteback_devices.credentials%rowtype;
  c byteback_devices.challenges%rowtype;
  devices jsonb;
  nonce_id uuid;
  actor_id uuid;
  target_id uuid;
  credential text;
  key_text text;
  old_counter bigint;
  next_counter bigint;
  requested_decision text;
  reason_text text;
  key_fingerprint text;
  db_now timestamptz;
begin
  if p_user is null or p_session_hash is null
     or p_session_hash !~ '^[0-9a-f]{64}$'
     or p_payload is null or jsonb_typeof(p_payload) <> 'object'
     or octet_length(p_payload::text) > 32768 then
    raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
  end if;

  if p_action = 'list' then
    select coalesce(jsonb_agg(byteback_devices.credential_json(x) order by x.created_at, x.id), '[]'::jsonb)
      into devices from byteback_devices.credentials x where x.owner_id = p_user;
    -- Server-only snapshot: the Node API must redact publicKey and counter for UI.
    return jsonb_build_object('devices', devices);
  elsif p_action = 'get_credential' then
    select * into d from byteback_devices.credentials
      where owner_id = p_user and credential_id = p_payload->>'credentialId';
    if not found then
      raise exception using errcode = 'P0001', message = 'DEVICE_REGISTRATION_REQUIRED';
    end if;
    return jsonb_build_object('device', byteback_devices.credential_json(d));
  elsif p_action = 'get_challenge' then
    nonce_id := (p_payload->>'nonceId')::uuid;
    select * into c from byteback_devices.challenges
      where id = nonce_id and owner_id = p_user and session_hash = p_session_hash;
    if not found then
      raise exception using errcode = 'P0001', message = 'DEVICE_REQUEST_MISMATCH';
    end if;
    return jsonb_build_object('challenge', byteback_devices.challenge_json(c));
  end if;

  -- All writes share the owner advisory lock, then credential row lock(s), then
  -- challenge row lock. This also makes per-owner resource limits race-safe.
  perform pg_advisory_xact_lock(hashtextextended('byteback-device:' || p_user::text, 11));

  if p_action = 'challenge' then
    nonce_id := (p_payload->>'id')::uuid;
    if nonce_id is null or p_payload->>'purpose' not in ('registration', 'request')
       or p_payload->>'purpose' is null
       or p_payload->>'challenge' is null
       or p_payload->>'challenge' !~ '^[A-Za-z0-9_-]{43,128}$'
       or length(p_payload->>'challenge') % 4 = 1
       or jsonb_typeof(p_payload->'binding') is distinct from 'object'
       or octet_length((p_payload->'binding')::text) > 8192 then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
    end if;
    credential := nullif(p_payload->>'credentialId', '');
    if p_payload->>'purpose' = 'request' then
      select * into d from byteback_devices.credentials
        where owner_id = p_user and credential_id = credential for update;
      if not found then
        raise exception using errcode = 'P0001', message = 'DEVICE_REGISTRATION_REQUIRED';
      end if;
      if d.state <> 'approved' then
        raise exception using errcode = 'P0001', message = 'DEVICE_NOT_APPROVED';
      end if;
    elsif credential is not null then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
    end if;
    db_now := clock_timestamp();
    if (select count(*) from byteback_devices.challenges
        where owner_id = p_user and consumed_at is null and expires_at > db_now) >= 30 then
      raise exception using errcode = 'P0001', message = 'DEVICE_LIMIT_REACHED';
    end if;
    begin
      insert into byteback_devices.challenges
        (id, owner_id, session_hash, purpose, challenge, credential_id, binding, created_at, expires_at)
      values (nonce_id, p_user, p_session_hash, p_payload->>'purpose',
        p_payload->>'challenge', credential, p_payload->'binding', db_now,
        db_now + interval '90 seconds') returning * into c;
    exception when unique_violation then
      raise exception using errcode = 'P0001', message = 'DEVICE_NONCE_REUSED';
    end;
    return jsonb_build_object('challenge', byteback_devices.challenge_json(c));

  elsif p_action = 'register' then
    nonce_id := (p_payload->>'nonceId')::uuid;
    credential := p_payload->>'credentialId';
    key_text := p_payload->>'publicKey';
    if credential is null or credential !~ '^[A-Za-z0-9_-]+$' or length(credential) not between 1 and 2048
       or length(credential) % 4 = 1
       or key_text is null or key_text !~ '^[A-Za-z0-9_-]+$' or length(key_text) not between 1 and 8192
       or length(key_text) % 4 = 1
       or jsonb_typeof(p_payload->'counter') is distinct from 'number'
       or p_payload->>'counter' !~ '^[0-9]{1,10}$'
       or jsonb_typeof(p_payload->'transports') is distinct from 'array'
       or jsonb_array_length(p_payload->'transports') > 10 then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
    end if;
    if p_payload->>'deviceType' is distinct from 'singleDevice'
       or p_payload->'backedUp' is distinct from 'false'::jsonb then
      raise exception using errcode = 'P0001', message = 'DEVICE_REGISTRATION_UNSUPPORTED';
    end if;
    if exists (select 1 from jsonb_array_elements(p_payload->'transports') t(value)
               where jsonb_typeof(t.value) <> 'string'
                  or t.value #>> '{}' not in ('ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb')) then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
    end if;
    next_counter := (p_payload->>'counter')::bigint;
    if next_counter > 4294967295 then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
    end if;
    if exists (select 1 from byteback_devices.credentials where credential_id = credential) then
      raise exception using errcode = 'P0001', message = 'DEVICE_CREDENTIAL_EXISTS';
    end if;
    if (select count(*) from byteback_devices.credentials
        where owner_id = p_user and state in ('pending', 'approved')) >= 10 then
      raise exception using errcode = 'P0001', message = 'DEVICE_LIMIT_REACHED';
    end if;
    -- No existing credential row is updated for registration; the challenge is
    -- locked before inserting a NEW pending row. Request verification locks its
    -- existing credential first and can never consume this registration nonce.
    select * into c from byteback_devices.challenges where id = nonce_id for update;
    if not found or c.owner_id is distinct from p_user
       or c.session_hash is distinct from p_session_hash or c.purpose <> 'registration'
       or c.credential_id is not null then
      raise exception using errcode = 'P0001', message = 'DEVICE_REQUEST_MISMATCH';
    end if;
    if c.consumed_at is not null then
      raise exception using errcode = 'P0001', message = 'DEVICE_NONCE_REUSED';
    end if;
    db_now := clock_timestamp();
    if c.expires_at <= db_now then
      raise exception using errcode = 'P0001', message = 'DEVICE_CHALLENGE_EXPIRED';
    end if;
    key_fingerprint := encode(extensions.digest(decode(
      translate(key_text, '-_', '+/') || repeat('=', (4 - length(key_text) % 4) % 4),
      'base64'), 'sha256'), 'hex');
    begin
      insert into byteback_devices.credentials
        (owner_id, credential_id, public_key, counter, transports, device_type,
         backed_up, state, public_key_sha256, created_at, updated_at)
      values (p_user, credential, key_text, next_counter, p_payload->'transports',
        'singleDevice', false, 'pending', key_fingerprint, db_now, db_now)
      returning * into d;
    exception when unique_violation then
      raise exception using errcode = 'P0001', message = 'DEVICE_CREDENTIAL_EXISTS';
    end;
    update byteback_devices.challenges set consumed_at = db_now where id = c.id;
    insert into byteback_devices.audit
      (owner_id, target_device_id, action, public_key_sha256)
    values (p_user, d.id, 'registration_requested', d.public_key_sha256);
    return jsonb_build_object('device', byteback_devices.credential_json(d));

  elsif p_action = 'consume' then
    nonce_id := (p_payload->>'nonceId')::uuid;
    credential := p_payload->>'credentialId';
    if jsonb_typeof(p_payload->'binding') is distinct from 'object'
       or jsonb_typeof(p_payload->'expectedCounter') is distinct from 'number'
       or p_payload->>'expectedCounter' !~ '^[0-9]{1,10}$'
       or jsonb_typeof(p_payload->'newCounter') is distinct from 'number'
       or p_payload->>'newCounter' !~ '^[0-9]{1,10}$' then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
    end if;
    old_counter := (p_payload->>'expectedCounter')::bigint;
    next_counter := (p_payload->>'newCounter')::bigint;
    if old_counter > 4294967295 or next_counter > 4294967295 then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
    end if;
    -- Required lock order: credential -> challenge. Both are rechecked under lock.
    select * into d from byteback_devices.credentials
      where owner_id = p_user and credential_id = credential for update;
    if not found then
      raise exception using errcode = 'P0001', message = 'DEVICE_REGISTRATION_REQUIRED';
    end if;
    if d.state <> 'approved' then
      raise exception using errcode = 'P0001', message = 'DEVICE_NOT_APPROVED';
    end if;
    select * into c from byteback_devices.challenges where id = nonce_id for update;
    if not found or c.owner_id is distinct from p_user
       or c.session_hash is distinct from p_session_hash or c.purpose <> 'request'
       or c.credential_id is distinct from credential
       or c.binding is distinct from p_payload->'binding' then
      raise exception using errcode = 'P0001', message = 'DEVICE_REQUEST_MISMATCH';
    end if;
    if c.consumed_at is not null then
      raise exception using errcode = 'P0001', message = 'DEVICE_NONCE_REUSED';
    end if;
    db_now := clock_timestamp();
    if c.expires_at <= db_now then
      raise exception using errcode = 'P0001', message = 'DEVICE_CHALLENGE_EXPIRED';
    end if;
    if d.counter <> old_counter
       or not ((old_counter = 0 and next_counter = 0) or next_counter > old_counter) then
      raise exception using errcode = 'P0001', message = 'DEVICE_COUNTER_CHANGED';
    end if;
    update byteback_devices.credentials set counter = next_counter, updated_at = db_now
      where id = d.id and counter = old_counter returning * into d;
    if not found then
      raise exception using errcode = 'P0001', message = 'DEVICE_COUNTER_CHANGED';
    end if;
    update byteback_devices.challenges set consumed_at = db_now where id = c.id;
    insert into byteback_devices.audit
      (owner_id, actor_device_id, target_device_id, action, public_key_sha256)
    values (p_user, d.id, d.id, 'request_verified', d.public_key_sha256);
    return jsonb_build_object('device', byteback_devices.credential_json(d));

  elsif p_action = 'decision' then
    actor_id := (p_payload->>'actorDeviceId')::uuid;
    target_id := (p_payload->>'targetDeviceId')::uuid;
    requested_decision := p_payload->>'decision';
    reason_text := p_payload->>'reason';
    if actor_id is null or target_id is null
       or requested_decision is null or requested_decision not in ('approved', 'rejected', 'revoked')
       or reason_text is null or length(btrim(reason_text)) not between 3 and 240 then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
    end if;
    -- Node must consume the actor's request proof bound to this exact decision
    -- before invoking this action. The DB independently rechecks current approval.
    perform x.id from byteback_devices.credentials x
      where x.owner_id = p_user and x.id in (actor_id, target_id) order by x.id for update;
    select * into actor from byteback_devices.credentials
      where owner_id = p_user and id = actor_id;
    if not found or actor.state <> 'approved' then
      raise exception using errcode = 'P0001', message = 'DEVICE_NOT_APPROVED';
    end if;
    select * into d from byteback_devices.credentials
      where owner_id = p_user and id = target_id;
    if not found then
      raise exception using errcode = 'P0001', message = 'DEVICE_REGISTRATION_REQUIRED';
    end if;
    if actor_id = target_id and requested_decision in ('approved', 'rejected') then
      raise exception using errcode = 'P0001', message = 'DEVICE_SELF_APPROVAL_FORBIDDEN';
    end if;
    if not ((d.state = 'pending' and requested_decision in ('approved', 'rejected'))
         or (d.state = 'approved' and requested_decision = 'revoked')) then
      raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_DECISION';
    end if;
    update byteback_devices.credentials set state = requested_decision, updated_at = clock_timestamp()
      where id = target_id returning * into d;
    insert into byteback_devices.audit
      (owner_id, actor_device_id, target_device_id, action, public_key_sha256, reason_sha256)
    values (p_user, actor_id, target_id, 'device_' || requested_decision,
      d.public_key_sha256, encode(extensions.digest(convert_to(reason_text, 'UTF8'), 'sha256'), 'hex'));
    return jsonb_build_object('device', byteback_devices.credential_json(d));
  end if;
  raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_ACTION';
exception
  when data_exception or check_violation or not_null_violation then
    raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
end;
$$;
alter function public.byteback_device_action(text, uuid, text, jsonb) owner to postgres;
revoke all on function public.byteback_device_action(text, uuid, text, jsonb)
  from public, anon, authenticated, service_role;
grant execute on function public.byteback_device_action(text, uuid, text, jsonb) to service_role;

-- Manual recovery/initial approval only. NOT a public RPC or service_role escape.
-- Operator must inspect the intended user's pending entry and independently
-- compare its full public_key_sha256 fingerprint before explicitly approving it.
-- A decision and a 3..240 character reason are mandatory; no automatic choice.
create or replace function byteback_devices.operator_decide(
  p_owner uuid, p_device uuid, p_fingerprint text, p_decision text, p_reason text
) returns jsonb language plpgsql security definer
set search_path = pg_catalog
set timezone = 'UTC'
as $$
declare
  d byteback_devices.credentials%rowtype;
begin
  if p_owner is null or p_device is null or p_fingerprint is null
     or p_fingerprint !~ '^[0-9a-f]{64}$' or p_decision is null
     or p_decision not in ('approved', 'rejected', 'revoked')
     or p_reason is null or length(btrim(p_reason)) not between 3 and 240 then
    raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_INPUT';
  end if;
  perform pg_advisory_xact_lock(hashtextextended('byteback-device:' || p_owner::text, 11));
  select * into d from byteback_devices.credentials
    where owner_id = p_owner and id = p_device for update;
  if not found then
    raise exception using errcode = 'P0001', message = 'DEVICE_REGISTRATION_REQUIRED';
  end if;
  if d.public_key_sha256 is distinct from p_fingerprint then
    raise exception using errcode = 'P0001', message = 'DEVICE_REQUEST_MISMATCH';
  end if;
  if not ((d.state = 'pending' and p_decision in ('approved', 'rejected'))
       or (d.state = 'approved' and p_decision = 'revoked')) then
    raise exception using errcode = 'P0001', message = 'DEVICE_INVALID_DECISION';
  end if;
  update byteback_devices.credentials set state = p_decision, updated_at = clock_timestamp()
    where id = p_device returning * into d;
  insert into byteback_devices.audit
    (owner_id, target_device_id, action, public_key_sha256, reason_sha256)
  values (p_owner, p_device, 'operator_' || p_decision, d.public_key_sha256,
    encode(extensions.digest(convert_to(p_reason, 'UTF8'), 'sha256'), 'hex'));
  return jsonb_build_object('device', byteback_devices.credential_json(d));
end;
$$;
alter function byteback_devices.operator_decide(uuid, uuid, text, text, text) owner to postgres;
revoke all on function byteback_devices.operator_decide(uuid, uuid, text, text, text)
  from public, anon, authenticated, service_role;
grant execute on function byteback_devices.operator_decide(uuid, uuid, text, text, text) to postgres;

-- Existing private-schema objects remain inaccessible through client/database roles.
revoke all on all functions in schema byteback_devices
  from public, anon, authenticated, service_role;
revoke all on schema byteback_devices from public, anon, authenticated, service_role;

notify pgrst, 'reload schema';
commit;