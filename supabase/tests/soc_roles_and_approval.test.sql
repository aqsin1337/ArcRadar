-- SOC tier roles (soc_l1, soc_l2) and admin-approved sign-up. Run with `npm run db:test`.
-- Everything happens in one transaction that is rolled back.

begin;

-- Fixtures: an approved L1 user, an approved viewer, and an admin.
insert into auth.users (id, instance_id, aud, role, email, raw_app_meta_data, raw_user_meta_data,
                        created_at, updated_at, confirmation_token, recovery_token, email_change,
                        email_change_token_new, email_change_token_current, phone_change,
                        phone_change_token, reauthentication_token)
select u.id, '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', u.email,
       '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '', '', '', '', ''
from (values
  ('c5c5c5c5-0000-4000-8000-000000000001'::uuid, 'fx-admin@arcradar.test'),
  ('c5c5c5c5-0000-4000-8000-000000000002'::uuid, 'fx-l1@arcradar.test'),
  ('c5c5c5c5-0000-4000-8000-000000000003'::uuid, 'fx-l2@arcradar.test')
) as u (id, email);

update public.profiles set role_name = 'admin' where id = 'c5c5c5c5-0000-4000-8000-000000000001';
update public.profiles set role_name = 'soc_l1' where id = 'c5c5c5c5-0000-4000-8000-000000000002';
update public.profiles set role_name = 'soc_l2' where id = 'c5c5c5c5-0000-4000-8000-000000000003';

-- 1. The role catalog: the analyst role became soc_l2, soc_l1 exists, nothing is left behind.
-- ---------------------------------------------------------------------------------------------
do $$
begin
  if exists (select 1 from public.roles where name = 'analyst') then
    raise exception 'FAIL the old analyst role still exists';
  end if;
  if (select count(*) from public.roles where name in ('admin', 'soc_l2', 'soc_l1', 'viewer')) <> 4 then
    raise exception 'FAIL expected exactly the four roles admin, soc_l2, soc_l1, viewer';
  end if;
  if (select count(*) from public.roles) <> 4 then
    raise exception 'FAIL unexpected extra roles in the catalog';
  end if;
  raise notice 'ok - roles are admin, soc_l2, soc_l1, viewer';
end $$;

-- 2. What each tier may do, as the database itself enforces it (has_permission is what RLS calls).
-- ---------------------------------------------------------------------------------------------
do $$
declare
  l1 constant uuid := 'c5c5c5c5-0000-4000-8000-000000000002';
  l2 constant uuid := 'c5c5c5c5-0000-4000-8000-000000000003';
  key text;
begin
  -- L1: triage and read, no cases, no indicator writes, nothing administrative.
  foreach key in array array['alerts:read', 'alerts:write', 'investigations:read', 'ai:use'] loop
    if not exists (select 1 from public.role_permissions where role_name = 'soc_l1' and permission_key = key) then
      raise exception 'FAIL soc_l1 lacks %', key;
    end if;
  end loop;
  foreach key in array array['investigations:write', 'indicators:write', 'reports:write', 'rules:manage',
                             'users:manage', 'settings:manage', 'alerts:delete'] loop
    if exists (select 1 from public.role_permissions where role_name = 'soc_l1' and permission_key = key) then
      raise exception 'FAIL soc_l1 must not have %', key;
    end if;
  end loop;

  -- L2 has everything L1 has, plus cases and indicators.
  if exists (
    select 1 from public.role_permissions l1p
    where l1p.role_name = 'soc_l1'
      and not exists (select 1 from public.role_permissions l2p
                      where l2p.role_name = 'soc_l2' and l2p.permission_key = l1p.permission_key)
  ) then
    raise exception 'FAIL soc_l2 is missing something soc_l1 can do';
  end if;
  foreach key in array array['investigations:write', 'indicators:write', 'reports:write'] loop
    if not exists (select 1 from public.role_permissions where role_name = 'soc_l2' and permission_key = key) then
      raise exception 'FAIL soc_l2 lacks %', key;
    end if;
  end loop;

  -- The permission check RLS uses agrees, for real callers.
  perform set_config('request.jwt.claim.sub', l1::text, true);
  set local role authenticated;
  if not public.has_permission('alerts:write') then raise exception 'FAIL L1 cannot write alerts'; end if;
  if public.has_permission('investigations:write') then raise exception 'FAIL L1 can write investigations'; end if;
  reset role;

  perform set_config('request.jwt.claim.sub', l2::text, true);
  set local role authenticated;
  if not public.has_permission('investigations:write') then raise exception 'FAIL L2 cannot write investigations'; end if;
  if public.has_permission('users:manage') then raise exception 'FAIL L2 can manage users'; end if;
  reset role;

  raise notice 'ok - soc_l1 triages, soc_l2 investigates, neither administers';
end $$;

-- 3. Accounts inserted by SQL are approved on insert (seed and tests rely on it). The other half, an
--    account created by Supabase Auth itself starting inactive, needs GoTrue's own database session
--    and is checked end to end in scripts/api-smoke.mjs against a real sign-up.
-- ---------------------------------------------------------------------------------------------
do $$
declare p record;
begin
  select * into p from public.profiles where id = 'c5c5c5c5-0000-4000-8000-000000000002';
  if not p.is_active or p.approved_at is null then
    raise exception 'FAIL an account inserted by SQL should be approved on insert';
  end if;
  raise notice 'ok - SQL-inserted accounts are approved on insert';
end $$;

-- A waiting account, as GoTrue would leave it: inactive, never approved, viewer.
insert into auth.users (id, instance_id, aud, role, email, raw_app_meta_data, raw_user_meta_data,
                        created_at, updated_at, confirmation_token, recovery_token, email_change,
                        email_change_token_new, email_change_token_current, phone_change,
                        phone_change_token, reauthentication_token)
values ('c5c5c5c5-0000-4000-8000-0000000000a1', '00000000-0000-0000-0000-000000000000',
        'authenticated', 'authenticated', 'fx-signup@arcradar.test',
        '{"provider":"email","providers":["email"]}', '{}', now(), now(), '', '', '', '', '', '', '', '');
update public.profiles set is_active = false, approved_at = null
where id = 'c5c5c5c5-0000-4000-8000-0000000000a1';

-- 4. account_state() tells the difference between waiting, disabled and active, for the caller only.
-- ---------------------------------------------------------------------------------------------
do $$
declare
  signup constant uuid := 'c5c5c5c5-0000-4000-8000-0000000000a1';
  l1 constant uuid := 'c5c5c5c5-0000-4000-8000-000000000002';
  state text;
  visible int;
begin
  perform set_config('request.jwt.claim.sub', signup::text, true);
  set local role authenticated;
  select public.account_state() into state;
  if state <> 'pending' then raise exception 'FAIL expected pending, got %', state; end if;
  -- An inactive person sees no profile row at all (RLS), which is why the function exists.
  select count(*) into visible from public.profiles;
  if visible <> 0 then raise exception 'FAIL a pending account can read % profile rows', visible; end if;
  reset role;

  perform set_config('request.jwt.claim.sub', l1::text, true);
  set local role authenticated;
  select public.account_state() into state;
  if state <> 'active' then raise exception 'FAIL expected active, got %', state; end if;
  reset role;

  -- Disabled after having been approved is not "pending".
  update public.profiles set is_active = false where id = l1;
  perform set_config('request.jwt.claim.sub', l1::text, true);
  set local role authenticated;
  select public.account_state() into state;
  if state <> 'disabled' then raise exception 'FAIL expected disabled, got %', state; end if;
  reset role;
  update public.profiles set is_active = true where id = l1;

  -- Nobody anonymous can call it.
  begin
    set local role anon;
    perform public.account_state();
    reset role;
    raise exception 'FAIL anon could call account_state';
  exception when insufficient_privilege then
    reset role;
  end;

  raise notice 'ok - account_state: pending, active, disabled; anon denied';
end $$;

-- 5. Approving: the first time an account becomes active it is stamped approved, and a person cannot
--    approve themselves (clients may only edit display_name and avatar_url).
-- ---------------------------------------------------------------------------------------------
do $$
declare
  signup constant uuid := 'c5c5c5c5-0000-4000-8000-0000000000a1';
  before_at timestamptz;
  after_at timestamptz;
  changed int;
begin
  perform set_config('request.jwt.claim.sub', signup::text, true);
  set local role authenticated;
  begin
    update public.profiles set is_active = true where id = signup;
    get diagnostics changed = row_count;
    if changed <> 0 then raise exception 'FAIL a pending person approved themselves'; end if;
  exception when insufficient_privilege then
    null; -- column grants stop it before RLS even looks: also correct
  end;
  reset role;

  select approved_at into before_at from public.profiles where id = signup;
  if before_at is not null then raise exception 'FAIL still expected unapproved'; end if;

  set local role service_role;
  update public.profiles set role_name = 'soc_l1', is_active = true where id = signup;
  reset role;

  select approved_at into after_at from public.profiles where id = signup;
  if after_at is null then raise exception 'FAIL activating a waiting account must stamp approved_at'; end if;

  -- Deactivating later keeps the stamp, so the account reads as disabled, not pending again.
  update public.profiles set is_active = false where id = signup;
  if (select approved_at from public.profiles where id = signup) is distinct from after_at then
    raise exception 'FAIL deactivating changed approved_at';
  end if;

  raise notice 'ok - approval stamps approved_at once; clients cannot approve themselves';
end $$;

rollback;

do $$ begin raise notice 'SOC ROLES AND APPROVAL DATABASE TESTS PASSED'; end $$;
