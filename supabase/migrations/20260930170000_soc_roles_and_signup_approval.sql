-- SOC tier roles and admin-approved sign-up.
--
-- 1. The `analyst` role becomes `soc_l2` (investigates and closes) and a new `soc_l1` role is added
--    (triages alerts and escalates, cannot open cases or write indicators). Renaming is safe: both
--    foreign keys to roles.name are ON UPDATE CASCADE.
-- 2. An account created through Supabase Auth (the public sign-up endpoint, or the admin API) starts
--    inactive and unapproved. An administrator approves it and chooses the role. The rule is enforced
--    here, not in the app, because the Auth sign-up endpoint is reachable with the public anon key.
--    Rows inserted by SQL (seed, tests) keep working: they are approved on insert.

-- Role names may now contain digits.
alter table public.roles drop constraint roles_name_check;
alter table public.roles
  add constraint roles_name_check check (name ~ '^[a-z][a-z0-9_]*$');

update public.roles
set name = 'soc_l2',
    description = 'SOC analyst, tier 2: investigates, opens cases, writes indicators and reports.'
where name = 'analyst';

insert into public.roles (name, description) values
  ('soc_l1', 'SOC analyst, tier 1: triages alerts, acknowledges, marks false positives and escalates.');

update public.roles
set description = 'Read-only access to security data.'
where name = 'viewer';

insert into public.role_permissions (role_name, permission_key) values
  ('soc_l1', 'indicators:read'),
  ('soc_l1', 'threat_intel:read'),
  ('soc_l1', 'vulnerabilities:read'),
  ('soc_l1', 'events:read'),
  ('soc_l1', 'alerts:read'),
  ('soc_l1', 'alerts:write'),
  ('soc_l1', 'investigations:read'),
  ('soc_l1', 'reports:read'),
  ('soc_l1', 'ai:use');

-- Approval state. `approved_at` is null while an account waits for an administrator.
alter table public.profiles add column approved_at timestamptz;
update public.profiles set approved_at = created_at where is_active;

-- Accounts made by Supabase Auth itself (GoTrue connects as supabase_auth_admin) wait for approval.
-- Everything else that inserts into auth.users (SQL seed, SQL tests) is approved on insert.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  via_auth_service boolean := session_user = 'supabase_auth_admin';
begin
  insert into public.profiles (id, display_name, is_active, approved_at)
  values (
    new.id,
    left(coalesce(nullif(btrim(new.raw_user_meta_data ->> 'display_name'), ''), split_part(new.email, '@', 1)), 100),
    not via_auth_service,
    case when via_auth_service then null else now() end
  );
  return new;
end;
$$;

-- The first time an account becomes active it counts as approved.
create function public.profiles_track_approval()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.is_active and new.approved_at is null then
    new.approved_at := now();
  end if;
  return new;
end;
$$;

create trigger profiles_track_approval
  before update on public.profiles
  for each row execute function public.profiles_track_approval();

-- Lets a signed-in person whose profile is hidden by RLS learn why: waiting for approval, or disabled.
create function public.account_state()
returns text
language sql
security definer
stable
set search_path = ''
as $$
  select case
    when p.id is null then 'none'
    when p.is_active then 'active'
    when p.approved_at is null then 'pending'
    else 'disabled'
  end
  from (select auth.uid() as uid) u
  left join public.profiles p on p.id = u.uid;
$$;

revoke all on function public.account_state() from public, anon;
grant execute on function public.account_state() to authenticated, service_role;
