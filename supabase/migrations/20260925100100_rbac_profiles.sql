-- Roles, permissions and user profiles.
-- Authentication and identity belong to Supabase Auth (auth.users). This file only holds
-- application authorization: which role a user has and what each role may do.

create table public.roles (
  name text primary key check (name ~ '^[a-z_]+$'),
  description text not null,
  created_at timestamptz not null default now()
);

create table public.permissions (
  key text primary key check (key ~ '^[a-z_]+:[a-z_]+$'),
  description text not null
);

create table public.role_permissions (
  role_name text not null references public.roles (name) on update cascade on delete cascade,
  permission_key text not null references public.permissions (key) on update cascade on delete cascade,
  primary key (role_name, permission_key)
);

create index role_permissions_permission_key_idx on public.role_permissions (permission_key);

-- Reference data: required in every environment, so it lives in a migration, not in seed.sql.
insert into public.roles (name, description) values
  ('admin', 'Full access, including users, integrations, API keys and settings.'),
  ('analyst', 'Investigates indicators, manages alerts, creates investigations and reports.'),
  ('viewer', 'Read-only access to security data.');

insert into public.permissions (key, description) values
  ('indicators:read', 'View indicators and their relationships'),
  ('indicators:write', 'Create and edit indicators, tags and links'),
  ('indicators:delete', 'Delete indicators'),
  ('threat_intel:read', 'View threat actors, campaigns, malware and MITRE techniques'),
  ('threat_intel:write', 'Create and edit threat actors, campaigns, malware and techniques'),
  ('vulnerabilities:read', 'View vulnerabilities'),
  ('vulnerabilities:write', 'Create and edit vulnerabilities'),
  ('events:read', 'View security events'),
  ('events:write', 'Create and edit security events'),
  ('alerts:read', 'View alerts'),
  ('alerts:write', 'Create alerts and change their status'),
  ('alerts:delete', 'Delete alerts'),
  ('investigations:read', 'View investigations'),
  ('investigations:write', 'Create and edit investigations, notes and evidence'),
  ('investigations:delete', 'Delete investigations'),
  ('reports:read', 'View reports'),
  ('reports:write', 'Generate and delete reports'),
  ('integrations:read', 'View integration status'),
  ('integrations:manage', 'Enable, disable and configure integrations'),
  ('api_keys:manage_own', 'Create and revoke own API keys'),
  ('api_keys:manage_all', 'View and revoke any API key'),
  ('audit:read', 'View the audit log'),
  ('users:read', 'View user accounts'),
  ('users:manage', 'Change user roles and deactivate users'),
  ('settings:manage', 'Change application settings');

insert into public.role_permissions (role_name, permission_key)
select 'admin', key from public.permissions;

insert into public.role_permissions (role_name, permission_key) values
  ('analyst', 'indicators:read'),
  ('analyst', 'indicators:write'),
  ('analyst', 'threat_intel:read'),
  ('analyst', 'vulnerabilities:read'),
  ('analyst', 'events:read'),
  ('analyst', 'alerts:read'),
  ('analyst', 'alerts:write'),
  ('analyst', 'investigations:read'),
  ('analyst', 'investigations:write'),
  ('analyst', 'reports:read'),
  ('analyst', 'reports:write'),
  ('analyst', 'integrations:read'),
  ('analyst', 'api_keys:manage_own'),
  ('viewer', 'indicators:read'),
  ('viewer', 'threat_intel:read'),
  ('viewer', 'vulnerabilities:read'),
  ('viewer', 'events:read'),
  ('viewer', 'alerts:read'),
  ('viewer', 'investigations:read'),
  ('viewer', 'reports:read');

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  display_name text check (display_name is null or char_length(display_name) between 1 and 100),
  avatar_url text check (avatar_url is null or char_length(avatar_url) <= 2048),
  role_name text not null default 'viewer' references public.roles (name) on update cascade,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index profiles_role_name_idx on public.profiles (role_name);

create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();

-- Every new auth user gets a least-privilege profile. The role is never read from
-- user-controlled metadata: promotion to analyst/admin is an explicit admin action.
create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    left(coalesce(nullif(btrim(new.raw_user_meta_data ->> 'display_name'), ''), split_part(new.email, '@', 1)), 100)
  );
  return new;
end;
$$;

revoke all on function public.handle_new_user() from public, anon, authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Authorization helpers used by RLS policies and server code. They are security definer so
-- that policies on profiles/role_permissions cannot recurse into themselves.
create function public.current_role_name()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select p.role_name
  from public.profiles p
  where p.id = (select auth.uid()) and p.is_active
$$;

create function public.has_permission(p_key text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.profiles p
    join public.role_permissions rp on rp.role_name = p.role_name
    where p.id = (select auth.uid())
      and p.is_active
      and rp.permission_key = p_key
  )
$$;

revoke all on function public.current_role_name() from public, anon;
revoke all on function public.has_permission(text) from public, anon;
grant execute on function public.current_role_name() to authenticated, service_role;
grant execute on function public.has_permission(text) to authenticated, service_role;
