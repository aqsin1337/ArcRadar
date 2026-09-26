-- Platform entities: integrations, user API keys and the audit log.

create table public.integrations (
  id uuid primary key default gen_random_uuid(),
  provider text not null unique check (provider ~ '^[a-z0-9_]+$'),
  display_name text not null,
  capabilities text[] not null default '{}'
    check (capabilities <@ array['ip', 'domain', 'url', 'hash', 'vulnerability', 'threat_intel']),
  enabled boolean not null default false,
  -- Non-secret settings only. Provider API keys live in server environment variables.
  config jsonb not null default '{}'::jsonb,
  last_sync_at timestamptz,
  updated_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger integrations_set_updated_at
  before update on public.integrations
  for each row execute function public.set_updated_at();

-- Provider catalog. 'demo' is the built-in fallback and is always available.
insert into public.integrations (provider, display_name, capabilities, enabled) values
  ('demo', 'Demo data provider', array['ip', 'domain', 'url', 'hash', 'vulnerability', 'threat_intel'], true),
  ('virustotal', 'VirusTotal', array['ip', 'domain', 'url', 'hash'], false),
  ('abuseipdb', 'AbuseIPDB', array['ip'], false),
  ('otx', 'AlienVault OTX', array['ip', 'domain', 'url', 'hash', 'threat_intel'], false),
  ('nvd', 'NIST NVD', array['vulnerability'], false),
  ('shodan', 'Shodan', array['ip'], false),
  ('misp', 'MISP', array['threat_intel'], false),
  ('opencti', 'OpenCTI', array['threat_intel'], false);

-- Only a SHA-256 hash of the key is stored. The raw key is shown once, at creation.
create table public.api_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles (id) on delete cascade,
  name text not null check (char_length(name) between 1 and 100),
  key_prefix text not null check (char_length(key_prefix) between 4 and 16),
  key_hash text not null unique check (key_hash ~ '^[a-f0-9]{64}$'),
  scopes text[] not null default '{}',
  last_used_at timestamptz,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create index api_keys_user_id_idx on public.api_keys (user_id);

-- Append-only. user_id deliberately has no foreign key: the trail must survive user deletion.
create table public.audit_logs (
  id bigint generated always as identity primary key,
  user_id uuid,
  action text not null check (action ~ '^[a-z_]+(\.[a-z_]+)*$'),
  entity_type text check (char_length(entity_type) <= 100),
  entity_id text check (char_length(entity_id) <= 200),
  ip_address inet,
  user_agent text check (char_length(user_agent) <= 500),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index audit_logs_created_at_idx on public.audit_logs (created_at desc);
create index audit_logs_user_id_idx on public.audit_logs (user_id);
create index audit_logs_entity_idx on public.audit_logs (entity_type, entity_id);
create index audit_logs_action_idx on public.audit_logs (action);

create trigger audit_logs_no_update_delete
  before update or delete on public.audit_logs
  for each row execute function public.reject_modification();

create trigger audit_logs_no_truncate
  before truncate on public.audit_logs
  for each statement execute function public.reject_modification();
