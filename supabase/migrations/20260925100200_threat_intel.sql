-- Threat intelligence entities: indicators (IOCs), tags, threat actors, campaigns, malware,
-- MITRE ATT&CK techniques and vulnerabilities, plus the join tables that relate them.
-- Every record carries `origin` (demo / local / external) so the UI can label its provenance.

create table public.tags (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 50),
  color text check (color is null or color ~ '^#[0-9a-fA-F]{6}$'),
  created_at timestamptz not null default now()
);

create unique index tags_name_lower_key on public.tags (lower(name));

-- Structural validation only. A value that passes is well-formed, not malicious.
create function public.is_valid_indicator(p_type public.indicator_type, p_value text)
returns boolean
language plpgsql
immutable
set search_path = ''
as $$
begin
  return case p_type
    when 'ipv4' then p_value ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
      and family(p_value::inet) = 4 and masklen(p_value::inet) = 32
    when 'ipv6' then p_value ~ ':' and p_value !~ '/'
      and family(p_value::inet) = 6 and masklen(p_value::inet) = 128
    when 'md5' then p_value ~* '^[a-f0-9]{32}$'
    when 'sha1' then p_value ~* '^[a-f0-9]{40}$'
    when 'sha256' then p_value ~* '^[a-f0-9]{64}$'
    when 'cve' then p_value ~* '^CVE-[0-9]{4}-[0-9]{4,}$'
    when 'email' then p_value ~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'
    when 'domain' then char_length(p_value) <= 253
      and p_value ~* '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$'
    when 'url' then p_value ~* '^https?://[^[:space:]/?#]+([/?#][^[:space:]]*)?$'
    else char_length(p_value) > 0
  end;
exception
  when others then
    return false;
end;
$$;

create table public.indicators (
  id uuid primary key default gen_random_uuid(),
  type public.indicator_type not null,
  value text not null check (char_length(value) between 1 and 2048),
  value_normalized text generated always as (
    case type
      when 'cve' then upper(value)
      when 'url' then value
      else lower(value)
    end
  ) stored,
  severity public.severity not null default 'medium',
  verdict public.verdict not null default 'unknown',
  confidence smallint not null default 50 check (confidence between 0 and 100),
  status public.indicator_status not null default 'active',
  source text not null default 'manual' check (char_length(source) between 1 and 100),
  description text check (char_length(description) <= 5000),
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint indicators_value_trimmed check (value = btrim(value)),
  constraint indicators_value_valid check (public.is_valid_indicator(type, value)),
  constraint indicators_seen_order check (last_seen >= first_seen),
  constraint indicators_type_value_key unique (type, value_normalized)
);

create index indicators_type_idx on public.indicators (type);
create index indicators_severity_idx on public.indicators (severity);
create index indicators_verdict_idx on public.indicators (verdict);
create index indicators_status_idx on public.indicators (status);
create index indicators_last_seen_idx on public.indicators (last_seen desc);
create index indicators_created_at_idx on public.indicators (created_at desc);
create index indicators_created_by_idx on public.indicators (created_by);
create index indicators_value_trgm_idx
  on public.indicators using gin (value_normalized extensions.gin_trgm_ops);

create trigger indicators_set_updated_at
  before update on public.indicators
  for each row execute function public.set_updated_at();

create table public.indicator_tags (
  indicator_id uuid not null references public.indicators (id) on delete cascade,
  tag_id uuid not null references public.tags (id) on delete cascade,
  primary key (indicator_id, tag_id)
);

create index indicator_tags_tag_id_idx on public.indicator_tags (tag_id);

create table public.indicator_relationships (
  id uuid primary key default gen_random_uuid(),
  source_indicator_id uuid not null references public.indicators (id) on delete cascade,
  target_indicator_id uuid not null references public.indicators (id) on delete cascade,
  relationship public.relationship_type not null default 'related_to',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  constraint indicator_relationships_distinct check (source_indicator_id <> target_indicator_id),
  constraint indicator_relationships_key unique (source_indicator_id, target_indicator_id, relationship)
);

create index indicator_relationships_target_idx on public.indicator_relationships (target_indicator_id);

create table public.threat_actors (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 200),
  aliases text[] not null default '{}',
  description text check (char_length(description) <= 10000),
  motivation text check (char_length(motivation) <= 200),
  -- Only documented attribution belongs here. Leave null when unknown.
  attribution_country text check (char_length(attribution_country) <= 100),
  target_industries text[] not null default '{}',
  target_countries text[] not null default '{}',
  first_seen timestamptz,
  last_seen timestamptz,
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index threat_actors_name_lower_key on public.threat_actors (lower(name));

create trigger threat_actors_set_updated_at
  before update on public.threat_actors
  for each row execute function public.set_updated_at();

create table public.campaigns (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 200),
  description text check (char_length(description) <= 10000),
  status public.campaign_status not null default 'active',
  first_seen timestamptz,
  last_seen timestamptz,
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index campaigns_name_lower_key on public.campaigns (lower(name));

create trigger campaigns_set_updated_at
  before update on public.campaigns
  for each row execute function public.set_updated_at();

create table public.malware (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 200),
  malware_type text check (char_length(malware_type) <= 100),
  platforms text[] not null default '{}',
  description text check (char_length(description) <= 10000),
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index malware_name_lower_key on public.malware (lower(name));

create trigger malware_set_updated_at
  before update on public.malware
  for each row execute function public.set_updated_at();

create table public.mitre_techniques (
  id text primary key check (id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
  name text not null,
  tactics text[] not null default '{}',
  description text,
  url text
);

create table public.threat_actor_campaigns (
  threat_actor_id uuid not null references public.threat_actors (id) on delete cascade,
  campaign_id uuid not null references public.campaigns (id) on delete cascade,
  primary key (threat_actor_id, campaign_id)
);

create index threat_actor_campaigns_campaign_idx on public.threat_actor_campaigns (campaign_id);

create table public.threat_actor_malware (
  threat_actor_id uuid not null references public.threat_actors (id) on delete cascade,
  malware_id uuid not null references public.malware (id) on delete cascade,
  primary key (threat_actor_id, malware_id)
);

create index threat_actor_malware_malware_idx on public.threat_actor_malware (malware_id);

create table public.threat_actor_techniques (
  threat_actor_id uuid not null references public.threat_actors (id) on delete cascade,
  technique_id text not null references public.mitre_techniques (id) on delete cascade,
  primary key (threat_actor_id, technique_id)
);

create index threat_actor_techniques_technique_idx on public.threat_actor_techniques (technique_id);

create table public.indicator_threat_actors (
  indicator_id uuid not null references public.indicators (id) on delete cascade,
  threat_actor_id uuid not null references public.threat_actors (id) on delete cascade,
  primary key (indicator_id, threat_actor_id)
);

create index indicator_threat_actors_actor_idx on public.indicator_threat_actors (threat_actor_id);

create table public.indicator_campaigns (
  indicator_id uuid not null references public.indicators (id) on delete cascade,
  campaign_id uuid not null references public.campaigns (id) on delete cascade,
  primary key (indicator_id, campaign_id)
);

create index indicator_campaigns_campaign_idx on public.indicator_campaigns (campaign_id);

create table public.indicator_malware (
  indicator_id uuid not null references public.indicators (id) on delete cascade,
  malware_id uuid not null references public.malware (id) on delete cascade,
  primary key (indicator_id, malware_id)
);

create index indicator_malware_malware_idx on public.indicator_malware (malware_id);

create table public.vulnerabilities (
  id uuid primary key default gen_random_uuid(),
  cve_id text not null unique check (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
  title text not null check (char_length(title) between 1 and 300),
  description text not null default '' check (char_length(description) <= 20000),
  cvss_score numeric(3, 1) check (cvss_score between 0 and 10),
  cvss_vector text check (char_length(cvss_vector) <= 200),
  cvss_version text check (cvss_version in ('2.0', '3.0', '3.1', '4.0')),
  severity public.severity not null default 'medium',
  exploit_status public.exploit_status not null default 'unknown',
  remediation text check (char_length(remediation) <= 10000),
  reference_urls text[] not null default '{}',
  published_at timestamptz,
  modified_at timestamptz,
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index vulnerabilities_severity_idx on public.vulnerabilities (severity);
create index vulnerabilities_cvss_score_idx on public.vulnerabilities (cvss_score desc);
create index vulnerabilities_published_at_idx on public.vulnerabilities (published_at desc);
create index vulnerabilities_exploit_status_idx on public.vulnerabilities (exploit_status);
create index vulnerabilities_search_trgm_idx
  on public.vulnerabilities using gin (title extensions.gin_trgm_ops);

create trigger vulnerabilities_set_updated_at
  before update on public.vulnerabilities
  for each row execute function public.set_updated_at();

create table public.vulnerability_affected_products (
  id uuid primary key default gen_random_uuid(),
  vulnerability_id uuid not null references public.vulnerabilities (id) on delete cascade,
  vendor text not null check (char_length(vendor) between 1 and 200),
  product text not null check (char_length(product) between 1 and 200),
  affected_versions text check (char_length(affected_versions) <= 500),
  fixed_version text check (char_length(fixed_version) <= 200)
);

create index vulnerability_affected_products_vuln_idx
  on public.vulnerability_affected_products (vulnerability_id);
