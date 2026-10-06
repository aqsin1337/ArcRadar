-- Detection rules for SIEMs other than Wazuh (detection-as-code, multi-SIEM).
--
-- siem_rules: one row per rule, whatever the SIEM. The rule is stored as STRUCTURED fields in `spec`
-- (its shape depends on the SIEM and is validated in TypeScript by that SIEM's dialect); the file the
-- SIEM loads is always rendered from them by ArcRadar, never accepted from a caller or from the AI, so
-- no command that changes a system can be smuggled into it. A rule moves draft -> pushed (committed to
-- the rules repository on GitHub) or draft -> rejected; a script on the SIEM host pulls the repository.
-- ArcRadar never connects to the SIEM.
--
-- Wazuh rules stay in wazuh_rules (real columns and constraints for Wazuh's own model, see migration
-- 20260930150000). Each new SIEM is added by widening the `siem` check below in its own migration.

create table public.siem_rules (
  id uuid primary key default gen_random_uuid(),
  siem text not null check (siem in ('splunk')),
  -- Identifies the rule inside its SIEM; becomes part of the saved file name.
  rule_key text not null check (rule_key ~ '^[A-Za-z0-9_-]{1,60}$'),
  name text not null check (char_length(name) between 1 and 200),
  description text check (description is null or char_length(description) <= 2000),
  severity text not null check (severity in ('low', 'medium', 'high', 'critical')),
  -- The SIEM-specific structured fields. Only the shape is pinned here (an object, bounded in size).
  spec jsonb not null check (jsonb_typeof(spec) = 'object' and pg_column_size(spec) <= 8192),
  mitre_ids text[] not null default '{}'
    check (
      cardinality(mitre_ids) <= 10
      and array_to_string(mitre_ids, ',') ~ '^(T[0-9]{4}(\.[0-9]{3})?(,T[0-9]{4}(\.[0-9]{3})?)*)?$'
    ),
  status text not null default 'draft' check (status in ('draft', 'pushed', 'rejected')),
  source text not null check (source in ('manual', 'ai')),
  ai_prompt text check (ai_prompt is null or char_length(ai_prompt) <= 2000),
  ai_provider text,
  ai_model text,
  github_path text,
  github_commit text,
  pushed_at timestamptz,
  pushed_by uuid references public.profiles (id) on delete set null,
  changed_since_push boolean not null default false,
  rejected_at timestamptz,
  reject_reason text check (reject_reason is null or char_length(reject_reason) <= 500),
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint siem_rules_key_unique unique (siem, rule_key),
  constraint siem_rules_source_ai_check check (source = 'ai' or ai_prompt is null),
  constraint siem_rules_pushed_check check (status <> 'pushed' or github_path is not null)
);

create index siem_rules_siem_status_idx on public.siem_rules (siem, status, created_at desc);

create trigger siem_rules_set_updated_at before update on public.siem_rules
  for each row execute function public.set_updated_at();
create trigger siem_rules_protect_origin before update on public.siem_rules
  for each row execute function public.protect_origin();
create trigger siem_rules_protect_created_by before update on public.siem_rules
  for each row execute function public.protect_created_by();

-- The SIEM and the key name a file in the repository: neither may change once the row exists.
create function public.siem_rules_protect_identity()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.siem is distinct from old.siem or new.rule_key is distinct from old.rule_key then
    raise exception 'The SIEM and rule key of a rule cannot be changed.'
      using errcode = '42501';
  end if;
  return new;
end;
$$;

create trigger siem_rules_protect_identity before update on public.siem_rules
  for each row execute function public.siem_rules_protect_identity();

alter table public.siem_rules enable row level security;

-- Administrators only (rules:manage), exactly like wazuh_rules: these files are loaded by a SIEM.
create policy siem_rules_select on public.siem_rules for select to authenticated
  using ((select public.has_permission('rules:manage')));

create policy siem_rules_insert on public.siem_rules for insert to authenticated
  with check (
    (select public.has_permission('rules:manage'))
    and created_by = (select auth.uid())
    and origin = 'local'
    and status = 'draft'
  );

create policy siem_rules_update on public.siem_rules for update to authenticated
  using ((select public.has_permission('rules:manage')))
  with check ((select public.has_permission('rules:manage')));

-- A pushed rule is already a file in the repository: it is never deleted from here.
create policy siem_rules_delete on public.siem_rules for delete to authenticated
  using ((select public.has_permission('rules:manage')) and status <> 'pushed');
