-- Wazuh detection rules (detection-as-code).
--
-- 1. wazuh_rules: rules an administrator writes by hand or has the AI draft. They are stored as
--    STRUCTURED fields (never free XML); the application renders the Wazuh XML from them, so no
--    caller can smuggle an element (active-response, command, ...) into a file the Manager loads.
--    A rule moves draft -> pushed (committed to the rules repository on GitHub) or draft -> rejected.
--    ArcRadar never executes anything on the Manager: a script there pulls the repository.
-- 2. wazuh_rule_trigger_stats(): how many alerts each Wazuh rule produced, read from the alerts
--    ArcRadar already holds (the Wazuh normalizer writes "Wazuh rule <id> (level <n>)..." first).
--
-- Separate from detection_rules (Phase 10), which raises an alert's severity inside ArcRadar after
-- the alert exists. These rules run inside Wazuh and decide whether the alert exists at all.

create table public.wazuh_rules (
  id integer primary key check (id between 100000 and 999999),
  name text not null check (char_length(name) between 1 and 200),
  description text check (description is null or char_length(description) <= 2000),
  level integer not null check (level between 1 and 15),
  -- How the rule attaches to Wazuh's ruleset: a rule group (if_group) or a parent rule id (if_sid).
  parent_kind text not null default 'group' check (parent_kind in ('group', 'sid')),
  parent_value text not null default 'windows'
    check (parent_value ~ '^[A-Za-z0-9_.-]{1,100}$'),
  -- 1-10 { field, op, value } conditions, ANDed. Validated in TypeScript; the database only pins the
  -- shape so a bad client cannot store a non-array.
  conditions jsonb not null check (
    jsonb_typeof(conditions) = 'array' and jsonb_array_length(conditions) between 1 and 10
  ),
  mitre_ids text[] not null default '{}'
    check (
      cardinality(mitre_ids) <= 10
      and array_to_string(mitre_ids, ',') ~ '^(T[0-9]{4}(\.[0-9]{3})?(,T[0-9]{4}(\.[0-9]{3})?)*)?$'
    ),
  status text not null default 'draft' check (status in ('draft', 'pushed', 'rejected')),
  -- Where the rule came from: typed in the form, or drafted by the AI provider from `ai_prompt`.
  source text not null check (source in ('manual', 'ai')),
  ai_prompt text check (ai_prompt is null or char_length(ai_prompt) <= 2000),
  ai_provider text,
  ai_model text,
  -- The repository file this rule was last committed to, and when.
  github_path text,
  github_commit text,
  pushed_at timestamptz,
  pushed_by uuid references public.profiles (id) on delete set null,
  -- Edited after the last push: the file in the repository no longer matches.
  changed_since_push boolean not null default false,
  rejected_at timestamptz,
  reject_reason text check (reject_reason is null or char_length(reject_reason) <= 500),
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint wazuh_rules_source_ai_check check (source = 'ai' or ai_prompt is null),
  constraint wazuh_rules_pushed_check check (status <> 'pushed' or github_path is not null)
);

create index wazuh_rules_status_idx on public.wazuh_rules (status, id);

create trigger wazuh_rules_set_updated_at before update on public.wazuh_rules
  for each row execute function public.set_updated_at();
create trigger wazuh_rules_protect_origin before update on public.wazuh_rules
  for each row execute function public.protect_origin();
create trigger wazuh_rules_protect_created_by before update on public.wazuh_rules
  for each row execute function public.protect_created_by();

alter table public.wazuh_rules enable row level security;

-- Administrators only (rules:manage): these files are loaded by the Manager, so who may draft or
-- push one is the same question as who may manage rules at all.
create policy wazuh_rules_select on public.wazuh_rules for select to authenticated
  using ((select public.has_permission('rules:manage')));

create policy wazuh_rules_insert on public.wazuh_rules for insert to authenticated
  with check (
    (select public.has_permission('rules:manage'))
    and created_by = (select auth.uid())
    and origin = 'local'
    and status = 'draft'
  );

create policy wazuh_rules_update on public.wazuh_rules for update to authenticated
  using ((select public.has_permission('rules:manage')))
  with check ((select public.has_permission('rules:manage')));

-- A pushed rule is already a file in the repository: it is never deleted from here (that would
-- leave the file behind). A draft or a rejected rule may be removed.
create policy wazuh_rules_delete on public.wazuh_rules for delete to authenticated
  using ((select public.has_permission('rules:manage')) and status <> 'pushed');

-- ---------------------------------------------------------------------------
-- Trigger statistics
-- ---------------------------------------------------------------------------
create function public.wazuh_rule_trigger_stats()
returns table (rule_id integer, triggers bigint, last_triggered timestamptz)
language sql
stable
set search_path = ''
as $$
  select (m)[1]::integer, count(*), max(a.created_at)
  from public.alerts a
  cross join lateral regexp_match(a.description, '^Wazuh rule ([0-9]{1,6}) \(level') as m
  where a.source = 'wazuh' and m is not null and a.duplicate_of is null
  group by (m)[1]::integer
$$;

revoke all on function public.wazuh_rule_trigger_stats() from public, anon;
grant execute on function public.wazuh_rule_trigger_stats() to authenticated;
