-- Phase 10: alert deduplication and custom detection rules.
--
-- 1. rules:manage permission (admin only).
-- 2. detection_rules: a small, curated catalog (id 100000-999999, mirroring Wazuh's own custom-rule
--    id space so the two number ranges never collide), evaluated inline, in priority order, against
--    every alert as it is created.
-- 3. alerts gains fingerprint / duplicate_of / duplicate_count / matched_rule_id.
-- 4. severity_rank() and detection_rule_matches(): small, pure helpers the trigger below uses. The
--    conditions grammar is a fixed, closed set of (field, op) pairs -- never a filter built from free
--    text -- and detection_rule_matches() fails closed on anything it does not recognize.
-- 5. alerts_dedup_and_rules(): one BEFORE INSERT trigger, fired for every alert however it is
--    created, so ingest_telemetry() and a manual POST /api/alerts share one implementation -- no code
--    path can create an alert that skips it, and there is no background worker to run it later
--    (decision 1 still holds: this all happens inline on the write that already has to happen).
-- 6. alert_status_counts() / alert_severity_counts() / activity_series() exclude a duplicate: it is
--    not a fresh occurrence in the queue, so it should not inflate a count nobody sees the extra row
--    for. The dashboard's own two alert head-counts get the same treatment in application code.

-- ---------------------------------------------------------------------------
-- 1. Permission
-- ---------------------------------------------------------------------------
insert into public.permissions (key, description) values
  ('rules:manage', 'Create, edit and delete custom detection rules');

insert into public.role_permissions (role_name, permission_key) values
  ('admin', 'rules:manage');

-- ---------------------------------------------------------------------------
-- 2. detection_rules
-- ---------------------------------------------------------------------------
create table public.detection_rules (
  id integer primary key check (id between 100000 and 999999),
  name text not null check (char_length(name) between 1 and 200),
  description text check (description is null or char_length(description) <= 2000),
  -- A fixed, closed grammar: an array of 1-10 conditions, ANDed together, each
  -- { field, op, value }. detection_rule_matches() below is the one place that interprets it.
  conditions jsonb not null check (
    jsonb_typeof(conditions) = 'array' and jsonb_array_length(conditions) between 1 and 10
  ),
  -- A match can only raise the severity (never lower it); null means "no override, just trace it".
  severity public.severity,
  priority integer not null default 100 check (priority between 1 and 1000),
  enabled boolean not null default true,
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index detection_rules_enabled_priority_idx
  on public.detection_rules (priority, id) where enabled;

create trigger detection_rules_set_updated_at before update on public.detection_rules
  for each row execute function public.set_updated_at();
create trigger detection_rules_protect_origin before update on public.detection_rules
  for each row execute function public.protect_origin();
create trigger detection_rules_protect_created_by before update on public.detection_rules
  for each row execute function public.protect_created_by();

alter table public.detection_rules enable row level security;

-- Readable by anyone who reads alerts (the same reasoning as response_actions): an analyst should be
-- able to see why a matched rule raised an alert's severity. Only rules:manage may write.
create policy detection_rules_select on public.detection_rules for select to authenticated
  using ((select public.has_permission('alerts:read')));

create policy detection_rules_insert on public.detection_rules for insert to authenticated
  with check (
    (select public.has_permission('rules:manage'))
    and created_by = (select auth.uid())
    and origin = 'local'
  );

create policy detection_rules_update on public.detection_rules for update to authenticated
  using ((select public.has_permission('rules:manage')))
  with check ((select public.has_permission('rules:manage')));

create policy detection_rules_delete on public.detection_rules for delete to authenticated
  using ((select public.has_permission('rules:manage')));

-- ---------------------------------------------------------------------------
-- 3. alerts: fingerprint, deduplication and the rule a match was traced to.
-- ---------------------------------------------------------------------------
alter table public.alerts
  add column fingerprint text,
  add column duplicate_of uuid references public.alerts (id) on delete set null,
  add column duplicate_count integer not null default 0 check (duplicate_count >= 0),
  add column matched_rule_id integer references public.detection_rules (id) on delete set null,
  add constraint alerts_duplicate_of_not_self check (duplicate_of is null or duplicate_of <> id),
  -- Only a primary (duplicate_of is null) ever accumulates a count; a duplicate's own stays 0.
  add constraint alerts_duplicate_count_only_primary check (duplicate_of is null or duplicate_count = 0);

create index alerts_fingerprint_idx on public.alerts (fingerprint) where duplicate_of is null;
create index alerts_duplicate_of_idx on public.alerts (duplicate_of);

-- ---------------------------------------------------------------------------
-- 4. Helpers
-- ---------------------------------------------------------------------------
create function public.severity_rank(p_severity public.severity)
returns int
language sql
immutable
set search_path = ''
as $$
  select case p_severity
    when 'info' then 0 when 'low' then 1 when 'medium' then 2 when 'high' then 3 when 'critical' then 4
  end
$$;

-- Every condition in the array must match (AND). A (field, op) pair this does not recognize never
-- matches -- it fails closed, so a rule can only ever do what this function explicitly implements,
-- never anything a client could smuggle into the jsonb.
create function public.detection_rule_matches(p_conditions jsonb, p_alert public.alerts)
returns boolean
language plpgsql
stable
set search_path = ''
as $$
declare
  cond jsonb;
  v_field text;
  v_op text;
  v_value text;
  v_ok boolean;
begin
  if jsonb_typeof(p_conditions) is distinct from 'array' or jsonb_array_length(p_conditions) = 0 then
    return false;
  end if;

  for cond in select value from jsonb_array_elements(p_conditions) loop
    v_field := cond ->> 'field';
    v_op := cond ->> 'op';
    v_value := cond ->> 'value';
    v_ok := false;

    if v_field = 'severity' and v_op = 'eq' then
      v_ok := p_alert.severity::text = lower(coalesce(v_value, ''));
    elsif v_field = 'source' and v_op = 'eq' then
      v_ok := lower(p_alert.source) = lower(coalesce(v_value, ''));
    elsif v_field = 'source' and v_op = 'contains' then
      v_ok := v_value is not null and position(lower(v_value) in lower(p_alert.source)) > 0;
    elsif v_field = 'title' and v_op = 'contains' then
      v_ok := v_value is not null and p_alert.title is not null
              and position(lower(v_value) in lower(p_alert.title)) > 0;
    elsif v_field = 'description' and v_op = 'contains' then
      v_ok := v_value is not null and p_alert.description is not null
              and position(lower(v_value) in lower(p_alert.description)) > 0;
    elsif v_field = 'technique_id' and v_op = 'eq' then
      v_ok := v_value is not null and v_value = any(p_alert.technique_ids);
    end if;

    if not v_ok then
      return false;
    end if;
  end loop;

  return true;
end;
$$;

revoke all on function public.severity_rank(public.severity) from public, anon;
revoke all on function public.detection_rule_matches(jsonb, public.alerts) from public, anon;
grant execute on function public.severity_rank(public.severity) to authenticated, service_role;
grant execute on function public.detection_rule_matches(jsonb, public.alerts) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 5. The trigger: rules first (may raise severity before the fingerprint is taken), then dedup.
-- ---------------------------------------------------------------------------
-- ingest_telemetry()'s own ON CONFLICT DO NOTHING on (source, source_event_id) never actually lets
-- this trigger's side effects apply to a row that ends up discarded: a retried record's *event*
-- insert conflicts first and the whole record is skipped (`continue`) before the alert insert is
-- even attempted, so the alert-table ON CONFLICT branch -- and this trigger with it -- is a backstop
-- that is never reached in practice for a genuine retry.
create function public.alerts_dedup_and_rules()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_rule record;
  v_primary_id uuid;
begin
  for v_rule in
    select * from public.detection_rules where enabled order by priority asc, id asc
  loop
    if public.detection_rule_matches(v_rule.conditions, new) then
      new.matched_rule_id := v_rule.id;
      if v_rule.severity is not null
         and public.severity_rank(v_rule.severity) > public.severity_rank(new.severity) then
        new.severity := v_rule.severity;
      end if;
      exit; -- the highest-priority match wins; a lower-priority rule never overrides it
    end if;
  end loop;

  new.fingerprint := md5(
    lower(coalesce(new.source, '')) || '|' ||
    lower(regexp_replace(coalesce(new.title, ''), '[^a-z0-9]+', '', 'gi')) || '|' ||
    coalesce(new.asset_id::text, '') || '|' ||
    coalesce(new.indicator_id::text, '')
  );

  if new.duplicate_of is null then
    select id into v_primary_id
      from public.alerts
      where fingerprint = new.fingerprint
        and duplicate_of is null
        and status not in ('resolved', 'false_positive')
        and created_at > now() - interval '60 minutes'
      order by created_at desc
      limit 1;
    if found then
      new.duplicate_of := v_primary_id;
      update public.alerts set duplicate_count = duplicate_count + 1 where id = v_primary_id;
    end if;
  end if;

  return new;
end;
$$;

create trigger alerts_dedup_and_rules_trigger before insert on public.alerts
  for each row execute function public.alerts_dedup_and_rules();

-- ---------------------------------------------------------------------------
-- 6. A duplicate is not a fresh occurrence: exclude it from counts nobody sees the extra row for.
-- ---------------------------------------------------------------------------
create or replace function public.alert_status_counts()
returns table (status public.alert_status, total bigint, unassigned bigint)
language sql
stable
set search_path = ''
as $$
  select a.status, count(*), count(*) filter (where a.assigned_to is null)
  from public.alerts a
  where a.duplicate_of is null
  group by a.status
$$;

create or replace function public.alert_severity_counts()
returns table (severity public.severity, total bigint)
language sql
stable
set search_path = ''
as $$
  select a.severity, count(*)
  from public.alerts a
  where a.duplicate_of is null
  group by a.severity
$$;

create or replace function public.activity_series(p_days int default 14)
returns table (day date, alerts bigint, events bigint)
language sql
stable
set search_path = ''
as $$
  with days as (
    select generate_series(
      current_date - (least(greatest(p_days, 1), 90) - 1),
      current_date,
      interval '1 day'
    )::date as day
  )
  select
    d.day,
    coalesce((select count(*) from public.alerts a where date(a.created_at) = d.day and a.duplicate_of is null), 0),
    coalesce((select count(*) from public.events e where date(e.occurred_at) = d.day), 0)
  from days d
  order by d.day
$$;
