-- Phase 7: dashboard aggregates, report provenance, and integration defaults.
--
-- Reports were part of the schema since Phase 1 but unused until now: they get the same
-- provenance protection every other record table has (origin = 'local' on insert, never
-- relabelled afterwards). The dashboard needs a few aggregate reads that PostgREST cannot express
-- (group by, day-bucketing, joined counts); each is `security invoker` so it only ever sees what
-- the caller's own RLS lets them see. `enabled` on `integrations` becomes a real, if optional,
-- switch: previously nothing read it.

-- ---------------------------------------------------------------------------
-- 1. Reports: provenance, as for every other record table (20260926120000, 20260926150000,
--    20260927100000). Signed-in users can only create 'local' reports; external or demo reports
--    would have to come from a server-side write, and none exists.
-- ---------------------------------------------------------------------------
create trigger reports_protect_origin before update on public.reports
  for each row execute function public.protect_origin();

drop policy reports_insert on public.reports;
create policy reports_insert on public.reports for insert to authenticated
  with check (
    (select public.has_permission('reports:write'))
    and created_by = (select auth.uid())
    and origin = 'local'
  );

-- Text search over report titles, ANDed terms, literal wildcards, same shape as every other
-- search_*() function.
create function public.search_reports(p_query text default null)
returns setof public.reports
language sql
stable
set search_path = ''
as $$
  select r.*
  from public.reports r
  where not exists (
    select 1
    from unnest((regexp_split_to_array(btrim(coalesce(p_query, '')), '\s+'))[1:8]) as term
    where term <> ''
      and not coalesce(r.title ilike '%' || public.escape_like(term) || '%', false)
  )
$$;

revoke all on function public.search_reports(text) from public, anon;
grant execute on function public.search_reports(text) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 2. Dashboard aggregates. Each counts only what the caller's RLS already lets them read, so a
--    viewer sees the same totals as everyone else (all three roles hold every *:read permission
--    the dashboard touches) and there is nothing extra to authorize here.
-- ---------------------------------------------------------------------------

create function public.alert_severity_counts()
returns table (severity public.severity, total bigint)
language sql
stable
set search_path = ''
as $$
  select a.severity, count(*)
  from public.alerts a
  group by a.severity
$$;

create function public.indicator_type_counts()
returns table (type public.indicator_type, total bigint)
language sql
stable
set search_path = ''
as $$
  select i.type, count(*)
  from public.indicators i
  group by i.type
$$;

create function public.indicator_verdict_counts()
returns table (verdict public.verdict, total bigint)
language sql
stable
set search_path = ''
as $$
  select i.verdict, count(*)
  from public.indicators i
  group by i.verdict
$$;

-- One row per day in the trailing window (always present, even at zero), with how many alerts and
-- events happened that day. p_days is clamped so nobody can ask for an unbounded series.
create function public.activity_series(p_days int default 14)
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
    coalesce((select count(*) from public.alerts a where date(a.created_at) = d.day), 0),
    coalesce((select count(*) from public.events e where date(e.occurred_at) = d.day), 0)
  from days d
  order by d.day
$$;

-- The threat actors with the most tracked indicators, most active first.
create function public.top_threat_actors(p_limit int default 5)
returns table (id uuid, name text, indicator_count bigint)
language sql
stable
set search_path = ''
as $$
  select t.id, t.name, count(it.indicator_id)
  from public.threat_actors t
  left join public.indicator_threat_actors it on it.threat_actor_id = t.id
  group by t.id, t.name
  order by count(it.indicator_id) desc, t.name
  limit least(greatest(p_limit, 1), 20)
$$;

revoke all on function public.alert_severity_counts() from public, anon;
revoke all on function public.indicator_type_counts() from public, anon;
revoke all on function public.indicator_verdict_counts() from public, anon;
revoke all on function public.activity_series(int) from public, anon;
revoke all on function public.top_threat_actors(int) from public, anon;
grant execute on function public.alert_severity_counts() to authenticated, service_role;
grant execute on function public.indicator_type_counts() to authenticated, service_role;
grant execute on function public.indicator_verdict_counts() to authenticated, service_role;
grant execute on function public.activity_series(int) to authenticated, service_role;
grant execute on function public.top_threat_actors(int) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 3. Integrations: `enabled` becomes a real administrative switch (previously unread by any code).
--    It means "administratively allowed", separate from "a server-side key is configured": the app
--    still only ever uses a live provider when both are true. Flip every non-demo row to true so
--    existing behaviour (gated on the key alone) does not change until an administrator disables one.
-- ---------------------------------------------------------------------------
update public.integrations set enabled = true where provider <> 'demo';
