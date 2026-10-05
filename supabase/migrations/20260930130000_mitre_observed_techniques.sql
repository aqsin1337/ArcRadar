-- The ATT&CK matrix page shows which techniques the workspace has actually seen: the ones named by
-- the alerts it holds (alerts.technique_ids, filled from a sensor's rule mapping). This returns, per
-- technique, how many alerts mention it, the most serious of them and the latest one.
--
--  * a duplicate alert (a repeat of a still-open primary) is not counted again, exactly like every
--    other alert count in the application
--  * a sub-technique (T1110.003) also counts for its parent technique (T1110), once per alert, so the
--    matrix can highlight the parent as well
--  * SECURITY INVOKER: the caller's own row level security decides which alerts they can see
create function public.mitre_observed_techniques()
returns table (technique_id text, alert_count bigint, max_severity public.severity, last_seen timestamptz)
language sql
stable
set search_path = ''
as $$
  with mentioned as (
    select a.id as alert_id, a.severity, a.created_at, t as technique_id
    from public.alerts a, unnest(a.technique_ids) as t
    where a.duplicate_of is null
    union
    select a.id, a.severity, a.created_at, split_part(t, '.', 1)
    from public.alerts a, unnest(a.technique_ids) as t
    where a.duplicate_of is null and position('.' in t) > 0
  )
  select m.technique_id, count(*)::bigint, max(m.severity), max(m.created_at)
  from mentioned m
  group by m.technique_id
$$;

revoke all on function public.mitre_observed_techniques() from public, anon;
grant execute on function public.mitre_observed_techniques() to authenticated, service_role;
