-- A cheap "has anything been pushed?" marker for the SIEM host to wait on.
--
-- The Splunk host keeps one long request open to ArcRadar (GET /api/ingest/splunk/wake) and is answered the
-- moment a rule is pushed, instead of asking every minute from cron. The revision is the time of the latest
-- push (a rule's pushed_at changes on every push, in either mode). It reveals nothing but that moment, and
-- only the service role (the route, after the API key is verified) may read it.

create function public.siem_rules_revision(p_siem text)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(max(pushed_at)::text, '')
  from public.siem_rules
  where siem = p_siem and status = 'pushed'
$$;

revoke all on function public.siem_rules_revision(text) from public, anon, authenticated;
grant execute on function public.siem_rules_revision(text) to service_role;
