-- Withdrawing a pushed rule (rejecting it after it went to GitHub deletes its file there) must wake the SIEM host
-- too: it has to drop the rule. The revision is now the time of the latest push OR withdrawal, so a rule that was
-- pushed and later rejected counts through its rejected_at. A rule that was never pushed does not count.

create or replace function public.siem_rules_revision(p_siem text)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(max(greatest(pushed_at, rejected_at))::text, '')
  from public.siem_rules
  where siem = p_siem and pushed_at is not null
$$;

revoke all on function public.siem_rules_revision(text) from public, anon, authenticated;
grant execute on function public.siem_rules_revision(text) to service_role;
