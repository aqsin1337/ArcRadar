-- Rule mode (test / live) and backtests.
--
-- 1. siem_rules.mode: a rule can be pushed in TEST mode: the file is committed and the SIEM loads it, but it
--    does not run on a schedule and has no action, so it never alerts. The SIEM host can still run its search
--    over past data, which is what a backtest is. "Live" is the rule as it always was.
-- 2. siem_rule_backtests: what that run found ("over the last 24 h / 7 days this search would have fired N
--    times"), reported by the SIEM host with its API key. Written only by sync_rule_backtests() (service role),
--    read by administrators. search_sha256 says which search was tested, so a result for an older version of the
--    rule can be shown as out of date.

alter table public.siem_rules
  add column mode text not null default 'live' check (mode in ('test', 'live'));

create table public.siem_rule_backtests (
  siem text not null check (siem in ('splunk')),
  rule_key text not null check (rule_key ~ '^[A-Za-z0-9_-]{1,60}$'),
  window_hours integer not null check (window_hours in (24, 168)),
  -- 'threshold': matches counts the (time bucket, group) pairs over the limit; 'events': matches counts events.
  kind text not null check (kind in ('threshold', 'events')),
  matches integer not null check (matches >= 0),
  scanned integer check (scanned is null or scanned >= 0),
  -- Up to five examples: [{ "time": iso, "count": n, "group": { field: value } }].
  sample jsonb not null default '[]'
    check (jsonb_typeof(sample) = 'array' and jsonb_array_length(sample) <= 5 and pg_column_size(sample) <= 4096),
  search_sha256 text not null check (search_sha256 ~ '^[0-9a-f]{64}$'),
  error text check (error is null or char_length(error) <= 300),
  reported_at timestamptz not null default now(),
  origin public.data_origin not null default 'external',
  primary key (siem, rule_key, window_hours)
);

alter table public.siem_rule_backtests enable row level security;

create policy siem_rule_backtests_select on public.siem_rule_backtests for select to authenticated
  using ((select public.has_permission('rules:manage')));

revoke insert, update, delete on public.siem_rule_backtests from authenticated, anon;

-- A deleted rule takes its backtests with it (they are keyed by rule key, not by a foreign key).
create function public.siem_rules_delete_backtests()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from public.siem_rule_backtests where siem = old.siem and rule_key = old.rule_key;
  return old;
end;
$$;

revoke all on function public.siem_rules_delete_backtests() from public, anon, authenticated;

create trigger siem_rules_delete_backtests after delete on public.siem_rules
  for each row execute function public.siem_rules_delete_backtests();

-- ---------------------------------------------------------------------------
-- sync_rule_backtests
-- ---------------------------------------------------------------------------
-- Stores what the SIEM host reported. Each element of p_results:
--   { rule_key, window_hours, kind, matches, scanned?, sample?, search_sha256, error? }
-- A later report for the same (rule, window) replaces the earlier one. At most 200 results per call.
create function public.sync_rule_backtests(p_siem text, p_results jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  r jsonb;
  n integer := 0;
begin
  if p_siem is null or p_siem not in ('splunk') then
    raise exception 'Unknown SIEM' using errcode = '22023';
  end if;
  if jsonb_typeof(p_results) is distinct from 'array' then
    raise exception 'Results must be an array' using errcode = '22023';
  end if;
  if jsonb_array_length(p_results) > 200 then
    raise exception 'Too many results in one call' using errcode = '22023';
  end if;

  for r in select value from jsonb_array_elements(p_results) loop
    insert into public.siem_rule_backtests
      (siem, rule_key, window_hours, kind, matches, scanned, sample, search_sha256, error, reported_at)
    values (
      p_siem, r ->> 'rule_key', (r ->> 'window_hours')::integer, r ->> 'kind',
      (r ->> 'matches')::integer, nullif(r ->> 'scanned', '')::integer,
      coalesce(r -> 'sample', '[]'::jsonb), r ->> 'search_sha256', left(nullif(r ->> 'error', ''), 300), now()
    )
    on conflict (siem, rule_key, window_hours) do update
      set kind = excluded.kind, matches = excluded.matches, scanned = excluded.scanned,
          sample = excluded.sample, search_sha256 = excluded.search_sha256, error = excluded.error,
          reported_at = excluded.reported_at;
    n := n + 1;
  end loop;

  return jsonb_build_object('results', n);
end;
$$;

revoke all on function public.sync_rule_backtests(text, jsonb) from public, anon, authenticated;
grant execute on function public.sync_rule_backtests(text, jsonb) to service_role;
