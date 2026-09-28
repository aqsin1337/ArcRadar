-- Dashboard aggregates, report provenance, and the integrations enabled switch.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer, ...0005 inactive analyst
-- Fixture data uses fxboard-prefixed titles/values so it can never collide with the seed.

begin;

insert into auth.users (id, email) values
  ('11111111-0000-4000-8000-000000000001', 'board-admin@arcradar.test'),
  ('11111111-0000-4000-8000-000000000002', 'board-analyst@arcradar.test'),
  ('11111111-0000-4000-8000-000000000003', 'board-viewer@arcradar.test'),
  ('11111111-0000-4000-8000-000000000005', 'board-inactive@arcradar.test');

update public.profiles set role_name = 'admin' where id = '11111111-0000-4000-8000-000000000001';
update public.profiles set role_name = 'analyst' where id in
  ('11111111-0000-4000-8000-000000000002', '11111111-0000-4000-8000-000000000005');
update public.profiles set is_active = false where id = '11111111-0000-4000-8000-000000000005';

-- Deterministic alerts: 2 high, 1 critical, so alert_severity_counts has a known shape. Two happen
-- today, one three days ago (outside a 1-day activity window, inside a 7-day one).
insert into public.alerts (id, title, severity, status, source, created_at, resolved_at, origin) values
  ('22222222-0000-4000-8000-000000000001', 'fxboard alert one', 'high', 'new', 'manual', now(), null, 'local'),
  ('22222222-0000-4000-8000-000000000002', 'fxboard alert two', 'high', 'resolved', 'manual', now(), now(), 'local'),
  ('22222222-0000-4000-8000-000000000003', 'fxboard alert three', 'critical', 'new', 'manual', now() - interval '3 days', null, 'local');

-- Deterministic events: one today, one three days ago, so activity_series can be checked per day.
insert into public.events (id, event_type, title, severity, source, occurred_at, origin) values
  ('33333333-0000-4000-8000-000000000001', 'fxboard_event', 'fxboard event today', 'medium', 'manual', now(), 'local'),
  ('33333333-0000-4000-8000-000000000002', 'fxboard_event', 'fxboard event old', 'medium', 'manual', now() - interval '3 days', 'local');

-- Deterministic indicators: 2 ipv4, 1 domain; 2 malicious, 1 suspicious.
insert into public.indicators (id, type, value, severity, verdict, source, first_seen, last_seen, origin) values
  ('44444444-0000-4000-8000-000000000001', 'ipv4', '203.0.113.220', 'high', 'malicious', 'manual', now(), now(), 'local'),
  ('44444444-0000-4000-8000-000000000002', 'ipv4', '203.0.113.221', 'high', 'malicious', 'manual', now(), now(), 'local'),
  ('44444444-0000-4000-8000-000000000003', 'domain', 'fxboard-sus.example', 'medium', 'suspicious', 'manual', now(), now(), 'local');

-- Two threat actors: one with two linked indicators, one with none. The busier one is named to
-- sort AFTER the quiet one, so a mutation that ranks by name instead of by count is caught.
insert into public.threat_actors (id, name, origin) values
  ('55555555-0000-4000-8000-000000000001', 'Fxboard Zulu Actor', 'local'),
  ('55555555-0000-4000-8000-000000000002', 'Fxboard Alpha Actor', 'local');
insert into public.indicator_threat_actors (indicator_id, threat_actor_id) values
  ('44444444-0000-4000-8000-000000000001', '55555555-0000-4000-8000-000000000001'),
  ('44444444-0000-4000-8000-000000000002', '55555555-0000-4000-8000-000000000001');

-- 1. aggregate functions: anon blocked, a viewer (who holds every *:read they touch) sees the fixture
-- ---------------------------------------------------------------------------------------------
do $$
declare n int; blocked boolean;
begin
  set local role anon;
  blocked := false;
  begin perform public.alert_severity_counts(); exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could call alert_severity_counts'; end if;
  blocked := false;
  begin perform public.indicator_type_counts(); exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could call indicator_type_counts'; end if;
  blocked := false;
  begin perform public.indicator_verdict_counts(); exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could call indicator_verdict_counts'; end if;
  blocked := false;
  begin perform public.activity_series(7); exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could call activity_series'; end if;
  blocked := false;
  begin perform public.top_threat_actors(5); exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could call top_threat_actors'; end if;
  reset role;

  -- anon is also blocked from the underlying tables, so the calls above stay blocked even if a
  -- function's own execute grant were mistakenly restored; check that grant directly too.
  if has_function_privilege('anon', 'public.alert_severity_counts()', 'execute') then
    raise exception 'FAIL anon holds execute on alert_severity_counts';
  end if;
  if has_function_privilege('anon', 'public.indicator_type_counts()', 'execute') then
    raise exception 'FAIL anon holds execute on indicator_type_counts';
  end if;
  if has_function_privilege('anon', 'public.indicator_verdict_counts()', 'execute') then
    raise exception 'FAIL anon holds execute on indicator_verdict_counts';
  end if;
  if has_function_privilege('anon', 'public.activity_series(int)', 'execute') then
    raise exception 'FAIL anon holds execute on activity_series';
  end if;
  if has_function_privilege('anon', 'public.top_threat_actors(int)', 'execute') then
    raise exception 'FAIL anon holds execute on top_threat_actors';
  end if;

  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- The seed already has alerts of these severities, so check a lower bound from the fixture, not
  -- an exact total.
  select total into n from public.alert_severity_counts() where severity = 'high';
  if n < 2 then raise exception 'FAIL alert_severity_counts high total was %', n; end if;
  select total into n from public.alert_severity_counts() where severity = 'critical';
  if n < 1 then raise exception 'FAIL alert_severity_counts critical total was %', n; end if;

  select total into n from public.indicator_type_counts() where type = 'ipv4';
  if n < 2 then raise exception 'FAIL indicator_type_counts ipv4 total was %', n; end if;
  select total into n from public.indicator_verdict_counts() where verdict = 'malicious';
  if n < 2 then raise exception 'FAIL indicator_verdict_counts malicious total was %', n; end if;

  reset role;
  raise notice 'ok - the aggregate functions are authenticated-only and count what a viewer can already read';
end $$;

-- 2. activity_series: one row per day, oldest first, today included, a bounded window
-- ---------------------------------------------------------------------------------------------
do $$
declare n int; r record;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  select count(*) into n from public.activity_series(1);
  if n <> 1 then raise exception 'FAIL activity_series(1) returned % rows, expected exactly 1', n; end if;
  select * into r from public.activity_series(1) where day = current_date;
  if r.alerts < 2 or r.events < 1 then
    raise exception 'FAIL today''s row undercounts: alerts %, events %', r.alerts, r.events;
  end if;

  select count(*) into n from public.activity_series(7);
  if n <> 7 then raise exception 'FAIL activity_series(7) returned % rows, expected exactly 7', n; end if;
  select * into r from public.activity_series(7) where day = current_date - 3;
  if r.alerts < 1 or r.events < 1 then
    raise exception 'FAIL the day-3-ago row undercounts: alerts %, events %', r.alerts, r.events;
  end if;

  -- The window is clamped, not unbounded: asking for a huge number never returns more than 90 rows.
  select count(*) into n from public.activity_series(10000);
  if n <> 90 then raise exception 'FAIL activity_series clamps to 90 days, returned %', n; end if;
  select count(*) into n from public.activity_series(0);
  if n <> 1 then raise exception 'FAIL activity_series(0) should clamp up to 1 day, returned %', n; end if;

  reset role;
  raise notice 'ok - activity_series buckets by day, includes today, and clamps its window to 1-90 days';
end $$;

-- 3. top_threat_actors: ranked by linked indicators, most active first, limit respected
-- (the seed's own actors have up to 2 links too, so this compares the two fixture actors to each
-- other rather than assuming either is the global first place.)
-- ---------------------------------------------------------------------------------------------
do $$
declare busy_rank int; quiet_rank int; busy_count bigint; n int;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- 20 is the function's own clamp (least(greatest(p_limit, 1), 20)); there are only 7 actors in
  -- this transaction (the seed's 5 plus these 2), so both fixture actors are well within it.
  select row_number, indicator_count into busy_rank, busy_count
    from (select id, indicator_count, row_number() over () from public.top_threat_actors(20)) t
    where id = '55555555-0000-4000-8000-000000000001';
  select row_number into quiet_rank
    from (select id, row_number() over () from public.top_threat_actors(20)) t
    where id = '55555555-0000-4000-8000-000000000002';
  if busy_count < 2 then raise exception 'FAIL the busy actor''s indicator_count was %', busy_count; end if;
  if busy_rank is null or quiet_rank is null then
    raise exception 'FAIL one of the fixture actors did not appear at all';
  end if;
  if busy_rank >= quiet_rank then
    raise exception 'FAIL the actor with more indicators (rank %) did not rank above the one with none (rank %)', busy_rank, quiet_rank;
  end if;

  select count(*) into n from public.top_threat_actors(1);
  if n <> 1 then raise exception 'FAIL top_threat_actors(1) returned % rows, expected 1', n; end if;

  reset role;
  raise notice 'ok - top_threat_actors ranks by linked indicators and respects its limit';
end $$;

-- 4. reports: provenance, as for every other record table
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; new_id uuid; o public.data_origin;
begin
  -- a viewer cannot create a report at all
  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.reports (title, type) values ('fxboard viewer attempt', 'alerts');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a viewer created a report'; end if;
  reset role;

  -- an analyst creates a local report
  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.reports (title, type) values ('fxboard analyst report', 'alerts') returning id into new_id;
  reset role;

  select origin into o from public.reports where id = new_id;
  if o <> 'local' then raise exception 'FAIL a client-created report was origin %', o; end if;

  -- a client cannot claim origin external or demo directly
  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.reports (title, type, origin) values ('fxboard forged origin', 'alerts', 'external');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a report was created with origin external'; end if;

  -- nor relabel one after the fact: the change is silently ignored, the rest of the update goes through
  update public.reports set origin = 'demo', title = 'fxboard analyst report (edited)' where id = new_id;
  select origin into o from public.reports where id = new_id;
  if o <> 'local' then raise exception 'FAIL an update relabelled a report to %', o; end if;
  if (select title from public.reports where id = new_id) <> 'fxboard analyst report (edited)' then
    raise exception 'FAIL the rest of the update was lost';
  end if;
  reset role;

  raise notice 'ok - reports: only reports:write creates one, always local, never relabelled';
end $$;

-- 4b. search_reports: ANDed terms, literal wildcards, denied to anon
-- ---------------------------------------------------------------------------------------------
do $$
declare n int; blocked boolean;
begin
  insert into public.reports (title, type) values ('fxboard50%_off report', 'alerts');

  set local role anon;
  blocked := false;
  begin perform public.search_reports('fxboard'); exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could call search_reports'; end if;
  reset role;
  if has_function_privilege('anon', 'public.search_reports(text)', 'execute') then
    raise exception 'FAIL anon holds execute on search_reports';
  end if;

  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  select count(*) into n from public.search_reports('fxboard analyst');
  if n <> 1 then raise exception 'FAIL search_reports ANDed terms found %', n; end if;
  select count(*) into n from public.search_reports('fxboard nothing-like-this');
  if n <> 0 then raise exception 'FAIL an unmatched extra word still matched'; end if;
  select count(*) into n from public.search_reports('fxboard50%_off');
  if n <> 1 then raise exception 'FAIL a literal %% in the search text did not match its report'; end if;
  -- If % were a real wildcard this would match ("fxboard" ... "report"); as a literal it does not,
  -- since the exact substring "fxboard%report" never occurs.
  select count(*) into n from public.search_reports('fxboard%report');
  if n <> 0 then raise exception 'FAIL a %% in the search text acted as a wildcard'; end if;

  reset role;
  raise notice 'ok - search_reports: ANDed terms, literal wildcards, denied to anon';
end $$;

-- 5. integrations: the migration's default flip, and who may flip it further
-- ---------------------------------------------------------------------------------------------
do $$
declare enabled boolean; n int;
begin
  select i.enabled into enabled from public.integrations i where i.provider = 'virustotal';
  if enabled is not true then raise exception 'FAIL virustotal was not defaulted to enabled = true'; end if;

  -- RLS (not a missing grant) is what stops an analyst here, so the statement succeeds but touches
  -- no rows, rather than raising an exception.
  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  update public.integrations set enabled = false where provider = 'virustotal';
  get diagnostics n = row_count;
  reset role;
  if n <> 0 then raise exception 'FAIL an analyst disabled an integration (% rows)', n; end if;

  perform set_config('request.jwt.claims', json_build_object('sub', '11111111-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  update public.integrations set enabled = false where provider = 'virustotal';
  select i.enabled into enabled from public.integrations i where i.provider = 'virustotal';
  reset role;
  if enabled is not false then raise exception 'FAIL an administrator could not disable an integration'; end if;

  raise notice 'ok - integrations default to enabled, and only integrations:manage flips the switch';
end $$;

rollback;

do $$ begin raise notice 'DASHBOARD AND REPORTS DATABASE TESTS PASSED'; end $$;
