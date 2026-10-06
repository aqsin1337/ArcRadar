-- Rule mode and backtests: the mode column, who may read backtests, that only sync_rule_backtests() writes
-- them, what it accepts, and that deleting a rule removes its backtests.
-- Run with `npm run db:test`. One transaction, rolled back.
--
-- Fixture users: ...0001 admin, ...0002 SOC L2.

begin;

insert into auth.users (id, email) values
  ('e7e7e7e7-0000-4000-8000-000000000001', 'fxbt-admin@arcradar.test'),
  ('e7e7e7e7-0000-4000-8000-000000000002', 'fxbt-l2@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'e7e7e7e7-0000-4000-8000-000000000001';
update public.profiles set role_name = 'soc_l2' where id = 'e7e7e7e7-0000-4000-8000-000000000002';

-- 1. The mode of a rule.
-- ---------------------------------------------------------------------------------------------
do $$
declare m text; blocked boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e7e7e7e7-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.siem_rules (siem, rule_key, name, severity, spec, source)
    values ('splunk', 'fxbt1', 'fxbt rule', 'low', '{}', 'manual');
  select mode into m from public.siem_rules where rule_key = 'fxbt1';
  if m <> 'live' then raise exception 'FAIL a new rule has mode %', m; end if;

  update public.siem_rules set mode = 'test' where rule_key = 'fxbt1';
  select mode into m from public.siem_rules where rule_key = 'fxbt1';
  if m <> 'test' then raise exception 'FAIL the mode did not change (%)', m; end if;

  blocked := false;
  begin
    update public.siem_rules set mode = 'staging' where rule_key = 'fxbt1';
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an unknown mode was accepted'; end if;
  reset role;
  raise notice 'ok - backtests: a rule is live by default, may be test, and nothing else';
end $$;

-- 2. The function is service-role only, and stores/replaces results.
-- ---------------------------------------------------------------------------------------------
do $$
declare who text; r jsonb; n int; hash text := repeat('a', 64);
begin
  foreach who in array array['anon', 'authenticated'] loop
    if has_function_privilege(who, 'public.sync_rule_backtests(text, jsonb)', 'execute') then
      raise exception 'FAIL % may execute sync_rule_backtests', who;
    end if;
  end loop;
  if not has_function_privilege('service_role', 'public.sync_rule_backtests(text, jsonb)', 'execute') then
    raise exception 'FAIL the service role cannot execute sync_rule_backtests';
  end if;

  r := public.sync_rule_backtests('splunk', jsonb_build_array(
    jsonb_build_object('rule_key', 'fxbt1', 'window_hours', 24, 'kind', 'threshold', 'matches', 3, 'scanned', 900,
      'sample', '[{"time": "2026-10-06T10:00:00Z", "count": 6, "group": {"ip": "203.0.113.5"}}]'::jsonb,
      'search_sha256', hash),
    jsonb_build_object('rule_key', 'fxbt1', 'window_hours', 168, 'kind', 'threshold', 'matches', 9, 'search_sha256', hash)));
  if (r ->> 'results')::int <> 2 then raise exception 'FAIL first report said %', r; end if;

  -- a later report for the same rule and window replaces the earlier one
  perform public.sync_rule_backtests('splunk', jsonb_build_array(
    jsonb_build_object('rule_key', 'fxbt1', 'window_hours', 24, 'kind', 'threshold', 'matches', 7, 'search_sha256', repeat('b', 64))));
  select count(*) into n from public.siem_rule_backtests where rule_key = 'fxbt1';
  if n <> 2 then raise exception 'FAIL a new report added a row instead of replacing (% rows)', n; end if;
  select matches into n from public.siem_rule_backtests where rule_key = 'fxbt1' and window_hours = 24;
  if n <> 7 then raise exception 'FAIL the replaced result kept % matches', n; end if;

  -- an error text is cut to 300 characters
  perform public.sync_rule_backtests('splunk', jsonb_build_array(
    jsonb_build_object('rule_key', 'fxbt1', 'window_hours', 24, 'kind', 'events', 'matches', 0,
      'search_sha256', hash, 'error', repeat('e', 500))));
  select char_length(error) into n from public.siem_rule_backtests where rule_key = 'fxbt1' and window_hours = 24;
  if n <> 300 then raise exception 'FAIL an error text was kept at % characters', n; end if;

  raise notice 'ok - backtests: service-role only, stored, replaced per rule and window, error text bounded';
end $$;

-- 3. What it refuses.
-- ---------------------------------------------------------------------------------------------
do $$
declare t text; blocked boolean; hash text := repeat('a', 64);
begin
  foreach t in array array[
    format($q$select public.sync_rule_backtests('qradar', '[]'::jsonb)$q$),
    format($q$select public.sync_rule_backtests('splunk', '{}'::jsonb)$q$),
    format($q$select public.sync_rule_backtests('splunk', '[{"rule_key":"a b","window_hours":24,"kind":"events","matches":1,"search_sha256":"%s"}]'::jsonb)$q$, hash),
    format($q$select public.sync_rule_backtests('splunk', '[{"rule_key":"fxbt1","window_hours":12,"kind":"events","matches":1,"search_sha256":"%s"}]'::jsonb)$q$, hash),
    format($q$select public.sync_rule_backtests('splunk', '[{"rule_key":"fxbt1","window_hours":24,"kind":"magic","matches":1,"search_sha256":"%s"}]'::jsonb)$q$, hash),
    format($q$select public.sync_rule_backtests('splunk', '[{"rule_key":"fxbt1","window_hours":24,"kind":"events","matches":-1,"search_sha256":"%s"}]'::jsonb)$q$, hash),
    $q$select public.sync_rule_backtests('splunk', '[{"rule_key":"fxbt1","window_hours":24,"kind":"events","matches":1,"search_sha256":"nothex"}]'::jsonb)$q$,
    format($q$select public.sync_rule_backtests('splunk', '[{"rule_key":"fxbt1","window_hours":24,"kind":"events","matches":1,"search_sha256":"%s","sample":[1,2,3,4,5,6]}]'::jsonb)$q$, hash),
    format($q$select public.sync_rule_backtests('splunk', '[{"rule_key":"fxbt1","window_hours":24,"kind":"events","matches":1,"search_sha256":"%s","sample":"x"}]'::jsonb)$q$, hash),
    $q$select public.sync_rule_backtests('splunk', (select jsonb_agg('{}'::jsonb) from generate_series(1, 201)))$q$
  ] loop
    blocked := false;
    begin
      execute t;
    exception when others then blocked := true;
    end;
    if not blocked then raise exception 'FAIL a bad backtest report was accepted: %', left(t, 140); end if;
  end loop;
  raise notice 'ok - backtests: unknown SIEM, wrong shapes, bad windows, kinds, counts, hashes and oversized reports are refused';
end $$;

-- 4. Reading: administrators only; nobody writes directly; deleting a rule removes its backtests.
-- ---------------------------------------------------------------------------------------------
do $$
declare visible int; blocked boolean; n int;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e7e7e7e7-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into visible from public.siem_rule_backtests where rule_key = 'fxbt1';
  if visible <> 2 then raise exception 'FAIL an admin saw % backtests', visible; end if;

  blocked := false;
  begin
    insert into public.siem_rule_backtests (siem, rule_key, window_hours, kind, matches, search_sha256)
      values ('splunk', 'fxbt1', 24, 'events', 1, repeat('c', 64));
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an admin inserted a backtest'; end if;
  blocked := false;
  begin
    update public.siem_rule_backtests set matches = 99 where rule_key = 'fxbt1';
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an admin updated a backtest'; end if;
  blocked := false;
  begin
    delete from public.siem_rule_backtests where rule_key = 'fxbt1';
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an admin deleted a backtest'; end if;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'e7e7e7e7-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into visible from public.siem_rule_backtests;
  reset role;
  if visible <> 0 then raise exception 'FAIL a non-admin saw % backtests', visible; end if;

  -- deleting the rule (a draft, as an admin) takes its backtests with it
  perform set_config('request.jwt.claims', json_build_object('sub', 'e7e7e7e7-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  delete from public.siem_rules where rule_key = 'fxbt1';
  reset role;
  select count(*) into n from public.siem_rule_backtests where rule_key = 'fxbt1';
  if n <> 0 then raise exception 'FAIL % backtests survived their rule', n; end if;

  raise notice 'ok - backtests: admins read, nobody writes directly, a deleted rule takes its backtests along';
end $$;

rollback;

do $$ begin raise notice 'SIEM RULE BACKTESTS DATABASE TESTS PASSED'; end $$;
