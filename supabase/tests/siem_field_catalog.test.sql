-- SIEM field catalog: who may read it, that nobody but sync_field_catalog() writes it, and what that
-- function accepts. Run with `npm run db:test`. One transaction, rolled back.
--
-- Fixture users: ...0001 admin, ...0002 SOC L2, ...0003 viewer.

begin;

insert into auth.users (id, email) values
  ('e6e6e6e6-0000-4000-8000-000000000001', 'fxfc-admin@arcradar.test'),
  ('e6e6e6e6-0000-4000-8000-000000000002', 'fxfc-l2@arcradar.test'),
  ('e6e6e6e6-0000-4000-8000-000000000003', 'fxfc-viewer@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'e6e6e6e6-0000-4000-8000-000000000001';
update public.profiles set role_name = 'soc_l2' where id = 'e6e6e6e6-0000-4000-8000-000000000002';

-- 1. The function is service-role only.
-- ---------------------------------------------------------------------------------------------
do $$
declare who text;
begin
  foreach who in array array['anon', 'authenticated'] loop
    if has_function_privilege(who, 'public.sync_field_catalog(text, jsonb)', 'execute') then
      raise exception 'FAIL % may execute sync_field_catalog', who;
    end if;
  end loop;
  if not has_function_privilege('service_role', 'public.sync_field_catalog(text, jsonb)', 'execute') then
    raise exception 'FAIL the service role cannot execute sync_field_catalog';
  end if;
  raise notice 'ok - field catalog: sync_field_catalog is service-role only';
end $$;

-- 2. It stores, replaces, filters and trims.
-- ---------------------------------------------------------------------------------------------
do $$
declare r jsonb; n int; v text[]; cnt int;
begin
  r := public.sync_field_catalog('splunk', $json$[
    {"index": "fxmain", "sourcetype": "FX:Security", "window_hours": 24, "events_sampled": 100,
     "fields": [
       {"name": "EventCode", "count": 100, "distinct": 5, "values": ["4624", "4625", "4672", "4634", "4648", "4720", "9999"]},
       {"name": "Source_Network_Address", "count": 40, "distinct": 3, "values": ["203.0.113.5"]},
       {"name": "bad field name", "count": 1},
       {"name": "x|delete", "count": 1},
       {"name": "Overcount", "count": 500, "values": []},
       {"name": "Long", "count": 1, "values": ["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]}
     ]}
  ]$json$::jsonb);
  -- 6 offered, two with illegal names skipped: 4 stored
  if (r ->> 'sources')::int <> 1 or (r ->> 'fields')::int <> 4 then
    raise exception 'FAIL first sync reported %', r;
  end if;

  select sample_values into v from public.siem_field_catalog where index_name = 'fxmain' and field = 'EventCode';
  if cardinality(v) <> 5 or v[1] <> '4624' then raise exception 'FAIL example values were %', v; end if;

  select events_with_field into n from public.siem_field_catalog where index_name = 'fxmain' and field = 'Overcount';
  if n <> 100 then raise exception 'FAIL a count above the sample was kept as %', n; end if;

  select public.max_text_len(sample_values) into n from public.siem_field_catalog where index_name = 'fxmain' and field = 'Long';
  if n <> 100 then raise exception 'FAIL a 150-character example value was kept at % characters', n; end if;

  select count(*) into cnt from public.siem_field_catalog
    where index_name = 'fxmain' and field in ('bad field name', 'x|delete');
  if cnt <> 0 then raise exception 'FAIL a field with an illegal name was stored'; end if;

  -- a second report for the same source replaces the first completely
  r := public.sync_field_catalog('splunk', $json$[
    {"index": "fxmain", "sourcetype": "FX:Security", "window_hours": 24, "events_sampled": 50,
     "fields": [ {"name": "EventCode", "count": 50} ]}
  ]$json$::jsonb);
  select count(*) into cnt from public.siem_field_catalog where index_name = 'fxmain';
  if cnt <> 1 then raise exception 'FAIL a new report did not replace the old one (% rows)', cnt; end if;

  -- another source is untouched by a report for this one
  perform public.sync_field_catalog('splunk', $json$[
    {"index": "fxother", "sourcetype": "FX:Other", "window_hours": 24, "events_sampled": 10,
     "fields": [ {"name": "user", "count": 10} ]}
  ]$json$::jsonb);
  perform public.sync_field_catalog('splunk', $json$[
    {"index": "fxmain", "sourcetype": "FX:Security", "window_hours": 24, "events_sampled": 50, "fields": []}
  ]$json$::jsonb);
  select count(*) into cnt from public.siem_field_catalog where index_name = 'fxother';
  if cnt <> 1 then raise exception 'FAIL a report for one source touched another'; end if;

  raise notice 'ok - field catalog: stored, replaced per source, bad names skipped, values trimmed, counts capped';
end $$;

-- 3. What it refuses.
-- ---------------------------------------------------------------------------------------------
do $$
declare t text; blocked boolean;
begin
  foreach t in array array[
    $q$select public.sync_field_catalog('qradar', '[]'::jsonb)$q$,
    $q$select public.sync_field_catalog('splunk', '{}'::jsonb)$q$,
    $q$select public.sync_field_catalog('splunk', '[{"index":"Bad Index","sourcetype":"x","window_hours":24,"events_sampled":1,"fields":[{"name":"a","count":1}]}]'::jsonb)$q$,
    $q$select public.sync_field_catalog('splunk', '[{"index":"fxmain","sourcetype":"x y","window_hours":24,"events_sampled":1,"fields":[{"name":"a","count":1}]}]'::jsonb)$q$,
    $q$select public.sync_field_catalog('splunk', '[{"index":"fxmain","sourcetype":"x","window_hours":0,"events_sampled":1,"fields":[{"name":"a","count":1}]}]'::jsonb)$q$,
    $q$select public.sync_field_catalog('splunk', '[{"index":"fxmain","sourcetype":"x","window_hours":24,"events_sampled":0,"fields":[{"name":"a","count":0}]}]'::jsonb)$q$,
    $q$select public.sync_field_catalog('splunk', '[{"index":"fxmain","sourcetype":"x","window_hours":24,"events_sampled":1,"fields":"nope"}]'::jsonb)$q$,
    $q$select public.sync_field_catalog('splunk', (select jsonb_agg(jsonb_build_object('index','fxi','sourcetype','s'||g,'window_hours',24,'events_sampled',1,'fields','[]'::jsonb)) from generate_series(1, 51) g))$q$
  ] loop
    blocked := false;
    begin
      execute t;
    exception when others then blocked := true;
    end;
    if not blocked then raise exception 'FAIL a bad catalog report was accepted: %', left(t, 120); end if;
  end loop;
  raise notice 'ok - field catalog: unknown SIEM, wrong shapes, bad names and oversized reports are refused';
end $$;

-- 4. Reading: administrators only; nobody writes directly.
-- ---------------------------------------------------------------------------------------------
do $$
declare visible int; blocked boolean; who text;
begin
  perform public.sync_field_catalog('splunk', $json$[
    {"index": "fxmain", "sourcetype": "FX:Security", "window_hours": 24, "events_sampled": 10,
     "fields": [ {"name": "EventCode", "count": 10, "values": ["4625"]} ]}
  ]$json$::jsonb);

  perform set_config('request.jwt.claims', json_build_object('sub', 'e6e6e6e6-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into visible from public.siem_field_catalog where index_name = 'fxmain';
  if visible <> 1 then raise exception 'FAIL an admin saw % catalog rows', visible; end if;

  -- not even an admin can write a row directly
  blocked := false;
  begin
    insert into public.siem_field_catalog (siem, index_name, sourcetype, field, events_with_field, events_sampled, window_hours)
      values ('splunk', 'fxmain', 'FX:Security', 'Forged', 1, 1, 24);
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an admin inserted a catalog row'; end if;
  blocked := false;
  begin
    update public.siem_field_catalog set field = 'Renamed' where index_name = 'fxmain';
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an admin updated a catalog row'; end if;
  blocked := false;
  begin
    delete from public.siem_field_catalog where index_name = 'fxmain';
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an admin deleted a catalog row'; end if;
  reset role;

  foreach who in array array['e6e6e6e6-0000-4000-8000-000000000002', 'e6e6e6e6-0000-4000-8000-000000000003'] loop
    perform set_config('request.jwt.claims', json_build_object('sub', who, 'role', 'authenticated')::text, true);
    set local role authenticated;
    select count(*) into visible from public.siem_field_catalog;
    reset role;
    if visible <> 0 then raise exception 'FAIL a non-admin saw % catalog rows', visible; end if;
  end loop;

  set local role anon;
  blocked := false;
  begin
    perform count(*) from public.siem_field_catalog;
  exception when insufficient_privilege then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL anon could read the catalog'; end if;

  raise notice 'ok - field catalog: readable by administrators only, never writable by a client';
end $$;

rollback;

do $$ begin raise notice 'SIEM FIELD CATALOG DATABASE TESTS PASSED'; end $$;
