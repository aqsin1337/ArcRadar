-- Telemetry ingestion: assets, ingest_telemetry(), idempotency, provenance, source health, alert search.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer, ...0005 inactive analyst
-- The batch used throughout (source wazuh):
--   mgr:1001.1  high    asset 001 FXWIN10-LAB   alert + techniques [T1110]  indicators: 999.1.1.1 (refused), 203.0.113.201, a sha256
--   mgr:1001.2  info    asset 001               event only (no alert, so no indicators are created)
--   mgr:1001.3  medium  asset 002 FXSRV-02      alert  indicators: fx-local.example (already tracked as local)

begin;

insert into auth.users (id, email) values
  ('ffffffff-0000-4000-8000-000000000001', 'tele-admin@arcradar.test'),
  ('ffffffff-0000-4000-8000-000000000002', 'tele-analyst@arcradar.test'),
  ('ffffffff-0000-4000-8000-000000000003', 'tele-viewer@arcradar.test'),
  ('ffffffff-0000-4000-8000-000000000005', 'tele-inactive@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'ffffffff-0000-4000-8000-000000000001';
update public.profiles set role_name = 'soc_l2' where id in
  ('ffffffff-0000-4000-8000-000000000002', 'ffffffff-0000-4000-8000-000000000005');
update public.profiles set is_active = false where id = 'ffffffff-0000-4000-8000-000000000005';

-- An indicator somebody already tracks (local, old): ingestion must link to it but never change it.
insert into public.indicators (id, type, value, severity, verdict, description, first_seen, last_seen) values
  ('ffffffff-1111-4000-8000-000000000001', 'domain', 'fx-local.example', 'low', 'benign', 'tracked by hand',
   '2020-01-01T00:00:00Z', '2020-01-02T00:00:00Z');

create temp table batch (records jsonb);
insert into batch values ($json$[
  {"source_event_id": "mgr:1001.1", "occurred_at": "2026-09-26T10:00:00Z", "event_type": "authentication_failed",
   "title": "fxtele Multiple Windows logon failures", "description": "Rule 60204, level 10.", "severity": "high",
   "payload": {"rule": {"id": "60204", "level": 10}, "marker": "fxpayload"},
   "asset": {"external_id": "001", "name": "FXWIN10-LAB", "ip_address": "192.168.56.101", "os": "Windows"},
   "alert": {"create": true, "technique_ids": ["T1110"]},
   "indicators": [{"type": "ipv4", "value": "999.1.1.1"}, {"type": "ipv4", "value": "203.0.113.201"},
                  {"type": "sha256", "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]},
  {"source_event_id": "mgr:1001.2", "occurred_at": "2026-09-26T10:01:00Z", "event_type": "sysmon_event_1",
   "title": "fxtele Process created", "severity": "info", "payload": {},
   "asset": {"external_id": "001", "name": "FXWIN10-LAB"},
   "alert": {"create": false},
   "indicators": [{"type": "domain", "value": "not-created.example"}]},
  {"source_event_id": "mgr:1001.3", "occurred_at": "2026-09-26T10:02:00Z", "event_type": "file_integrity",
   "title": "fxtele Integrity checksum changed", "severity": "medium", "payload": {},
   "asset": {"external_id": "002", "name": "FXSRV-02"},
   "alert": {"create": true},
   "indicators": [{"type": "domain", "value": "fx-local.example"}]}
]$json$::jsonb);
grant select on batch to authenticated, service_role;

-- 1. who may do what -------------------------------------------------------------------------------
do $$
declare blocked boolean; n int; who text;
begin
  -- Nobody but the service role may call the ingest function.
  foreach who in array array['anon', 'authenticated'] loop
    blocked := false;
    begin
      perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000001', 'role', who)::text, true);
      execute format('set local role %I', who);
      perform public.ingest_telemetry('wazuh', '[]'::jsonb);
    exception when insufficient_privilege then blocked := true;
    end;
    reset role;
    if not blocked then raise exception 'FAIL % could call ingest_telemetry', who; end if;
  end loop;

  set local role service_role;
  perform public.ingest_telemetry('wazuh', '[]'::jsonb);
  reset role;

  -- Assets: readable with events:read, never writable by a client, invisible to inactive users and anon.
  set local role service_role;
  perform public.ingest_telemetry('wazuh', (select records from batch));
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.assets where name = 'FXWIN10-LAB';
  reset role;
  if n <> 1 then raise exception 'FAIL a viewer could not read an asset (saw %)', n; end if;

  foreach who in array array['ffffffff-0000-4000-8000-000000000001', 'ffffffff-0000-4000-8000-000000000002', 'ffffffff-0000-4000-8000-000000000003'] loop
    perform set_config('request.jwt.claims', json_build_object('sub', who, 'role', 'authenticated')::text, true);
    set local role authenticated;
    blocked := false;
    begin
      insert into public.assets (source, external_id, name) values ('wazuh', 'forged', 'forged asset');
    exception when insufficient_privilege then blocked := true;
    end;
    if not blocked then raise exception 'FAIL user % could insert an asset', who; end if;
    blocked := false;
    begin
      update public.assets set name = 'renamed' where name = 'FXWIN10-LAB';
      get diagnostics n = row_count;
    exception when insufficient_privilege then blocked := true;
    end;
    if not blocked then raise exception 'FAIL user % could update an asset', who; end if;
    blocked := false;
    begin
      delete from public.assets where name = 'FXWIN10-LAB';
    exception when insufficient_privilege then blocked := true;
    end;
    if not blocked then raise exception 'FAIL user % could delete an asset', who; end if;
    reset role;
  end loop;

  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000005', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.assets;
  reset role;
  if n <> 0 then raise exception 'FAIL an inactive user saw % assets', n; end if;

  set local role anon;
  blocked := false;
  begin
    select count(*) into n from public.assets;
  exception when insufficient_privilege then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL anon could read assets'; end if;

  raise notice 'ok - ingest_telemetry is service-role only; assets are read-only for clients, hidden from inactive users and anon';
end $$;

-- 2. what one batch creates --------------------------------------------------------------------------
do $$
declare
  n int; r record; s jsonb;
begin
  -- (the batch was ingested in section 1; the whole database is rolled back at the end)
  select count(*) into n from public.events where source = 'wazuh' and title like 'fxtele%';
  if n <> 3 then raise exception 'FAIL expected 3 events, found %', n; end if;

  select * into r from public.events where source_event_id = 'mgr:1001.1' and source = 'wazuh';
  if r.origin <> 'external' or r.created_by is not null or r.severity <> 'high'
     or r.occurred_at <> '2026-09-26T10:00:00Z' or r.payload ->> 'marker' <> 'fxpayload' or r.event_type <> 'authentication_failed'
  then raise exception 'FAIL the first event was recorded wrongly: %', to_jsonb(r); end if;

  select count(*) into n from public.alerts where source = 'wazuh' and title like 'fxtele%';
  if n <> 2 then raise exception 'FAIL expected 2 alerts (the info event is not one), found %', n; end if;

  select * into r from public.alerts where source_event_id = 'mgr:1001.1' and source = 'wazuh';
  if r.origin <> 'external' or r.status <> 'new' or r.assigned_to is not null or r.created_by is not null
     or r.technique_ids <> array['T1110'] or r.event_id is null or r.asset_id is null or r.resolved_at is not null
     or r.created_at <> '2026-09-26T10:00:00Z'
  then raise exception 'FAIL the first alert was recorded wrongly: %', to_jsonb(r); end if;

  -- The alert points at the first indicator the database accepted: 999.1.1.1 was refused and skipped.
  select value into s from (select to_jsonb(i.value) as value from public.indicators i where i.id = r.indicator_id) x;
  if s is distinct from to_jsonb('203.0.113.201'::text) then raise exception 'FAIL the alert indicator was %', s; end if;

  select * into r from public.indicators where type = 'ipv4' and value = '203.0.113.201';
  if r.origin <> 'external' or r.verdict <> 'unknown' or r.source <> 'wazuh' or r.confidence <> 30 or r.severity <> 'high'
     or r.created_by is not null or r.first_seen <> '2026-09-26T10:00:00Z'
  then raise exception 'FAIL the ingested indicator was recorded wrongly: %', to_jsonb(r); end if;

  select count(*) into n from public.indicators where value in ('999.1.1.1', 'not-created.example');
  if n <> 0 then raise exception 'FAIL an invalid value, or a value of an alert-less event, became an indicator'; end if;
  select count(*) into n from public.indicators where type = 'sha256' and value like 'aaaa%' and origin = 'external';
  if n <> 1 then raise exception 'FAIL the hash indicator is missing'; end if;

  -- The tracked local indicator is linked, never changed.
  select * into r from public.indicators where id = 'ffffffff-1111-4000-8000-000000000001';
  if r.origin <> 'local' or r.verdict <> 'benign' or r.severity <> 'low' or r.last_seen <> '2020-01-02T00:00:00Z'
     or r.description <> 'tracked by hand'
  then raise exception 'FAIL ingestion changed a local indicator: %', to_jsonb(r); end if;
  select count(*) into n from public.alerts
    where source_event_id = 'mgr:1001.3' and source = 'wazuh' and indicator_id = 'ffffffff-1111-4000-8000-000000000001';
  if n <> 1 then raise exception 'FAIL the alert was not linked to the indicator that was already tracked'; end if;

  select count(*) into n from public.assets where source = 'wazuh' and external_id in ('001', '002');
  if n <> 2 then raise exception 'FAIL expected 2 assets, found %', n; end if;
  select * into r from public.assets where source = 'wazuh' and external_id = '001';
  if r.name <> 'FXWIN10-LAB' or r.ip_address <> '192.168.56.101' or r.os <> 'Windows' or r.origin <> 'external'
     or r.first_seen <> '2026-09-26T10:00:00Z' or r.last_seen <> '2026-09-26T10:01:00Z'
  then raise exception 'FAIL the asset was recorded wrongly: %', to_jsonb(r); end if;

  -- (now() is the start of this transaction, so an exact match means this ingestion set it, not the seed.)
  select count(*) into n from public.integrations where provider = 'wazuh' and last_sync_at = now();
  if n <> 1 then raise exception 'FAIL the connector''s last_sync_at was not set by the ingestion'; end if;

  raise notice 'ok - a batch records external events, alerts, assets and indicators (unknown verdict), skips a refused value, links but never changes a tracked indicator';
end $$;

-- 3. return value, idempotency, atomicity -------------------------------------------------------------
do $$
declare
  first_run jsonb; second_run jsonb; n_before int; n_after int; blocked boolean; res jsonb;
begin
  select count(*) into n_before from public.events;
  -- The second identical batch changes nothing.
  set local role service_role;
  second_run := public.ingest_telemetry('wazuh', (select records from batch));
  reset role;
  select count(*) into n_after from public.events;
  if n_before <> n_after then raise exception 'FAIL a repeated batch created events'; end if;
  if second_run <> '{"events_created": 0, "alerts_created": 0, "duplicates": 3, "assets_created": 0, "indicators_created": 0}'::jsonb
  then raise exception 'FAIL the summary of a repeated batch was %', second_run; end if;
  if (select count(*) from public.alerts where source = 'wazuh' and title like 'fxtele%') <> 2 then
    raise exception 'FAIL a repeated batch created alerts';
  end if;

  -- A new record: counted; and an indicator seen again by the sensor gets a later last_seen, a tracked one does not.
  set local role service_role;
  res := public.ingest_telemetry('wazuh', $json$[
    {"source_event_id": "mgr:1002.1", "occurred_at": "2026-09-27T08:00:00Z", "event_type": "authentication_failed",
     "title": "fxtele Again", "severity": "high", "payload": {},
     "asset": {"external_id": "001", "name": "FXWIN10-LAB-RENAMED"}, "alert": {"create": true},
     "indicators": [{"type": "ipv4", "value": "203.0.113.201"}, {"type": "domain", "value": "fx-local.example"}]}
  ]$json$::jsonb);
  reset role;
  if res <> '{"events_created": 1, "alerts_created": 1, "duplicates": 0, "assets_created": 0, "indicators_created": 0}'::jsonb
  then raise exception 'FAIL the summary of a new record was %', res; end if;
  if (select last_seen from public.indicators where type = 'ipv4' and value = '203.0.113.201') <> '2026-09-27T08:00:00Z' then
    raise exception 'FAIL a seen-again external indicator did not get a later last_seen';
  end if;
  if (select last_seen from public.indicators where id = 'ffffffff-1111-4000-8000-000000000001') <> '2020-01-02T00:00:00Z' then
    raise exception 'FAIL a tracked indicator was touched';
  end if;
  if (select name || '|' || last_seen::text from public.assets where source = 'wazuh' and external_id = '001')
     is distinct from 'FXWIN10-LAB-RENAMED|2026-09-27 08:00:00+00' then
    raise exception 'FAIL the asset was not updated (name and last_seen): %', (select name || '|' || last_seen::text from public.assets where external_id = '001' and source = 'wazuh');
  end if;

  -- An older record must not move an asset's last_seen backwards.
  set local role service_role;
  perform public.ingest_telemetry('wazuh', $json$[
    {"source_event_id": "mgr:0999.1", "occurred_at": "2026-01-01T00:00:00Z", "event_type": "x", "title": "fxtele Old", "severity": "info",
     "payload": {}, "asset": {"external_id": "001", "name": "FXWIN10-LAB-RENAMED"}, "alert": {"create": false}}
  ]$json$::jsonb);
  reset role;
  if (select last_seen from public.assets where source = 'wazuh' and external_id = '001') <> '2026-09-27T08:00:00Z' then
    raise exception 'FAIL an older event moved last_seen backwards';
  end if;
  if (select first_seen from public.assets where source = 'wazuh' and external_id = '001') <> '2026-01-01T00:00:00Z' then
    raise exception 'FAIL an older event did not extend first_seen';
  end if;

  -- The function skips a known event before it reaches the alert, so the unique indexes are the
  -- last line of defence: an insert that bypasses the function must be refused by them.
  blocked := false;
  begin
    insert into public.events (event_type, title, severity, source, source_event_id, origin)
    values ('x', 'fxtele duplicate event', 'info', 'wazuh', 'mgr:1001.1', 'external');
  exception when unique_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a second external event with the same source id was stored'; end if;
  blocked := false;
  begin
    insert into public.alerts (title, severity, source, source_event_id, status, origin)
    values ('fxtele duplicate alert', 'info', 'wazuh', 'mgr:1001.1', 'new', 'external');
  exception when unique_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a second external alert with the same source id was stored'; end if;

  -- A batch is all or nothing: a bad record in the middle rolls back the good one before it.
  select count(*) into n_before from public.events where source = 'wazuh';
  blocked := false;
  begin
    set local role service_role;
    perform public.ingest_telemetry('wazuh', $json$[
      {"source_event_id": "mgr:2000.1", "occurred_at": "2026-09-28T08:00:00Z", "event_type": "x", "title": "fxtele Good", "severity": "low", "payload": {}},
      {"source_event_id": "mgr:2000.2", "occurred_at": "2026-09-28T08:00:00Z", "event_type": "x", "title": "fxtele Bad", "severity": "urgent", "payload": {}}
    ]$json$::jsonb);
  exception when invalid_text_representation then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL a bad severity was accepted'; end if;
  select count(*) into n_after from public.events where source = 'wazuh';
  if n_before <> n_after then raise exception 'FAIL a failed batch left records behind'; end if;

  -- Bad technique ids and unknown sources or shapes are refused.
  blocked := false;
  begin
    set local role service_role;
    perform public.ingest_telemetry('wazuh', $json$[
      {"source_event_id": "mgr:3000.1", "occurred_at": "2026-09-28T08:00:00Z", "event_type": "x", "title": "fxtele Tech", "severity": "low",
       "payload": {}, "alert": {"create": true, "technique_ids": ["not-a-technique"]}}
    ]$json$::jsonb);
  exception when check_violation then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL a malformed technique id was accepted'; end if;

  foreach res in array array['"not an array"'::jsonb, '{}'::jsonb] loop
    blocked := false;
    begin
      set local role service_role;
      perform public.ingest_telemetry('wazuh', res);
    exception when invalid_parameter_value then blocked := true;
    end;
    reset role;
    if not blocked then raise exception 'FAIL records of the wrong shape were accepted: %', res; end if;
  end loop;

  blocked := false;
  begin
    set local role service_role;
    perform public.ingest_telemetry('somewhere-else', '[]'::jsonb);
  exception when invalid_parameter_value then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL an unknown source was accepted'; end if;

  blocked := false;
  begin
    set local role service_role;
    perform public.ingest_telemetry('wazuh', (select jsonb_agg('{}'::jsonb) from generate_series(1, 501)));
  exception when invalid_parameter_value then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL a batch of 501 records was accepted'; end if;

  raise notice 'ok - repeated batches change nothing, later sightings extend an external indicator and an asset, a bad batch is all-or-nothing, bad input is refused';
end $$;

-- 4. nobody can squat on an ingestion id, or forge sensor data ---------------------------------------------
do $$
declare blocked boolean; res jsonb; n int;
begin
  -- An analyst records their own alert claiming the sensor's name and id: allowed (it is local) ...
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.alerts (title, source, source_event_id) values ('fxtele squatter', 'wazuh', 'mgr:4000.1');
  -- ... but it cannot claim to be external, and cannot forge a technique list that breaks the format.
  blocked := false;
  begin
    insert into public.alerts (title, source, origin) values ('fxtele forged external', 'wazuh', 'external');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an analyst created an external alert'; end if;
  blocked := false;
  begin
    insert into public.alerts (title, technique_ids) values ('fxtele bad techniques', array['bogus']);
  exception when check_violation then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL a malformed technique list was accepted from a client'; end if;

  -- ... and the real record with the same id is still ingested.
  set local role service_role;
  res := public.ingest_telemetry('wazuh', $json$[
    {"source_event_id": "mgr:4000.1", "occurred_at": "2026-09-28T09:00:00Z", "event_type": "x", "title": "fxtele Real", "severity": "medium",
     "payload": {}, "alert": {"create": true}}
  ]$json$::jsonb);
  reset role;
  if (res ->> 'alerts_created')::int <> 1 then raise exception 'FAIL a local squatter blocked the real alert: %', res; end if;
  select count(*) into n from public.alerts where source_event_id = 'mgr:4000.1' and source = 'wazuh';
  if n <> 2 then raise exception 'FAIL expected the local and the external alert, found %', n; end if;

  raise notice 'ok - a client cannot create external alerts or squat on an ingestion id (the key only covers external rows)';
end $$;

-- 5. source health and alert search --------------------------------------------------------------------
do $$
declare r record; n int; blocked boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select * into r from public.telemetry_source_health() where source = 'wazuh' and origin = 'external';
  reset role;
  if r.source is null then raise exception 'FAIL the wazuh source is missing from the health list'; end if;
  if r.events_total <> 6 or r.alerts_total <> 4 or r.assets_total <> 2
     or r.last_event_at <> '2026-09-28T09:00:00Z' or r.last_received_at is null or r.events_24h <> 6
  then raise exception 'FAIL the health row was %', to_jsonb(r); end if;

  -- The demo feeds are listed too, labelled by their origin.
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.telemetry_source_health() where origin = 'demo';
  reset role;
  if n < 3 then raise exception 'FAIL the demo sources were not listed (found %)', n; end if;

  -- An inactive user sees nothing; anon may not call it.
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000005', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.telemetry_source_health();
  reset role;
  if n <> 0 then raise exception 'FAIL an inactive user saw % health rows', n; end if;
  blocked := false;
  begin
    set local role anon;
    perform * from public.telemetry_source_health();
  exception when insufficient_privilege then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL anon could call telemetry_source_health'; end if;
  -- (anon has no access to the tables either, so the call above fails anyway: check the grant itself.)
  if has_function_privilege('anon', 'public.telemetry_source_health()', 'execute') then
    raise exception 'FAIL anon holds execute on telemetry_source_health';
  end if;
  if not has_function_privilege('authenticated', 'public.telemetry_source_health()', 'execute') then
    raise exception 'FAIL signed-in users cannot execute telemetry_source_health';
  end if;

  -- Alerts are found by the name or address of their asset (ANDed with the other words).
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.search_alerts('fxwin10-lab');
  if n <> 2 then raise exception 'FAIL searching by asset name found % (expected the 2 alerts of that machine)', n; end if;
  select count(*) into n from public.search_alerts('192.168.56.101 logon');
  if n <> 1 then raise exception 'FAIL searching by asset address and a title word found %', n; end if;
  select count(*) into n from public.search_alerts('fxwin10-lab nothing-like-this');
  if n <> 0 then raise exception 'FAIL an unmatched extra word still matched'; end if;
  select count(*) into n from public.search_alerts('fxsrv-02');
  if n <> 1 then raise exception 'FAIL the second machine was not found'; end if;
  -- A % or _ typed by the user is a literal character, not a wildcard.
  select count(*) into n from public.search_alerts('fxtele');
  if n < 2 then raise exception 'FAIL the fxtele alerts were not found (%)', n; end if;
  select count(*) into n from public.search_alerts('fxtele%');
  if n <> 0 then raise exception 'FAIL a % in an alert search acted as a wildcard (found %)', '%', n; end if;
  reset role;

  raise notice 'ok - source health (counts, last event, demo feeds, access) and alert search by asset';
end $$;

rollback;

do $$ begin raise notice 'TELEMETRY DATABASE TESTS PASSED'; end $$;
