-- Splunk as a telemetry source: the same ingest_telemetry() path as Wazuh, accepting p_source 'splunk'.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.

begin;

-- 1. The connector exists, and only the service role may call the function.
-- ---------------------------------------------------------------------------------------------
do $$
declare n int; who text;
begin
  select count(*) into n from public.integrations
    where provider = 'splunk' and capabilities = array['telemetry'];
  if n <> 1 then raise exception 'FAIL the splunk integration row is missing (%)', n; end if;

  foreach who in array array['anon', 'authenticated'] loop
    if has_function_privilege(who, 'public.ingest_telemetry(text, jsonb)', 'execute') then
      raise exception 'FAIL % may execute ingest_telemetry', who;
    end if;
  end loop;
  if not has_function_privilege('service_role', 'public.ingest_telemetry(text, jsonb)', 'execute') then
    raise exception 'FAIL the service role cannot execute ingest_telemetry';
  end if;
  raise notice 'ok - splunk: integration row present, ingest_telemetry service-role only';
end $$;

-- 2. A Splunk batch is stored as external events, alerts and assets, idempotently.
-- ---------------------------------------------------------------------------------------------
do $$
declare r jsonb; n int; o public.data_origin; s text; t text[];
begin
  r := public.ingest_telemetry('splunk', $json$[
    {"source_event_id": "arcradar_9001:sid1:aaaa", "occurred_at": "2026-10-06T10:00:00Z",
     "event_type": "splunk_alert", "title": "fxsplunk Brute force", "description": "Splunk rule 9001 (high).",
     "severity": "high", "payload": {"sid": "sid1"},
     "asset": {"external_id": "fxsplunk-host", "name": "fxsplunk-host"},
     "alert": {"create": true, "technique_ids": ["T1110"]},
     "indicators": [{"type": "ipv4", "value": "203.0.113.77"}]}
  ]$json$::jsonb);
  if (r ->> 'events_created')::int <> 1 or (r ->> 'alerts_created')::int <> 1
     or (r ->> 'assets_created')::int <> 1 or (r ->> 'indicators_created')::int <> 1 then
    raise exception 'FAIL first splunk batch: %', r;
  end if;

  select origin, source into o, s from public.alerts where source_event_id = 'arcradar_9001:sid1:aaaa';
  if o <> 'external' or s <> 'splunk' then raise exception 'FAIL splunk alert was % / %', o, s; end if;
  select technique_ids into t from public.alerts where source_event_id = 'arcradar_9001:sid1:aaaa';
  if t <> array['T1110'] then raise exception 'FAIL splunk techniques were %', t; end if;
  select count(*) into n from public.assets where source = 'splunk' and external_id = 'fxsplunk-host';
  if n <> 1 then raise exception 'FAIL the splunk asset was not recorded'; end if;
  select count(*) into n from public.indicators
    where value = '203.0.113.77' and verdict = 'unknown' and source = 'splunk' and origin = 'external';
  if n <> 1 then raise exception 'FAIL the splunk indicator was not recorded as unknown'; end if;

  -- the same record again changes nothing
  r := public.ingest_telemetry('splunk', $json$[
    {"source_event_id": "arcradar_9001:sid1:aaaa", "occurred_at": "2026-10-06T10:00:00Z",
     "event_type": "splunk_alert", "title": "fxsplunk Brute force", "severity": "high", "payload": {},
     "alert": {"create": true}}
  ]$json$::jsonb);
  if (r ->> 'duplicates')::int <> 1 or (r ->> 'events_created')::int <> 0 then
    raise exception 'FAIL a repeated splunk record was not a duplicate: %', r;
  end if;

  -- the same id from another source is a different record
  r := public.ingest_telemetry('wazuh', $json$[
    {"source_event_id": "arcradar_9001:sid1:aaaa", "occurred_at": "2026-10-06T10:00:00Z",
     "event_type": "x", "title": "fxsplunk same id, other source", "severity": "low", "payload": {}}
  ]$json$::jsonb);
  if (r ->> 'events_created')::int <> 1 then
    raise exception 'FAIL the same id under another source was treated as a duplicate: %', r;
  end if;

  raise notice 'ok - splunk: stored as external event, alert, asset and unknown indicator; idempotent per source';
end $$;

-- 3. An unknown source is still refused.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean;
begin
  blocked := false;
  begin
    perform public.ingest_telemetry('qradar', '[]'::jsonb);
  exception when invalid_parameter_value then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an unknown telemetry source was accepted'; end if;
  raise notice 'ok - splunk: unknown sources are still refused';
end $$;

rollback;

do $$ begin raise notice 'SPLUNK TELEMETRY DATABASE TESTS PASSED'; end $$;
