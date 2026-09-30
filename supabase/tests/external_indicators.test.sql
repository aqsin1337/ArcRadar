-- record_external_indicators(): who may call it, provenance, what it may and may not overwrite,
-- verdict only moves up, bad values are skipped, idempotency.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.

begin;

insert into auth.users (id, email) values
  ('ffffffff-0000-4000-8000-0000000000e1', 'ext-admin@arcradar.test');
update public.profiles set role_name = 'admin' where id = 'ffffffff-0000-4000-8000-0000000000e1';

-- Somebody's own judgment: local, and one that is demo.
insert into public.indicators (type, value, severity, verdict, confidence, description, origin, first_seen, last_seen) values
  ('domain', 'fxext-local.example', 'low', 'benign', 90, 'checked by hand', 'local', '2020-01-01T00:00:00Z', '2020-01-02T00:00:00Z'),
  ('ipv4', '203.0.113.150', 'low', 'unknown', 10, 'demo row', 'demo', '2020-01-01T00:00:00Z', '2020-01-02T00:00:00Z');

-- 1. who may call it -------------------------------------------------------------------------------
do $$
declare blocked boolean; who text;
begin
  foreach who in array array['anon', 'authenticated'] loop
    blocked := false;
    begin
      perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-0000000000e1', 'role', who)::text, true);
      execute format('set local role %I', who);
      perform public.record_external_indicators('urlhaus', '[]'::jsonb);
    exception when insufficient_privilege then blocked := true;
    end;
    reset role;
    if not blocked then raise exception 'FAIL % could call record_external_indicators', who; end if;
  end loop;

  if has_function_privilege('authenticated', 'public.verdict_rank(public.verdict)', 'execute')
     or has_function_privilege('anon', 'public.verdict_rank(public.verdict)', 'execute') then
    raise exception 'FAIL verdict_rank is callable by a client role';
  end if;

  set local role service_role;
  perform public.record_external_indicators('urlhaus', '[]'::jsonb);
  reset role;
end $$;

-- 2. the source and the batch are validated --------------------------------------------------------
do $$
declare refused boolean; bad text;
begin
  set local role service_role;
  foreach bad in array array['', 'Has Space', 'UPPER', repeat('a', 61)] loop
    refused := false;
    begin
      perform public.record_external_indicators(bad, '[]'::jsonb);
    exception when sqlstate '22023' then refused := true;
    end;
    if not refused then raise exception 'FAIL source "%" was accepted', bad; end if;
  end loop;

  refused := false;
  begin
    perform public.record_external_indicators('urlhaus', '{"not": "an array"}'::jsonb);
  exception when sqlstate '22023' then refused := true;
  end;
  if not refused then raise exception 'FAIL a non-array batch was accepted'; end if;

  refused := false;
  begin
    perform public.record_external_indicators('urlhaus',
      (select jsonb_agg(jsonb_build_object('type', 'domain', 'value', 'a' || g || '.example',
        'verdict', 'unknown', 'severity', 'low', 'confidence', 1)) from generate_series(1, 5001) g));
  exception when sqlstate '22023' then refused := true;
  end;
  if not refused then raise exception 'FAIL a batch over the limit was accepted'; end if;
  reset role;
end $$;

-- 3. new records are external, whatever is asked; bad values are skipped ---------------------------
create temp table result1 (r jsonb);
grant all on result1 to service_role;
do $$
begin
  set local role service_role;
  insert into result1 select public.record_external_indicators('urlhaus', $json$[
    {"type": "domain", "value": "fxext-new.example", "verdict": "malicious", "severity": "high",
     "confidence": 85, "description": "listed by the feed", "seen_at": "2026-09-01T00:00:00Z"},
    {"type": "ipv4", "value": "999.1.1.1", "verdict": "malicious", "severity": "high", "confidence": 50},
    {"type": "ipv4", "value": "203.0.113.151", "verdict": "not-a-verdict", "severity": "high", "confidence": 50},
    {"type": "sha256", "value": "abc", "verdict": "unknown", "severity": "low", "confidence": 50},
    {"type": "domain", "value": "fxext-clamped.example", "verdict": "suspicious", "severity": "medium", "confidence": 500}
  ]$json$::jsonb);
  reset role;
end $$;

do $$
declare r jsonb; ind public.indicators;
begin
  select result1.r into r from result1;
  if r <> '{"created": 2, "updated": 0, "untouched": 0, "skipped": 3}'::jsonb then
    raise exception 'FAIL first batch summary is %', r;
  end if;

  select * into ind from public.indicators where value = 'fxext-new.example';
  if ind.origin <> 'external' or ind.created_by is not null or ind.source <> 'urlhaus'
     or ind.verdict <> 'malicious' or ind.severity <> 'high' or ind.confidence <> 85
     or ind.first_seen <> '2026-09-01T00:00:00Z' then
    raise exception 'FAIL new record was stored as %', to_jsonb(ind);
  end if;
  -- a feed entry has not been researched by a lookup
  if ind.researched_at is not null then raise exception 'FAIL a feed entry counts as researched'; end if;
  if exists (select 1 from public.indicators where value in ('999.1.1.1', '203.0.113.151', 'abc')) then
    raise exception 'FAIL a value the database refuses was stored';
  end if;
  select * into ind from public.indicators where value = 'fxext-clamped.example';
  if ind.confidence <> 100 then raise exception 'FAIL confidence was not clamped (%)', ind.confidence; end if;
end $$;

-- 4. local and demo indicators are never touched ---------------------------------------------------
create temp table result2 (r jsonb);
grant all on result2 to service_role;
do $$
begin
  set local role service_role;
  insert into result2 select public.record_external_indicators('lookup:virustotal', $json$[
    {"type": "domain", "value": "FXEXT-LOCAL.example", "verdict": "malicious", "severity": "critical",
     "confidence": 99, "description": "machine says so", "seen_at": "2026-09-20T00:00:00Z"},
    {"type": "ipv4", "value": "203.0.113.150", "verdict": "malicious", "severity": "critical", "confidence": 99}
  ]$json$::jsonb);
  reset role;
end $$;

do $$
declare r jsonb; ind public.indicators;
begin
  select result2.r into r from result2;
  if r <> '{"created": 0, "updated": 0, "untouched": 2, "skipped": 0}'::jsonb then
    raise exception 'FAIL local/demo batch summary is %', r;
  end if;
  select * into ind from public.indicators where value = 'fxext-local.example';
  if ind.origin <> 'local' or ind.verdict <> 'benign' or ind.severity <> 'low' or ind.confidence <> 90
     or ind.description <> 'checked by hand' or ind.last_seen <> '2020-01-02T00:00:00Z' or ind.source <> 'manual'
     or ind.researched_at is not null then
    raise exception 'FAIL a local indicator was changed: %', to_jsonb(ind);
  end if;
  select * into ind from public.indicators where value = '203.0.113.150';
  if ind.origin <> 'demo' or ind.verdict <> 'unknown' or ind.confidence <> 10 then
    raise exception 'FAIL a demo indicator was changed: %', to_jsonb(ind);
  end if;
end $$;

-- 5. an external indicator is refreshed; the verdict only moves up ---------------------------------
create temp table result3 (r jsonb);
grant all on result3 to service_role;
do $$
begin
  set local role service_role;
  -- A later lookup that found nothing must not erase the feed's malicious verdict...
  insert into result3 select public.record_external_indicators('lookup:otx', $json$[
    {"type": "domain", "value": "fxext-new.example", "verdict": "unknown", "severity": "low",
     "confidence": 30, "description": "nothing found", "seen_at": "2026-09-25T00:00:00Z"}
  ]$json$::jsonb);
  reset role;
end $$;

do $$
declare r jsonb; ind public.indicators;
begin
  select result3.r into r from result3;
  if r <> '{"created": 0, "updated": 1, "untouched": 0, "skipped": 0}'::jsonb then
    raise exception 'FAIL refresh summary is %', r;
  end if;
  select * into ind from public.indicators where value = 'fxext-new.example';
  if ind.verdict <> 'malicious' or ind.severity <> 'high' or ind.confidence <> 85
     or ind.source <> 'urlhaus' or ind.description <> 'listed by the feed' then
    raise exception 'FAIL a weaker answer overwrote the verdict: %', to_jsonb(ind);
  end if;
  if ind.last_seen <> '2026-09-25T00:00:00Z' or ind.first_seen <> '2026-09-01T00:00:00Z' then
    raise exception 'FAIL last_seen did not move forward, or first_seen moved (% / %)', ind.last_seen, ind.first_seen;
  end if;
  -- "nothing found" is still an answer: the lookup counts as research although the verdict stayed
  if ind.researched_at is null then raise exception 'FAIL a lookup that changed nothing was not recorded as research'; end if;

  -- ...but a worse one replaces a weaker one, with its severity, confidence and source.
  set local role service_role;
  perform public.record_external_indicators('lookup:virustotal', $json$[
    {"type": "domain", "value": "fxext-clamped.example", "verdict": "malicious", "severity": "high",
     "confidence": 70, "description": "now malicious", "seen_at": "2026-09-26T00:00:00Z"}
  ]$json$::jsonb);
  reset role;
  select * into ind from public.indicators where value = 'fxext-clamped.example';
  if ind.verdict <> 'malicious' or ind.severity <> 'high' or ind.confidence <> 70
     or ind.source <> 'lookup:virustotal' or ind.description <> 'now malicious' then
    raise exception 'FAIL a worse verdict did not replace a weaker one: %', to_jsonb(ind);
  end if;
  if ind.researched_at is null then raise exception 'FAIL an upgrading lookup was not recorded as research'; end if;

  -- A date in the future is clamped to now.
  set local role service_role;
  perform public.record_external_indicators('lookup:otx', $json$[
    {"type": "domain", "value": "fxext-future.example", "verdict": "unknown", "severity": "low",
     "confidence": 30, "seen_at": "2999-01-01T00:00:00Z"}
  ]$json$::jsonb);
  reset role;
  if (select last_seen from public.indicators where value = 'fxext-future.example') > now() then
    raise exception 'FAIL a future date was stored';
  end if;
end $$;

-- 5b. researched_at follows the lookups, never the feeds
do $$
declare before_at timestamptz;
begin
  set local role service_role;
  perform public.record_external_indicators('lookup:virustotal', $json$[
    {"type": "ipv4", "value": "203.0.113.155", "verdict": "unknown", "severity": "low", "confidence": 30}
  ]$json$::jsonb);
  reset role;
  if (select researched_at from public.indicators where value = '203.0.113.155') is null then
    raise exception 'FAIL a new indicator from a lookup was not marked researched';
  end if;

  select researched_at into before_at from public.indicators where value = 'fxext-new.example';
  set local role service_role;
  perform public.record_external_indicators('urlhaus', $json$[
    {"type": "domain", "value": "fxext-new.example", "verdict": "malicious", "severity": "high", "confidence": 85}
  ]$json$::jsonb);
  reset role;
  if (select researched_at from public.indicators where value = 'fxext-new.example') is distinct from before_at then
    raise exception 'FAIL a feed refresh moved researched_at';
  end if;
end $$;

-- 6. the same batch twice changes nothing more -----------------------------------------------------
do $$
declare before_count int; r jsonb;
begin
  select count(*) into before_count from public.indicators;
  set local role service_role;
  r := public.record_external_indicators('urlhaus', $json$[
    {"type": "domain", "value": "fxext-new.example", "verdict": "malicious", "severity": "high",
     "confidence": 85, "seen_at": "2026-09-25T00:00:00Z"}
  ]$json$::jsonb);
  reset role;
  if (r ->> 'created')::int <> 0 or (select count(*) from public.indicators) <> before_count then
    raise exception 'FAIL a repeated batch created rows: %', r;
  end if;
end $$;

-- 7. clients still cannot create an external indicator themselves ----------------------------------
do $$
declare blocked boolean := false;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-0000000000e1', 'role', 'authenticated')::text, true);
  set local role authenticated;
  begin
    insert into public.indicators (type, value, severity, verdict, confidence, origin, created_by)
    values ('domain', 'fxext-client.example', 'low', 'unknown', 10, 'external', 'ffffffff-0000-4000-8000-0000000000e1');
  exception when insufficient_privilege or check_violation then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL a client created an external indicator'; end if;
end $$;

rollback;
select 'external_indicators: all checks passed' as result;
