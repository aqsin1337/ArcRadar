-- Indicator search, tag editing and provenance protection.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer, ...0005 inactive analyst
-- Fixture indicators (ids ...dddd...):
--   01 domain fxlogin-secure.example       "Credential harvesting fxpage" source fxfeed-a  tag fixture-phish
--   02 ipv4   203.0.113.201                "Command fxserver"            source fxfeed-b
--   03 domain fxliteral-percent.example    "Sale fx50%_off literal"
--   04 domain fxplain-text.example         "Sale fx50 percent off"

begin;

insert into auth.users (id, email) values
  ('bbbbbbbb-0000-4000-8000-000000000001', 'ind-admin@arcradar.test'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'ind-analyst@arcradar.test'),
  ('bbbbbbbb-0000-4000-8000-000000000003', 'ind-viewer@arcradar.test'),
  ('bbbbbbbb-0000-4000-8000-000000000005', 'ind-inactive@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'bbbbbbbb-0000-4000-8000-000000000001';
update public.profiles set role_name = 'analyst' where id in
  ('bbbbbbbb-0000-4000-8000-000000000002', 'bbbbbbbb-0000-4000-8000-000000000005');
update public.profiles set is_active = false where id = 'bbbbbbbb-0000-4000-8000-000000000005';

insert into public.indicators (id, type, value, description, source) values
  ('dddddddd-0000-4000-8000-000000000001', 'domain', 'fxlogin-secure.example', 'Credential harvesting fxpage', 'fxfeed-a'),
  ('dddddddd-0000-4000-8000-000000000002', 'ipv4', '203.0.113.201', 'Command fxserver', 'fxfeed-b'),
  ('dddddddd-0000-4000-8000-000000000003', 'domain', 'fxliteral-percent.example', 'Sale fx50%_off literal', 'manual'),
  ('dddddddd-0000-4000-8000-000000000004', 'domain', 'fxplain-text.example', 'Sale fx50 percent off', 'manual');

insert into public.tags (id, name) values ('dddddddd-0000-4000-8000-0000000000a1', 'fixture-phish');
insert into public.indicator_tags (indicator_id, tag_id)
  values ('dddddddd-0000-4000-8000-000000000001', 'dddddddd-0000-4000-8000-0000000000a1');

-- 1. search: terms, wildcards, tags -------------------------------------------------------
do $$
declare ids uuid[];

  function_count int;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  select count(*) into function_count from public.search_indicators('fxlogin-secure');
  if function_count <> 1 then raise exception 'FAIL value search found % rows', function_count; end if;

  select count(*) into function_count from public.search_indicators('  FXLOGIN-SECURE   .example  ');
  if function_count <> 1 then raise exception 'FAIL search is not case-insensitive or whitespace-tolerant (%)', function_count; end if;

  select count(*) into function_count from public.search_indicators('fxlogin zzz-no-such-term');
  if function_count <> 0 then raise exception 'FAIL terms are not ANDed (%)', function_count; end if;

  select count(*) into function_count from public.search_indicators('fxpage fxlogin');
  if function_count <> 1 then raise exception 'FAIL terms do not match across value and description (%)', function_count; end if;

  select count(*) into function_count from public.search_indicators('fxfeed-b');
  if function_count <> 1 then raise exception 'FAIL source search failed (%)', function_count; end if;

  select count(*) into function_count from public.search_indicators('fixture-phish');
  if function_count <> 1 then raise exception 'FAIL tag-name search failed (%)', function_count; end if;

  -- % and _ are literal characters, never wildcards.
  select array_agg(id) into ids from public.search_indicators('fx50%_off');
  if ids is distinct from array['dddddddd-0000-4000-8000-000000000003'::uuid] then
    raise exception 'FAIL literal %%_ search returned %', ids;
  end if;
  select array_agg(id) into ids from public.search_indicators('%');
  if 'dddddddd-0000-4000-8000-000000000004'::uuid = any (coalesce(ids, '{}')) then
    raise exception 'FAIL a lone percent sign acted as a wildcard';
  end if;
  select array_agg(id) into ids from public.search_indicators('_');
  if 'dddddddd-0000-4000-8000-000000000002'::uuid = any (coalesce(ids, '{}')) then
    raise exception 'FAIL a lone underscore acted as a wildcard';
  end if;

  select count(*) into function_count from public.search_indicators(null);
  if function_count < 4 then raise exception 'FAIL empty search does not return everything (%)', function_count; end if;
  select count(*) into function_count from public.search_indicators('   ');
  if function_count < 4 then raise exception 'FAIL blank search does not return everything (%)', function_count; end if;

  -- tag filter
  select count(*) into function_count from public.search_indicators(null, 'FIXTURE-PHISH');
  if function_count <> 1 then raise exception 'FAIL tag filter is not case-insensitive (%)', function_count; end if;
  select count(*) into function_count from public.search_indicators('fxserver', 'fixture-phish');
  if function_count <> 0 then raise exception 'FAIL tag filter and text are not combined (%)', function_count; end if;
  select count(*) into function_count from public.search_indicators('fxlogin', 'no-such-tag');
  if function_count <> 0 then raise exception 'FAIL unknown tag matched (%)', function_count; end if;

  reset role;
  raise notice 'ok - search: ANDed terms across value/description/source/tags, literal wildcards, tag filter';
end $$;

-- 2. search respects access ------------------------------------------------------------------
do $$
declare n int;
begin
  set local role anon;
  begin
    perform * from public.search_indicators('login');
    raise exception 'FAIL anon can call search_indicators';
  exception when insufficient_privilege then null;
  end;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000005', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.search_indicators('fxlogin');
  if n <> 0 then raise exception 'FAIL inactive user found % indicators through search', n; end if;
  reset role;

  raise notice 'ok - search is denied to anon and returns nothing to inactive users';
end $$;

-- 3. set_indicator_tags -----------------------------------------------------------------------
do $$
declare names text[]; blocked boolean; got text;
begin
  -- viewers cannot edit tags
  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    perform public.set_indicator_tags('dddddddd-0000-4000-8000-000000000002', array['fixture-tag-a']);
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL viewer edited tags'; end if;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- creates missing tags, dedupes case-insensitively, trims, ignores blanks
  perform public.set_indicator_tags('dddddddd-0000-4000-8000-000000000002',
    array['Fixture-Tag-A', '  fixture-tag-a ', '', 'fixture-tag-b']);
  select array_agg(t.name order by t.name) into names
  from public.indicator_tags it join public.tags t on t.id = it.tag_id
  where it.indicator_id = 'dddddddd-0000-4000-8000-000000000002';
  if names is distinct from array['Fixture-Tag-A', 'fixture-tag-b'] then
    raise exception 'FAIL tag set after create/dedupe was %', names;
  end if;

  -- replaces the set: A is unlinked, C added; existing tag rows are reused
  perform public.set_indicator_tags('dddddddd-0000-4000-8000-000000000002', array['FIXTURE-TAG-B', 'fixture-tag-c']);
  select array_agg(t.name order by t.name) into names
  from public.indicator_tags it join public.tags t on t.id = it.tag_id
  where it.indicator_id = 'dddddddd-0000-4000-8000-000000000002';
  if names is distinct from array['fixture-tag-b', 'fixture-tag-c'] then
    raise exception 'FAIL tag set after replace was %', names;
  end if;
  if (select count(*) from public.tags where lower(name) = 'fixture-tag-b') <> 1 then
    raise exception 'FAIL an existing tag was duplicated';
  end if;

  -- an empty array clears the links
  perform public.set_indicator_tags('dddddddd-0000-4000-8000-000000000002', '{}');
  if exists (select 1 from public.indicator_tags where indicator_id = 'dddddddd-0000-4000-8000-000000000002') then
    raise exception 'FAIL tags were not cleared';
  end if;

  -- unknown indicator
  got := null;
  begin
    perform public.set_indicator_tags('dddddddd-0000-4000-8000-0000000000ff', array['x']);
  exception when others then got := sqlstate;
  end;
  if got is distinct from 'P0002' then raise exception 'FAIL unknown indicator gave %', got; end if;

  -- limits
  got := null;
  begin
    perform public.set_indicator_tags('dddddddd-0000-4000-8000-000000000002',
      (select array_agg('t' || g) from generate_series(1, 21) g));
  exception when others then got := sqlstate;
  end;
  if got is distinct from '23514' then raise exception 'FAIL 21 tags gave %', got; end if;

  got := null;
  begin
    perform public.set_indicator_tags('dddddddd-0000-4000-8000-000000000002', array[repeat('x', 51)]);
  exception when others then got := sqlstate;
  end;
  if got is distinct from '23514' then raise exception 'FAIL a 51-character tag gave %', got; end if;

  reset role;
  raise notice 'ok - set_indicator_tags: permission, create + dedupe, replace, clear, not found, limits';
end $$;

-- 4. provenance --------------------------------------------------------------------------------
do $$
declare blocked boolean; o public.data_origin;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  insert into public.indicators (id, type, value) values ('dddddddd-0000-4000-8000-000000000010', 'domain', 'default-origin.example');
  select origin into o from public.indicators where id = 'dddddddd-0000-4000-8000-000000000010';
  if o is distinct from 'local' then raise exception 'FAIL default origin was %', o; end if;

  foreach o in array array['external', 'demo']::public.data_origin[] loop
    blocked := false;
    begin
      insert into public.indicators (type, value, origin) values ('domain', 'forged-' || o || '.example', o);
    exception when insufficient_privilege then blocked := true;
    end;
    if not blocked then raise exception 'FAIL analyst created an indicator with origin %', o; end if;
  end loop;

  -- relabelling is silently ignored
  update public.indicators set origin = 'external', severity = 'low' where id = 'dddddddd-0000-4000-8000-000000000010';
  select origin into o from public.indicators where id = 'dddddddd-0000-4000-8000-000000000010';
  if o is distinct from 'local' then raise exception 'FAIL an update relabelled origin to %', o; end if;
  if (select severity from public.indicators where id = 'dddddddd-0000-4000-8000-000000000010') <> 'low' then
    raise exception 'FAIL the rest of the update was lost';
  end if;
  reset role;

  -- admins are held to the same rule
  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.indicators (type, value, origin) values ('domain', 'admin-forged.example', 'external');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL admin created an external indicator through the client role'; end if;
  reset role;

  -- server-side ingestion (service role) can still record external data
  set local role service_role;
  insert into public.indicators (id, type, value, origin) values ('dddddddd-0000-4000-8000-000000000011', 'domain', 'ingested.example', 'external');
  reset role;
  if (select origin from public.indicators where id = 'dddddddd-0000-4000-8000-000000000011') <> 'external' then
    raise exception 'FAIL service role could not record external data';
  end if;

  raise notice 'ok - provenance: clients create only local records and cannot relabel; the service role can ingest external';
end $$;

rollback;
\echo INDICATOR DATABASE TESTS PASSED
