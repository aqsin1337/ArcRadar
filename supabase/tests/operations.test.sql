-- Alerts, investigations and MITRE techniques: provenance, investigation items and notes,
-- search, statistics and the atomic tag function.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer, ...0005 inactive analyst
-- Fixture ids follow the pattern <kind prefix>-0000-4000-8000-0000000000NN:
--   ea  alerts          01 "fxalert Beacon" source fxsource-a, indicator fx.example, new, unassigned
--                       02 "fxalert Scan" source fxsource-b, assigned to the analyst, resolved
--   ei  investigations  01 "fxinvestigation Alpha" (tag fx-tag, indicator fx.example, "fxdesc case")  02 "fxinvestigation Beta"
--   ff  indicator       01 fx.example

begin;

insert into auth.users (id, email) values
  ('ffffffff-0000-4000-8000-000000000001', 'ops-admin@arcradar.test'),
  ('ffffffff-0000-4000-8000-000000000002', 'ops-analyst@arcradar.test'),
  ('ffffffff-0000-4000-8000-000000000003', 'ops-viewer@arcradar.test'),
  ('ffffffff-0000-4000-8000-000000000005', 'ops-inactive@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'ffffffff-0000-4000-8000-000000000001';
update public.profiles set role_name = 'analyst' where id in
  ('ffffffff-0000-4000-8000-000000000002', 'ffffffff-0000-4000-8000-000000000005');
update public.profiles set is_active = false where id = 'ffffffff-0000-4000-8000-000000000005';

insert into public.indicators (id, type, value) values
  ('ffffffff-1111-4000-8000-000000000001', 'domain', 'fx.example');

insert into public.mitre_techniques (id, name, tactics, description) values
  ('T9999', 'Fxtechnique name', array['Fxtactic'], 'fxtech description');

insert into public.alerts (id, title, description, severity, source, status, indicator_id, assigned_to, resolved_at) values
  ('eaeaeaea-0000-4000-8000-000000000001', 'fxalert Beacon', 'Beacon to fxhost', 'high', 'fxsource-a', 'new', 'ffffffff-1111-4000-8000-000000000001', null, null),
  ('eaeaeaea-0000-4000-8000-000000000002', 'fxalert Scan', 'Sale fx50%_off literal', 'low', 'fxsource-b', 'resolved', null, 'ffffffff-0000-4000-8000-000000000002', now());
insert into public.investigations (id, title, description) values
  ('e1e1e1e1-0000-4000-8000-000000000001', 'fxinvestigation Alpha', 'fxdesc case'),
  ('e1e1e1e1-0000-4000-8000-000000000002', 'fxinvestigation Beta', 'other');
insert into public.tags (id, name) values ('e1e1e1e1-aaaa-4000-8000-0000000000a1', 'fx-tag');
insert into public.investigation_tags values ('e1e1e1e1-0000-4000-8000-000000000001', 'e1e1e1e1-aaaa-4000-8000-0000000000a1');
insert into public.investigation_indicators (investigation_id, indicator_id)
  values ('e1e1e1e1-0000-4000-8000-000000000001', 'ffffffff-1111-4000-8000-000000000001');

-- 1. provenance of the record tables --------------------------------------------------------------
do $$
declare
  spec record; blocked boolean; o public.data_origin; n int; n2 text;
begin
  -- table, the user allowed to write it, the columns and values of a minimal row
  for spec in
    select * from (values
      ('events',         'ffffffff-0000-4000-8000-000000000001', 'event_type, title',   'title'),
      ('alerts',         'ffffffff-0000-4000-8000-000000000002', 'title',               'title'),
      ('investigations', 'ffffffff-0000-4000-8000-000000000002', 'title',               'title')
    ) as v (tbl, writer, cols, first_col)
  loop
    perform set_config('request.jwt.claims', json_build_object('sub', spec.writer, 'role', 'authenticated')::text, true);
    set local role authenticated;

    -- one value per column: a unique fixture text
    execute format('insert into public.%I (%s) select %s', spec.tbl, spec.cols,
      case spec.tbl when 'events' then '''fx_type'', ''fx event title''' else '''prov-default-'' || ''' || spec.tbl || '''' end);
    execute format('select origin from public.%I order by created_at desc limit 1', spec.tbl) into o;
    if o is distinct from 'local' then raise exception 'FAIL % default origin was %', spec.tbl, o; end if;

    foreach o in array array['external', 'demo']::public.data_origin[] loop
      blocked := false;
      begin
        execute format('insert into public.%I (%s, origin) select %s, %L', spec.tbl, spec.cols,
          case spec.tbl when 'events' then '''fx_type'', ''forged event''' else '''forged-'' || ''' || o || '-' || spec.tbl || '''' end,
          o);
      exception when insufficient_privilege then blocked := true;
      end;
      if not blocked then raise exception 'FAIL % accepted a client-chosen origin %', spec.tbl, o; end if;
    end loop;

    -- relabelling is silently ignored
    execute format('update public.%I set origin = ''external'' where id = (select id from public.%I order by created_at desc limit 1)', spec.tbl, spec.tbl);
    execute format('select origin from public.%I order by created_at desc limit 1', spec.tbl) into o;
    if o is distinct from 'local' then raise exception 'FAIL % was relabelled to %', spec.tbl, o; end if;
    reset role;

    -- the service role (server-side ingestion) can still record external data
    set local role service_role;
    execute format('insert into public.%I (%s, origin) select %s, ''external''', spec.tbl, spec.cols,
      case spec.tbl when 'events' then '''fx_type'', ''ingested event''' else '''ingested-'' || ''' || spec.tbl || '''' end);
    reset role;
    execute format('select count(*) from public.%I where origin = ''external'' and %I like ''ingested%%''', spec.tbl, spec.first_col) into n;
    if n <> 1 then raise exception 'FAIL the service role could not record external data in % (found %)', spec.tbl, n; end if;
  end loop;

  raise notice 'ok - provenance: clients create only local records in three tables, cannot relabel; the service role ingests external';
end $$;

-- 2. who added an item to an investigation ----------------------------------------------------------
do $$
declare blocked boolean; who uuid;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  insert into public.investigation_alerts (investigation_id, alert_id)
    values ('e1e1e1e1-0000-4000-8000-000000000002', 'eaeaeaea-0000-4000-8000-000000000001');
  select added_by into who from public.investigation_alerts
    where investigation_id = 'e1e1e1e1-0000-4000-8000-000000000002' and alert_id = 'eaeaeaea-0000-4000-8000-000000000001';
  if who is distinct from 'ffffffff-0000-4000-8000-000000000002' then raise exception 'FAIL added_by defaulted to %', who; end if;

  blocked := false;
  begin
    insert into public.investigation_indicators (investigation_id, indicator_id, added_by)
      values ('e1e1e1e1-0000-4000-8000-000000000002', 'ffffffff-1111-4000-8000-000000000001', 'ffffffff-0000-4000-8000-000000000001');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an analyst recorded someone else as the one who added an indicator'; end if;

  blocked := false;
  begin
    insert into public.investigation_alerts (investigation_id, alert_id, added_by)
      values ('e1e1e1e1-0000-4000-8000-000000000002', 'eaeaeaea-0000-4000-8000-000000000002', 'ffffffff-0000-4000-8000-000000000001');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an analyst recorded someone else as the one who added an alert'; end if;
  reset role;

  -- viewers cannot link anything
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.investigation_alerts (investigation_id, alert_id)
      values ('e1e1e1e1-0000-4000-8000-000000000001', 'eaeaeaea-0000-4000-8000-000000000002');
  exception when insufficient_privilege then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL a viewer linked an alert'; end if;

  raise notice 'ok - investigation items record who added them, and only as the caller';
end $$;

-- 3. notes and system notes ---------------------------------------------------------------------------
do $$
declare blocked boolean; n int; note_id uuid; system_id uuid;
begin
  -- the server records a system note (service role), attributed to the analyst
  set local role service_role;
  insert into public.investigation_notes (investigation_id, author_id, kind, body)
    values ('e1e1e1e1-0000-4000-8000-000000000001', 'ffffffff-0000-4000-8000-000000000002', 'system', 'Status changed from Open to Investigating.')
    returning id into system_id;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  blocked := false;
  begin
    insert into public.investigation_notes (investigation_id, author_id, kind, body)
      values ('e1e1e1e1-0000-4000-8000-000000000001', 'ffffffff-0000-4000-8000-000000000002', 'system', 'forged history');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an analyst created a system note'; end if;

  insert into public.investigation_notes (investigation_id, body)
    values ('e1e1e1e1-0000-4000-8000-000000000001', 'A real note') returning id into note_id;
  update public.investigation_notes set body = 'Edited note' where id = note_id;
  if (select body from public.investigation_notes where id = note_id) <> 'Edited note' then raise exception 'FAIL the author could not edit a note'; end if;

  update public.investigation_notes set body = 'rewritten history' where id = system_id;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL an analyst edited a system note'; end if;
  blocked := false;
  begin
    update public.investigation_notes set kind = 'system' where id = note_id;
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an analyst turned a note into a system note'; end if;

  delete from public.investigation_notes where id = system_id;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL an analyst deleted a system note'; end if;
  reset role;

  -- an administrator may remove any ordinary note, but not the history
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  delete from public.investigation_notes where id = system_id;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL an administrator deleted a system note'; end if;
  delete from public.investigation_notes where id = note_id;
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'FAIL an administrator could not delete an ordinary note'; end if;
  reset role;

  if not exists (select 1 from public.investigation_notes where id = system_id) then raise exception 'FAIL the system note is gone'; end if;
  raise notice 'ok - system notes are written by the server only and cannot be edited or deleted by clients';
end $$;

-- 4. search -----------------------------------------------------------------------------------------------
do $$
declare n int; ids uuid[];
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- alerts: title, description, source, the value of the indicator; terms are ANDed; wildcards are literal
  select count(*) into n from public.search_alerts('fxalert beacon'); if n <> 1 then raise exception 'FAIL alert title search found %', n; end if;
  select count(*) into n from public.search_alerts('fxhost'); if n <> 1 then raise exception 'FAIL alert description search found %', n; end if;
  select count(*) into n from public.search_alerts('fxsource-b'); if n <> 1 then raise exception 'FAIL alert source search found %', n; end if;
  select count(*) into n from public.search_alerts('FX.EXAMPLE'); if n <> 1 then raise exception 'FAIL alert indicator search found %', n; end if;
  select count(*) into n from public.search_alerts('fxalert zzz-none'); if n <> 0 then raise exception 'FAIL alert terms are not ANDed (%)', n; end if;
  select count(*) into n from public.search_alerts('fxalert  fxsource-a'); if n <> 1 then raise exception 'FAIL alert terms across fields found %', n; end if;
  select array_agg(id) into ids from public.search_alerts('fx50%_off');
  if ids is distinct from array['eaeaeaea-0000-4000-8000-000000000002'::uuid] then raise exception 'FAIL literal %%_ alert search returned %', ids; end if;
  select array_agg(id) into ids from public.search_alerts('%');
  if 'eaeaeaea-0000-4000-8000-000000000001'::uuid = any (coalesce(ids, '{}')) then raise exception 'FAIL a lone percent sign matched every alert'; end if;
  select count(*) into n from public.search_alerts(null); if n < 2 then raise exception 'FAIL empty alert search returned %', n; end if;

  -- investigations: title, description, tag names, linked indicator values; tag filter
  select count(*) into n from public.search_investigations('fxinvestigation'); if n <> 2 then raise exception 'FAIL investigation title search found %', n; end if;
  select count(*) into n from public.search_investigations('fxdesc'); if n <> 1 then raise exception 'FAIL investigation description search found %', n; end if;
  select count(*) into n from public.search_investigations('fx-tag'); if n <> 1 then raise exception 'FAIL investigation tag search found %', n; end if;
  select count(*) into n from public.search_investigations('fx.example'); if n <> 1 then raise exception 'FAIL investigation indicator search found %', n; end if;
  select count(*) into n from public.search_investigations('fxinvestigation', 'FX-TAG'); if n <> 1 then raise exception 'FAIL investigation tag filter found %', n; end if;
  select count(*) into n from public.search_investigations('fxinvestigation', 'no-such-tag'); if n <> 0 then raise exception 'FAIL unknown tag matched %', n; end if;

  -- techniques
  select count(*) into n from public.search_mitre_techniques('t9999'); if n <> 1 then raise exception 'FAIL technique id search found %', n; end if;
  select count(*) into n from public.search_mitre_techniques('fxtactic'); if n <> 1 then raise exception 'FAIL technique tactic search found %', n; end if;

  -- Rows with NULL optional columns (the provenance test above created some) must not match a text
  -- that appears nowhere: a NULL in the match once made "NOT (...)" NULL and matched everything.
  select count(*) into n from public.search_alerts('zzz-appears-nowhere'); if n <> 0 then raise exception 'FAIL an unrelated alert search found % rows', n; end if;
  select count(*) into n from public.search_investigations('zzz-appears-nowhere'); if n <> 0 then raise exception 'FAIL an unrelated investigation search found % rows', n; end if;
  select count(*) into n from public.search_mitre_techniques('zzz-appears-nowhere'); if n <> 0 then raise exception 'FAIL an unrelated technique search found % rows', n; end if;
  select count(*) into n from public.search_indicators('zzz-appears-nowhere'); if n <> 0 then raise exception 'FAIL an unrelated indicator search found % rows', n; end if;

  reset role;
  raise notice 'ok - search: alerts, investigations and techniques (ANDed terms, literal wildcards, tags, NULL columns)';
end $$;

-- 5. search and statistics respect access ---------------------------------------------------------------------
do $$
declare blocked boolean; f text; n int;
begin
  foreach f in array array[
    'select * from public.search_alerts(''fx'')', 'select * from public.search_investigations(''fx'')',
    'select * from public.search_mitre_techniques(''fx'')',
    'select * from public.alert_status_counts()', 'select * from public.investigation_status_counts()',
    'select * from public.alert_sources()'
  ] loop
    set local role anon;
    blocked := false;
    begin
      execute f;
    exception when insufficient_privilege then blocked := true;
    end;
    reset role;
    if not blocked then raise exception 'FAIL anon could run: %', f; end if;
  end loop;

  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000005', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.search_alerts('fx'); if n <> 0 then raise exception 'FAIL an inactive user found % alerts', n; end if;
  select count(*) into n from public.search_investigations('fx'); if n <> 0 then raise exception 'FAIL an inactive user found % investigations', n; end if;
  select coalesce(sum(total), 0) into n from public.alert_status_counts(); if n <> 0 then raise exception 'FAIL an inactive user counted % alerts', n; end if;
  reset role;

  raise notice 'ok - the functions are denied to anon and show nothing to inactive users';
end $$;

-- 6. statistics ----------------------------------------------------------------------------------------------------
do $$
declare a bigint; b bigint; s text[];
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  select sum(total) into a from public.alert_status_counts();
  select count(*) into b from public.alerts;
  if a is distinct from b then raise exception 'FAIL alert counts add up to % but there are % alerts', a, b; end if;
  if exists (select 1 from public.alert_status_counts() where unassigned > total) then raise exception 'FAIL more unassigned alerts than alerts'; end if;
  if (select unassigned from public.alert_status_counts() where status = 'new') < 1 then raise exception 'FAIL the unassigned new fixture alert is not counted'; end if;

  select sum(total) into a from public.investigation_status_counts();
  select count(*) into b from public.investigations;
  if a is distinct from b then raise exception 'FAIL investigation counts add up to % but there are % investigations', a, b; end if;

  select array_agg(x) into s from public.alert_sources() as x;
  if not ('fxsource-a' = any (s) and 'fxsource-b' = any (s)) then raise exception 'FAIL alert sources were %', s; end if;
  if (select count(*) from unnest(s) as x) <> (select count(distinct x) from unnest(s) as x) then raise exception 'FAIL alert sources are not distinct'; end if;

  reset role;
  raise notice 'ok - status counts add up, unassigned alerts are counted, alert sources are distinct';
end $$;

-- 7. investigation tags --------------------------------------------------------------------------------------------------
do $$
declare blocked boolean; got text; names text[];
begin
  -- investigation tags
  blocked := false;
  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  begin perform public.set_investigation_tags('e1e1e1e1-0000-4000-8000-000000000001', array['x']);
  exception when insufficient_privilege then blocked := true; end;
  reset role;
  if not blocked then raise exception 'FAIL a viewer edited investigation tags'; end if;

  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  perform public.set_investigation_tags('e1e1e1e1-0000-4000-8000-000000000001', array['FX-Tag', '  fx-tag ', '', 'fx-new']);
  select array_agg(t.name order by t.name) into names
  from public.investigation_tags it join public.tags t on t.id = it.tag_id where it.investigation_id = 'e1e1e1e1-0000-4000-8000-000000000001';
  if names is distinct from array['fx-new', 'fx-tag'] then raise exception 'FAIL investigation tags were % (existing tag reused case-insensitively, blanks ignored)', names; end if;
  perform public.set_investigation_tags('e1e1e1e1-0000-4000-8000-000000000001', '{}');
  if exists (select 1 from public.investigation_tags where investigation_id = 'e1e1e1e1-0000-4000-8000-000000000001') then raise exception 'FAIL tags were not cleared'; end if;
  got := null;
  begin perform public.set_investigation_tags('e1e1e1e1-0000-4000-8000-000000000001', (select array_agg('t' || g) from generate_series(1, 21) g));
  exception when others then got := sqlstate; end;
  if got is distinct from '23514' then raise exception 'FAIL 21 tags gave %', got; end if;
  got := null;
  begin perform public.set_investigation_tags('e1e1e1e1-0000-4000-8000-0000000000ff', array['x']);
  exception when others then got := sqlstate; end;
  if got is distinct from 'P0002' then raise exception 'FAIL an unknown investigation gave %', got; end if;
  reset role;

  raise notice 'ok - investigation tags: permissions, set / clear / leave alone, limits, not found';
end $$;

rollback;
\echo OPERATIONS DATABASE TESTS PASSED
