-- ArcRadar database security and constraint tests.
-- Run with `npm run db:test` (needs the local Supabase stack). Everything happens inside one
-- transaction that is rolled back, so no data is left behind. Any failed assertion raises an
-- exception and the run aborts with a non-zero exit code.
--
-- Fixture users:
--   ...0001 admin, ...0002 analyst, ...0003 viewer, ...0004 viewer (other), ...0005 inactive analyst

begin;

insert into auth.users (id, email) values
  ('bbbbbbbb-0000-4000-8000-000000000001', 'test-admin@arcradar.test'),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'test-analyst@arcradar.test'),
  ('bbbbbbbb-0000-4000-8000-000000000003', 'test-viewer@arcradar.test'),
  ('bbbbbbbb-0000-4000-8000-000000000004', 'test-other@arcradar.test'),
  ('bbbbbbbb-0000-4000-8000-000000000005', 'test-inactive@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'bbbbbbbb-0000-4000-8000-000000000001';
update public.profiles set role_name = 'analyst' where id in
  ('bbbbbbbb-0000-4000-8000-000000000002', 'bbbbbbbb-0000-4000-8000-000000000005');
update public.profiles set is_active = false where id = 'bbbbbbbb-0000-4000-8000-000000000005';

insert into public.indicators (id, type, value, created_by) values
  ('cccccccc-0000-4000-8000-000000000001', 'domain', 'fixture.example', 'bbbbbbbb-0000-4000-8000-000000000002');
insert into public.alerts (id, title, created_by) values
  ('cccccccc-0000-4000-8000-000000000002', 'Fixture alert', 'bbbbbbbb-0000-4000-8000-000000000002');
insert into public.investigations (id, title, created_by) values
  ('cccccccc-0000-4000-8000-000000000003', 'Fixture investigation', 'bbbbbbbb-0000-4000-8000-000000000002');
insert into public.investigation_notes (id, investigation_id, author_id, body) values
  ('cccccccc-0000-4000-8000-000000000004', 'cccccccc-0000-4000-8000-000000000003', 'bbbbbbbb-0000-4000-8000-000000000001', 'Admin note');
insert into public.api_keys (user_id, name, key_prefix, key_hash) values
  ('bbbbbbbb-0000-4000-8000-000000000001', 'admin key', 'arc_aaaa', repeat('a', 64)),
  ('bbbbbbbb-0000-4000-8000-000000000002', 'analyst key', 'arc_bbbb', repeat('b', 64));
insert into public.audit_logs (user_id, action, entity_type, entity_id)
  values ('bbbbbbbb-0000-4000-8000-000000000001', 'test.fixture', 'indicator', 'x');

-- 1. Coverage ---------------------------------------------------------------
do $$
declare bad int;
begin
  select count(*) into bad
  from pg_tables t
  where t.schemaname = 'public'
    and (not t.rowsecurity
      or not exists (select 1 from pg_policies p where p.schemaname = 'public' and p.tablename = t.tablename));
  if bad <> 0 then raise exception 'FAIL % public table(s) lack RLS or a policy', bad; end if;

  select count(*) into bad
  from pg_tables t
  where t.schemaname = 'public'
    and (has_table_privilege('anon', format('%I.%I', t.schemaname, t.tablename), 'SELECT')
      or has_table_privilege('authenticated', format('%I.%I', t.schemaname, t.tablename), 'TRUNCATE'));
  if bad <> 0 then raise exception 'FAIL % table(s) give anon SELECT or authenticated TRUNCATE', bad; end if;

  raise notice 'ok - every table has RLS and a policy; anon has no table access; no client TRUNCATE';
end $$;

-- 2. Profile trigger never trusts user metadata -----------------------------
do $$
declare r text;
begin
  insert into auth.users (id, email, raw_user_meta_data) values
    ('bbbbbbbb-0000-4000-8000-0000000000f1', 'meta-escalation@arcradar.test', '{"role":"admin","role_name":"admin"}');
  select role_name into r from public.profiles where id = 'bbbbbbbb-0000-4000-8000-0000000000f1';
  if r is distinct from 'viewer' then raise exception 'FAIL new user received role %', r; end if;
  raise notice 'ok - new users are viewers regardless of signup metadata';
end $$;

-- 3. anon ---------------------------------------------------------------------
do $$
begin
  set local role anon;
  begin
    perform 1 from public.indicators;
    raise exception 'FAIL anon could read indicators';
  exception when insufficient_privilege then null;
  end;
  reset role;
  raise notice 'ok - anon is denied';
end $$;

-- 4. viewer: read-only ----------------------------------------------------------
do $$
declare n int; blocked boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  select count(*) into n from public.indicators;
  if n < 1 then raise exception 'FAIL viewer cannot read indicators'; end if;

  blocked := false;
  begin
    insert into public.indicators (type, value) values ('domain', 'viewer-insert.example');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL viewer inserted an indicator'; end if;

  update public.indicators set severity = 'low' where id = 'cccccccc-0000-4000-8000-000000000001';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL viewer updated an indicator'; end if;

  delete from public.indicators where id = 'cccccccc-0000-4000-8000-000000000001';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL viewer deleted an indicator'; end if;

  select count(*) into n from public.audit_logs;
  if n <> 0 then raise exception 'FAIL viewer can read the audit log'; end if;

  select count(*) into n from public.api_keys;
  if n <> 0 then raise exception 'FAIL viewer can read API keys'; end if;

  if (select public.has_permission('indicators:write')) then raise exception 'FAIL viewer has indicators:write'; end if;
  reset role;
  raise notice 'ok - viewer is read-only and sees no audit log or API keys';
end $$;

-- 5. analyst ----------------------------------------------------------------------
do $$
declare n int; blocked boolean; who uuid;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  insert into public.indicators (id, type, value) values ('cccccccc-0000-4000-8000-000000000010', 'domain', 'analyst-insert.example');
  select created_by into who from public.indicators where id = 'cccccccc-0000-4000-8000-000000000010';
  if who is distinct from 'bbbbbbbb-0000-4000-8000-000000000002'::uuid then raise exception 'FAIL created_by did not default to the caller'; end if;

  blocked := false;
  begin
    insert into public.indicators (type, value, created_by)
    values ('domain', 'spoofed-owner.example', 'bbbbbbbb-0000-4000-8000-000000000001');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL analyst inserted a row owned by someone else'; end if;

  update public.indicators set severity = 'high', created_by = 'bbbbbbbb-0000-4000-8000-000000000001'
  where id = 'cccccccc-0000-4000-8000-000000000001';
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'FAIL analyst could not update an indicator'; end if;
  select created_by into who from public.indicators where id = 'cccccccc-0000-4000-8000-000000000001';
  if who is distinct from 'bbbbbbbb-0000-4000-8000-000000000002'::uuid then raise exception 'FAIL created_by was rewritten'; end if;

  delete from public.indicators where id = 'cccccccc-0000-4000-8000-000000000001';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL analyst deleted an indicator (needs indicators:delete)'; end if;

  update public.alerts set status = 'acknowledged', acknowledged_at = now() where id = 'cccccccc-0000-4000-8000-000000000002';
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'FAIL analyst could not acknowledge an alert'; end if;

  delete from public.alerts where id = 'cccccccc-0000-4000-8000-000000000002';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL analyst deleted an alert'; end if;

  insert into public.investigation_notes (investigation_id, body) values ('cccccccc-0000-4000-8000-000000000003', 'Analyst note');
  update public.investigation_notes set body = 'tampered' where id = 'cccccccc-0000-4000-8000-000000000004';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL analyst edited another user''s note'; end if;

  select count(*) into n from public.api_keys;
  if n <> 1 then raise exception 'FAIL analyst sees % API keys, expected only their own', n; end if;

  blocked := false;
  begin
    perform key_hash from public.api_keys;
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL key_hash is readable by clients'; end if;

  blocked := false;
  begin
    insert into public.api_keys (user_id, name, key_prefix, key_hash)
    values ('bbbbbbbb-0000-4000-8000-000000000002', 'self-made', 'arc_cccc', repeat('c', 64));
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL client created an API key directly'; end if;

  reset role;
  raise notice 'ok - analyst can work indicators/alerts/investigations but not delete, curate actors, or touch others'' data';
end $$;

-- 6. admin -----------------------------------------------------------------------------
do $$
declare n int; blocked boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;

  delete from public.indicators where id = 'cccccccc-0000-4000-8000-000000000001';
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'FAIL admin could not delete an indicator'; end if;

  select count(*) into n from public.audit_logs;
  if n < 1 then raise exception 'FAIL admin cannot read the audit log'; end if;

  select count(*) into n from public.api_keys;
  if n <> 2 then raise exception 'FAIL admin sees % API keys, expected 2', n; end if;

  blocked := false;
  begin
    insert into public.audit_logs (action) values ('client.forged');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a client wrote to the audit log'; end if;

  reset role;
  raise notice 'ok - admin has full access except client-side audit writes';
end $$;

-- 7. profiles: no self-promotion, inactive users lose access ------------------------------
do $$
declare n int; blocked boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  update public.profiles set display_name = 'Renamed Viewer' where id = 'bbbbbbbb-0000-4000-8000-000000000003';
  get diagnostics n = row_count;
  if n <> 1 then raise exception 'FAIL user cannot edit own display name'; end if;

  update public.profiles set display_name = 'Hijacked' where id = 'bbbbbbbb-0000-4000-8000-000000000004';
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL user edited another profile'; end if;

  blocked := false;
  begin
    update public.profiles set role_name = 'admin' where id = 'bbbbbbbb-0000-4000-8000-000000000003';
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL user promoted themselves to admin'; end if;

  blocked := false;
  begin
    update public.profiles set is_active = true where id = 'bbbbbbbb-0000-4000-8000-000000000003';
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL user changed is_active'; end if;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'bbbbbbbb-0000-4000-8000-000000000005', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.indicators;
  if n <> 0 then raise exception 'FAIL inactive user can still read indicators'; end if;
  reset role;

  raise notice 'ok - users cannot change role/is_active; inactive users lose all access';
end $$;

-- 8. audit_logs is append-only even for the table owner ------------------------------------
do $$
declare blocked boolean;
begin
  blocked := false;
  begin update public.audit_logs set action = 'test.tampered'; exception when sqlstate 'P0001' then blocked := true; end;
  if not blocked then raise exception 'FAIL audit log row was updated'; end if;

  blocked := false;
  begin delete from public.audit_logs; exception when sqlstate 'P0001' then blocked := true; end;
  if not blocked then raise exception 'FAIL audit log row was deleted'; end if;

  blocked := false;
  begin truncate public.audit_logs; exception when sqlstate 'P0001' then blocked := true; end;
  if not blocked then raise exception 'FAIL audit log was truncated'; end if;

  raise notice 'ok - audit_logs rejects update, delete and truncate';
end $$;

-- 9. Data constraints -------------------------------------------------------------------------
do $$
declare
  cases text[][] := array[
    array['invalid ipv4 octet',        $q$insert into public.indicators (type, value) values ('ipv4', '999.1.1.1')$q$,                          '23514'],
    array['ipv4 with prefix length',   $q$insert into public.indicators (type, value) values ('ipv4', '10.0.0.1/24')$q$,                        '23514'],
    array['md5 wrong length',          $q$insert into public.indicators (type, value) values ('md5', 'abc123')$q$,                              '23514'],
    array['sha256 non-hex',            $q$insert into public.indicators (type, value) values ('sha256', repeat('z', 64))$q$,                     '23514'],
    array['url without scheme',        $q$insert into public.indicators (type, value) values ('url', 'example.com/path')$q$,                     '23514'],
    array['domain without dot',        $q$insert into public.indicators (type, value) values ('domain', 'localhost')$q$,                         '23514'],
    array['value with padding',        $q$insert into public.indicators (type, value) values ('domain', ' padded.example')$q$,                   '23514'],
    array['case-insensitive duplicate',$q$insert into public.indicators (type, value) values ('domain', 'ANALYST-INSERT.example')$q$,            '23505'],
    array['last_seen before first_seen',$q$insert into public.indicators (type, value, first_seen, last_seen) values ('domain', 'time-travel.example', now(), now() - interval '1 day')$q$, '23514'],
    array['resolved alert without timestamp', $q$insert into public.alerts (title, status) values ('bad', 'resolved')$q$,                          '23514'],
    array['open alert with resolved_at',      $q$insert into public.alerts (title, status, resolved_at) values ('bad', 'new', now())$q$,           '23514'],
    array['closed investigation without closed_at', $q$insert into public.investigations (title, status) values ('bad', 'closed')$q$,             '23514'],
    array['malformed CVE id',          $q$insert into public.vulnerabilities (cve_id, title) values ('CVE-21-1', 'bad')$q$,                     '23514'],
    array['cvss out of range',         $q$insert into public.vulnerabilities (cve_id, title, cvss_score) values ('CVE-2099-0001', 'bad', 10.5)$q$, '23514'],
    array['malformed audit action',    $q$insert into public.audit_logs (action) values ('Not Valid')$q$,                                       '23514'],
    array['malformed api key hash',    $q$insert into public.api_keys (user_id, name, key_prefix, key_hash) values ('bbbbbbbb-0000-4000-8000-000000000001', 'k', 'arc_dddd', 'short')$q$, '23514']
  ];
  i int;
  got text;
begin
  for i in 1 .. array_length(cases, 1) loop
    got := 'no error';
    begin
      execute cases[i][2];
    exception when others then
      got := sqlstate;
    end;
    if got is distinct from cases[i][3] then
      raise exception 'FAIL constraint "%": expected sqlstate %, got %', cases[i][1], cases[i][3], got;
    end if;
  end loop;
  raise notice 'ok - % data constraints reject invalid input', array_length(cases, 1);
end $$;

rollback;
\echo ALL DATABASE SECURITY TESTS PASSED
