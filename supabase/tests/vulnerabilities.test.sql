-- Vulnerability search, statistics, provenance and the external import function.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer, ...0005 inactive analyst
-- Fixture vulnerabilities (CVE-2099 ids never exist in the seed):
--   01 CVE-2099-1001  "fxvuln Alpha parser overflow"   demo      critical  exploited_in_wild  product FxVendor FxProduct
--   02 CVE-2099-1002  "fxvuln Beta fx50%_off literal"  local     medium    none
--   03 CVE-2099-1003  "fxvuln Gamma"                   external  high      poc_available

begin;

insert into auth.users (id, email) values
  ('cccccccc-0000-4000-8000-000000000001', 'vul-admin@arcradar.test'),
  ('cccccccc-0000-4000-8000-000000000002', 'vul-analyst@arcradar.test'),
  ('cccccccc-0000-4000-8000-000000000003', 'vul-viewer@arcradar.test'),
  ('cccccccc-0000-4000-8000-000000000005', 'vul-inactive@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'cccccccc-0000-4000-8000-000000000001';
update public.profiles set role_name = 'soc_l2' where id in
  ('cccccccc-0000-4000-8000-000000000002', 'cccccccc-0000-4000-8000-000000000005');
update public.profiles set is_active = false where id = 'cccccccc-0000-4000-8000-000000000005';

insert into public.vulnerabilities (id, cve_id, title, description, cvss_score, severity, exploit_status, origin) values
  ('eeeeeeee-0000-4000-8000-000000000001', 'CVE-2099-1001', 'fxvuln Alpha parser overflow', 'Heap overflow in the fxparser library', 9.8, 'critical', 'exploited_in_wild', 'demo'),
  ('eeeeeeee-0000-4000-8000-000000000002', 'CVE-2099-1002', 'fxvuln Beta fx50%_off literal', 'Sale price parsing', 5.0, 'medium', 'none', 'local'),
  ('eeeeeeee-0000-4000-8000-000000000003', 'CVE-2099-1003', 'fxvuln Gamma', 'Gamma description', 7.5, 'high', 'poc_available', 'external');

insert into public.vulnerability_affected_products (vulnerability_id, vendor, product)
  values ('eeeeeeee-0000-4000-8000-000000000001', 'FxVendor', 'FxProduct');

-- 1. search -----------------------------------------------------------------------------------
do $$
declare n int; ids uuid[];
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'cccccccc-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  select count(*) into n from public.search_vulnerabilities('cve-2099-1001');
  if n <> 1 then raise exception 'FAIL CVE id search (case-insensitive) found % rows', n; end if;

  select count(*) into n from public.search_vulnerabilities('  FXVULN   alpha  ');
  if n <> 1 then raise exception 'FAIL title search is not case-insensitive or whitespace-tolerant (%)', n; end if;

  select count(*) into n from public.search_vulnerabilities('fxparser');
  if n <> 1 then raise exception 'FAIL description search found % rows', n; end if;

  select count(*) into n from public.search_vulnerabilities('fxproduct');
  if n <> 1 then raise exception 'FAIL affected product search found % rows', n; end if;

  select count(*) into n from public.search_vulnerabilities('fxvendor');
  if n <> 1 then raise exception 'FAIL affected vendor search found % rows', n; end if;

  select count(*) into n from public.search_vulnerabilities('fxvuln fxvendor');
  if n <> 1 then raise exception 'FAIL terms do not match across title and vendor (%)', n; end if;

  select count(*) into n from public.search_vulnerabilities('fxvuln zzz-no-such-term');
  if n <> 0 then raise exception 'FAIL terms are not ANDed (%)', n; end if;

  select count(*) into n from public.search_vulnerabilities('fxvuln');
  if n <> 3 then raise exception 'FAIL a shared term found % rows instead of 3', n; end if;

  -- % and _ are literal characters, never wildcards.
  select array_agg(id) into ids from public.search_vulnerabilities('fx50%_off');
  if ids is distinct from array['eeeeeeee-0000-4000-8000-000000000002'::uuid] then
    raise exception 'FAIL literal %%_ search returned %', ids;
  end if;
  select array_agg(id) into ids from public.search_vulnerabilities('%');
  if 'eeeeeeee-0000-4000-8000-000000000001'::uuid = any (coalesce(ids, '{}')) then
    raise exception 'FAIL a lone percent sign acted as a wildcard';
  end if;

  select count(*) into n from public.search_vulnerabilities(null);
  if n < 3 then raise exception 'FAIL empty search does not return everything (%)', n; end if;

  reset role;
  raise notice 'ok - vulnerability search: id, title, description, product and vendor, ANDed terms, literal wildcards';
end $$;

-- 2. search and statistics respect access ---------------------------------------------------------
do $$
declare n int; blocked boolean;
begin
  set local role anon;
  blocked := false;
  begin
    perform * from public.search_vulnerabilities('fxvuln');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL anon can call search_vulnerabilities'; end if;
  blocked := false;
  begin
    perform * from public.vulnerability_severity_counts();
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL anon can call vulnerability_severity_counts'; end if;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'cccccccc-0000-4000-8000-000000000005', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.search_vulnerabilities('fxvuln');
  if n <> 0 then raise exception 'FAIL an inactive user found % vulnerabilities through search', n; end if;
  select coalesce(sum(total), 0) into n from public.vulnerability_severity_counts();
  if n <> 0 then raise exception 'FAIL an inactive user counted % vulnerabilities', n; end if;
  reset role;

  raise notice 'ok - vulnerability functions are denied to anon and show nothing to inactive users';
end $$;

-- 3. severity statistics --------------------------------------------------------------------------------
do $$
declare total_rows bigint; counted bigint; critical_total bigint; critical_exploited bigint;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'cccccccc-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;

  select count(*) into total_rows from public.vulnerabilities;
  select sum(total) into counted from public.vulnerability_severity_counts();
  if counted is distinct from total_rows then
    raise exception 'FAIL severity counts add up to % but there are % vulnerabilities', counted, total_rows;
  end if;

  select total, exploited into critical_total, critical_exploited
  from public.vulnerability_severity_counts() where severity = 'critical';
  if critical_total < 1 or critical_exploited < 1 then
    raise exception 'FAIL the critical row is missing or does not count the exploited fixture (% / %)', critical_total, critical_exploited;
  end if;
  if exists (select 1 from public.vulnerability_severity_counts() where exploited > total) then
    raise exception 'FAIL a severity row has more exploited than total';
  end if;

  reset role;
  raise notice 'ok - severity counts add up and count exploited records';
end $$;

-- 4. provenance --------------------------------------------------------------------------------------------
do $$
declare blocked boolean; o public.data_origin;
begin
  -- analysts cannot write vulnerabilities at all
  perform set_config('request.jwt.claims', json_build_object('sub', 'cccccccc-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.vulnerabilities (cve_id, title) values ('CVE-2099-2001', 'analyst attempt');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an analyst created a vulnerability'; end if;
  reset role;

  -- admins create local records only
  perform set_config('request.jwt.claims', json_build_object('sub', 'cccccccc-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.vulnerabilities (id, cve_id, title) values ('eeeeeeee-0000-4000-8000-000000000010', 'CVE-2099-2002', 'admin local record');
  select origin into o from public.vulnerabilities where id = 'eeeeeeee-0000-4000-8000-000000000010';
  if o is distinct from 'local' then raise exception 'FAIL default origin was %', o; end if;

  foreach o in array array['external', 'demo']::public.data_origin[] loop
    blocked := false;
    begin
      insert into public.vulnerabilities (cve_id, title, origin) values ('CVE-2099-3' || (case o when 'external' then '001' else '002' end), 'forged', o);
    exception when insufficient_privilege then blocked := true;
    end;
    if not blocked then raise exception 'FAIL an admin created a vulnerability with origin %', o; end if;
  end loop;

  -- relabelling is silently ignored, the rest of the update goes through
  update public.vulnerabilities set origin = 'external', severity = 'low' where id = 'eeeeeeee-0000-4000-8000-000000000010';
  select origin into o from public.vulnerabilities where id = 'eeeeeeee-0000-4000-8000-000000000010';
  if o is distinct from 'local' then raise exception 'FAIL an update relabelled origin to %', o; end if;
  if (select severity from public.vulnerabilities where id = 'eeeeeeee-0000-4000-8000-000000000010') <> 'low' then
    raise exception 'FAIL the rest of the update was lost';
  end if;
  reset role;

  raise notice 'ok - provenance: only admins write, only local records, no relabelling';
end $$;

-- 5. import_external_vulnerability ---------------------------------------------------------------------------
do $$
declare
  v_id uuid; v_again uuid; blocked boolean; got text; n int; r record;
  doc jsonb := jsonb_build_object(
    'cve_id', 'cve-2099-4001', 'title', 'Imported first', 'description', 'From the provider',
    'cvss_score', 8.8, 'cvss_vector', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'cvss_version', '3.1',
    'severity', 'high', 'exploit_status', 'poc_available', 'remediation', 'Update.',
    'reference_urls', jsonb_build_array('https://example.test/a', 'https://example.test/b'),
    'published_at', '2099-01-02T00:00:00Z', 'modified_at', '2099-02-03T00:00:00Z',
    'affected_products', jsonb_build_array(
      jsonb_build_object('vendor', 'FxVendor', 'product', 'One', 'affected_versions', '< 2.0', 'fixed_version', '2.0'),
      jsonb_build_object('vendor', 'FxVendor', 'product', 'Two'),
      jsonb_build_object('vendor', '', 'product', 'skipped because the vendor is blank')
    )
  );
begin
  -- clients cannot call it
  set local role anon;
  blocked := false;
  begin
    perform public.import_external_vulnerability(doc);
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL anon called import_external_vulnerability'; end if;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'cccccccc-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    perform public.import_external_vulnerability(doc);
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an admin called import_external_vulnerability through the client role'; end if;
  reset role;

  -- the service role creates an external record with its products (a service call carries no user)
  perform set_config('request.jwt.claims', json_build_object('role', 'service_role')::text, true);
  set local role service_role;
  v_id := public.import_external_vulnerability(doc);
  reset role;
  select * into r from public.vulnerabilities where id = v_id;
  if r.cve_id <> 'CVE-2099-4001' or r.origin <> 'external' or r.severity <> 'high'
     or r.exploit_status <> 'poc_available' or r.cvss_score <> 8.8 or r.cvss_version <> '3.1'
     or array_length(r.reference_urls, 1) <> 2 or r.created_by is not null then
    raise exception 'FAIL imported row is wrong: %', to_jsonb(r);
  end if;
  select count(*) into n from public.vulnerability_affected_products where vulnerability_id = v_id;
  if n <> 2 then raise exception 'FAIL % affected products were stored instead of 2 (blank vendor skipped)', n; end if;

  -- a second import refreshes the same row and replaces the products
  set local role service_role;
  v_again := public.import_external_vulnerability(doc || jsonb_build_object(
    'title', 'Imported again', 'affected_products', jsonb_build_array(jsonb_build_object('vendor', 'FxVendor', 'product', 'Three'))));
  reset role;
  if v_again <> v_id then raise exception 'FAIL a refresh created a second row'; end if;
  if (select title from public.vulnerabilities where id = v_id) <> 'Imported again' then
    raise exception 'FAIL the refresh did not update the title';
  end if;
  select count(*) into n from public.vulnerability_affected_products where vulnerability_id = v_id;
  if n <> 1 or not exists (select 1 from public.vulnerability_affected_products where vulnerability_id = v_id and product = 'Three') then
    raise exception 'FAIL the refresh did not replace the affected products (%)', n;
  end if;
  if (select origin from public.vulnerabilities where id = v_id) <> 'external' then
    raise exception 'FAIL the refresh changed the origin';
  end if;

  -- demo and local records are never overwritten
  foreach got in array array['CVE-2099-1001', 'CVE-2099-1002']::text[] loop
    set local role service_role;
    blocked := false;
    begin
      perform public.import_external_vulnerability(doc || jsonb_build_object('cve_id', got));
    exception when unique_violation then blocked := true;
    end;
    reset role;
    if not blocked then raise exception 'FAIL the import overwrote %', got; end if;
  end loop;
  if (select title from public.vulnerabilities where cve_id = 'CVE-2099-1001') <> 'fxvuln Alpha parser overflow' then
    raise exception 'FAIL a demo record was changed by a refused import';
  end if;

  -- input checks
  foreach got in array array['not-a-cve', '', 'CVE-99-1']::text[] loop
    set local role service_role;
    blocked := false;
    begin
      perform public.import_external_vulnerability(jsonb_build_object('cve_id', got));
    exception when invalid_parameter_value then blocked := true;
    end;
    reset role;
    if not blocked then raise exception 'FAIL the import accepted the id "%"', got; end if;
  end loop;

  set local role service_role;
  blocked := false;
  begin
    perform public.import_external_vulnerability(doc || jsonb_build_object('cve_id', 'CVE-2099-4002', 'cvss_score', 11));
  exception when check_violation then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL the import accepted a CVSS score above 10'; end if;

  raise notice 'ok - import_external_vulnerability: service role only, create, refresh, demo/local protected, input checks';
end $$;

rollback;
\echo VULNERABILITY DATABASE TESTS PASSED
