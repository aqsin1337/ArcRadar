-- import_external_vulnerabilities() and import_mitre_attack(): who may call them, provenance, what
-- they may never overwrite, atomic replacement of links, idempotency.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.

begin;

insert into auth.users (id, email) values
  ('ffffffff-0000-4000-8000-0000000000f1', 'feed-admin@arcradar.test');
update public.profiles set role_name = 'admin' where id = 'ffffffff-0000-4000-8000-0000000000f1';

-- 1. who may call them -----------------------------------------------------------------------------
do $$
declare blocked boolean; who text; fn text;
begin
  foreach fn in array array['import_external_vulnerabilities', 'import_mitre_attack'] loop
    foreach who in array array['anon', 'authenticated'] loop
      blocked := false;
      begin
        perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-0000000000f1', 'role', who)::text, true);
        execute format('set local role %I', who);
        if fn = 'import_mitre_attack' then
          perform public.import_mitre_attack('{}'::jsonb);
        else
          perform public.import_external_vulnerabilities('[]'::jsonb);
        end if;
      exception when insufficient_privilege then blocked := true;
      end;
      reset role;
      if not blocked then raise exception 'FAIL % could call %', who, fn; end if;
    end loop;
  end loop;

  set local role service_role;
  perform public.import_mitre_attack('{}'::jsonb);
  perform public.import_external_vulnerabilities('[]'::jsonb);
  reset role;
end $$;

-- 2. the feed and the catalog are on the Integrations list ---------------------------------------
do $$
begin
  if (select count(*) from public.integrations where provider in ('abusech', 'cisa_kev') and enabled) <> 2 then
    raise exception 'FAIL the feed integrations are missing or off by default';
  end if;
end $$;

-- 3. vulnerabilities in a batch --------------------------------------------------------------------
insert into public.vulnerabilities (cve_id, title, description, severity, origin, created_by) values
  ('CVE-2099-0002', 'mine', 'entered by hand', 'low', 'local', 'ffffffff-0000-4000-8000-0000000000f1');

create temp table vres (r jsonb);
grant all on vres to service_role;
do $$
begin
  set local role service_role;
  insert into vres select public.import_external_vulnerabilities($json$[
    {"cve_id": "CVE-2099-0001", "title": "fxfeed Example flaw", "description": "d", "severity": "high",
     "exploit_status": "exploited_in_wild", "remediation": "Patch it.",
     "reference_urls": ["https://example.test/a"], "published_at": "2026-01-01T00:00:00Z",
     "affected_products": [{"vendor": "Example", "product": "Widget"}]},
    {"cve_id": "CVE-2099-0002", "title": "machine title", "description": "machine", "severity": "critical"},
    {"cve_id": "not-a-cve", "title": "bad"},
    {"cve_id": "CVE-2099-0003", "title": "bad severity", "severity": "catastrophic"}
  ]$json$::jsonb);
  reset role;
end $$;

do $$
declare r jsonb; v public.vulnerabilities;
begin
  select vres.r into r from vres;
  if r <> '{"imported": 1, "updated": 0, "untouched": 1, "skipped": 2}'::jsonb then
    raise exception 'FAIL vulnerability batch summary is %', r;
  end if;
  select * into v from public.vulnerabilities where cve_id = 'CVE-2099-0001';
  if v.origin <> 'external' or v.exploit_status <> 'exploited_in_wild' or v.severity <> 'high' then
    raise exception 'FAIL imported CVE is %', to_jsonb(v);
  end if;
  if (select count(*) from public.vulnerability_affected_products where vulnerability_id = v.id) <> 1 then
    raise exception 'FAIL affected products were not stored';
  end if;
  select * into v from public.vulnerabilities where cve_id = 'CVE-2099-0002';
  if v.origin <> 'local' or v.title <> 'mine' or v.severity <> 'low' then
    raise exception 'FAIL a local CVE was overwritten: %', to_jsonb(v);
  end if;
  if exists (select 1 from public.vulnerabilities where cve_id in ('CVE-2099-0003')) then
    raise exception 'FAIL an invalid record was stored';
  end if;
  if (select last_sync_at from public.integrations where provider = 'cisa_kev') is null then
    raise exception 'FAIL last_sync_at was not set';
  end if;

  -- The same CVE again is a refresh, not a second import.
  set local role service_role;
  r := public.import_external_vulnerabilities(
    '[{"cve_id": "CVE-2099-0001", "title": "fxfeed Example flaw, renamed", "severity": "high"}]'::jsonb);
  reset role;
  if r <> '{"imported": 0, "updated": 1, "untouched": 0, "skipped": 0}'::jsonb then
    raise exception 'FAIL refresh summary is %', r;
  end if;
  if (select title from public.vulnerabilities where cve_id = 'CVE-2099-0001') <> 'fxfeed Example flaw, renamed' then
    raise exception 'FAIL an external CVE was not refreshed';
  end if;
end $$;

-- 4. MITRE: first import -----------------------------------------------------------------------------
-- A local actor and a local malware entry that share a name with catalog entries.
insert into public.threat_actors (name, description, origin, created_by) values
  ('FXMitre Local Actor', 'entered by hand', 'local', 'ffffffff-0000-4000-8000-0000000000f1');
insert into public.malware (name, description, origin, created_by) values
  ('FXMitre LocalWare', 'entered by hand', 'local', 'ffffffff-0000-4000-8000-0000000000f1');

create temp table mres (r jsonb);
grant all on mres to service_role;
do $$
begin
  set local role service_role;
  insert into mres select public.import_mitre_attack($json$
  {
    "techniques": [
      {"id": "T9901", "name": "FXMitre Technique One", "tactics": ["execution"], "description": "d1", "url": "https://example.test/T9901"},
      {"id": "T9901.001", "name": "FXMitre Sub", "tactics": ["execution", "persistence"]},
      {"id": "not-an-id", "name": "bad"}
    ],
    "malware": [
      {"name": "FXMitre Worm", "malware_type": "malware", "platforms": ["Windows"], "description": "w"},
      {"name": "fxmitre localware", "description": "machine"}
    ],
    "campaigns": [
      {"name": "FXMitre Recent Campaign", "description": "c", "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-09-01T00:00:00Z"},
      {"name": "FXMitre Old Campaign", "first_seen": "2015-01-01T00:00:00Z", "last_seen": "2016-01-01T00:00:00Z"}
    ],
    "actors": [
      {"name": "FXMitre Group", "aliases": ["FX-Alias"], "description": "g",
       "first_seen": "2020-01-01T00:00:00Z", "last_seen": "2026-01-01T00:00:00Z",
       "technique_ids": ["T9901", "T9901.001", "T0000-unknown"], "malware_names": ["FXMitre Worm", "FXMitre LocalWare"],
       "campaign_names": ["FXMitre Recent Campaign"]},
      {"name": "fxmitre local actor", "description": "machine", "technique_ids": ["T9901"], "malware_names": ["FXMitre Worm"]}
    ]
  }
  $json$::jsonb);
  reset role;
end $$;

do $$
declare r jsonb; a public.threat_actors; c public.campaigns; local_actor uuid;
begin
  select mres.r into r from mres;
  if r <> '{"actors": 1, "malware": 1, "skipped": 3, "campaigns": 2, "techniques": 2}'::jsonb then
    raise exception 'FAIL first MITRE summary is %', r;
  end if;

  if (select count(*) from public.mitre_techniques where id like 'T9901%') <> 2 then
    raise exception 'FAIL techniques were not stored';
  end if;

  select * into a from public.threat_actors where name = 'FXMitre Group';
  if a.origin <> 'external' or a.created_by is not null or a.aliases <> array['FX-Alias'] then
    raise exception 'FAIL actor stored as %', to_jsonb(a);
  end if;
  if (select count(*) from public.threat_actor_techniques where threat_actor_id = a.id) <> 2 then
    raise exception 'FAIL an unknown technique id was linked, or a known one was not';
  end if;
  -- only the external malware is linked, never the local one with a matching name
  if (select array_agg(m.name) from public.threat_actor_malware l join public.malware m on m.id = l.malware_id
        where l.threat_actor_id = a.id) is distinct from array['FXMitre Worm'] then
    raise exception 'FAIL actor malware links are wrong';
  end if;
  if (select count(*) from public.threat_actor_campaigns where threat_actor_id = a.id) <> 1 then
    raise exception 'FAIL campaign link missing';
  end if;

  select * into c from public.campaigns where name = 'FXMitre Recent Campaign';
  if c.origin <> 'external' or c.status <> 'active' then raise exception 'FAIL recent campaign is %', to_jsonb(c); end if;
  select * into c from public.campaigns where name = 'FXMitre Old Campaign';
  if c.status <> 'concluded' then raise exception 'FAIL old campaign is %', to_jsonb(c); end if;

  -- the local records and their links are untouched
  select id into local_actor from public.threat_actors where name = 'FXMitre Local Actor';
  select * into a from public.threat_actors where id = local_actor;
  if a.origin <> 'local' or a.description <> 'entered by hand' then
    raise exception 'FAIL a local actor was overwritten: %', to_jsonb(a);
  end if;
  if exists (select 1 from public.threat_actor_techniques where threat_actor_id = local_actor)
     or exists (select 1 from public.threat_actor_malware where threat_actor_id = local_actor) then
    raise exception 'FAIL a local actor received links';
  end if;
  if (select description from public.malware where name = 'FXMitre LocalWare') <> 'entered by hand'
     or (select origin from public.malware where name = 'FXMitre LocalWare') <> 'local' then
    raise exception 'FAIL a local malware entry was overwritten';
  end if;
end $$;

-- 5. MITRE: a second import refreshes, replaces the links as a whole, and creates nothing twice ------
do $$
declare before_actors int; before_malware int; a public.threat_actors;
begin
  select count(*) into before_actors from public.threat_actors;
  select count(*) into before_malware from public.malware;

  set local role service_role;
  perform public.import_mitre_attack($json$
  {
    "techniques": [{"id": "T9901", "name": "FXMitre Technique One Renamed", "tactics": ["impact"]}],
    "actors": [
      {"name": "FXMitre Group", "aliases": ["FX-Alias", "FX-Alias-2"], "description": "g2",
       "technique_ids": ["T9901"], "malware_names": [], "campaign_names": []}
    ]
  }
  $json$::jsonb);
  reset role;

  if (select count(*) from public.threat_actors) <> before_actors
     or (select count(*) from public.malware) <> before_malware then
    raise exception 'FAIL the second import created duplicates';
  end if;
  if (select name from public.mitre_techniques where id = 'T9901') <> 'FXMitre Technique One Renamed' then
    raise exception 'FAIL a technique was not refreshed';
  end if;
  select * into a from public.threat_actors where name = 'FXMitre Group';
  if a.description <> 'g2' or cardinality(a.aliases) <> 2 then raise exception 'FAIL actor not refreshed'; end if;
  if (select count(*) from public.threat_actor_techniques where threat_actor_id = a.id) <> 1
     or exists (select 1 from public.threat_actor_malware where threat_actor_id = a.id)
     or exists (select 1 from public.threat_actor_campaigns where threat_actor_id = a.id) then
    raise exception 'FAIL links were not replaced as a whole';
  end if;
end $$;

-- 6. the shape of the call is validated ------------------------------------------------------------
do $$
declare refused boolean := false;
begin
  set local role service_role;
  begin
    perform public.import_mitre_attack('[]'::jsonb);
  exception when sqlstate '22023' then refused := true;
  end;
  if not refused then raise exception 'FAIL a non-object was accepted'; end if;

  refused := false;
  begin
    perform public.import_external_vulnerabilities('{"a": 1}'::jsonb);
  exception when sqlstate '22023' then refused := true;
  end;
  if not refused then
    reset role;
    raise exception 'FAIL a non-array vulnerability batch was accepted';
  end if;

  refused := false;
  begin
    perform public.import_external_vulnerabilities(
      (select jsonb_agg(jsonb_build_object('cve_id', 'CVE-2098-' || lpad(g::text, 5, '0'))) from generate_series(1, 3001) g));
  exception when sqlstate '22023' then refused := true;
  end;
  reset role;
  if not refused then raise exception 'FAIL an oversized vulnerability batch was accepted'; end if;
end $$;

rollback;
select 'feeds_and_mitre: all checks passed' as result;
