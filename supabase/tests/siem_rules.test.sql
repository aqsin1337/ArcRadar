-- SIEM detection rules (Splunk and later SIEMs): permissions, provenance, shape checks, the
-- identity and push invariants.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 SOC L2, ...0003 viewer.

begin;

insert into auth.users (id, email) values
  ('e5e5e5e5-0000-4000-8000-000000000001', 'fxsr-admin@arcradar.test'),
  ('e5e5e5e5-0000-4000-8000-000000000002', 'fxsr-l2@arcradar.test'),
  ('e5e5e5e5-0000-4000-8000-000000000003', 'fxsr-viewer@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'e5e5e5e5-0000-4000-8000-000000000001';
update public.profiles set role_name = 'soc_l2' where id = 'e5e5e5e5-0000-4000-8000-000000000002';

-- 1. Only rules:manage (admin) reads or writes; always local, always a draft on insert.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; visible int; o public.data_origin; st text;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e5e5e5e5-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.siem_rules (siem, rule_key, name, severity, spec, source)
    values ('splunk', 'fxsr1', 'fxsr admin rule', 'high', '{"index": "main"}', 'manual');
  select origin, status into o, st from public.siem_rules where rule_key = 'fxsr1';
  if o <> 'local' or st <> 'draft' then
    raise exception 'FAIL an admin-created rule was origin % / status %', o, st;
  end if;

  blocked := false;
  begin
    insert into public.siem_rules (siem, rule_key, name, severity, spec, source, origin)
      values ('splunk', 'fxsr2', 'fxsr forged origin', 'low', '{}', 'manual', 'external');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a SIEM rule was created with origin external'; end if;

  blocked := false;
  begin
    insert into public.siem_rules (siem, rule_key, name, severity, spec, source, status, github_path)
      values ('splunk', 'fxsr3', 'fxsr born pushed', 'low', '{}', 'manual', 'pushed', 'splunk/x.conf');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a SIEM rule was created already pushed'; end if;

  update public.siem_rules set origin = 'demo', name = 'fxsr admin rule (edited)' where rule_key = 'fxsr1';
  select origin into o from public.siem_rules where rule_key = 'fxsr1';
  if o <> 'local' then raise exception 'FAIL an update relabelled a SIEM rule to %', o; end if;
  reset role;

  foreach st in array array['e5e5e5e5-0000-4000-8000-000000000002', 'e5e5e5e5-0000-4000-8000-000000000003'] loop
    perform set_config('request.jwt.claims', json_build_object('sub', st, 'role', 'authenticated')::text, true);
    set local role authenticated;
    select count(*) into visible from public.siem_rules;
    if visible <> 0 then raise exception 'FAIL a non-admin saw % SIEM rules', visible; end if;
    blocked := false;
    begin
      insert into public.siem_rules (siem, rule_key, name, severity, spec, source)
        values ('splunk', 'fxsr4', 'fxsr non-admin', 'low', '{}', 'manual');
    exception when insufficient_privilege then blocked := true;
    end;
    if not blocked then raise exception 'FAIL a non-admin created a SIEM rule'; end if;
    update public.siem_rules set name = 'hijacked' where rule_key = 'fxsr1';
    reset role;
    if (select name from public.siem_rules where rule_key = 'fxsr1') = 'hijacked' then
      raise exception 'FAIL a non-admin edited a SIEM rule';
    end if;
  end loop;

  raise notice 'ok - siem_rules: admin only, always local and draft on insert, never relabelled';
end $$;

-- 2. Shape checks.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; t text;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e5e5e5e5-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;

  foreach t in array array[
    $q$values ('qradar', 'fxsr10', 'fxsr unknown siem', 'low', '{}', '{}', 'manual')$q$,
    $q$values ('splunk', 'a b', 'fxsr key with space', 'low', '{}', '{}', 'manual')$q$,
    $q$values ('splunk', '[evil]', 'fxsr key with bracket', 'low', '{}', '{}', 'manual')$q$,
    $q$values ('splunk', 'fxsr11', '', 'low', '{}', '{}', 'manual')$q$,
    $q$values ('splunk', 'fxsr12', 'fxsr bad severity', 'urgent', '{}', '{}', 'manual')$q$,
    $q$values ('splunk', 'fxsr13', 'fxsr array spec', 'low', '[]', '{}', 'manual')$q$,
    $q$values ('splunk', 'fxsr14', 'fxsr bad mitre', 'low', '{}', '{"nope"}', 'manual')$q$,
    $q$values ('splunk', 'fxsr15', 'fxsr bad source', 'low', '{}', '{}', 'robot')$q$,
    $q$values ('splunk', 'fxsr16', 'fxsr huge spec', 'low', jsonb_build_object('x', repeat('a', 9000)), '{}', 'manual')$q$
  ] loop
    blocked := false;
    begin
      execute 'insert into public.siem_rules (siem, rule_key, name, severity, spec, mitre_ids, source) ' || t;
    exception when check_violation then blocked := true;
    end;
    if not blocked then raise exception 'FAIL a bad rule was accepted: %', t; end if;
  end loop;

  -- the same key twice for one SIEM is a conflict
  blocked := false;
  begin
    insert into public.siem_rules (siem, rule_key, name, severity, spec, source)
      values ('splunk', 'fxsr1', 'fxsr duplicate key', 'low', '{}', 'manual');
  exception when unique_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a duplicate rule key was accepted'; end if;

  -- a manual rule cannot carry an AI prompt
  blocked := false;
  begin
    insert into public.siem_rules (siem, rule_key, name, severity, spec, source, ai_prompt)
      values ('splunk', 'fxsr17', 'fxsr manual with prompt', 'low', '{}', 'manual', 'draft me a rule');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a manual rule carried an ai_prompt'; end if;

  insert into public.siem_rules (siem, rule_key, name, severity, spec, mitre_ids, source)
    values ('splunk', 'fxsr18', 'fxsr mitre ok', 'low', '{}', '{T1110,T1562.001}', 'manual');

  reset role;
  raise notice 'ok - siem_rules: siem, key, severity, spec, MITRE and source shapes enforced by the database';
end $$;

-- 3. The SIEM and the key (they name a file in the repository) cannot change.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e5e5e5e5-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;

  blocked := false;
  begin
    update public.siem_rules set rule_key = 'fxsr-renamed' where rule_key = 'fxsr1';
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a rule key was changed'; end if;

  reset role;
  raise notice 'ok - siem_rules: the key cannot change';
end $$;

-- 4. A pushed rule needs its repository path, and cannot be deleted from ArcRadar.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; gone int;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e5e5e5e5-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;

  blocked := false;
  begin
    update public.siem_rules set status = 'pushed' where rule_key = 'fxsr1';
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a rule became pushed without a repository path'; end if;

  update public.siem_rules
    set status = 'pushed', github_path = 'splunk/arcradar_fxsr1.conf', github_commit = 'abc123', pushed_at = now()
    where rule_key = 'fxsr1';

  delete from public.siem_rules where rule_key = 'fxsr1';
  select count(*) into gone from public.siem_rules where rule_key = 'fxsr1';
  if gone <> 1 then raise exception 'FAIL a pushed SIEM rule was deleted'; end if;

  delete from public.siem_rules where rule_key = 'fxsr18';
  select count(*) into gone from public.siem_rules where rule_key = 'fxsr18';
  if gone <> 0 then raise exception 'FAIL a draft SIEM rule could not be deleted'; end if;

  reset role;
  raise notice 'ok - siem_rules: pushed requires a path and is never deleted from ArcRadar';
end $$;

rollback;

do $$ begin raise notice 'SIEM RULES DATABASE TESTS PASSED'; end $$;
