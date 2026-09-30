-- Wazuh detection rules (detection-as-code): permissions, provenance, shape checks, the push
-- invariants and the trigger statistics.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer.

begin;

insert into auth.users (id, email) values
  ('e4e4e4e4-0000-4000-8000-000000000001', 'fxwr-admin@arcradar.test'),
  ('e4e4e4e4-0000-4000-8000-000000000002', 'fxwr-analyst@arcradar.test'),
  ('e4e4e4e4-0000-4000-8000-000000000003', 'fxwr-viewer@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'e4e4e4e4-0000-4000-8000-000000000001';
update public.profiles set role_name = 'analyst' where id = 'e4e4e4e4-0000-4000-8000-000000000002';

-- 1. Only rules:manage (admin) reads or writes; always local, always a draft on insert.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; visible int; o public.data_origin; st text;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e4e4e4e4-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.wazuh_rules (id, name, level, conditions, source)
    values (100200, 'fxwr admin rule', 10,
      '[{"field": "win.eventdata.commandLine", "op": "contains", "value": "x"}]', 'manual');
  select origin, status into o, st from public.wazuh_rules where id = 100200;
  if o <> 'local' or st <> 'draft' then
    raise exception 'FAIL an admin-created rule was origin % / status %', o, st;
  end if;

  -- a client cannot claim another origin, nor create a rule as already pushed
  blocked := false;
  begin
    insert into public.wazuh_rules (id, name, level, conditions, source, origin)
      values (100201, 'fxwr forged origin', 5, '[{"field": "win.a", "op": "contains", "value": "x"}]', 'manual', 'external');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a Wazuh rule was created with origin external'; end if;

  blocked := false;
  begin
    insert into public.wazuh_rules (id, name, level, conditions, source, status, github_path)
      values (100202, 'fxwr born pushed', 5, '[{"field": "win.a", "op": "contains", "value": "x"}]', 'manual', 'pushed', 'rules/x.xml');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a Wazuh rule was created already pushed'; end if;

  -- an update cannot relabel the origin
  update public.wazuh_rules set origin = 'demo', name = 'fxwr admin rule (edited)' where id = 100200;
  select origin into o from public.wazuh_rules where id = 100200;
  if o <> 'local' then raise exception 'FAIL an update relabelled a Wazuh rule to %', o; end if;
  reset role;

  -- an analyst and a viewer neither see nor write rules
  foreach st in array array['e4e4e4e4-0000-4000-8000-000000000002', 'e4e4e4e4-0000-4000-8000-000000000003'] loop
    perform set_config('request.jwt.claims', json_build_object('sub', st, 'role', 'authenticated')::text, true);
    set local role authenticated;
    select count(*) into visible from public.wazuh_rules;
    if visible <> 0 then raise exception 'FAIL a non-admin saw % Wazuh rules', visible; end if;
    blocked := false;
    begin
      insert into public.wazuh_rules (id, name, level, conditions, source)
        values (100203, 'fxwr non-admin', 5, '[{"field": "win.a", "op": "contains", "value": "x"}]', 'manual');
    exception when insufficient_privilege then blocked := true;
    end;
    if not blocked then raise exception 'FAIL a non-admin created a Wazuh rule'; end if;
    update public.wazuh_rules set name = 'hijacked' where id = 100200;
    reset role;
    if (select name from public.wazuh_rules where id = 100200) = 'hijacked' then
      raise exception 'FAIL a non-admin edited a Wazuh rule';
    end if;
  end loop;

  raise notice 'ok - wazuh_rules: admin only, always local and draft on insert, never relabelled';
end $$;

-- 2. Shape checks.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; t text;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e4e4e4e4-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- each case must be refused by a check constraint
  foreach t in array array[
    $q$values (99999, 'fxwr id low', 5, 'group', 'windows', '[{"a":1}]', '{}', 'manual')$q$,
    $q$values (1000000, 'fxwr id high', 5, 'group', 'windows', '[{"a":1}]', '{}', 'manual')$q$,
    $q$values (100210, 'fxwr level 0', 0, 'group', 'windows', '[{"a":1}]', '{}', 'manual')$q$,
    $q$values (100211, 'fxwr level 16', 16, 'group', 'windows', '[{"a":1}]', '{}', 'manual')$q$,
    $q$values (100212, 'fxwr empty conditions', 5, 'group', 'windows', '[]', '{}', 'manual')$q$,
    $q$values (100213, 'fxwr object conditions', 5, 'group', 'windows', '{"a":1}', '{}', 'manual')$q$,
    $q$values (100214, 'fxwr bad parent kind', 5, 'command', 'windows', '[{"a":1}]', '{}', 'manual')$q$,
    $q$values (100215, 'fxwr injected parent', 5, 'group', 'windows</if_group><active-response>', '[{"a":1}]', '{}', 'manual')$q$,
    $q$values (100216, 'fxwr bad mitre', 5, 'group', 'windows', '[{"a":1}]', '{"not-a-technique"}', 'manual')$q$,
    $q$values (100217, 'fxwr bad source', 5, 'group', 'windows', '[{"a":1}]', '{}', 'robot')$q$
  ] loop
    blocked := false;
    begin
      execute 'insert into public.wazuh_rules (id, name, level, parent_kind, parent_value, conditions, mitre_ids, source) ' || t;
    exception when check_violation then blocked := true;
    end;
    if not blocked then raise exception 'FAIL a bad rule was accepted: %', t; end if;
  end loop;

  -- a duplicate id is a conflict
  blocked := false;
  begin
    insert into public.wazuh_rules (id, name, level, conditions, source)
      values (100200, 'fxwr duplicate id', 5, '[{"a":1}]', 'manual');
  exception when unique_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a duplicate Wazuh rule id was accepted'; end if;

  -- a manual rule cannot carry an AI prompt
  blocked := false;
  begin
    insert into public.wazuh_rules (id, name, level, conditions, source, ai_prompt)
      values (100218, 'fxwr manual with prompt', 5, '[{"a":1}]', 'manual', 'draft me a rule');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a manual rule carried an ai_prompt'; end if;

  -- valid MITRE ids (technique and sub-technique) are fine
  insert into public.wazuh_rules (id, name, level, conditions, mitre_ids, source)
    values (100219, 'fxwr mitre ok', 5, '[{"a":1}]', '{T1562.001,T1059}', 'manual');

  reset role;
  raise notice 'ok - wazuh_rules: id, level, conditions, parent, MITRE and source shapes enforced by the database';
end $$;

-- 3. A pushed rule needs its repository path, and cannot be deleted from ArcRadar.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; gone int;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e4e4e4e4-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;

  blocked := false;
  begin
    update public.wazuh_rules set status = 'pushed' where id = 100200;
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a rule became pushed without a repository path'; end if;

  update public.wazuh_rules
    set status = 'pushed', github_path = 'rules/arcradar_100200.xml', github_commit = 'abc123', pushed_at = now()
    where id = 100200;

  delete from public.wazuh_rules where id = 100200;
  select count(*) into gone from public.wazuh_rules where id = 100200;
  if gone <> 1 then raise exception 'FAIL a pushed Wazuh rule was deleted'; end if;

  -- a draft and a rejected rule can be deleted
  delete from public.wazuh_rules where id = 100219;
  select count(*) into gone from public.wazuh_rules where id = 100219;
  if gone <> 0 then raise exception 'FAIL a draft Wazuh rule could not be deleted'; end if;

  reset role;
  raise notice 'ok - wazuh_rules: pushed requires a path and is never deleted from ArcRadar';
end $$;

-- 4. wazuh_rule_trigger_stats(): counts alerts by the rule id in their description, ignores
--    duplicates and non-Wazuh alerts, and is not open to anonymous callers.
-- ---------------------------------------------------------------------------------------------
do $$
declare got bigint; blocked boolean;
begin
  insert into public.alerts (title, description, severity, status, source, origin, created_at) values
    ('fxwr a1', 'Wazuh rule 100200 (level 10) on WIN10. Location: x.', 'high', 'new', 'wazuh', 'external', now() - interval '3 hours'),
    ('fxwr a2', 'Wazuh rule 100200 (level 10) on WIN10. Location: y.', 'high', 'new', 'wazuh', 'external', now() - interval '2 hours'),
    ('fxwr a3', 'Wazuh rule 100201 (level 4) on WIN10.', 'low', 'new', 'wazuh', 'external', now()),
    ('fxwr a4', 'Wazuh rule 100200 (level 10) typed by a person.', 'high', 'new', 'manual', 'local', now()),
    ('fxwr a5', 'Something about Wazuh rule 100200 (level 10) in the middle.', 'high', 'new', 'wazuh', 'external', now());

  select triggers into got from public.wazuh_rule_trigger_stats() where rule_id = 100200;
  if got <> 2 then raise exception 'FAIL rule 100200 counted % triggers, expected 2', got; end if;
  select triggers into got from public.wazuh_rule_trigger_stats() where rule_id = 100201;
  if got <> 1 then raise exception 'FAIL rule 100201 counted % triggers, expected 1', got; end if;
  if (select last_triggered from public.wazuh_rule_trigger_stats() where rule_id = 100200)
       > now() - interval '90 minutes' then
    raise exception 'FAIL the last trigger time of rule 100200 is wrong';
  end if;

  set local role anon;
  blocked := false;
  begin
    perform * from public.wazuh_rule_trigger_stats();
  exception when insufficient_privilege then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL an anonymous caller could read the trigger statistics'; end if;

  raise notice 'ok - wazuh_rule_trigger_stats: counts by rule id, Wazuh alerts only, not open to anon';
end $$;

-- 5. Repeating rules: count and window come together, same_fields need repetition, and only a
--    repeating rule may have no conditions.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; t text;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'e4e4e4e4-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;

  foreach t in array array[
    $q$select 100230, 'fxwr count only', '[{"a":1}]'::jsonb, 5, null::int, '{}'::text[]$q$,
    $q$select 100231, 'fxwr window only', '[{"a":1}]'::jsonb, null::int, 300, '{}'::text[]$q$,
    $q$select 100232, 'fxwr count of 1', '[{"a":1}]'::jsonb, 1, 300, '{}'::text[]$q$,
    $q$select 100233, 'fxwr zero window', '[{"a":1}]'::jsonb, 5, 0, '{}'::text[]$q$,
    $q$select 100236, 'fxwr window over a day', '[{"a":1}]'::jsonb, 5, 86401, '{}'::text[]$q$,
    $q$select 100237, 'fxwr same field without repetition', '[{"a":1}]'::jsonb, null::int, null::int, '{win.a}'::text[]$q$,
    $q$select 100238, 'fxwr injected same field', '[{"a":1}]'::jsonb, 5, 300, array['x</same_field><command>']$q$,
    $q$select 100239, 'fxwr four same fields', '[{"a":1}]'::jsonb, 5, 300, '{a,b,c,d}'::text[]$q$,
    $q$select 100240, 'fxwr plain rule without conditions', '[]'::jsonb, null::int, null::int, '{}'::text[]$q$
  ] loop
    blocked := false;
    begin
      execute 'insert into public.wazuh_rules (id, name, conditions, frequency, timeframe, same_fields, level, source) select v.*, 5, ''manual'' from (' || t || ') as v(id, name, conditions, frequency, timeframe, same_fields)';
    exception when check_violation then blocked := true;
    end;
    if not blocked then raise exception 'FAIL a bad repeating rule was accepted: %', t; end if;
  end loop;

  -- a repeating rule with no conditions of its own, and with same_fields, is valid
  insert into public.wazuh_rules (id, name, level, parent_value, conditions, frequency, timeframe, same_fields, source)
    values (100241, 'fxwr five failures in five minutes', 10, 'authentication_failed', '[]', 5, 300, '{win.eventdata.ipAddress}', 'manual');

  reset role;
  raise notice 'ok - wazuh_rules: count and window together, same_fields only with repetition, conditions optional only when repeating';
end $$;

rollback;

do $$ begin raise notice 'WAZUH RULES DATABASE TESTS PASSED'; end $$;
