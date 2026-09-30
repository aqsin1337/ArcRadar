-- Phase 10: alert deduplication and custom detection rules.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer.

begin;

insert into auth.users (id, email) values
  ('d3d3d3d3-0000-4000-8000-000000000001', 'fxdr-admin@arcradar.test'),
  ('d3d3d3d3-0000-4000-8000-000000000002', 'fxdr-analyst@arcradar.test'),
  ('d3d3d3d3-0000-4000-8000-000000000003', 'fxdr-viewer@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'd3d3d3d3-0000-4000-8000-000000000001';
update public.profiles set role_name = 'soc_l2' where id = 'd3d3d3d3-0000-4000-8000-000000000002';

-- 1. detection_rules: permissions, provenance, id range and conditions shape.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; o public.data_origin;
begin
  -- a viewer can read the catalog (alerts:read) but not write it
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.detection_rules (id, name, conditions)
      values (100001, 'fx viewer rule', '[{"field": "source", "op": "eq", "value": "manual"}]');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a viewer created a detection rule'; end if;
  reset role;

  -- an analyst cannot manage rules either: rules:manage is admin only, unlike response_actions
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.detection_rules (id, name, conditions)
      values (100002, 'fx analyst rule', '[{"field": "source", "op": "eq", "value": "manual"}]');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an analyst created a detection rule'; end if;
  reset role;

  -- an admin creates one, always local, as themselves
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.detection_rules (id, name, conditions)
    values (100003, 'fx admin rule', '[{"field": "source", "op": "eq", "value": "manual"}]');
  select origin into o from public.detection_rules where id = 100003;
  if o <> 'local' then raise exception 'FAIL a client-created detection rule was origin %', o; end if;

  -- a client cannot claim origin external or demo directly, nor relabel one after the fact
  blocked := false;
  begin
    insert into public.detection_rules (id, name, conditions, origin)
      values (100004, 'fx forged origin', '[{"field": "source", "op": "eq", "value": "manual"}]', 'external');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a detection rule was created with origin external'; end if;

  update public.detection_rules set origin = 'demo', name = 'fx admin rule (edited)' where id = 100003;
  select origin into o from public.detection_rules where id = 100003;
  if o <> 'local' then raise exception 'FAIL an update relabelled a detection rule to %', o; end if;
  if (select name from public.detection_rules where id = 100003) <> 'fx admin rule (edited)' then
    raise exception 'FAIL the rest of the update was lost';
  end if;

  -- the id must sit in the reserved 100000-999999 band
  blocked := false;
  begin
    insert into public.detection_rules (id, name, conditions)
      values (99999, 'fx too low', '[{"field": "source", "op": "eq", "value": "manual"}]');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a rule id below 100000 was accepted'; end if;

  blocked := false;
  begin
    insert into public.detection_rules (id, name, conditions)
      values (1000000, 'fx too high', '[{"field": "source", "op": "eq", "value": "manual"}]');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a rule id above 999999 was accepted'; end if;

  -- conditions must be a non-empty array of at most 10
  blocked := false;
  begin
    insert into public.detection_rules (id, name, conditions) values (100005, 'fx empty conditions', '[]');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an empty conditions array was accepted'; end if;

  -- a duplicate id is a conflict, not a silent overwrite
  blocked := false;
  begin
    insert into public.detection_rules (id, name, conditions)
      values (100003, 'fx duplicate id', '[{"field": "source", "op": "eq", "value": "manual"}]');
  exception when unique_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a duplicate rule id was accepted'; end if;

  delete from public.detection_rules where id = 100003;
  reset role;

  raise notice 'ok - detection_rules: rules:manage (admin only) to write, always local, never relabelled, id/shape enforced';
end $$;

-- 2. Rule matching: AND semantics, raise-only severity, priority order, disabled rules, tracing.
-- ---------------------------------------------------------------------------------------------
do $$
declare rule_id int; new_id uuid; got_severity public.severity; got_rule int;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.detection_rules (id, name, conditions, severity, priority) values
    (100010, 'fx ransomware watch', '[{"field": "title", "op": "contains", "value": "ransom"}]', 'critical', 50),
    (100011, 'fx manual+high AND', '[{"field": "source", "op": "eq", "value": "manual"}, {"field": "severity", "op": "eq", "value": "high"}]', 'critical', 60),
    (100012, 'fx disabled watch', '[{"field": "title", "op": "contains", "value": "quiet"}]', 'critical', 10);
  update public.detection_rules set enabled = false where id = 100012;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- a match raises severity and records which rule fired
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Ransomware file encryption pattern', 'medium', 'new', 'manual', 'local')
    returning id into new_id;
  select severity, matched_rule_id into got_severity, got_rule from public.alerts where id = new_id;
  if got_severity <> 'critical' or got_rule <> 100010 then
    raise exception 'FAIL a matching rule did not raise severity/trace itself (got % / %)', got_severity, got_rule;
  end if;

  -- a match never lowers an already-higher severity, but still traces itself
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Ransomware already critical', 'critical', 'new', 'manual', 'local')
    returning id into new_id;
  select severity, matched_rule_id into got_severity, got_rule from public.alerts where id = new_id;
  if got_severity <> 'critical' or got_rule <> 100010 then
    raise exception 'FAIL severity was changed or tracing lost for an already-critical alert (got % / %)', got_severity, got_rule;
  end if;

  -- AND semantics: both conditions of 100011 must match, not just one
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx AND partial only source', 'low', 'new', 'manual', 'local')
    returning id into new_id;
  select matched_rule_id into got_rule from public.alerts where id = new_id;
  if got_rule is not null then raise exception 'FAIL a rule matched with only one of its two conditions true'; end if;

  insert into public.alerts (title, severity, status, source, origin)
    values ('fx AND both source and severity', 'high', 'new', 'manual', 'local')
    returning id into new_id;
  select severity, matched_rule_id into got_severity, got_rule from public.alerts where id = new_id;
  if got_severity <> 'critical' or got_rule <> 100011 then
    raise exception 'FAIL an alert matching both AND conditions was not raised/traced (got % / %)', got_severity, got_rule;
  end if;

  -- a disabled rule is never even considered
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx a quiet moment', 'low', 'new', 'manual', 'local')
    returning id into new_id;
  select severity, matched_rule_id into got_severity, got_rule from public.alerts where id = new_id;
  if got_rule is not null or got_severity <> 'low' then
    raise exception 'FAIL a disabled rule still matched (got % / %)', got_severity, got_rule;
  end if;

  -- a rule field/op the database's own matcher does not recognize never matches -- it fails closed,
  -- not open, even though only the application's Zod schema (not a DB constraint) normally keeps a
  -- client from writing one.
  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.detection_rules (id, name, conditions, severity, priority)
    values (100015, 'fx unrecognized field', '[{"field": "totally_unknown", "op": "eq", "value": "x"}]', 'critical', 1);
  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx anything at all', 'low', 'new', 'manual', 'local')
    returning id into new_id;
  select matched_rule_id into got_rule from public.alerts where id = new_id;
  if got_rule = 100015 then raise exception 'FAIL an unrecognized (field, op) pair matched anyway'; end if;

  -- the highest-priority (lowest number) match wins when more than one rule would match
  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.detection_rules (id, name, conditions, severity, priority) values
    (100013, 'fx beacon low priority', '[{"field": "title", "op": "contains", "value": "beacon"}]', 'high', 80),
    (100014, 'fx beacon high priority', '[{"field": "title", "op": "contains", "value": "beacon"}]', 'critical', 5);
  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx beacon activity observed', 'low', 'new', 'manual', 'local')
    returning id into new_id;
  select severity, matched_rule_id into got_severity, got_rule from public.alerts where id = new_id;
  if got_rule <> 100014 or got_severity <> 'critical' then
    raise exception 'FAIL the lower-priority-number rule did not win (got % / %)', got_severity, got_rule;
  end if;

  reset role;

  -- deleting a rule clears the trace on any alert it matched, never the alert itself
  delete from public.detection_rules where id = 100010;
  if exists (select 1 from public.alerts where matched_rule_id = 100010) then
    raise exception 'FAIL a deleted rule''s id survived on an alert';
  end if;

  rule_id := (select count(*) from public.detection_rules where id in (100011, 100013, 100014));
  if rule_id <> 3 then raise exception 'FAIL fixture rules went missing unexpectedly'; end if;

  raise notice 'ok - rule matching: AND conditions, severity only ever rises, highest priority wins, disabled rules skipped, matched_rule_id traces and clears on delete';
end $$;

-- 3. Deduplication: fingerprint, still-open only, the 60-minute window.
-- ---------------------------------------------------------------------------------------------
do $$
declare first_id uuid; second_id uuid; third_id uuid; got_dup uuid; got_count int; got_status public.alert_status;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- a first occurrence is its own primary
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Suspicious login from 192.0.2.201', 'medium', 'new', 'manual', 'local')
    returning id into first_id;
  select duplicate_of, duplicate_count into got_dup, got_count from public.alerts where id = first_id;
  if got_dup is not null or got_count <> 0 then
    raise exception 'FAIL a first occurrence was not its own primary (dup_of=%, count=%)', got_dup, got_count;
  end if;

  -- a second, identical occurrence links to the first instead of opening a fresh row
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Suspicious login from 192.0.2.201', 'medium', 'new', 'manual', 'local')
    returning id into second_id;
  select duplicate_of into got_dup from public.alerts where id = second_id;
  if got_dup <> first_id then raise exception 'FAIL a duplicate did not link to the first occurrence'; end if;
  select duplicate_count into got_count from public.alerts where id = first_id;
  if got_count <> 1 then raise exception 'FAIL the primary''s duplicate_count did not reach 1 (got %)', got_count; end if;

  -- a resolved primary does not attract a further duplicate: a recurrence opens a fresh one
  update public.alerts set status = 'resolved', resolved_at = now() where id = first_id;
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Suspicious login from 192.0.2.201', 'medium', 'new', 'manual', 'local')
    returning id into third_id;
  select duplicate_of into got_dup from public.alerts where id = third_id;
  if got_dup is not null then raise exception 'FAIL a new occurrence linked to an already-resolved primary'; end if;
  select duplicate_count into got_count from public.alerts where id = first_id;
  if got_count <> 1 then raise exception 'FAIL a resolved primary''s duplicate_count changed (got %)', got_count; end if;

  -- structural invariants hold even on a direct update (defense in depth: the app never sends these
  -- columns at all, but the database does not rely on that alone)
  declare blocked boolean;
  begin
    blocked := false;
    begin
      update public.alerts set duplicate_of = id where id = second_id;
    exception when check_violation then blocked := true;
    end;
    if not blocked then raise exception 'FAIL an alert was linked as a duplicate of itself'; end if;

    blocked := false;
    begin
      update public.alerts set duplicate_count = 5 where id = second_id;
    exception when check_violation then blocked := true;
    end;
    if not blocked then raise exception 'FAIL a duplicate (duplicate_of is not null) accumulated its own count'; end if;
  end;

  -- an occurrence outside the 60-minute window does not attract a duplicate either
  insert into public.alerts (title, severity, status, source, origin, created_at)
    values ('fx Old beacon to 203.0.113.50', 'medium', 'new', 'manual', 'local', now() - interval '2 hours');
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Old beacon to 203.0.113.50', 'medium', 'new', 'manual', 'local')
    returning id into third_id;
  select duplicate_of into got_dup from public.alerts where id = third_id;
  if got_dup is not null then raise exception 'FAIL a duplicate linked to an occurrence outside the dedup window'; end if;

  -- distinct titles never collide, whatever the asset/indicator
  insert into public.alerts (title, severity, status, source, origin) values
    ('fx distinct title A', 'low', 'new', 'manual', 'local'),
    ('fx distinct title B', 'low', 'new', 'manual', 'local');
  select count(*) into got_count from public.alerts where title in ('fx distinct title A', 'fx distinct title B') and duplicate_of is not null;
  if got_count <> 0 then raise exception 'FAIL distinct titles were linked as duplicates of each other'; end if;

  select status into got_status from public.alerts where id = first_id;
  if got_status <> 'resolved' then raise exception 'FAIL fixture cleanup check failed unexpectedly'; end if;

  reset role;

  raise notice 'ok - deduplication: a repeat links to its still-open primary and bumps its count; a resolved or stale (>60min) primary does not attract one';
end $$;

rollback;

do $$ begin raise notice 'DETECTION RULES AND DEDUPLICATION DATABASE TESTS PASSED'; end $$;
