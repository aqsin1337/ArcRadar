-- Phase 9: investigation checklists and response orchestration.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer.
-- Fixture alert: b2b2b2b2-0000-4000-8000-000000000010 "fxro alert" (local).
-- Fixture investigation: b2b2b2b2-0000-4000-8000-000000000011 "fxro investigation" (local, open).

begin;

insert into auth.users (id, email) values
  ('b2b2b2b2-0000-4000-8000-000000000001', 'fxro-admin@arcradar.test'),
  ('b2b2b2b2-0000-4000-8000-000000000002', 'fxro-analyst@arcradar.test'),
  ('b2b2b2b2-0000-4000-8000-000000000003', 'fxro-viewer@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'b2b2b2b2-0000-4000-8000-000000000001';
update public.profiles set role_name = 'analyst' where id = 'b2b2b2b2-0000-4000-8000-000000000002';

insert into public.alerts (id, title, severity, status, source, origin) values
  ('b2b2b2b2-0000-4000-8000-000000000010', 'fxro alert', 'high', 'new', 'manual', 'local');
insert into public.investigations (id, title, status, priority, origin) values
  ('b2b2b2b2-0000-4000-8000-000000000011', 'fxro investigation', 'open', 'medium', 'local');

-- 1. ai_analyses: widened kind/subject_type, and the pairing between them.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; new_id uuid;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'b2b2b2b2-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- a checklist analysis on an investigation is fine
  insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content)
    values ('investigation_checklist', 'investigation', 'b2b2b2b2-0000-4000-8000-000000000011', 'groq', 'm', 1,
            '{"items": ["fx step one"]}')
    returning id into new_id;
  if new_id is null then raise exception 'FAIL an investigation_checklist analysis was rejected'; end if;

  -- a verdict recommendation needs indicators:read, which this analyst has, but the subject must be
  -- an indicator, not an alert or investigation
  blocked := false;
  begin
    insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content)
      values ('verdict_recommendation', 'alert', 'b2b2b2b2-0000-4000-8000-000000000010', 'groq', 'm', 1, '{}');
  exception when check_violation or insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL verdict_recommendation was accepted for an alert'; end if;

  -- a threat_summary (an alert-only kind) is rejected for an investigation
  blocked := false;
  begin
    insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content)
      values ('threat_summary', 'investigation', 'b2b2b2b2-0000-4000-8000-000000000011', 'groq', 'm', 1, '{}');
  exception when check_violation or insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL threat_summary was accepted for an investigation'; end if;

  reset role;
  raise notice 'ok - ai_analyses only accepts the kind that matches its subject_type';
end $$;

-- 2. investigation_checklist_items
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; new_id uuid; n int;
begin
  -- a viewer cannot add an item
  perform set_config('request.jwt.claims', json_build_object('sub', 'b2b2b2b2-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.investigation_checklist_items (investigation_id, text, source)
      values ('b2b2b2b2-0000-4000-8000-000000000011', 'fx viewer item', 'analyst');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a viewer added a checklist item'; end if;
  reset role;

  -- an analyst adds one, as themselves, and it defaults to source analyst if not an AI seed
  perform set_config('request.jwt.claims', json_build_object('sub', 'b2b2b2b2-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.investigation_checklist_items (investigation_id, text, source)
    values ('b2b2b2b2-0000-4000-8000-000000000011', 'fx analyst item', 'analyst')
    returning id into new_id;
  if (select created_by from public.investigation_checklist_items where id = new_id) <> 'b2b2b2b2-0000-4000-8000-000000000002' then
    raise exception 'FAIL created_by did not default to the caller';
  end if;

  -- an unknown source is rejected
  blocked := false;
  begin
    insert into public.investigation_checklist_items (investigation_id, text, source)
      values ('b2b2b2b2-0000-4000-8000-000000000011', 'fx bad source', 'robot');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an unknown checklist source was accepted'; end if;

  -- toggling done and deleting both work for investigations:write
  update public.investigation_checklist_items set done = true, done_by = 'b2b2b2b2-0000-4000-8000-000000000002' where id = new_id;
  select done into blocked from public.investigation_checklist_items where id = new_id;
  if not blocked then raise exception 'FAIL toggling an item done did not stick'; end if;

  delete from public.investigation_checklist_items where id = new_id;
  select count(*) into n from public.investigation_checklist_items where id = new_id;
  if n <> 0 then raise exception 'FAIL deleting a checklist item did not stick'; end if;

  reset role;
  raise notice 'ok - investigation_checklist_items: investigations:write to add/toggle/remove, as yourself';
end $$;

-- 3. response_actions: the catalog, provenance-protected.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; new_id uuid; o public.data_origin;
begin
  -- a viewer can read the catalog (alerts:read) but not write it
  perform set_config('request.jwt.claims', json_build_object('sub', 'b2b2b2b2-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.response_actions (title) values ('fx viewer action');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a viewer created a response action'; end if;
  reset role;

  -- an analyst creates one (investigations:write), always local, as themselves
  perform set_config('request.jwt.claims', json_build_object('sub', 'b2b2b2b2-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.response_actions (title, description, category)
    values ('fx isolate the host', 'fx description', 'containment')
    returning id into new_id;
  select origin into o from public.response_actions where id = new_id;
  if o <> 'local' then raise exception 'FAIL a client-created response action was origin %', o; end if;

  -- a client cannot claim origin external or demo directly
  blocked := false;
  begin
    insert into public.response_actions (title, origin) values ('fx forged origin', 'external');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a response action was created with origin external'; end if;

  -- nor relabel one after the fact; the rest of the update still goes through
  update public.response_actions set origin = 'demo', title = 'fx isolate the host (edited)' where id = new_id;
  select origin into o from public.response_actions where id = new_id;
  if o <> 'local' then raise exception 'FAIL an update relabelled a response action to %', o; end if;
  if (select title from public.response_actions where id = new_id) <> 'fx isolate the host (edited)' then
    raise exception 'FAIL the rest of the update was lost';
  end if;
  reset role;

  raise notice 'ok - response_actions: investigations:write creates one, always local, never relabelled';
end $$;

-- 4. response_action_log: exactly one of alert_id/investigation_id, and the matching permission.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; new_id uuid; action_id uuid; n int;
begin
  select id into action_id from public.response_actions where title like 'fx isolate the host%' limit 1;

  perform set_config('request.jwt.claims', json_build_object('sub', 'b2b2b2b2-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- both or neither of alert_id/investigation_id is rejected
  blocked := false;
  begin
    insert into public.response_action_log (action_id, alert_id, investigation_id, status, source)
      values (action_id, 'b2b2b2b2-0000-4000-8000-000000000010', 'b2b2b2b2-0000-4000-8000-000000000011', 'recommended', 'analyst');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a log row with both alert_id and investigation_id was accepted'; end if;

  -- Blocked either by the table's own check constraint or by the insert policy (neither of its
  -- alert_id/investigation_id disjuncts can be true when both are null) -- either is correct proof.
  blocked := false;
  begin
    insert into public.response_action_log (action_id, status, source)
      values (action_id, 'recommended', 'analyst');
  exception when check_violation or insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a log row with neither alert_id nor investigation_id was accepted'; end if;

  -- a real alert-attached recommendation works, defaults requested_by to the caller
  insert into public.response_action_log (action_id, alert_id, status, source)
    values (action_id, 'b2b2b2b2-0000-4000-8000-000000000010', 'recommended', 'analyst')
    returning id into new_id;
  if (select created_by from public.response_action_log where id = new_id) <> 'b2b2b2b2-0000-4000-8000-000000000002' then
    raise exception 'FAIL created_by did not default to the caller';
  end if;

  -- an unknown status is rejected
  blocked := false;
  begin
    insert into public.response_action_log (action_id, alert_id, status, source)
      values (action_id, 'b2b2b2b2-0000-4000-8000-000000000010', 'not_a_status', 'analyst');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an unknown status was accepted'; end if;

  -- an unknown action is rejected (foreign key)
  blocked := false;
  begin
    insert into public.response_action_log (action_id, alert_id, status, source)
      values (gen_random_uuid(), 'b2b2b2b2-0000-4000-8000-000000000010', 'recommended', 'analyst');
  exception when foreign_key_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an unknown action_id was accepted'; end if;

  reset role;

  -- a viewer can read the alert's log (alerts:read) but cannot move it forward: no update policy
  -- matches them, so (as with ai_settings/ai_analyses in Phase 8) it is 0 rows silently, not an
  -- exception.
  perform set_config('request.jwt.claims', json_build_object('sub', 'b2b2b2b2-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  perform 1 from public.response_action_log where id = new_id;
  if not found then raise exception 'FAIL a viewer could not read the alert''s response action log'; end if;

  update public.response_action_log set status = 'acknowledged' where id = new_id;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL a viewer moved a response action forward (% rows)', n; end if;
  reset role;

  raise notice 'ok - response_action_log: exactly one subject, alerts:write/investigations:write to write, matching read';
end $$;

rollback;

do $$ begin raise notice 'RESPONSE ORCHESTRATION DATABASE TESTS PASSED'; end $$;
