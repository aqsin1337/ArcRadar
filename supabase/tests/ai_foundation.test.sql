-- Phase 8: AI integration foundation -- permissions, the integrations capability, ai_settings (the
-- one-row active-provider choice), ai_analyses (immutable, per-alert answers) and alerts.ai_fp_score.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture users: ...0001 admin, ...0002 analyst, ...0003 viewer.
-- Fixture alert: a1a1a1a1-0000-4000-8000-000000000010 "fxai alert" (local, open, unassigned).

begin;

insert into auth.users (id, email) values
  ('a1a1a1a1-0000-4000-8000-000000000001', 'fxai-admin@arcradar.test'),
  ('a1a1a1a1-0000-4000-8000-000000000002', 'fxai-analyst@arcradar.test'),
  ('a1a1a1a1-0000-4000-8000-000000000003', 'fxai-viewer@arcradar.test');

update public.profiles set role_name = 'admin' where id = 'a1a1a1a1-0000-4000-8000-000000000001';
update public.profiles set role_name = 'analyst' where id = 'a1a1a1a1-0000-4000-8000-000000000002';
-- role 3 stays the default 'viewer'.

insert into public.alerts (id, title, severity, status, source, origin) values
  ('a1a1a1a1-0000-4000-8000-000000000010', 'fxai alert', 'high', 'new', 'manual', 'local');

-- 1. Permissions: ai:use is analyst+admin, ai:manage is admin only.
-- ---------------------------------------------------------------------------------------------
do $$
declare can_use boolean; can_manage boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select public.has_permission('ai:use') into can_use;
  select public.has_permission('ai:manage') into can_manage;
  if not can_use then raise exception 'FAIL analyst lacks ai:use'; end if;
  if can_manage then raise exception 'FAIL analyst holds ai:manage'; end if;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select public.has_permission('ai:use') into can_use;
  if can_use then raise exception 'FAIL viewer holds ai:use'; end if;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select public.has_permission('ai:use') into can_use;
  select public.has_permission('ai:manage') into can_manage;
  if not (can_use and can_manage) then raise exception 'FAIL admin lacks ai:use or ai:manage'; end if;
  reset role;

  raise notice 'ok - ai:use is analyst+admin, ai:manage is admin only';
end $$;

-- 2. integrations: the capability check now allows 'ai', the five providers exist with it, and the
--    constraint still rejects anything outside the known set.
-- ---------------------------------------------------------------------------------------------
do $$
declare n int; blocked boolean;
begin
  select count(*) into n from public.integrations
    where provider in ('groq', 'openai', 'anthropic', 'deepseek', 'ollama') and capabilities = array['ai'];
  if n <> 5 then raise exception 'FAIL expected 5 AI provider rows with capabilities = {ai}, found %', n; end if;

  blocked := false;
  begin
    update public.integrations set capabilities = array['bogus'] where provider = 'groq';
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an unknown capability was accepted'; end if;

  raise notice 'ok - integrations gained the ai capability without loosening the check constraint';
end $$;

-- 3. ai_settings: readable by ai:use or ai:manage, writable only by ai:manage, exactly one row ever.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; n int; active text;
begin
  set local role anon;
  blocked := false;
  begin perform * from public.ai_settings; exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could read ai_settings'; end if;
  reset role;

  -- viewer: neither ai:use nor ai:manage, sees nothing
  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.ai_settings;
  if n <> 0 then raise exception 'FAIL a viewer read ai_settings'; end if;
  reset role;

  -- analyst: ai:use lets them read, but not change it. An analyst fails the update policy's own
  -- USING clause (no ai:manage), so RLS simply matches no row to update: 0 rows, not an exception,
  -- the same way a WHERE clause that matches nothing is not an error.
  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.ai_settings;
  if n <> 1 then raise exception 'FAIL an analyst could not read the single ai_settings row'; end if;
  update public.ai_settings set active_provider = 'groq', updated_by = 'a1a1a1a1-0000-4000-8000-000000000002' where id = true;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL an analyst updated ai_settings (% rows)', n; end if;
  reset role;

  -- admin: ai:manage lets them choose the active provider, but only as themselves
  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    update public.ai_settings set active_provider = 'groq', updated_by = 'a1a1a1a1-0000-4000-8000-000000000002' where id = true;
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an admin set updated_by to someone else and it was accepted'; end if;

  update public.ai_settings set active_provider = 'groq', active_model = 'llama-3.3-70b-versatile',
      updated_by = 'a1a1a1a1-0000-4000-8000-000000000001'
    where id = true;
  select active_provider into active from public.ai_settings where id = true;
  if active <> 'groq' then raise exception 'FAIL ai_settings.active_provider was not saved, got %', active; end if;

  -- exactly one row can ever exist: neither insert policy nor a second `id = true` row is possible
  blocked := false;
  begin
    insert into public.ai_settings (id, updated_by) values (true, 'a1a1a1a1-0000-4000-8000-000000000001');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a second row could be inserted into ai_settings'; end if;
  reset role;

  raise notice 'ok - ai_settings: read by ai:use/ai:manage, written only by ai:manage as themselves, one row only';
end $$;

-- 4. ai_analyses: immutable per-alert answers.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean; new_id uuid; n int;
begin
  set local role anon;
  blocked := false;
  begin perform * from public.ai_analyses; exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could read ai_analyses'; end if;
  reset role;

  -- a viewer (alerts:read, no ai:use) cannot create an analysis
  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  blocked := false;
  begin
    insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content)
      values ('threat_summary', 'alert', 'a1a1a1a1-0000-4000-8000-000000000010', 'groq', 'm', 1, '{}');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a viewer created an ai_analyses row'; end if;
  reset role;

  -- an analyst (ai:use) creates one, requested_by defaults to themselves
  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content)
    values ('threat_summary', 'alert', 'a1a1a1a1-0000-4000-8000-000000000010', 'groq', 'llama-3.3-70b-versatile', 1,
            '{"summary": "fx summary", "key_points": []}')
    returning id into new_id;
  if (select requested_by from public.ai_analyses where id = new_id) <> 'a1a1a1a1-0000-4000-8000-000000000002' then
    raise exception 'FAIL requested_by did not default to the caller';
  end if;

  -- cannot forge requested_by as someone else
  blocked := false;
  begin
    insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content, requested_by)
      values ('threat_summary', 'alert', 'a1a1a1a1-0000-4000-8000-000000000010', 'groq', 'm', 1, '{}',
              'a1a1a1a1-0000-4000-8000-000000000001');
  exception when insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL requested_by was forged to another user'; end if;

  -- an unknown kind or subject_type is rejected outright
  blocked := false;
  begin
    insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content)
      values ('not_a_kind', 'alert', 'a1a1a1a1-0000-4000-8000-000000000010', 'groq', 'm', 1, '{}');
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an unknown kind was accepted'; end if;

  -- Blocked either by the table's own check constraint or by the insert policy's own
  -- subject_type = 'alert' clause: either is correct proof that it cannot get in.
  blocked := false;
  begin
    insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content)
      values ('threat_summary', 'investigation', 'a1a1a1a1-0000-4000-8000-000000000010', 'groq', 'm', 1, '{}');
  exception when check_violation or insufficient_privilege then blocked := true;
  end;
  if not blocked then raise exception 'FAIL a non-alert subject_type was accepted (Phase 8 only writes alert)'; end if;

  -- an unknown provider is rejected (foreign key into integrations)
  blocked := false;
  begin
    insert into public.ai_analyses (kind, subject_type, subject_id, provider, model, prompt_version, content)
      values ('threat_summary', 'alert', 'a1a1a1a1-0000-4000-8000-000000000010', 'not-a-real-provider', 'm', 1, '{}');
  exception when foreign_key_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL an unknown provider was accepted'; end if;

  -- immutable: nobody, not even the author or an admin, can update or delete a row. With no
  -- update/delete policy at all, RLS matches nothing for either command: 0 rows affected, not an
  -- exception (the analogous check for ai_settings above explains why).
  update public.ai_analyses set content = '{"summary": "edited", "key_points": []}' where id = new_id;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL an ai_analyses row was updated by its own author (% rows)', n; end if;
  delete from public.ai_analyses where id = new_id;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL an ai_analyses row was deleted by its own author (% rows)', n; end if;
  reset role;

  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  delete from public.ai_analyses where id = new_id;
  get diagnostics n = row_count;
  if n <> 0 then raise exception 'FAIL an admin deleted an ai_analyses row (% rows)', n; end if;
  reset role;

  -- Defense in depth: the service role bypasses RLS entirely (it is how audit_logs, investigation
  -- history and API key creation are written), so the trigger, not RLS, is what stops it here.
  blocked := false;
  begin
    update public.ai_analyses set content = '{"summary": "edited", "key_points": []}' where id = new_id;
  exception when raise_exception then blocked := true;
  end;
  if not blocked then raise exception 'FAIL the append-only trigger did not block an update as table owner'; end if;

  -- a viewer can still read it: the card is visible to anyone who can read the alert
  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000003', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.ai_analyses where id = new_id;
  if n <> 1 then raise exception 'FAIL a viewer could not read an existing analysis'; end if;
  reset role;

  raise notice 'ok - ai_analyses: ai:use + alerts:read to create as yourself, alerts:read to read, immutable';
end $$;

-- 5. alerts.ai_fp_score: a plain numeric cache, bounded to 0-100.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'a1a1a1a1-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  update public.alerts set ai_fp_score = 0 where id = 'a1a1a1a1-0000-4000-8000-000000000010';
  update public.alerts set ai_fp_score = 100 where id = 'a1a1a1a1-0000-4000-8000-000000000010';
  update public.alerts set ai_fp_score = null where id = 'a1a1a1a1-0000-4000-8000-000000000010';

  blocked := false;
  begin
    update public.alerts set ai_fp_score = 101 where id = 'a1a1a1a1-0000-4000-8000-000000000010';
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL ai_fp_score accepted 101'; end if;

  blocked := false;
  begin
    update public.alerts set ai_fp_score = -1 where id = 'a1a1a1a1-0000-4000-8000-000000000010';
  exception when check_violation then blocked := true;
  end;
  if not blocked then raise exception 'FAIL ai_fp_score accepted -1'; end if;

  reset role;
  raise notice 'ok - alerts.ai_fp_score accepts 0-100 and null, rejects out of range';
end $$;

rollback;

do $$ begin raise notice 'AI FOUNDATION DATABASE TESTS PASSED'; end $$;
