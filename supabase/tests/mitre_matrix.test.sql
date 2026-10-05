-- mitre_observed_techniques(): what the ATT&CK matrix highlights.
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.

begin;

insert into auth.users (id, email) values
  ('ffffffff-0000-4000-8000-0000000000a1', 'mx-viewer@arcradar.test'),
  ('ffffffff-0000-4000-8000-0000000000a2', 'mx-inactive@arcradar.test');
update public.profiles set is_active = false where id = 'ffffffff-0000-4000-8000-0000000000a2';

-- Alerts (source fxmx keeps them apart from the seed's alerts, and their titles differ so the
-- deduplication trigger does not link them, except for the repeat inserted last):
--   one   high      [T1110.003]        -> counts for T1110.003 and, once, for its parent T1110
--   two   medium    [T1110, T1110.001] -> T1110 must count this alert once, not twice
--   three low       [T1059]
--   four  critical  []                 -> no technique, mentioned nowhere
--   one again       a repeat of "one": a duplicate, never counted
insert into public.alerts (id, title, severity, source, status, technique_ids, created_at) values
  ('ffffffff-2222-4000-8000-000000000001', 'fxmx one',   'high',     'fxmx', 'new', array['T1110.003'],           now() - interval '30 minutes'),
  ('ffffffff-2222-4000-8000-000000000002', 'fxmx two',   'medium',   'fxmx', 'new', array['T1110', 'T1110.001'],  now() - interval '2 hours'),
  ('ffffffff-2222-4000-8000-000000000003', 'fxmx three', 'low',      'fxmx', 'new', array['T1059'],               now() - interval '1 hour'),
  ('ffffffff-2222-4000-8000-000000000004', 'fxmx four',  'critical', 'fxmx', 'new', '{}',                         now());
insert into public.alerts (id, title, severity, source, status, technique_ids, created_at) values
  ('ffffffff-2222-4000-8000-000000000005', 'fxmx one',   'high',     'fxmx', 'new', array['T1110.003'],           now());

do $$
begin
  if (select duplicate_of from public.alerts where id = 'ffffffff-2222-4000-8000-000000000005') is null then
    raise exception 'FAIL fixture: the repeat alert was not linked as a duplicate';
  end if;
end $$;

-- 1. who may call it -------------------------------------------------------------------------------
do $$
declare blocked boolean := false; n int;
begin
  set local role anon;
  begin perform * from public.mitre_observed_techniques();
  exception when insufficient_privilege then blocked := true;
  end;
  reset role;
  if not blocked then raise exception 'FAIL anon could call mitre_observed_techniques'; end if;
  if has_function_privilege('anon', 'public.mitre_observed_techniques()', 'execute') then
    raise exception 'FAIL anon holds execute on mitre_observed_techniques';
  end if;

  -- an inactive user sees no alerts, so nothing is observed
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-0000000000a2', 'role', 'authenticated')::text, true);
  set local role authenticated;
  select count(*) into n from public.mitre_observed_techniques();
  reset role;
  if n <> 0 then raise exception 'FAIL an inactive user observed % techniques', n; end if;
end $$;

-- 2. the counts ------------------------------------------------------------------------------------
do $$
declare r record;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'ffffffff-0000-4000-8000-0000000000a1', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- T1110: alerts one (through its sub-technique) and two: 2, the worst is "high", the latest is one
  select * into r from public.mitre_observed_techniques() where technique_id = 'T1110';
  if r.alert_count is distinct from 2 or r.max_severity is distinct from 'high'
     or r.last_seen is distinct from (select created_at from public.alerts where id = 'ffffffff-2222-4000-8000-000000000001') then
    raise exception 'FAIL T1110 was %', to_jsonb(r);
  end if;

  -- T1110.003: only alert one (its duplicate is not counted)
  select * into r from public.mitre_observed_techniques() where technique_id = 'T1110.003';
  if r.alert_count is distinct from 1 or r.max_severity is distinct from 'high' then
    raise exception 'FAIL T1110.003 was %', to_jsonb(r);
  end if;

  -- T1110.001: only alert two
  select * into r from public.mitre_observed_techniques() where technique_id = 'T1110.001';
  if r.alert_count is distinct from 1 or r.max_severity is distinct from 'medium' then
    raise exception 'FAIL T1110.001 was %', to_jsonb(r);
  end if;

  select * into r from public.mitre_observed_techniques() where technique_id = 'T1059';
  if r.alert_count is distinct from 1 or r.max_severity is distinct from 'low' then
    raise exception 'FAIL T1059 was %', to_jsonb(r);
  end if;

  -- one row per technique, and an alert without techniques adds nothing
  if exists (
    select 1 from public.mitre_observed_techniques() group by technique_id having count(*) > 1
  ) then raise exception 'FAIL a technique appeared twice'; end if;
  reset role;
end $$;

rollback;
select 'mitre_matrix: all checks passed' as result;
