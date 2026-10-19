-- Alert deduplication (Phase 10; the severity rules that shared its trigger were removed on
-- 2026-10-19, decision 34).
-- Run with `npm run db:test`. Everything happens in one transaction that is rolled back.
--
-- Fixture user: ...0002 analyst.

begin;

insert into auth.users (id, email) values
  ('d3d3d3d3-0000-4000-8000-000000000002', 'fxdr-analyst@arcradar.test');

update public.profiles set role_name = 'soc_l2' where id = 'd3d3d3d3-0000-4000-8000-000000000002';

-- 1. The severity rules are gone; one insert trigger on alerts, and it only deduplicates.
-- ---------------------------------------------------------------------------------------------
do $$
begin
  if to_regclass('public.detection_rules') is not null then
    raise exception 'FAIL the detection_rules table still exists';
  end if;
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'alerts' and column_name = 'matched_rule_id'
  ) then
    raise exception 'FAIL alerts.matched_rule_id still exists';
  end if;
  if to_regprocedure('public.alerts_dedup_and_rules()') is not null
     or to_regprocedure('public.detection_rule_matches(jsonb, public.alerts)') is not null
     or to_regprocedure('public.severity_rank(public.severity)') is not null then
    raise exception 'FAIL a severity-rule function is still defined';
  end if;
  if not exists (
    select 1 from pg_trigger
    where tgrelid = 'public.alerts'::regclass and not tgisinternal
      and tgname = 'alerts_dedup_trigger'
      and tgfoid = 'public.alerts_dedup()'::regprocedure
  ) then
    raise exception 'FAIL alerts_dedup_trigger is missing or runs another function';
  end if;
  if exists (
    select 1 from pg_trigger
    where tgrelid = 'public.alerts'::regclass and not tgisinternal and tgname = 'alerts_dedup_and_rules_trigger'
  ) then
    raise exception 'FAIL the old dedup-and-rules trigger is still attached';
  end if;

  raise notice 'ok - severity rules removed: no table, column or functions left; alerts_dedup_trigger is the one dedup trigger';
end $$;

-- 2. Deduplication: fingerprint, still-open only, the 60-minute window.
-- ---------------------------------------------------------------------------------------------
do $$
declare first_id uuid; second_id uuid; third_id uuid; got_dup uuid; got_count int;
  got_severity public.severity; got_status public.alert_status;
begin
  perform set_config('request.jwt.claims', json_build_object('sub', 'd3d3d3d3-0000-4000-8000-000000000002', 'role', 'authenticated')::text, true);
  set local role authenticated;

  -- a first occurrence is its own primary, and its severity is exactly what it was created with
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Suspicious login from 192.0.2.201', 'medium', 'new', 'manual', 'local')
    returning id into first_id;
  select duplicate_of, duplicate_count, severity into got_dup, got_count, got_severity
    from public.alerts where id = first_id;
  if got_dup is not null or got_count <> 0 then
    raise exception 'FAIL a first occurrence was not its own primary (dup_of=%, count=%)', got_dup, got_count;
  end if;
  if got_severity <> 'medium' then
    raise exception 'FAIL the trigger changed a new alert''s severity (got %)', got_severity;
  end if;

  -- a second, identical occurrence links to the first instead of opening a fresh row
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Suspicious login from 192.0.2.201', 'medium', 'new', 'manual', 'local')
    returning id into second_id;
  select duplicate_of into got_dup from public.alerts where id = second_id;
  if got_dup <> first_id then raise exception 'FAIL a duplicate did not link to the first occurrence'; end if;
  select duplicate_count into got_count from public.alerts where id = first_id;
  if got_count <> 1 then raise exception 'FAIL the primary''s duplicate_count did not reach 1 (got %)', got_count; end if;

  -- the fingerprint ignores case and punctuation in the title, as before
  insert into public.alerts (title, severity, status, source, origin)
    values ('FX suspicious LOGIN from 192-0-2-201!', 'medium', 'new', 'manual', 'local')
    returning id into third_id;
  select duplicate_of into got_dup from public.alerts where id = third_id;
  if got_dup <> first_id then raise exception 'FAIL a title differing only in case/punctuation did not link'; end if;

  -- a resolved primary does not attract a further duplicate: a recurrence opens a fresh one
  update public.alerts set status = 'resolved', resolved_at = now() where id = first_id;
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Suspicious login from 192.0.2.201', 'medium', 'new', 'manual', 'local')
    returning id into third_id;
  select duplicate_of into got_dup from public.alerts where id = third_id;
  if got_dup is not null then raise exception 'FAIL a new occurrence linked to an already-resolved primary'; end if;
  select duplicate_count into got_count from public.alerts where id = first_id;
  if got_count <> 2 then raise exception 'FAIL a resolved primary''s duplicate_count changed (got %)', got_count; end if;

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

  -- the same title from another source is not a duplicate
  insert into public.alerts (title, severity, status, source, origin)
    values ('fx Old beacon to 203.0.113.50', 'medium', 'new', 'splunk', 'local')
    returning id into third_id;
  select duplicate_of into got_dup from public.alerts where id = third_id;
  if got_dup is not null then raise exception 'FAIL the same title from another source was linked as a duplicate'; end if;

  select status into got_status from public.alerts where id = first_id;
  if got_status <> 'resolved' then raise exception 'FAIL fixture cleanup check failed unexpectedly'; end if;

  reset role;

  raise notice 'ok - deduplication: a repeat links to its still-open primary and bumps its count; a resolved or stale (>60min) primary, another title or another source does not';
end $$;

rollback;

do $$ begin raise notice 'ALERT DEDUPLICATION DATABASE TESTS PASSED'; end $$;
