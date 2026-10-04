-- Phase 11: rate_limit_buckets and check_rate_limit() -- the shared, database-backed counter every
-- rate-limited route calls through (src/lib/rate-limit/). Run with `npm run db:test`. Everything
-- happens in one transaction that is rolled back.

begin;

-- 1. Nobody but the function itself may touch the table directly.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean;
begin
  set local role anon;
  blocked := false;
  begin perform * from public.rate_limit_buckets; exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could read rate_limit_buckets'; end if;
  blocked := false;
  begin insert into public.rate_limit_buckets (bucket_key, window_start, count) values ('x', now(), 1);
  exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could write rate_limit_buckets'; end if;
  reset role;

  set local role authenticated;
  blocked := false;
  begin perform * from public.rate_limit_buckets; exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL authenticated could read rate_limit_buckets'; end if;
  reset role;

  raise notice 'ok - rate_limit_buckets has no direct access for anon or authenticated';
end $$;

-- 2. Nobody but the service role may call check_rate_limit().
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean;
begin
  set local role anon;
  blocked := false;
  begin perform * from public.check_rate_limit('t', 5, 60); exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could call check_rate_limit'; end if;
  reset role;

  set local role authenticated;
  blocked := false;
  begin perform * from public.check_rate_limit('t', 5, 60); exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL authenticated could call check_rate_limit'; end if;
  reset role;

  raise notice 'ok - check_rate_limit is service_role only';
end $$;

-- 3. A fixed window: allowed while under the limit, refused once over it, with a positive
--    retry_after_seconds only when refused.
-- ---------------------------------------------------------------------------------------------
do $$
declare r record;
begin
  set local role service_role;

  select * into r from public.check_rate_limit('fx:window-a', 3, 60);
  if not r.allowed or r.retry_after_seconds <> 0 then
    raise exception 'FAIL call 1/3 was not allowed cleanly, got allowed=%, retry_after=%', r.allowed, r.retry_after_seconds;
  end if;

  select * into r from public.check_rate_limit('fx:window-a', 3, 60);
  select * into r from public.check_rate_limit('fx:window-a', 3, 60);
  if not r.allowed then raise exception 'FAIL call 3/3 was refused'; end if;

  select * into r from public.check_rate_limit('fx:window-a', 3, 60);
  if r.allowed then raise exception 'FAIL call 4 (over the limit of 3) was allowed'; end if;
  if r.retry_after_seconds <= 0 or r.retry_after_seconds > 60 then
    raise exception 'FAIL retry_after_seconds out of range once refused, got %', r.retry_after_seconds;
  end if;

  reset role;
  raise notice 'ok - check_rate_limit allows up to the limit, then refuses with a positive Retry-After';
end $$;

-- 4. A different key is a different bucket: being over the limit on one key never touches another.
-- ---------------------------------------------------------------------------------------------
do $$
declare r record;
begin
  set local role service_role;
  perform public.check_rate_limit('fx:window-b', 1, 60);
  perform public.check_rate_limit('fx:window-b', 1, 60); -- now over the limit
  select * into r from public.check_rate_limit('fx:other-key', 1, 60);
  if not r.allowed then raise exception 'FAIL an unrelated key was refused because another key was over its limit'; end if;
  reset role;
  raise notice 'ok - buckets are isolated per key';
end $$;

-- 5. Once the window has passed, the count resets instead of accumulating forever.
-- ---------------------------------------------------------------------------------------------
do $$
declare r record;
begin
  set local role service_role;
  perform public.check_rate_limit('fx:window-c', 1, 60);
  perform public.check_rate_limit('fx:window-c', 1, 60); -- over the limit within this window
  reset role;

  update public.rate_limit_buckets set window_start = now() - interval '61 seconds'
    where bucket_key = 'fx:window-c';

  set local role service_role;
  select * into r from public.check_rate_limit('fx:window-c', 1, 60);
  if not r.allowed then raise exception 'FAIL a new window did not reset the count'; end if;
  reset role;

  raise notice 'ok - a bucket resets once its window has fully elapsed';
end $$;

-- 6. Misuse (a non-positive limit or window) is a programming error, not a request to allow.
-- ---------------------------------------------------------------------------------------------
do $$
declare blocked boolean;
begin
  set local role service_role;
  blocked := false;
  begin perform public.check_rate_limit('fx:misuse', 0, 60); exception when raise_exception then blocked := true; end;
  if not blocked then raise exception 'FAIL a zero limit was accepted'; end if;
  blocked := false;
  begin perform public.check_rate_limit('fx:misuse', 5, 0); exception when raise_exception then blocked := true; end;
  if not blocked then raise exception 'FAIL a zero window was accepted'; end if;
  reset role;
  raise notice 'ok - a non-positive limit or window is refused outright';
end $$;

-- 7. Housekeeping: a bucket whose window closed a day or more ago is eventually swept, without a
--    scheduled job -- setseed() makes the function's own random() draws deterministic here so the
--    test does not depend on chance.
-- ---------------------------------------------------------------------------------------------
do $$
declare stale_gone boolean := false;
begin
  set local role service_role;
  perform public.check_rate_limit('fx:stale', 1000, 60);
  update public.rate_limit_buckets set window_start = now() - interval '2 days' where bucket_key = 'fx:stale';

  perform setseed(0);
  for i in 1..1000 loop
    perform public.check_rate_limit('fx:sweep-driver:' || i, 1000, 60);
    if not exists (select 1 from public.rate_limit_buckets where bucket_key = 'fx:stale') then
      stale_gone := true;
      exit;
    end if;
  end loop;
  reset role;

  if not stale_gone then raise exception 'FAIL a day-old bucket was never swept in 1000 calls'; end if;
  raise notice 'ok - a stale bucket is swept without a scheduled job';
end $$;

rollback;

do $$ begin raise notice 'RATE LIMITING DATABASE TESTS PASSED'; end $$;
