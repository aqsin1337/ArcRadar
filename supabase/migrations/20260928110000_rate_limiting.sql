-- Phase 11: application-level rate limiting.
--
-- Production has no always-on server and no in-memory cross-request state (decision 1): a Vercel
-- function remembers nothing between invocations, so a counter kept in the process is useless the
-- moment there is more than one instance. The database is the only shared state allowed, so the
-- limiter's counters live in one small table, moved atomically by one function.
--
-- 1. rate_limit_buckets: one row per (route class, subject) pair. Its own policy can never match
--    (`using (false)`) and every table privilege is revoked besides — nobody, not even an
--    authenticated user reading their own bucket, may touch it directly; only check_rate_limit()
--    (security definer) may.
-- 2. check_rate_limit(key, limit, window_seconds): a fixed-window counter. Atomic (one
--    insert .. on conflict .. returning statement, so concurrent requests from the same subject
--    cannot both read a stale count and both be let through), fails closed only on its own
--    misuse (a non-positive limit or window is a programming error, not a request to allow).
--    Self-cleans old rows on a small fraction of calls (no cron, no background worker: it is
--    ordinary work piggy-backed on a request that already has to touch this table).

create table public.rate_limit_buckets (
  bucket_key text primary key,
  window_start timestamptz not null,
  count integer not null default 0
);

create index rate_limit_buckets_window_start_idx on public.rate_limit_buckets (window_start);

alter table public.rate_limit_buckets enable row level security;

-- Matches every other table's "RLS enabled and at least one policy" (supabase/tests/security.test.sql),
-- but this policy can never match: it exists so that invariant holds by an explicit, self-documenting
-- rule rather than by the absence of one. The table is reachable only through check_rate_limit() below,
-- which runs as its owner and bypasses RLS the same way ingest_telemetry() already does.
create policy rate_limit_buckets_no_direct_access on public.rate_limit_buckets
  for all to authenticated, anon
  using (false)
  with check (false);

revoke all on public.rate_limit_buckets from public, anon, authenticated;

create or replace function public.check_rate_limit(
  p_key text,
  p_limit integer,
  p_window_seconds integer
) returns table (allowed boolean, retry_after_seconds integer)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := now();
  v_window_start timestamptz;
  v_count integer;
begin
  if p_key is null or char_length(p_key) = 0 or char_length(p_key) > 300 then
    raise exception 'check_rate_limit: key must be 1-300 characters';
  end if;
  if p_limit is null or p_limit <= 0 or p_window_seconds is null or p_window_seconds <= 0 then
    raise exception 'check_rate_limit: limit and window_seconds must be positive';
  end if;

  insert into public.rate_limit_buckets as b (bucket_key, window_start, count)
  values (p_key, v_now, 1)
  on conflict (bucket_key) do update set
    window_start = case
      when b.window_start <= v_now - make_interval(secs => p_window_seconds) then v_now
      else b.window_start
    end,
    count = case
      when b.window_start <= v_now - make_interval(secs => p_window_seconds) then 1
      else b.count + 1
    end
  returning b.window_start, b.count into v_window_start, v_count;

  -- Housekeeping, not a background job: roughly one call in a hundred also sweeps buckets whose
  -- window closed a day or more ago, so the table stays bounded to active subjects without a
  -- scheduled task (decision 1 rules those out). A day is far beyond any window this app uses.
  if random() < 0.01 then
    delete from public.rate_limit_buckets
    where window_start < v_now - interval '1 day';
  end if;

  return query select
    v_count <= p_limit,
    case
      when v_count <= p_limit then 0
      else greatest(
        1,
        ceil(extract(epoch from (v_window_start + make_interval(secs => p_window_seconds) - v_now)))
      )::integer
    end;
end;
$$;

revoke all on function public.check_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.check_rate_limit(text, integer, integer) to service_role;
