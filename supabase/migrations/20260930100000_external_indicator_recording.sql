-- Recording indicators that came from a live intelligence lookup or a threat feed.
--
-- Until now an indicator existed only if a person typed it in or a sensor alert happened to carry it.
-- This adds the one write path for indicators that ArcRadar itself learned from an external service:
-- the answer of a live provider after an analyst looked something up, and the entries of a public
-- threat feed. Both are recorded as origin 'external' (never 'local', never 'demo'), by the service
-- role only, after the application has authorized the action.
--
--   p_source   who says so: a provider or feed id such as 'virustotal', 'lookup:otx', 'urlhaus'
--   p_records  [ { type, value, verdict, severity, confidence (0-100), description?, seen_at?,
--                  tags?: [text] } ]
--
-- Rules:
--  * An indicator somebody already tracks as 'local' or 'demo' is never touched: an analyst's own
--    judgment is not overwritten by a machine.
--  * An existing 'external' indicator is refreshed: last_seen moves forward, and the verdict only
--    ever moves up (unknown < benign < suspicious < malicious), so a later "nothing found" lookup
--    cannot erase what a feed said. Severity and confidence follow a verdict that was replaced.
--  * A value the database refuses is skipped, not fatal; the rest of the batch is still recorded.
--  * One transaction per call, idempotent: running the same batch twice changes nothing more.
create function public.verdict_rank(p_verdict public.verdict)
returns integer
language sql
immutable
set search_path = ''
as $$
  select case p_verdict
    when 'unknown' then 0
    when 'benign' then 1
    when 'suspicious' then 2
    when 'malicious' then 3
  end;
$$;

create function public.record_external_indicators(p_source text, p_records jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  rec jsonb;
  v_type public.indicator_type;
  v_verdict public.verdict;
  v_severity public.severity;
  v_confidence smallint;
  v_seen timestamptz;
  v_id uuid;
  v_existing public.indicators;
  v_normalized text;
  n_created integer := 0;
  n_updated integer := 0;
  n_untouched integer := 0;
  n_skipped integer := 0;
begin
  if p_source is null or p_source !~ '^[a-z0-9_:.-]{1,60}$' then
    raise exception 'Invalid source' using errcode = '22023';
  end if;
  if jsonb_typeof(p_records) is distinct from 'array' then
    raise exception 'Records must be an array' using errcode = '22023';
  end if;
  if jsonb_array_length(p_records) > 5000 then
    raise exception 'Too many records in one batch' using errcode = '22023';
  end if;

  for rec in select value from jsonb_array_elements(p_records) loop
    begin
      v_type := (rec ->> 'type')::public.indicator_type;
      v_verdict := (rec ->> 'verdict')::public.verdict;
      v_severity := (rec ->> 'severity')::public.severity;
      v_confidence := greatest(0, least(100, coalesce((rec ->> 'confidence')::integer, 50)));
      v_seen := least(coalesce((rec ->> 'seen_at')::timestamptz, now()), now());
      v_normalized := case v_type
        when 'cve' then upper(rec ->> 'value')
        when 'url' then rec ->> 'value'
        else lower(rec ->> 'value')
      end;

      v_id := null;
      insert into public.indicators
        (type, value, severity, verdict, confidence, status, source, description, first_seen, last_seen, origin, created_by)
      values (
        v_type, rec ->> 'value', v_severity, v_verdict, v_confidence, 'active', p_source,
        left(nullif(rec ->> 'description', ''), 5000), v_seen, v_seen, 'external', null
      )
      on conflict on constraint indicators_type_value_key do nothing
      returning id into v_id;

      if v_id is not null then
        n_created := n_created + 1;
      else
        select * into v_existing from public.indicators
          where type = v_type and value_normalized = v_normalized;
        if v_existing.origin is distinct from 'external' then
          n_untouched := n_untouched + 1;
        elsif public.verdict_rank(v_verdict) > public.verdict_rank(v_existing.verdict) then
          update public.indicators
            set verdict = v_verdict,
                severity = v_severity,
                confidence = v_confidence,
                source = p_source,
                description = coalesce(left(nullif(rec ->> 'description', ''), 5000), description),
                first_seen = least(first_seen, v_seen),
                last_seen = greatest(last_seen, v_seen)
            where id = v_existing.id;
          n_updated := n_updated + 1;
        else
          update public.indicators
            set first_seen = least(first_seen, v_seen),
                last_seen = greatest(last_seen, v_seen)
            where id = v_existing.id;
          n_updated := n_updated + 1;
        end if;
      end if;
    exception
      when check_violation or invalid_text_representation or string_data_right_truncation
        or not_null_violation or datetime_field_overflow or invalid_datetime_format then
        n_skipped := n_skipped + 1;
    end;
  end loop;

  return jsonb_build_object(
    'created', n_created,
    'updated', n_updated,
    'untouched', n_untouched,
    'skipped', n_skipped
  );
end;
$$;

revoke all on function public.verdict_rank(public.verdict) from public, anon, authenticated;
revoke all on function public.record_external_indicators(text, jsonb) from public, anon, authenticated;
grant execute on function public.verdict_rank(public.verdict) to service_role;
grant execute on function public.record_external_indicators(text, jsonb) to service_role;
