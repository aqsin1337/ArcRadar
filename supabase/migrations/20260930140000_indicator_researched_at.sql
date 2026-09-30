-- When was an indicator last researched at external providers?
--
-- An indicator a sensor alert brought in starts as "unknown": nobody has asked VirusTotal, OTX,
-- AbuseIPDB or Shodan about it yet. ArcRadar now researches such indicators by itself when the alert
-- arrives (and an analyst's own lookup counts too). researched_at is the record of that: null means
-- "never researched", so the automatic research asks once per indicator instead of on every alert
-- that mentions it again, and the page can say when the verdict was last checked.
--
-- record_external_indicators() sets it whenever the source is a lookup ('lookup:<providers>'), for a
-- new indicator and for a refreshed external one, whether or not the answer changed the verdict
-- ("nothing found" is still an answer). An indicator somebody tracks as their own (local or demo) is
-- still never touched. Everything else in the function is unchanged (see 20260930100000).
alter table public.indicators add column researched_at timestamptz;

create or replace function public.record_external_indicators(p_source text, p_records jsonb)
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
  v_researched timestamptz := case when p_source like 'lookup:%' then now() end;
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
        (type, value, severity, verdict, confidence, status, source, description, first_seen, last_seen, origin, created_by, researched_at)
      values (
        v_type, rec ->> 'value', v_severity, v_verdict, v_confidence, 'active', p_source,
        left(nullif(rec ->> 'description', ''), 5000), v_seen, v_seen, 'external', null, v_researched
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
                last_seen = greatest(last_seen, v_seen),
                researched_at = coalesce(v_researched, researched_at)
            where id = v_existing.id;
          n_updated := n_updated + 1;
        else
          update public.indicators
            set first_seen = least(first_seen, v_seen),
                last_seen = greatest(last_seen, v_seen),
                researched_at = coalesce(v_researched, researched_at)
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
