-- Splunk as a second telemetry source.
--
-- 1. The Splunk connector in the integrations catalog (like wazuh: configured per API key).
-- 2. ingest_telemetry() accepts p_source 'splunk'. The body is the one from 20260927110000, unchanged
--    except for that single list: every other behavior (one transaction per batch, origin 'external',
--    idempotent by (source, source_event_id), indicators recorded 'unknown') is the same for both sources.
--    The grants are re-stated below; create or replace keeps them, but a migration should not depend on that.

insert into public.integrations (provider, display_name, capabilities)
values ('splunk', 'Splunk', array['telemetry']);

create or replace function public.ingest_telemetry(p_source text, p_records jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  rec jsonb;
  ind jsonb;
  v_occurred timestamptz;
  v_severity public.severity;
  v_type public.indicator_type;
  v_value text;
  v_normalized text;
  v_asset_id uuid;
  v_asset_new boolean;
  v_indicator_id uuid;
  v_alert_indicator uuid;
  v_event_id uuid;
  v_alert_id uuid;
  n_events integer := 0;
  n_alerts integer := 0;
  n_duplicates integer := 0;
  n_assets integer := 0;
  n_indicators integer := 0;
begin
  if p_source is null or p_source not in ('wazuh', 'splunk') then
    raise exception 'Unknown telemetry source' using errcode = '22023';
  end if;
  if jsonb_typeof(p_records) is distinct from 'array' then
    raise exception 'Records must be an array' using errcode = '22023';
  end if;
  if jsonb_array_length(p_records) > 500 then
    raise exception 'Too many records in one batch' using errcode = '22023';
  end if;

  for rec in select value from jsonb_array_elements(p_records) loop
    v_occurred := (rec ->> 'occurred_at')::timestamptz;
    v_severity := (rec ->> 'severity')::public.severity;

    v_asset_id := null;
    if jsonb_typeof(rec -> 'asset') = 'object' then
      insert into public.assets (source, external_id, name, ip_address, os, origin, first_seen, last_seen)
      values (
        p_source, rec -> 'asset' ->> 'external_id', rec -> 'asset' ->> 'name',
        nullif(rec -> 'asset' ->> 'ip_address', ''), nullif(rec -> 'asset' ->> 'os', ''),
        'external', v_occurred, v_occurred
      )
      on conflict (source, external_id) do update
        set name = excluded.name,
            ip_address = coalesce(excluded.ip_address, public.assets.ip_address),
            os = coalesce(excluded.os, public.assets.os),
            first_seen = least(public.assets.first_seen, excluded.first_seen),
            last_seen = greatest(public.assets.last_seen, excluded.last_seen)
      returning id, (xmax = 0) into v_asset_id, v_asset_new;
      if v_asset_new then n_assets := n_assets + 1; end if;
    end if;

    v_event_id := null;
    insert into public.events
      (event_type, title, description, severity, source, source_event_id, asset_id, payload, occurred_at, origin, created_by)
    values (
      rec ->> 'event_type', rec ->> 'title', nullif(rec ->> 'description', ''), v_severity, p_source,
      rec ->> 'source_event_id', v_asset_id, coalesce(rec -> 'payload', '{}'::jsonb), v_occurred, 'external', null
    )
    on conflict (source, source_event_id) where source_event_id is not null and origin = 'external'
      do nothing
    returning id into v_event_id;

    if v_event_id is null then
      n_duplicates := n_duplicates + 1;
      continue;
    end if;
    n_events := n_events + 1;

    if coalesce((rec -> 'alert' ->> 'create')::boolean, false) then
      v_alert_indicator := null;
      for ind in select value from jsonb_array_elements(coalesce(rec -> 'indicators', '[]'::jsonb)) loop
        begin
          v_type := (ind ->> 'type')::public.indicator_type;
          v_value := ind ->> 'value';
          v_normalized := case v_type when 'cve' then upper(v_value) when 'url' then v_value else lower(v_value) end;
          v_indicator_id := null;

          insert into public.indicators
            (type, value, severity, verdict, confidence, status, source, description, first_seen, last_seen, origin, created_by)
          values (
            v_type, v_value, v_severity, 'unknown', 30, 'active', p_source,
            left('Seen in a ' || p_source || ' alert: ' || (rec ->> 'title'), 5000),
            v_occurred, v_occurred, 'external', null
          )
          on conflict on constraint indicators_type_value_key do nothing
          returning id into v_indicator_id;

          if v_indicator_id is not null then
            n_indicators := n_indicators + 1;
          else
            select id into v_indicator_id from public.indicators
              where type = v_type and value_normalized = v_normalized;
            update public.indicators
              set last_seen = greatest(last_seen, v_occurred)
              where id = v_indicator_id and origin = 'external';
          end if;
          v_alert_indicator := coalesce(v_alert_indicator, v_indicator_id);
        exception
          when check_violation or invalid_text_representation or string_data_right_truncation or not_null_violation then
            null; -- a value the database refuses is skipped; the alert is still recorded
        end;
      end loop;

      v_alert_id := null;
      insert into public.alerts
        (title, description, severity, source, source_event_id, status, indicator_id, event_id, asset_id,
         technique_ids, origin, created_by, created_at)
      values (
        rec ->> 'title', nullif(rec ->> 'description', ''), v_severity, p_source, rec ->> 'source_event_id',
        'new', v_alert_indicator, v_event_id, v_asset_id,
        coalesce(array(select jsonb_array_elements_text(coalesce(rec -> 'alert' -> 'technique_ids', '[]'::jsonb))), '{}'),
        'external', null, least(v_occurred, now())
      )
      on conflict (source, source_event_id) where source_event_id is not null and origin = 'external'
        do nothing
      returning id into v_alert_id;
      if v_alert_id is not null then n_alerts := n_alerts + 1; end if;
    end if;
  end loop;

  update public.integrations set last_sync_at = now() where provider = p_source;

  return jsonb_build_object(
    'events_created', n_events,
    'alerts_created', n_alerts,
    'duplicates', n_duplicates,
    'assets_created', n_assets,
    'indicators_created', n_indicators
  );
end;
$$;

revoke all on function public.ingest_telemetry(text, jsonb) from public, anon, authenticated;
grant execute on function public.ingest_telemetry(text, jsonb) to service_role;
