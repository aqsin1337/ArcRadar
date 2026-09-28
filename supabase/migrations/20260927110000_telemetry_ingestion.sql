-- Phase 6b: telemetry ingestion (Wazuh first).
--
-- 1. Assets: the machines telemetry comes from (written by ingestion only).
-- 2. Idempotency keys, asset links and MITRE technique ids on events and alerts.
-- 3. The Wazuh connector in the integrations catalog.
-- 4. ingest_telemetry(): the one write path for sensor data, callable by the service role only.
-- 5. telemetry_source_health(): "last event received" per source.
-- 6. Alert search also finds an alert by the name of its asset.

-- ---------------------------------------------------------------------------
-- 1. Assets
-- ---------------------------------------------------------------------------
-- An asset is created by ingestion (origin 'external') or by the demo seed (origin 'demo'). Clients
-- can read assets but never write them: there is no write policy and no write privilege.
create table public.assets (
  id uuid primary key default gen_random_uuid(),
  source text not null check (char_length(source) between 1 and 100),
  -- The sensor's own id for the machine (for Wazuh, the agent id such as '001').
  external_id text not null check (char_length(external_id) between 1 and 100),
  name text not null check (char_length(name) between 1 and 200),
  ip_address text check (char_length(ip_address) <= 100),
  os text check (char_length(os) <= 200),
  origin public.data_origin not null default 'external',
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint assets_source_external_id_key unique (source, external_id),
  constraint assets_seen_order check (last_seen >= first_seen)
);

create index assets_last_seen_idx on public.assets (last_seen desc);

create trigger assets_set_updated_at
  before update on public.assets
  for each row execute function public.set_updated_at();

alter table public.assets enable row level security;

create policy assets_select on public.assets for select to authenticated
  using ((select public.has_permission('events:read')));

revoke insert, update, delete on public.assets from authenticated;

-- ---------------------------------------------------------------------------
-- 2. Events and alerts: idempotency key, asset, techniques
-- ---------------------------------------------------------------------------
alter table public.events
  add column source_event_id text check (char_length(source_event_id) between 1 and 200),
  add column asset_id uuid references public.assets (id) on delete set null;

alter table public.alerts
  add column source_event_id text check (char_length(source_event_id) between 1 and 200),
  add column asset_id uuid references public.assets (id) on delete set null,
  add column technique_ids text[] not null default '{}',
  add constraint alerts_technique_ids_valid check (
    cardinality(technique_ids) <= 20
    and array_to_string(technique_ids, ',') ~ '^(T[0-9]{4}(\.[0-9]{3})?(,T[0-9]{4}(\.[0-9]{3})?)*)?$'
  );

-- A sensor retrying or resending a batch must not create a second record. The key only applies to
-- external rows: clients can neither create nor relabel those, so nobody can squat on an id.
create unique index events_source_event_key
  on public.events (source, source_event_id)
  where source_event_id is not null and origin = 'external';

create unique index alerts_source_event_key
  on public.alerts (source, source_event_id)
  where source_event_id is not null and origin = 'external';

create index events_asset_id_idx on public.events (asset_id);
create index alerts_asset_id_idx on public.alerts (asset_id);
create index events_source_created_idx on public.events (source, created_at desc);

-- ---------------------------------------------------------------------------
-- 3. The Wazuh connector
-- ---------------------------------------------------------------------------
alter table public.integrations drop constraint integrations_capabilities_check;
alter table public.integrations add constraint integrations_capabilities_check
  check (capabilities <@ array['ip', 'domain', 'url', 'hash', 'vulnerability', 'threat_intel', 'telemetry']);

insert into public.integrations (provider, display_name, capabilities, enabled)
values ('wazuh', 'Wazuh', array['telemetry'], false);

-- ---------------------------------------------------------------------------
-- 4. ingest_telemetry
-- ---------------------------------------------------------------------------
-- Records sensor data that the application has already authenticated (an API key with the right
-- scope) and normalized. It is the only way external events, alerts, assets and indicators get in:
-- clients can only create local rows, so this runs as the function owner and only the service role
-- may call it. The whole batch is one transaction; every record is idempotent by
-- (source, source_event_id), so a retried or duplicated record changes nothing.
--
-- Each element of p_records:
--   { source_event_id, occurred_at, event_type, title, description?, severity, payload,
--     asset?: { external_id, name, ip_address?, os? },
--     alert?: { create: bool, technique_ids?: [text] },
--     indicators?: [ { type, value } ] }   -- the first one that is stored becomes the alert's indicator
--
-- Indicators are created as external, verdict 'unknown' (a sensor sighting is not a verdict). An
-- indicator someone already tracks (any origin) is never changed, except that a previously ingested one
-- gets a later last_seen. An indicator value the database refuses is skipped, not fatal.
create function public.ingest_telemetry(p_source text, p_records jsonb)
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
  if p_source is null or p_source not in ('wazuh') then
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

-- ---------------------------------------------------------------------------
-- 5. Connector health
-- ---------------------------------------------------------------------------
-- One row per (source, origin) that has events the caller may read: when the last event happened,
-- when the last one was received, and how much there is. SECURITY INVOKER: the caller's policies
-- decide what counts.
create function public.telemetry_source_health()
returns table (
  source text,
  origin public.data_origin,
  last_event_at timestamptz,
  last_received_at timestamptz,
  events_total bigint,
  events_24h bigint,
  alerts_total bigint,
  assets_total bigint
)
language sql
stable
set search_path = ''
as $$
  select
    e.source,
    e.origin,
    max(e.occurred_at),
    max(e.created_at),
    count(*),
    count(*) filter (where e.created_at > now() - interval '24 hours'),
    (select count(*) from public.alerts a where a.source = e.source and a.origin = e.origin),
    (select count(*) from public.assets s where s.source = e.source and s.origin = e.origin)
  from public.events e
  group by e.source, e.origin
  order by e.origin desc, e.source
$$;

revoke all on function public.telemetry_source_health() from public, anon;
grant execute on function public.telemetry_source_health() to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 6. Alert search also matches the asset's name and address
-- ---------------------------------------------------------------------------
create or replace function public.search_alerts(p_query text default null)
returns setof public.alerts
language sql
stable
set search_path = ''
as $$
  select a.*
  from public.alerts a
  where not exists (
    select 1
    from unnest((regexp_split_to_array(btrim(coalesce(p_query, '')), '\s+'))[1:8]) as term
    where term <> ''
      and not coalesce((
        a.title ilike '%' || public.escape_like(term) || '%'
        or a.description ilike '%' || public.escape_like(term) || '%'
        or a.source ilike '%' || public.escape_like(term) || '%'
        or exists (
          select 1 from public.indicators i
          where i.id = a.indicator_id and i.value_normalized ilike '%' || public.escape_like(term) || '%'
        )
        or exists (
          select 1 from public.assets s
          where s.id = a.asset_id
            and (s.name ilike '%' || public.escape_like(term) || '%'
                 or s.ip_address ilike '%' || public.escape_like(term) || '%')
        )
      ), false)
  )
$$;
