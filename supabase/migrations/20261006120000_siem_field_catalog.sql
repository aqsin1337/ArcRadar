-- Field catalog: which fields a SIEM really holds, reported by the SIEM host.
--
-- The Splunk host runs a small script that asks Splunk (on localhost) which indexes and sourcetypes have data
-- and which fields those events carry, how often, and a few example values, and reports it here with its
-- API key. The rule form offers these real names instead of guessing them, and the AI is told which fields
-- exist. Nothing here reaches a SIEM: the SIEM host calls ArcRadar.
--
-- siem_field_catalog is written only by sync_field_catalog() (service role, after the API key is verified),
-- like telemetry; clients can read it (administrators, rules:manage) and never write it. The example values
-- come from real logs, so they stay behind the same permission as the rules.

create function public.max_text_len(p_values text[])
returns integer
language sql
immutable
set search_path = ''
as $$
  select coalesce(max(char_length(v)), 0) from unnest(p_values) as v
$$;

create table public.siem_field_catalog (
  siem text not null check (siem in ('splunk')),
  index_name text not null check (index_name ~ '^[a-z0-9_][a-z0-9_-]{0,59}$'),
  sourcetype text not null check (sourcetype ~ '^[A-Za-z0-9_:./-]{1,80}$'),
  field text not null check (field ~ '^[A-Za-z_][A-Za-z0-9_.]{0,79}$'),
  -- Out of a sample of events_sampled events, this many carried the field.
  events_with_field integer not null check (events_with_field >= 0),
  events_sampled integer not null check (events_sampled > 0),
  distinct_values integer check (distinct_values is null or distinct_values >= 0),
  sample_values text[] not null default '{}'
    check (cardinality(sample_values) <= 5 and public.max_text_len(sample_values) <= 100),
  window_hours integer not null check (window_hours between 1 and 720),
  reported_at timestamptz not null default now(),
  origin public.data_origin not null default 'external',
  primary key (siem, index_name, sourcetype, field),
  constraint siem_field_catalog_sample_check check (events_with_field <= events_sampled)
);

create index siem_field_catalog_source_idx
  on public.siem_field_catalog (siem, index_name, sourcetype, events_with_field desc);

alter table public.siem_field_catalog enable row level security;

create policy siem_field_catalog_select on public.siem_field_catalog for select to authenticated
  using ((select public.has_permission('rules:manage')));

revoke insert, update, delete on public.siem_field_catalog from authenticated, anon;

-- ---------------------------------------------------------------------------
-- sync_field_catalog
-- ---------------------------------------------------------------------------
-- Replaces the catalog of every (index, sourcetype) in p_sources, in one transaction. Each element:
--   { index, sourcetype, window_hours, events_sampled,
--     fields: [ { name, count, distinct?, values?: [text] } ] }
-- A field whose name the table would refuse is skipped rather than failing the batch; example values are
-- cut to 100 characters and to five.
create function public.sync_field_catalog(p_siem text, p_sources jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  src jsonb;
  v_index text;
  v_sourcetype text;
  v_sampled integer;
  v_window integer;
  v_fields integer := 0;
  v_sources integer := 0;
  n integer;
begin
  if p_siem is null or p_siem not in ('splunk') then
    raise exception 'Unknown SIEM' using errcode = '22023';
  end if;
  if jsonb_typeof(p_sources) is distinct from 'array' then
    raise exception 'Sources must be an array' using errcode = '22023';
  end if;
  if jsonb_array_length(p_sources) > 50 then
    raise exception 'Too many sources in one call' using errcode = '22023';
  end if;

  for src in select value from jsonb_array_elements(p_sources) loop
    v_index := src ->> 'index';
    v_sourcetype := src ->> 'sourcetype';
    v_sampled := (src ->> 'events_sampled')::integer;
    v_window := (src ->> 'window_hours')::integer;
    if jsonb_typeof(src -> 'fields') is distinct from 'array'
       or jsonb_array_length(src -> 'fields') > 500 then
      raise exception 'Fields must be an array of at most 500' using errcode = '22023';
    end if;

    delete from public.siem_field_catalog
      where siem = p_siem and index_name = v_index and sourcetype = v_sourcetype;

    insert into public.siem_field_catalog
      (siem, index_name, sourcetype, field, events_with_field, events_sampled, distinct_values,
       sample_values, window_hours)
    select
      p_siem, v_index, v_sourcetype, f ->> 'name',
      least((f ->> 'count')::integer, v_sampled), v_sampled,
      nullif(f ->> 'distinct', '')::integer,
      coalesce(array(
        select left(x, 100)
        from jsonb_array_elements_text(coalesce(f -> 'values', '[]'::jsonb)) with ordinality as t(x, i)
        order by i limit 5
      ), '{}'),
      v_window
    from jsonb_array_elements(src -> 'fields') as f
    where (f ->> 'name') ~ '^[A-Za-z_][A-Za-z0-9_.]{0,79}$';

    get diagnostics n = row_count;
    v_fields := v_fields + n;
    v_sources := v_sources + 1;
  end loop;

  return jsonb_build_object('sources', v_sources, 'fields', v_fields);
end;
$$;

revoke all on function public.sync_field_catalog(text, jsonb) from public, anon, authenticated;
grant execute on function public.sync_field_catalog(text, jsonb) to service_role;
