-- Phase 6: alerts, investigations and threat intelligence.
--
-- 1. Provenance for the remaining record tables (see 20260926120000 for indicators).
-- 2. Who added an item to an investigation, and when: the investigation timeline needs it.
-- 3. System notes: the status history of an investigation, written by the server only.
-- 4. Search and statistics functions (all SECURITY INVOKER: the caller's policies decide what they see).
-- 5. Atomic editing of links and tags.

-- ---------------------------------------------------------------------------
-- 1. Provenance
-- ---------------------------------------------------------------------------
-- Signed-in users can only create 'local' records (external records come from server-side ingestion
-- with the service role, demo records from the seed) and nobody can relabel a record afterwards.
do $$
declare
  t record;
begin
  for t in
    select * from (values
      ('threat_actors',  'threat_intel:write'),
      ('campaigns',      'threat_intel:write'),
      ('malware',        'threat_intel:write'),
      ('events',         'events:write'),
      ('alerts',         'alerts:write'),
      ('investigations', 'investigations:write')
    ) as v (tbl, write_perm)
  loop
    execute format(
      'create trigger %I before update on public.%I for each row execute function public.protect_origin()',
      t.tbl || '_protect_origin', t.tbl);
    execute format('drop policy %I on public.%I', t.tbl || '_insert', t.tbl);
    execute format(
      'create policy %I on public.%I for insert to authenticated with check ((select public.has_permission(%L)) and created_by = (select auth.uid()) and origin = ''local'')',
      t.tbl || '_insert', t.tbl, t.write_perm);
  end loop;
end
$$;

-- ---------------------------------------------------------------------------
-- 2. Who added an item to an investigation, and when
-- ---------------------------------------------------------------------------
alter table public.investigation_indicators
  add column added_at timestamptz not null default now(),
  add column added_by uuid default auth.uid() references public.profiles (id) on delete set null;

alter table public.investigation_alerts
  add column added_at timestamptz not null default now(),
  add column added_by uuid default auth.uid() references public.profiles (id) on delete set null;

-- A client can only record itself as the one who added an item.
do $$
declare
  t text;
begin
  foreach t in array array['investigation_indicators', 'investigation_alerts'] loop
    execute format('drop policy %I on public.%I', t || '_insert', t);
    execute format(
      'create policy %I on public.%I for insert to authenticated with check ((select public.has_permission(''investigations:write'')) and added_by = (select auth.uid()))',
      t || '_insert', t);
  end loop;
end
$$;

-- ---------------------------------------------------------------------------
-- 3. System notes
-- ---------------------------------------------------------------------------
-- 'system' notes record what happened to an investigation (status changes). Only the server writes
-- them (with the service role); clients can neither create, edit nor delete one.
alter table public.investigation_notes
  add column kind text not null default 'note' check (kind in ('note', 'system'));

drop policy investigation_notes_insert on public.investigation_notes;
create policy investigation_notes_insert on public.investigation_notes for insert to authenticated
  with check (
    (select public.has_permission('investigations:write'))
    and author_id = (select auth.uid())
    and kind = 'note'
  );

drop policy investigation_notes_update on public.investigation_notes;
create policy investigation_notes_update on public.investigation_notes for update to authenticated
  using (
    (select public.has_permission('investigations:write')) and author_id = (select auth.uid()) and kind = 'note'
  )
  with check (
    (select public.has_permission('investigations:write')) and author_id = (select auth.uid()) and kind = 'note'
  );

drop policy investigation_notes_delete on public.investigation_notes;
create policy investigation_notes_delete on public.investigation_notes for delete to authenticated
  using (
    kind = 'note'
    and (
      ((select public.has_permission('investigations:write')) and author_id = (select auth.uid()))
      or (select public.has_permission('investigations:delete'))
    )
  );

create index alerts_source_idx on public.alerts (source);

-- ---------------------------------------------------------------------------
-- 4. Search and statistics
-- ---------------------------------------------------------------------------
-- All of them split the text into at most 8 words, every one of which must match somewhere, with
-- LIKE wildcards escaped (escape_like, from 20260926120000).

create function public.search_alerts(p_query text default null)
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
      ), false)
  )
$$;

create function public.search_investigations(p_query text default null, p_tag text default null)
returns setof public.investigations
language sql
stable
set search_path = ''
as $$
  select v.*
  from public.investigations v
  where (
      nullif(btrim(p_tag), '') is null
      or exists (
        select 1
        from public.investigation_tags it
        join public.tags t on t.id = it.tag_id
        where it.investigation_id = v.id and lower(t.name) = lower(btrim(p_tag))
      )
    )
    and not exists (
      select 1
      from unnest((regexp_split_to_array(btrim(coalesce(p_query, '')), '\s+'))[1:8]) as term
      where term <> ''
        and not coalesce((
          v.title ilike '%' || public.escape_like(term) || '%'
          or v.description ilike '%' || public.escape_like(term) || '%'
          or exists (
            select 1
            from public.investigation_tags it
            join public.tags t on t.id = it.tag_id
            where it.investigation_id = v.id and t.name ilike '%' || public.escape_like(term) || '%'
          )
          or exists (
            select 1
            from public.investigation_indicators ii
            join public.indicators i on i.id = ii.indicator_id
            where ii.investigation_id = v.id and i.value_normalized ilike '%' || public.escape_like(term) || '%'
          )
        ), false)
    )
$$;

create function public.search_threat_actors(p_query text default null)
returns setof public.threat_actors
language sql
stable
set search_path = ''
as $$
  select a.*
  from public.threat_actors a
  where not exists (
    select 1
    from unnest((regexp_split_to_array(btrim(coalesce(p_query, '')), '\s+'))[1:8]) as term
    where term <> ''
      and not coalesce((
        a.name ilike '%' || public.escape_like(term) || '%'
        or a.description ilike '%' || public.escape_like(term) || '%'
        or a.motivation ilike '%' || public.escape_like(term) || '%'
        or a.attribution_country ilike '%' || public.escape_like(term) || '%'
        or exists (
          select 1
          from unnest(a.aliases || a.target_industries || a.target_countries) as x
          where x ilike '%' || public.escape_like(term) || '%'
        )
      ), false)
  )
$$;

create function public.search_campaigns(p_query text default null)
returns setof public.campaigns
language sql
stable
set search_path = ''
as $$
  select c.*
  from public.campaigns c
  where not exists (
    select 1
    from unnest((regexp_split_to_array(btrim(coalesce(p_query, '')), '\s+'))[1:8]) as term
    where term <> ''
      and not coalesce((
        c.name ilike '%' || public.escape_like(term) || '%'
        or c.description ilike '%' || public.escape_like(term) || '%'
      ), false)
  )
$$;

create function public.search_malware(p_query text default null)
returns setof public.malware
language sql
stable
set search_path = ''
as $$
  select m.*
  from public.malware m
  where not exists (
    select 1
    from unnest((regexp_split_to_array(btrim(coalesce(p_query, '')), '\s+'))[1:8]) as term
    where term <> ''
      and not coalesce((
        m.name ilike '%' || public.escape_like(term) || '%'
        or m.malware_type ilike '%' || public.escape_like(term) || '%'
        or m.description ilike '%' || public.escape_like(term) || '%'
        or exists (select 1 from unnest(m.platforms) as x where x ilike '%' || public.escape_like(term) || '%')
      ), false)
  )
$$;

create function public.search_mitre_techniques(p_query text default null)
returns setof public.mitre_techniques
language sql
stable
set search_path = ''
as $$
  select m.*
  from public.mitre_techniques m
  where not exists (
    select 1
    from unnest((regexp_split_to_array(btrim(coalesce(p_query, '')), '\s+'))[1:8]) as term
    where term <> ''
      and not coalesce((
        m.id ilike '%' || public.escape_like(term) || '%'
        or m.name ilike '%' || public.escape_like(term) || '%'
        or m.description ilike '%' || public.escape_like(term) || '%'
        or exists (select 1 from unnest(m.tactics) as x where x ilike '%' || public.escape_like(term) || '%')
      ), false)
  )
$$;

-- Fix for search_indicators (20260926120000): a NULL description made the whole match NULL, and
-- NOT NULL is NULL, so an indicator without a description matched every search. The match is now
-- wrapped in coalesce(..., false), like the functions above.
create or replace function public.search_indicators(p_query text default null, p_tag text default null)
returns setof public.indicators
language sql
stable
set search_path = ''
as $$
  select i.*
  from public.indicators i
  where (
      nullif(btrim(p_tag), '') is null
      or exists (
        select 1
        from public.indicator_tags it
        join public.tags t on t.id = it.tag_id
        where it.indicator_id = i.id and lower(t.name) = lower(btrim(p_tag))
      )
    )
    and not exists (
      select 1
      from unnest((regexp_split_to_array(btrim(coalesce(p_query, '')), '\s+'))[1:8]) as term
      where term <> ''
        and not coalesce((
          i.value_normalized ilike '%' || public.escape_like(term) || '%'
          or i.description ilike '%' || public.escape_like(term) || '%'
          or i.source ilike '%' || public.escape_like(term) || '%'
          or exists (
            select 1
            from public.indicator_tags it
            join public.tags t on t.id = it.tag_id
            where it.indicator_id = i.id and t.name ilike '%' || public.escape_like(term) || '%'
          )
        ), false)
    )
$$;

-- Alerts per status, and how many of them nobody has picked up. Counts only what the caller may read.
create function public.alert_status_counts()
returns table (status public.alert_status, total bigint, unassigned bigint)
language sql
stable
set search_path = ''
as $$
  select a.status, count(*), count(*) filter (where a.assigned_to is null)
  from public.alerts a
  group by a.status
$$;

create function public.investigation_status_counts()
returns table (status public.investigation_status, total bigint)
language sql
stable
set search_path = ''
as $$
  select v.status, count(*) from public.investigations v group by v.status
$$;

-- The distinct alert sources, for a filter menu.
create function public.alert_sources()
returns setof text
language sql
stable
set search_path = ''
as $$
  select distinct a.source from public.alerts a order by 1
$$;

-- ---------------------------------------------------------------------------
-- 5. Atomic editing of links and tags
-- ---------------------------------------------------------------------------
-- A null array leaves that kind of link alone; an empty array clears it. Each function needs the
-- permission that writes the tables it touches (row level security would refuse anyway, this gives a
-- clear error), and every id must exist (foreign keys) or the whole call fails.

create function public.set_threat_actor_links(
  p_actor_id uuid,
  p_malware uuid[] default null,
  p_campaigns uuid[] default null,
  p_techniques text[] default null
)
returns void
language plpgsql
set search_path = ''
as $$
begin
  if not (select public.has_permission('threat_intel:write')) then
    raise exception 'Not allowed to edit threat intelligence' using errcode = '42501';
  end if;
  perform 1 from public.threat_actors where id = p_actor_id;
  if not found then
    raise exception 'Threat actor not found' using errcode = 'P0002';
  end if;

  if p_malware is not null then
    delete from public.threat_actor_malware where threat_actor_id = p_actor_id and malware_id <> all (p_malware);
    insert into public.threat_actor_malware (threat_actor_id, malware_id)
    select p_actor_id, m from unnest(p_malware) as m on conflict do nothing;
  end if;
  if p_campaigns is not null then
    delete from public.threat_actor_campaigns where threat_actor_id = p_actor_id and campaign_id <> all (p_campaigns);
    insert into public.threat_actor_campaigns (threat_actor_id, campaign_id)
    select p_actor_id, c from unnest(p_campaigns) as c on conflict do nothing;
  end if;
  if p_techniques is not null then
    delete from public.threat_actor_techniques where threat_actor_id = p_actor_id and technique_id <> all (p_techniques);
    insert into public.threat_actor_techniques (threat_actor_id, technique_id)
    select p_actor_id, t from unnest(p_techniques) as t on conflict do nothing;
  end if;
end;
$$;

create function public.set_campaign_actors(p_campaign_id uuid, p_actors uuid[])
returns void
language plpgsql
set search_path = ''
as $$
begin
  if not (select public.has_permission('threat_intel:write')) then
    raise exception 'Not allowed to edit threat intelligence' using errcode = '42501';
  end if;
  perform 1 from public.campaigns where id = p_campaign_id;
  if not found then
    raise exception 'Campaign not found' using errcode = 'P0002';
  end if;

  delete from public.threat_actor_campaigns
  where campaign_id = p_campaign_id and threat_actor_id <> all (coalesce(p_actors, '{}'));
  insert into public.threat_actor_campaigns (threat_actor_id, campaign_id)
  select a, p_campaign_id from unnest(coalesce(p_actors, '{}')) as a on conflict do nothing;
end;
$$;

create function public.set_malware_actors(p_malware_id uuid, p_actors uuid[])
returns void
language plpgsql
set search_path = ''
as $$
begin
  if not (select public.has_permission('threat_intel:write')) then
    raise exception 'Not allowed to edit threat intelligence' using errcode = '42501';
  end if;
  perform 1 from public.malware where id = p_malware_id;
  if not found then
    raise exception 'Malware not found' using errcode = 'P0002';
  end if;

  delete from public.threat_actor_malware
  where malware_id = p_malware_id and threat_actor_id <> all (coalesce(p_actors, '{}'));
  insert into public.threat_actor_malware (threat_actor_id, malware_id)
  select a, p_malware_id from unnest(coalesce(p_actors, '{}')) as a on conflict do nothing;
end;
$$;

-- The threat actors, campaigns and malware families an indicator is linked to.
create function public.set_indicator_links(
  p_indicator_id uuid,
  p_actors uuid[] default null,
  p_campaigns uuid[] default null,
  p_malware uuid[] default null
)
returns void
language plpgsql
set search_path = ''
as $$
begin
  if not (select public.has_permission('indicators:write')) then
    raise exception 'Not allowed to edit indicators' using errcode = '42501';
  end if;
  perform 1 from public.indicators where id = p_indicator_id;
  if not found then
    raise exception 'Indicator not found' using errcode = 'P0002';
  end if;

  if p_actors is not null then
    delete from public.indicator_threat_actors where indicator_id = p_indicator_id and threat_actor_id <> all (p_actors);
    insert into public.indicator_threat_actors (indicator_id, threat_actor_id)
    select p_indicator_id, a from unnest(p_actors) as a on conflict do nothing;
  end if;
  if p_campaigns is not null then
    delete from public.indicator_campaigns where indicator_id = p_indicator_id and campaign_id <> all (p_campaigns);
    insert into public.indicator_campaigns (indicator_id, campaign_id)
    select p_indicator_id, c from unnest(p_campaigns) as c on conflict do nothing;
  end if;
  if p_malware is not null then
    delete from public.indicator_malware where indicator_id = p_indicator_id and malware_id <> all (p_malware);
    insert into public.indicator_malware (indicator_id, malware_id)
    select p_indicator_id, m from unnest(p_malware) as m on conflict do nothing;
  end if;
end;
$$;

-- Replaces the tag set of one investigation (unknown tag names are created, case-insensitively unique).
create function public.set_investigation_tags(p_investigation_id uuid, p_tags text[])
returns void
language plpgsql
set search_path = ''
as $$
declare
  v_name text;
  v_id uuid;
  v_ids uuid[] := '{}';
begin
  if not (select public.has_permission('investigations:write')) then
    raise exception 'Not allowed to edit investigations' using errcode = '42501';
  end if;
  perform 1 from public.investigations where id = p_investigation_id;
  if not found then
    raise exception 'Investigation not found' using errcode = 'P0002';
  end if;
  if coalesce(array_length(p_tags, 1), 0) > 20 then
    raise exception 'An investigation can have at most 20 tags' using errcode = '23514';
  end if;

  foreach v_name in array coalesce(p_tags, '{}') loop
    v_name := btrim(v_name);
    continue when v_name = '';

    insert into public.tags (name) values (v_name) on conflict (lower(name)) do nothing;
    select t.id into v_id from public.tags t where lower(t.name) = lower(v_name);
    v_ids := v_ids || v_id;
  end loop;

  delete from public.investigation_tags where investigation_id = p_investigation_id and tag_id <> all (v_ids);
  insert into public.investigation_tags (investigation_id, tag_id)
  select p_investigation_id, t from unnest(v_ids) as t on conflict do nothing;
end;
$$;

-- ---------------------------------------------------------------------------
-- Privileges
-- ---------------------------------------------------------------------------
do $$
declare
  f text;
begin
  foreach f in array array[
    'search_alerts(text)',
    'search_investigations(text, text)',
    'search_threat_actors(text)',
    'search_campaigns(text)',
    'search_malware(text)',
    'search_mitre_techniques(text)',
    'alert_status_counts()',
    'investigation_status_counts()',
    'alert_sources()',
    'set_threat_actor_links(uuid, uuid[], uuid[], text[])',
    'set_campaign_actors(uuid, uuid[])',
    'set_malware_actors(uuid, uuid[])',
    'set_indicator_links(uuid, uuid[], uuid[], uuid[])',
    'set_investigation_tags(uuid, text[])'
  ] loop
    execute format('revoke all on function public.%s from public, anon', f);
    execute format('grant execute on function public.%s to authenticated, service_role', f);
  end loop;
end
$$;
