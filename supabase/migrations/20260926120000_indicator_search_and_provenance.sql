-- Indicators, phase 4: text search, atomic tag editing, and protection of provenance.
--
-- All functions are SECURITY INVOKER (the default): they run with the caller's privileges, so the
-- row level security policies from 20260925100500 decide what each caller can see and change.

-- LIKE patterns are built from user input, so the wildcard characters must be escaped.
create function public.escape_like(p_text text)
returns text
language sql
immutable
parallel safe
set search_path = ''
as $$
  select replace(replace(replace(p_text, '\', '\\'), '%', '\%'), '_', '\_')
$$;

-- Free-text search. Every whitespace-separated term (at most 8) must match somewhere: the value,
-- the description, the source, or one of the indicator's tags. `p_tag`, when given, restricts the
-- result to indicators carrying that tag (case-insensitive). Callers add filters, sorting and
-- pagination on top through PostgREST, so this only answers "which indicators match the text".
create function public.search_indicators(p_query text default null, p_tag text default null)
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
        and not (
          i.value_normalized ilike '%' || public.escape_like(term) || '%'
          or i.description ilike '%' || public.escape_like(term) || '%'
          or i.source ilike '%' || public.escape_like(term) || '%'
          or exists (
            select 1
            from public.indicator_tags it
            join public.tags t on t.id = it.tag_id
            where it.indicator_id = i.id and t.name ilike '%' || public.escape_like(term) || '%'
          )
        )
    )
$$;

-- Replaces the tag set of one indicator in a single transaction: unknown tag names are created
-- (case-insensitively unique), links that are no longer wanted are removed. Needs indicators:write.
create function public.set_indicator_tags(p_indicator_id uuid, p_tags text[])
returns void
language plpgsql
set search_path = ''
as $$
declare
  v_name text;
  v_id uuid;
  v_ids uuid[] := '{}';
begin
  if not (select public.has_permission('indicators:write')) then
    raise exception 'Not allowed to edit indicators' using errcode = '42501';
  end if;

  perform 1 from public.indicators where id = p_indicator_id;
  if not found then
    raise exception 'Indicator not found' using errcode = 'P0002';
  end if;

  if coalesce(array_length(p_tags, 1), 0) > 20 then
    raise exception 'An indicator can have at most 20 tags' using errcode = '23514';
  end if;

  foreach v_name in array coalesce(p_tags, '{}') loop
    v_name := btrim(v_name);
    continue when v_name = '';

    insert into public.tags (name) values (v_name) on conflict (lower(name)) do nothing;
    select t.id into v_id from public.tags t where lower(t.name) = lower(v_name);
    v_ids := v_ids || v_id;
  end loop;

  delete from public.indicator_tags where indicator_id = p_indicator_id and tag_id <> all (v_ids);
  insert into public.indicator_tags (indicator_id, tag_id)
  select p_indicator_id, t from unnest(v_ids) as t
  on conflict do nothing;
end;
$$;

revoke all on function public.escape_like(text) from public, anon;
revoke all on function public.search_indicators(text, text) from public, anon;
revoke all on function public.set_indicator_tags(uuid, text[]) from public, anon;
grant execute on function public.escape_like(text) to authenticated, service_role;
grant execute on function public.search_indicators(text, text) to authenticated, service_role;
grant execute on function public.set_indicator_tags(uuid, text[]) to authenticated, service_role;

-- Provenance. `origin` says whether a record is demo, locally entered or from an external provider,
-- and the UI relies on it to never present demo or local data as live intelligence. Signed-in users
-- can only create 'local' records (external records are written by server-side ingestion with the
-- service role, demo records by the seed), and nobody can relabel a record afterwards.
create function public.protect_origin()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.origin = old.origin;
  return new;
end;
$$;

create trigger indicators_protect_origin before update on public.indicators
  for each row execute function public.protect_origin();

drop policy indicators_insert on public.indicators;
create policy indicators_insert on public.indicators for insert to authenticated
  with check (
    (select public.has_permission('indicators:write'))
    and created_by = (select auth.uid())
    and origin = 'local'
  );
