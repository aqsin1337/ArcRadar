-- Automatic data: public threat feeds, the CISA known-exploited list and the MITRE ATT&CK catalog.
--
--  * two integration rows so the feeds show up (with a last-sync time and an on/off switch) on the
--    Integrations page: 'abusech' (URLhaus, Feodo Tracker, ThreatFox) and 'cisa_kev'
--  * import_external_vulnerabilities(): the batch form of import_external_vulnerability()
--  * import_mitre_attack(): techniques, threat actors, malware and campaigns from the MITRE catalog
--
-- Both functions are callable by the service role only, like every other function that writes
-- external data: the application (or a script run by an administrator) authorizes first. Nothing
-- here ever overwrites a record somebody entered by hand (origin 'local') or the demo seed.
insert into public.integrations (provider, display_name, capabilities, enabled) values
  ('abusech', 'abuse.ch threat feeds', array['ip', 'url', 'hash', 'domain', 'threat_intel'], true),
  ('cisa_kev', 'CISA Known Exploited Vulnerabilities', array['vulnerability'], true);

-- The batch form: each record goes through import_external_vulnerability(), one failure does not
-- stop the rest. 'imported' is new, 'updated' an external record refreshed, 'untouched' a CVE
-- that already exists as local or demo data.
create function public.import_external_vulnerabilities(p_records jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  rec jsonb;
  v_known boolean;
  n_imported integer := 0;
  n_updated integer := 0;
  n_untouched integer := 0;
  n_skipped integer := 0;
begin
  if jsonb_typeof(p_records) is distinct from 'array' then
    raise exception 'Records must be an array' using errcode = '22023';
  end if;
  if jsonb_array_length(p_records) > 3000 then
    raise exception 'Too many records in one batch' using errcode = '22023';
  end if;

  for rec in select value from jsonb_array_elements(p_records) loop
    begin
      v_known := exists (
        select 1 from public.vulnerabilities where cve_id = upper(btrim(coalesce(rec ->> 'cve_id', '')))
      );
      perform public.import_external_vulnerability(rec);
      if v_known then n_updated := n_updated + 1; else n_imported := n_imported + 1; end if;
    exception
      when unique_violation then
        n_untouched := n_untouched + 1;
      when others then
        n_skipped := n_skipped + 1;
    end;
  end loop;

  update public.integrations set last_sync_at = now() where provider = 'cisa_kev';

  return jsonb_build_object(
    'imported', n_imported, 'updated', n_updated, 'untouched', n_untouched, 'skipped', n_skipped
  );
end;
$$;

revoke all on function public.import_external_vulnerabilities(jsonb) from public, anon, authenticated;
grant execute on function public.import_external_vulnerabilities(jsonb) to service_role;

-- MITRE ATT&CK. Any subset of the four keys may be present in one call; the links of an actor are
-- resolved by name, so send techniques, malware and campaigns before the actors that use them.
--   techniques [ { id, name, tactics[], description?, url? } ]           (reference data, upserted)
--   malware    [ { name, malware_type?, platforms[]?, description? } ]
--   campaigns  [ { name, description?, first_seen?, last_seen? } ]
--   actors     [ { name, aliases[]?, description?, first_seen?, last_seen?,
--                  technique_ids[]?, malware_names[]?, campaign_names[]? } ]
-- A name that already exists as a local or demo record is skipped (and so are its links): the
-- catalog never overwrites or extends what somebody entered by hand. An actor's links are replaced
-- as a whole on every import, so a relationship MITRE dropped disappears here too.
create function public.import_mitre_attack(p jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  x jsonb;
  v_id uuid;
  n_techniques integer := 0;
  n_malware integer := 0;
  n_campaigns integer := 0;
  n_actors integer := 0;
  n_skipped integer := 0;
begin
  if jsonb_typeof(p) is distinct from 'object' then
    raise exception 'Expected an object' using errcode = '22023';
  end if;

  for x in select value from jsonb_array_elements(coalesce(p -> 'techniques', '[]'::jsonb)) loop
    begin
      insert into public.mitre_techniques (id, name, tactics, description, url)
      values (
        x ->> 'id', left(x ->> 'name', 300),
        array(select jsonb_array_elements_text(coalesce(x -> 'tactics', '[]'::jsonb))),
        nullif(x ->> 'description', ''), nullif(x ->> 'url', '')
      )
      on conflict (id) do update
        set name = excluded.name, tactics = excluded.tactics,
            description = excluded.description, url = excluded.url;
      n_techniques := n_techniques + 1;
    exception when check_violation or not_null_violation or invalid_text_representation then
      n_skipped := n_skipped + 1;
    end;
  end loop;

  for x in select value from jsonb_array_elements(coalesce(p -> 'malware', '[]'::jsonb)) loop
    begin
      insert into public.malware (name, malware_type, platforms, description, origin, created_by)
      values (
        left(btrim(x ->> 'name'), 200), left(nullif(x ->> 'malware_type', ''), 100),
        array(select jsonb_array_elements_text(coalesce(x -> 'platforms', '[]'::jsonb))),
        left(nullif(x ->> 'description', ''), 10000), 'external', null
      )
      on conflict (lower(name)) do update
        set malware_type = excluded.malware_type, platforms = excluded.platforms,
            description = excluded.description
        where public.malware.origin = 'external';
      if found then n_malware := n_malware + 1; else n_skipped := n_skipped + 1; end if;
    exception when check_violation or not_null_violation or string_data_right_truncation then
      n_skipped := n_skipped + 1;
    end;
  end loop;

  for x in select value from jsonb_array_elements(coalesce(p -> 'campaigns', '[]'::jsonb)) loop
    begin
      insert into public.campaigns (name, description, status, first_seen, last_seen, origin, created_by)
      values (
        left(btrim(x ->> 'name'), 200), left(nullif(x ->> 'description', ''), 10000),
        case when (x ->> 'last_seen')::timestamptz > now() - interval '365 days'
             then 'active' else 'concluded' end::public.campaign_status,
        (x ->> 'first_seen')::timestamptz, (x ->> 'last_seen')::timestamptz, 'external', null
      )
      on conflict (lower(name)) do update
        set description = excluded.description, status = excluded.status,
            first_seen = excluded.first_seen, last_seen = excluded.last_seen
        where public.campaigns.origin = 'external';
      if found then n_campaigns := n_campaigns + 1; else n_skipped := n_skipped + 1; end if;
    exception when check_violation or not_null_violation or string_data_right_truncation
      or invalid_datetime_format or datetime_field_overflow then
      n_skipped := n_skipped + 1;
    end;
  end loop;

  for x in select value from jsonb_array_elements(coalesce(p -> 'actors', '[]'::jsonb)) loop
    begin
      v_id := null;
      insert into public.threat_actors
        (name, aliases, description, first_seen, last_seen, origin, created_by)
      values (
        left(btrim(x ->> 'name'), 200),
        array(select jsonb_array_elements_text(coalesce(x -> 'aliases', '[]'::jsonb))),
        left(nullif(x ->> 'description', ''), 10000),
        (x ->> 'first_seen')::timestamptz, (x ->> 'last_seen')::timestamptz, 'external', null
      )
      on conflict (lower(name)) do update
        set aliases = excluded.aliases, description = excluded.description,
            first_seen = excluded.first_seen, last_seen = excluded.last_seen
        where public.threat_actors.origin = 'external'
      returning id into v_id;

      if v_id is null then
        n_skipped := n_skipped + 1; -- a name somebody entered by hand
        continue;
      end if;
      n_actors := n_actors + 1;

      delete from public.threat_actor_techniques where threat_actor_id = v_id;
      insert into public.threat_actor_techniques (threat_actor_id, technique_id)
      select distinct v_id, t.id from public.mitre_techniques t
      where t.id in (select jsonb_array_elements_text(coalesce(x -> 'technique_ids', '[]'::jsonb)));

      delete from public.threat_actor_malware where threat_actor_id = v_id;
      insert into public.threat_actor_malware (threat_actor_id, malware_id)
      select distinct v_id, m.id from public.malware m
      where m.origin = 'external'
        and lower(m.name) in (select lower(jsonb_array_elements_text(coalesce(x -> 'malware_names', '[]'::jsonb))));

      delete from public.threat_actor_campaigns where threat_actor_id = v_id;
      insert into public.threat_actor_campaigns (threat_actor_id, campaign_id)
      select distinct v_id, c.id from public.campaigns c
      where c.origin = 'external'
        and lower(c.name) in (select lower(jsonb_array_elements_text(coalesce(x -> 'campaign_names', '[]'::jsonb))));
    exception when check_violation or not_null_violation or string_data_right_truncation
      or invalid_datetime_format or datetime_field_overflow then
      n_skipped := n_skipped + 1;
    end;
  end loop;

  return jsonb_build_object(
    'techniques', n_techniques, 'malware', n_malware, 'campaigns', n_campaigns,
    'actors', n_actors, 'skipped', n_skipped
  );
end;
$$;

revoke all on function public.import_mitre_attack(jsonb) from public, anon, authenticated;
grant execute on function public.import_mitre_attack(jsonb) to service_role;
