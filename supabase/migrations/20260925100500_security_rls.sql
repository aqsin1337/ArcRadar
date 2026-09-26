-- Row Level Security for every application table.
--
-- Model: the browser and the server's user-scoped client talk to the database as the
-- `authenticated` role, so every policy below is enforced. Privileged server work uses the
-- service-role key, which bypasses RLS and therefore stays server-side only. `anon` gets nothing.
--
-- Each standard policy asks public.has_permission(<key>), which resolves the caller's role
-- from public.profiles. The call is wrapped in (select ...) so Postgres evaluates it once per
-- statement instead of once per row.

-- ---------------------------------------------------------------------------
-- Standard policies: read / write (insert + update) / delete permission per table.
-- owner_col, when set, must equal the caller's uid on insert (its column default is auth.uid()).
-- ---------------------------------------------------------------------------
do $$
declare
  t record;
  owner_check text;
begin
  for t in
    select * from (values
      ('tags',                           'indicators:read',      'indicators:write',      'indicators:write',      null::text),
      ('indicators',                     'indicators:read',      'indicators:write',      'indicators:delete',     'created_by'),
      ('indicator_tags',                 'indicators:read',      'indicators:write',      'indicators:write',      null),
      ('indicator_relationships',        'indicators:read',      'indicators:write',      'indicators:write',      'created_by'),
      ('indicator_threat_actors',        'indicators:read',      'indicators:write',      'indicators:write',      null),
      ('indicator_campaigns',            'indicators:read',      'indicators:write',      'indicators:write',      null),
      ('indicator_malware',              'indicators:read',      'indicators:write',      'indicators:write',      null),
      ('threat_actors',                  'threat_intel:read',    'threat_intel:write',    'threat_intel:write',    'created_by'),
      ('campaigns',                      'threat_intel:read',    'threat_intel:write',    'threat_intel:write',    'created_by'),
      ('malware',                        'threat_intel:read',    'threat_intel:write',    'threat_intel:write',    'created_by'),
      ('mitre_techniques',               'threat_intel:read',    'threat_intel:write',    'threat_intel:write',    null),
      ('threat_actor_campaigns',         'threat_intel:read',    'threat_intel:write',    'threat_intel:write',    null),
      ('threat_actor_malware',           'threat_intel:read',    'threat_intel:write',    'threat_intel:write',    null),
      ('threat_actor_techniques',        'threat_intel:read',    'threat_intel:write',    'threat_intel:write',    null),
      ('vulnerabilities',                'vulnerabilities:read', 'vulnerabilities:write', 'vulnerabilities:write', 'created_by'),
      ('vulnerability_affected_products','vulnerabilities:read', 'vulnerabilities:write', 'vulnerabilities:write', null),
      ('events',                         'events:read',          'events:write',          'events:write',          'created_by'),
      ('alerts',                         'alerts:read',          'alerts:write',          'alerts:delete',         'created_by'),
      ('investigations',                 'investigations:read',  'investigations:write',  'investigations:delete', 'created_by'),
      ('investigation_indicators',       'investigations:read',  'investigations:write',  'investigations:write',  null),
      ('investigation_alerts',           'investigations:read',  'investigations:write',  'investigations:write',  null),
      ('investigation_tags',             'investigations:read',  'investigations:write',  'investigations:write',  null),
      ('investigation_evidence',         'investigations:read',  'investigations:write',  'investigations:write',  'added_by'),
      ('reports',                        'reports:read',         'reports:write',         'reports:write',         'created_by'),
      ('integrations',                   'integrations:read',    'integrations:manage',   'integrations:manage',    null)
    ) as v (tbl, read_perm, write_perm, delete_perm, owner_col)
  loop
    execute format('alter table public.%I enable row level security', t.tbl);

    execute format(
      'create policy %I on public.%I for select to authenticated using ((select public.has_permission(%L)))',
      t.tbl || '_select', t.tbl, t.read_perm);

    owner_check := case
      when t.owner_col is null then ''
      else format(' and %I = (select auth.uid())', t.owner_col)
    end;

    execute format(
      'create policy %I on public.%I for insert to authenticated with check ((select public.has_permission(%L))%s)',
      t.tbl || '_insert', t.tbl, t.write_perm, owner_check);

    execute format(
      'create policy %I on public.%I for update to authenticated using ((select public.has_permission(%L))) with check ((select public.has_permission(%L)))',
      t.tbl || '_update', t.tbl, t.write_perm, t.write_perm);

    execute format(
      'create policy %I on public.%I for delete to authenticated using ((select public.has_permission(%L)))',
      t.tbl || '_delete', t.tbl, t.delete_perm);
  end loop;
end
$$;

-- created_by is provenance: keep it fixed after insert.
create trigger indicators_protect_created_by before update on public.indicators
  for each row execute function public.protect_created_by();
create trigger indicator_relationships_protect_created_by before update on public.indicator_relationships
  for each row execute function public.protect_created_by();
create trigger threat_actors_protect_created_by before update on public.threat_actors
  for each row execute function public.protect_created_by();
create trigger campaigns_protect_created_by before update on public.campaigns
  for each row execute function public.protect_created_by();
create trigger malware_protect_created_by before update on public.malware
  for each row execute function public.protect_created_by();
create trigger vulnerabilities_protect_created_by before update on public.vulnerabilities
  for each row execute function public.protect_created_by();
create trigger events_protect_created_by before update on public.events
  for each row execute function public.protect_created_by();
create trigger alerts_protect_created_by before update on public.alerts
  for each row execute function public.protect_created_by();
create trigger investigations_protect_created_by before update on public.investigations
  for each row execute function public.protect_created_by();
create trigger reports_protect_created_by before update on public.reports
  for each row execute function public.protect_created_by();

-- ---------------------------------------------------------------------------
-- RBAC reference tables: readable by any signed-in user, changed only through migrations
-- or the service role.
-- ---------------------------------------------------------------------------
alter table public.roles enable row level security;
alter table public.permissions enable row level security;
alter table public.role_permissions enable row level security;

create policy roles_select on public.roles for select to authenticated using (true);
create policy permissions_select on public.permissions for select to authenticated using (true);
create policy role_permissions_select on public.role_permissions for select to authenticated using (true);

-- ---------------------------------------------------------------------------
-- profiles: active users can see teammates (needed for assignment), edit only their own
-- display name / avatar. Roles and is_active are changed by the server (service role).
-- ---------------------------------------------------------------------------
alter table public.profiles enable row level security;

create policy profiles_select on public.profiles for select to authenticated
  using ((select public.current_role_name()) is not null);

create policy profiles_update_own on public.profiles for update to authenticated
  using (id = (select auth.uid()) and is_active)
  with check (id = (select auth.uid()) and is_active);

-- ---------------------------------------------------------------------------
-- investigation_notes: analysts add notes; only the author edits or removes their own
-- (admins with investigations:delete may remove any).
-- ---------------------------------------------------------------------------
alter table public.investigation_notes enable row level security;

create policy investigation_notes_select on public.investigation_notes for select to authenticated
  using ((select public.has_permission('investigations:read')));

create policy investigation_notes_insert on public.investigation_notes for insert to authenticated
  with check ((select public.has_permission('investigations:write')) and author_id = (select auth.uid()));

create policy investigation_notes_update on public.investigation_notes for update to authenticated
  using ((select public.has_permission('investigations:write')) and author_id = (select auth.uid()))
  with check ((select public.has_permission('investigations:write')) and author_id = (select auth.uid()));

create policy investigation_notes_delete on public.investigation_notes for delete to authenticated
  using (
    ((select public.has_permission('investigations:write')) and author_id = (select auth.uid()))
    or (select public.has_permission('investigations:delete'))
  );

-- ---------------------------------------------------------------------------
-- api_keys: users see their own keys (admins see all). Rows are created, revoked and
-- touched by the server with the service role, so no write policies exist for clients.
-- ---------------------------------------------------------------------------
alter table public.api_keys enable row level security;

create policy api_keys_select on public.api_keys for select to authenticated
  using (
    (user_id = (select auth.uid()) and (select public.has_permission('api_keys:manage_own')))
    or (select public.has_permission('api_keys:manage_all'))
  );

-- ---------------------------------------------------------------------------
-- audit_logs: readable by holders of audit:read; written only by the server (service role).
-- ---------------------------------------------------------------------------
alter table public.audit_logs enable row level security;

create policy audit_logs_select on public.audit_logs for select to authenticated
  using ((select public.has_permission('audit:read')));

-- ---------------------------------------------------------------------------
-- Privileges (defense in depth on top of RLS)
-- ---------------------------------------------------------------------------

-- anon never touches application tables.
revoke all on all tables in schema public from anon;
revoke all on all sequences in schema public from anon;
alter default privileges in schema public revoke all on tables from anon;
alter default privileges in schema public revoke all on sequences from anon;

-- TRUNCATE, REFERENCES and TRIGGER are not subject to RLS; clients never need them.
revoke truncate, references, trigger on all tables in schema public from authenticated;
alter default privileges in schema public revoke truncate, references, trigger on tables from authenticated;

-- RBAC reference tables are read-only for clients.
revoke insert, update, delete on public.roles, public.permissions, public.role_permissions from authenticated;

-- profiles: clients may update only display_name and avatar_url (never role_name / is_active).
revoke insert, update, delete on public.profiles from authenticated;
grant update (display_name, avatar_url) on public.profiles to authenticated;

-- api_keys: clients may read metadata but never key_hash, and cannot write at all.
revoke all on public.api_keys from authenticated;
grant select (id, user_id, name, key_prefix, scopes, last_used_at, expires_at, revoked_at, created_at)
  on public.api_keys to authenticated;

-- audit_logs: append-only for everyone; the trigger also blocks the table owner.
revoke all on public.audit_logs from anon, authenticated, service_role;
grant select on public.audit_logs to authenticated;
grant select, insert on public.audit_logs to service_role;
grant usage on sequence public.audit_logs_id_seq to service_role;
