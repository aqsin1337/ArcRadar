-- Phase 9: investigation checklists and response orchestration.
--
-- No new permissions: checklist items and response actions reuse investigations:write/alerts:write,
-- exactly as planned in docs/AI_AND_ORCHESTRATION_ARCHITECTURE.md ("Response actions ... reuse the
-- existing investigations:write/alerts:write"). AI still needs ai:use, already added in Phase 8.
--
-- 1. ai_analyses widens to two more kinds (investigation_checklist, verdict_recommendation) and two
--    more subject types (investigation, indicator) -- a new migration, never editing 20260927130000.
-- 2. investigation_checklist_items: a checklist an AI suggestion or an analyst can add to, checked
--    off one at a time (not the immutable ai_analyses row itself -- that stays the suggestion; this is
--    the trackable, editable list it seeds).
-- 3. response_actions: a small catalog of response actions, curated like threat intelligence
--    (provenance-protected, origin='local' from clients).
-- 4. response_action_log: one row per recommendation/execution of a catalog action against a specific
--    alert (Phase 9's scope -- investigation_id exists for a later phase's UI, schema-ready today).

-- ---------------------------------------------------------------------------
-- 1. ai_analyses: widen kind and subject_type, and the two policies that name them.
-- ---------------------------------------------------------------------------
alter table public.ai_analyses drop constraint ai_analyses_kind_check;
alter table public.ai_analyses add constraint ai_analyses_kind_check
  check (kind in (
    'threat_summary', 'attack_vector', 'severity_validation', 'response_actions', 'false_positive_score',
    'investigation_checklist', 'verdict_recommendation'
  ));

alter table public.ai_analyses drop constraint ai_analyses_subject_type_check;
alter table public.ai_analyses add constraint ai_analyses_subject_type_check
  check (subject_type in ('alert', 'investigation', 'indicator'));

-- Which kind belongs to which subject type (the application checks this too, but the database is the
-- authority): the five alert-page kinds only ever attach to an alert, the checklist only to an
-- investigation, the verdict recommendation only to an indicator.
alter table public.ai_analyses add constraint ai_analyses_kind_subject_match_check
  check (
    (subject_type = 'alert' and kind in (
      'threat_summary', 'attack_vector', 'severity_validation', 'response_actions', 'false_positive_score'
    ))
    or (subject_type = 'investigation' and kind = 'investigation_checklist')
    or (subject_type = 'indicator' and kind = 'verdict_recommendation')
  );

drop policy ai_analyses_select on public.ai_analyses;
create policy ai_analyses_select on public.ai_analyses for select to authenticated
  using (
    (subject_type = 'alert' and (select public.has_permission('alerts:read')))
    or (subject_type = 'investigation' and (select public.has_permission('investigations:read')))
    or (subject_type = 'indicator' and (select public.has_permission('indicators:read')))
  );

drop policy ai_analyses_insert on public.ai_analyses;
create policy ai_analyses_insert on public.ai_analyses for insert to authenticated
  with check (
    (select public.has_permission('ai:use'))
    and requested_by = (select auth.uid())
    and (
      (subject_type = 'alert' and (select public.has_permission('alerts:read')))
      or (subject_type = 'investigation' and (select public.has_permission('investigations:read')))
      or (subject_type = 'indicator' and (select public.has_permission('indicators:read')))
    )
  );

-- ---------------------------------------------------------------------------
-- 2. Investigation checklist items
-- ---------------------------------------------------------------------------
create table public.investigation_checklist_items (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.investigations (id) on delete cascade,
  text text not null check (char_length(text) between 1 and 500),
  done boolean not null default false,
  source text not null check (source in ('ai', 'analyst')),
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  done_by uuid references public.profiles (id) on delete set null,
  done_at timestamptz
);

create index investigation_checklist_items_investigation_idx
  on public.investigation_checklist_items (investigation_id);

alter table public.investigation_checklist_items enable row level security;

create policy investigation_checklist_items_select on public.investigation_checklist_items
  for select to authenticated
  using ((select public.has_permission('investigations:read')));

create policy investigation_checklist_items_insert on public.investigation_checklist_items
  for insert to authenticated
  with check (
    (select public.has_permission('investigations:write'))
    and created_by = (select auth.uid())
  );

create policy investigation_checklist_items_update on public.investigation_checklist_items
  for update to authenticated
  using ((select public.has_permission('investigations:write')))
  with check ((select public.has_permission('investigations:write')));

create policy investigation_checklist_items_delete on public.investigation_checklist_items
  for delete to authenticated
  using ((select public.has_permission('investigations:write')));

-- ---------------------------------------------------------------------------
-- 3. Response actions: the catalog, curated like threat intelligence.
-- ---------------------------------------------------------------------------
create table public.response_actions (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 200),
  description text check (description is null or char_length(description) <= 2000),
  category text check (category is null or char_length(category) <= 50),
  origin data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger response_actions_set_updated_at before update on public.response_actions
  for each row execute function public.set_updated_at();
create trigger response_actions_protect_origin before update on public.response_actions
  for each row execute function public.protect_origin();
create trigger response_actions_protect_created_by before update on public.response_actions
  for each row execute function public.protect_created_by();

alter table public.response_actions enable row level security;

create policy response_actions_select on public.response_actions for select to authenticated
  using ((select public.has_permission('alerts:read')));

create policy response_actions_insert on public.response_actions for insert to authenticated
  with check (
    (select public.has_permission('investigations:write'))
    and created_by = (select auth.uid())
    and origin = 'local'
  );

create policy response_actions_update on public.response_actions for update to authenticated
  using ((select public.has_permission('investigations:write')))
  with check ((select public.has_permission('investigations:write')));

create policy response_actions_delete on public.response_actions for delete to authenticated
  using ((select public.has_permission('investigations:write')));

-- ---------------------------------------------------------------------------
-- 4. Response action log: tracked, human-executed (or AI-recommended) status per alert.
-- ---------------------------------------------------------------------------
create table public.response_action_log (
  id uuid primary key default gen_random_uuid(),
  action_id uuid not null references public.response_actions (id),
  alert_id uuid references public.alerts (id) on delete cascade,
  investigation_id uuid references public.investigations (id) on delete cascade,
  status text not null default 'recommended'
    check (status in ('recommended', 'acknowledged', 'completed', 'skipped')),
  source text not null check (source in ('ai', 'analyst')),
  notes text check (notes is null or char_length(notes) <= 2000),
  performed_by uuid references public.profiles (id) on delete set null,
  performed_at timestamptz,
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  check (
    (alert_id is not null and investigation_id is null)
    or (alert_id is null and investigation_id is not null)
  )
);

create index response_action_log_alert_idx on public.response_action_log (alert_id);
create index response_action_log_investigation_idx on public.response_action_log (investigation_id);

alter table public.response_action_log enable row level security;

create policy response_action_log_select on public.response_action_log for select to authenticated
  using (
    (alert_id is not null and (select public.has_permission('alerts:read')))
    or (investigation_id is not null and (select public.has_permission('investigations:read')))
  );

create policy response_action_log_insert on public.response_action_log for insert to authenticated
  with check (
    created_by = (select auth.uid())
    and (
      (alert_id is not null and (select public.has_permission('alerts:write')))
      or (investigation_id is not null and (select public.has_permission('investigations:write')))
    )
  );

create policy response_action_log_update on public.response_action_log for update to authenticated
  using (
    (alert_id is not null and (select public.has_permission('alerts:write')))
    or (investigation_id is not null and (select public.has_permission('investigations:write')))
  )
  with check (
    (alert_id is not null and (select public.has_permission('alerts:write')))
    or (investigation_id is not null and (select public.has_permission('investigations:write')))
  );

create policy response_action_log_delete on public.response_action_log for delete to authenticated
  using (
    (alert_id is not null and (select public.has_permission('alerts:write')))
    or (investigation_id is not null and (select public.has_permission('investigations:write')))
  );
