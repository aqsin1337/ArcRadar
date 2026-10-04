-- Phase 8: AI integration foundation.
--
-- A third provider family, next to intel lookups and telemetry ingestion: language-model providers
-- that turn an alert an analyst can already read into a structured, labelled analysis. Nothing here
-- runs on its own; every row is the answer to one explicit "ask AI" click, kept as an immutable
-- record (like a report snapshot) rather than something that changes under the analyst.
--
-- 1. Two new permissions: ai:use (ask for an analysis) and ai:manage (choose the active provider).
-- 2. Five new integration rows (capabilities gains 'ai') for Groq (the default), OpenAI, Anthropic,
--    DeepSeek and a local Ollama server. "Configured" (a server-side key/URL is set) and "enabled"
--    (an administrator allows it) already mean what they mean for every other provider.
-- 3. ai_settings: a genuine one-row table holding which configured, enabled provider is active right
--    now, since a deployment can have several keys set but only one model should answer.
-- 4. ai_analyses: one row per "ask AI" click, holding the validated, typed answer. subject_type /
--    subject_id is a polymorphic reference with no foreign key, the same shape audit_logs already
--    uses, because the table will grow more subject types (investigations, indicators) later. Phase
--    8 only ever writes subject_type = 'alert'; a later phase widens the check constraints, the same
--    way earlier phases have added a new migration rather than edited an old one.
-- 5. alerts.ai_fp_score caches the latest false-positive score so the alert list can sort by it
--    without joining ai_analyses on every row (the same reasoning as integrations.last_sync_at).

-- ---------------------------------------------------------------------------
-- 1. Permissions
-- ---------------------------------------------------------------------------
insert into public.permissions (key, description) values
  ('ai:use', 'Ask an AI provider to analyse an alert'),
  ('ai:manage', 'Choose the active AI provider and model');

insert into public.role_permissions (role_name, permission_key) values
  ('admin', 'ai:use'),
  ('admin', 'ai:manage'),
  ('analyst', 'ai:use');

-- ---------------------------------------------------------------------------
-- 2. Integration catalog
-- ---------------------------------------------------------------------------
alter table public.integrations drop constraint integrations_capabilities_check;
alter table public.integrations add constraint integrations_capabilities_check
  check (capabilities <@ array['ip', 'domain', 'url', 'hash', 'vulnerability', 'threat_intel', 'telemetry', 'ai']);

-- Enabled by default, matching every other provider as of 20260927120000: an administrator pauses
-- one explicitly, rather than opting each one in after its key is set.
insert into public.integrations (provider, display_name, capabilities, enabled) values
  ('groq', 'Groq', array['ai'], true),
  ('openai', 'OpenAI', array['ai'], true),
  ('anthropic', 'Anthropic Claude', array['ai'], true),
  ('deepseek', 'DeepSeek', array['ai'], true),
  ('ollama', 'Ollama (local)', array['ai'], true);

-- ---------------------------------------------------------------------------
-- 3. ai_settings: exactly one row, ever (id is boolean and must be true).
-- ---------------------------------------------------------------------------
create table public.ai_settings (
  id boolean primary key default true check (id),
  active_provider text references public.integrations (provider) on delete set null,
  active_model text check (active_model is null or char_length(active_model) between 1 and 200),
  updated_by uuid references public.profiles (id) on delete set null,
  updated_at timestamptz not null default now()
);

create trigger ai_settings_set_updated_at
  before update on public.ai_settings
  for each row execute function public.set_updated_at();

insert into public.ai_settings (id) values (true);

alter table public.ai_settings enable row level security;

-- Readable by anyone who can ask for or manage an analysis, so the alert page can explain why the
-- AI buttons are (or are not) available; changeable only by an administrator.
create policy ai_settings_select on public.ai_settings for select to authenticated
  using ((select public.has_permission('ai:use')) or (select public.has_permission('ai:manage')));

create policy ai_settings_update on public.ai_settings for update to authenticated
  using ((select public.has_permission('ai:manage')))
  with check ((select public.has_permission('ai:manage')) and updated_by = (select auth.uid()));

-- ---------------------------------------------------------------------------
-- 4. ai_analyses
-- ---------------------------------------------------------------------------
create table public.ai_analyses (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in (
    'threat_summary', 'attack_vector', 'severity_validation', 'response_actions', 'false_positive_score'
  )),
  subject_type text not null check (subject_type in ('alert')),
  subject_id uuid not null,
  provider text not null references public.integrations (provider),
  model text not null check (char_length(model) between 1 and 200),
  prompt_version integer not null check (prompt_version > 0),
  content jsonb not null,
  requested_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now()
);

create index ai_analyses_subject_idx on public.ai_analyses (subject_type, subject_id, kind, created_at desc);

alter table public.ai_analyses enable row level security;

-- No update or delete policy at all: an analysis is an immutable record of what was asked and
-- answered at that moment, the same as a generated report. Re-running a kind adds a new row.
create policy ai_analyses_select on public.ai_analyses for select to authenticated
  using (subject_type = 'alert' and (select public.has_permission('alerts:read')));

create policy ai_analyses_insert on public.ai_analyses for insert to authenticated
  with check (
    (select public.has_permission('ai:use'))
    and requested_by = (select auth.uid())
    and subject_type = 'alert'
    and (select public.has_permission('alerts:read'))
  );

-- With no update/delete policy at all, RLS already keeps every `authenticated` caller from matching
-- a row to change (the same silent-zero-rows behaviour a missing policy always has for UPDATE/DELETE).
-- The trigger is defense in depth for the one caller RLS does not restrict at all: the service role,
-- which bypasses RLS by design (the same reason audit_logs carries this same trigger).
create trigger ai_analyses_no_update_delete
  before update or delete on public.ai_analyses
  for each row execute function public.reject_modification();

-- ---------------------------------------------------------------------------
-- 5. Cached false-positive score on the alert itself
-- ---------------------------------------------------------------------------
alter table public.alerts
  add column ai_fp_score numeric check (ai_fp_score is null or (ai_fp_score >= 0 and ai_fp_score <= 100));
