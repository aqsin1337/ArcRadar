-- Security operations entities: events, alerts, investigations (with notes/evidence/links)
-- and reports.

create table public.events (
  id uuid primary key default gen_random_uuid(),
  event_type text not null check (char_length(event_type) between 1 and 100),
  title text not null check (char_length(title) between 1 and 300),
  description text check (char_length(description) <= 5000),
  severity public.severity not null default 'info',
  source text not null default 'manual' check (char_length(source) between 1 and 100),
  indicator_id uuid references public.indicators (id) on delete set null,
  payload jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now(),
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now()
);

create index events_occurred_at_idx on public.events (occurred_at desc);
create index events_severity_idx on public.events (severity);
create index events_event_type_idx on public.events (event_type);
create index events_indicator_id_idx on public.events (indicator_id);

create table public.alerts (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 300),
  description text check (char_length(description) <= 5000),
  severity public.severity not null default 'medium',
  source text not null default 'manual' check (char_length(source) between 1 and 100),
  status public.alert_status not null default 'new',
  indicator_id uuid references public.indicators (id) on delete set null,
  event_id uuid references public.events (id) on delete set null,
  assigned_to uuid references public.profiles (id) on delete set null,
  acknowledged_at timestamptz,
  resolved_at timestamptz,
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint alerts_acknowledged_order check (acknowledged_at is null or acknowledged_at >= created_at),
  constraint alerts_resolved_order check (resolved_at is null or resolved_at >= created_at),
  -- resolved_at is set exactly when the alert is in a terminal state.
  constraint alerts_resolved_matches_status
    check ((status in ('resolved', 'false_positive')) = (resolved_at is not null))
);

create index alerts_status_idx on public.alerts (status);
create index alerts_severity_idx on public.alerts (severity);
create index alerts_created_at_idx on public.alerts (created_at desc);
create index alerts_indicator_id_idx on public.alerts (indicator_id);
create index alerts_event_id_idx on public.alerts (event_id);
create index alerts_assigned_to_idx on public.alerts (assigned_to);

create trigger alerts_set_updated_at
  before update on public.alerts
  for each row execute function public.set_updated_at();

create table public.investigations (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 300),
  description text check (char_length(description) <= 10000),
  status public.investigation_status not null default 'open',
  priority public.priority not null default 'medium',
  analyst_id uuid references public.profiles (id) on delete set null,
  closed_at timestamptz,
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint investigations_closed_matches_status check ((status = 'closed') = (closed_at is not null))
);

create index investigations_status_idx on public.investigations (status);
create index investigations_priority_idx on public.investigations (priority);
create index investigations_analyst_id_idx on public.investigations (analyst_id);
create index investigations_created_at_idx on public.investigations (created_at desc);

create trigger investigations_set_updated_at
  before update on public.investigations
  for each row execute function public.set_updated_at();

create table public.investigation_indicators (
  investigation_id uuid not null references public.investigations (id) on delete cascade,
  indicator_id uuid not null references public.indicators (id) on delete cascade,
  primary key (investigation_id, indicator_id)
);

create index investigation_indicators_indicator_idx on public.investigation_indicators (indicator_id);

create table public.investigation_alerts (
  investigation_id uuid not null references public.investigations (id) on delete cascade,
  alert_id uuid not null references public.alerts (id) on delete cascade,
  primary key (investigation_id, alert_id)
);

create index investigation_alerts_alert_idx on public.investigation_alerts (alert_id);

create table public.investigation_tags (
  investigation_id uuid not null references public.investigations (id) on delete cascade,
  tag_id uuid not null references public.tags (id) on delete cascade,
  primary key (investigation_id, tag_id)
);

create index investigation_tags_tag_idx on public.investigation_tags (tag_id);

create table public.investigation_notes (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.investigations (id) on delete cascade,
  author_id uuid default auth.uid() references public.profiles (id) on delete set null,
  body text not null check (char_length(body) between 1 and 10000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index investigation_notes_investigation_idx
  on public.investigation_notes (investigation_id, created_at);

create trigger investigation_notes_set_updated_at
  before update on public.investigation_notes
  for each row execute function public.set_updated_at();

-- Evidence is a reference (URL, file hash, ticket id, ...), not an uploaded file.
create table public.investigation_evidence (
  id uuid primary key default gen_random_uuid(),
  investigation_id uuid not null references public.investigations (id) on delete cascade,
  title text not null check (char_length(title) between 1 and 200),
  location text not null check (char_length(location) between 1 and 2048),
  description text check (char_length(description) <= 5000),
  added_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now()
);

create index investigation_evidence_investigation_idx
  on public.investigation_evidence (investigation_id, created_at);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 300),
  type public.report_type not null,
  investigation_id uuid references public.investigations (id) on delete set null,
  -- Inputs the report was generated from, and the generated snapshot itself.
  parameters jsonb not null default '{}'::jsonb,
  content jsonb not null default '{}'::jsonb,
  origin public.data_origin not null default 'local',
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now()
);

create index reports_created_at_idx on public.reports (created_at desc);
create index reports_type_idx on public.reports (type);
create index reports_investigation_id_idx on public.reports (investigation_id);
