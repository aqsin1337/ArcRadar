-- ArcRadar foundation: extensions, shared enum types, generic trigger functions.

create extension if not exists pg_trgm with schema extensions;

-- Where a record came from. UI must never present 'demo' or 'local' data as live intelligence.
create type public.data_origin as enum ('demo', 'local', 'external');

create type public.severity as enum ('info', 'low', 'medium', 'high', 'critical');
create type public.verdict as enum ('unknown', 'benign', 'suspicious', 'malicious');
create type public.priority as enum ('low', 'medium', 'high', 'critical');

create type public.indicator_type as enum (
  'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'cve', 'other'
);
create type public.indicator_status as enum (
  'active', 'inactive', 'expired', 'whitelisted', 'under_review'
);
create type public.relationship_type as enum (
  'resolves_to', 'communicates_with', 'downloads', 'hosted_on', 'related_to'
);

create type public.exploit_status as enum ('unknown', 'none', 'poc_available', 'exploited_in_wild');
create type public.campaign_status as enum ('active', 'dormant', 'concluded');

create type public.alert_status as enum (
  'new', 'acknowledged', 'investigating', 'resolved', 'false_positive'
);
create type public.investigation_status as enum (
  'open', 'investigating', 'contained', 'resolved', 'closed'
);
create type public.report_type as enum (
  'investigation', 'indicators', 'alerts', 'vulnerabilities', 'threat_actor'
);

create function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- Provenance must not be rewritten after insert, even by users allowed to update the row.
create function public.protect_created_by()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.created_by = old.created_by;
  return new;
end;
$$;

-- Used by triggers that make a table append-only.
create function public.reject_modification()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception '% on % is not allowed: table is append-only', tg_op, tg_table_name
    using errcode = 'P0001';
end;
$$;
