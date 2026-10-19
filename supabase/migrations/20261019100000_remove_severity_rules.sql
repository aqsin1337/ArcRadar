-- Remove the ArcRadar-side severity rules (Phase 10's detection_rules) at the user's request
-- (2026-10-19, decision 34). Wazuh and Splunk rules already set an alert's severity at the source;
-- a second layer inside ArcRadar that could only raise it was redundant next to them. Alert
-- deduplication, which shared the same insert trigger, stays exactly as it was: same fingerprint,
-- same still-open primary, same 60-minute window.
--
-- rules:manage stays: wazuh_rules and siem_rules are guarded by it.

-- ---------------------------------------------------------------------------
-- 1. The insert trigger now only deduplicates.
-- ---------------------------------------------------------------------------
create function public.alerts_dedup()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_primary_id uuid;
begin
  new.fingerprint := md5(
    lower(coalesce(new.source, '')) || '|' ||
    lower(regexp_replace(coalesce(new.title, ''), '[^a-z0-9]+', '', 'gi')) || '|' ||
    coalesce(new.asset_id::text, '') || '|' ||
    coalesce(new.indicator_id::text, '')
  );

  if new.duplicate_of is null then
    select id into v_primary_id
      from public.alerts
      where fingerprint = new.fingerprint
        and duplicate_of is null
        and status not in ('resolved', 'false_positive')
        and created_at > now() - interval '60 minutes'
      order by created_at desc
      limit 1;
    if found then
      new.duplicate_of := v_primary_id;
      update public.alerts set duplicate_count = duplicate_count + 1 where id = v_primary_id;
    end if;
  end if;

  return new;
end;
$$;

drop trigger alerts_dedup_and_rules_trigger on public.alerts;
create trigger alerts_dedup_trigger before insert on public.alerts
  for each row execute function public.alerts_dedup();
drop function public.alerts_dedup_and_rules();

-- ---------------------------------------------------------------------------
-- 2. The rule catalog, its matcher, its helper and the trace column on alerts.
-- ---------------------------------------------------------------------------
drop function public.detection_rule_matches(jsonb, public.alerts);
alter table public.alerts drop column matched_rule_id;
drop table public.detection_rules;
drop function public.severity_rank(public.severity);
