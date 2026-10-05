-- Wazuh rules that fire on repetition ("5 failed logons within 5 minutes").
--
-- A frequency rule is a child of an event rule: Wazuh counts how often the parent matched inside a
-- window and alerts on the count. It attaches with if_matched_group / if_matched_sid instead of
-- if_group / if_sid, and may require the same value in some field each time (same_field). Such a rule
-- can have no conditions of its own (the count is the condition); an ordinary rule still needs one.

alter table public.wazuh_rules
  add column frequency integer check (frequency is null or frequency between 2 and 100),
  add column timeframe integer check (timeframe is null or timeframe between 1 and 86400),
  add column same_fields text[] not null default '{}'
    check (
      cardinality(same_fields) <= 3
      and array_to_string(same_fields, ',') ~ '^([A-Za-z0-9_.-]{1,100}(,[A-Za-z0-9_.-]{1,100})*)?$'
    ),
  add constraint wazuh_rules_repeat_pair_check check ((frequency is null) = (timeframe is null)),
  add constraint wazuh_rules_same_fields_repeat_check
    check (frequency is not null or cardinality(same_fields) = 0);

-- 1-10 conditions, except that a repeating rule may have none.
alter table public.wazuh_rules drop constraint wazuh_rules_conditions_check;
alter table public.wazuh_rules
  add constraint wazuh_rules_conditions_check check (
    jsonb_typeof(conditions) = 'array'
    and jsonb_array_length(conditions) <= 10
    and (jsonb_array_length(conditions) >= 1 or frequency is not null)
  );
