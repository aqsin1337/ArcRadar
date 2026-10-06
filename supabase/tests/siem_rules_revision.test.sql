-- siem_rules_revision(): service-role only, and it moves when a rule is pushed.
-- Run with `npm run db:test`. One transaction, rolled back.

begin;

insert into auth.users (id, email) values ('e8e8e8e8-0000-4000-8000-000000000001', 'fxrev-admin@arcradar.test');
update public.profiles set role_name = 'admin' where id = 'e8e8e8e8-0000-4000-8000-000000000001';

do $$
declare who text; before_rev text; after_rev text; again_rev text;
begin
  foreach who in array array['anon', 'authenticated'] loop
    if has_function_privilege(who, 'public.siem_rules_revision(text)', 'execute') then
      raise exception 'FAIL % may execute siem_rules_revision', who;
    end if;
  end loop;
  if not has_function_privilege('service_role', 'public.siem_rules_revision(text)', 'execute') then
    raise exception 'FAIL the service role cannot execute siem_rules_revision';
  end if;

  before_rev := public.siem_rules_revision('splunk');

  perform set_config('request.jwt.claims', json_build_object('sub', 'e8e8e8e8-0000-4000-8000-000000000001', 'role', 'authenticated')::text, true);
  set local role authenticated;
  insert into public.siem_rules (siem, rule_key, name, severity, spec, source)
    values ('splunk', 'fxrev1', 'fxrev rule', 'low', '{}', 'manual');
  reset role;

  -- a draft is not a push: the revision does not move
  again_rev := public.siem_rules_revision('splunk');
  if again_rev <> before_rev then raise exception 'FAIL a draft moved the revision'; end if;

  update public.siem_rules
    set status = 'pushed', github_path = 'splunk/arcradar_fxrev1.conf', pushed_at = now() + interval '1 hour'
    where rule_key = 'fxrev1';
  after_rev := public.siem_rules_revision('splunk');
  if after_rev = before_rev or after_rev = '' then raise exception 'FAIL a push did not move the revision (% -> %)', before_rev, after_rev; end if;

  -- pushing again moves it again; another SIEM is not affected
  update public.siem_rules set pushed_at = now() + interval '2 hours' where rule_key = 'fxrev1';
  if public.siem_rules_revision('splunk') = after_rev then raise exception 'FAIL a second push did not move the revision'; end if;
  if public.siem_rules_revision('qradar') <> '' then raise exception 'FAIL another SIEM saw a revision'; end if;

  raise notice 'ok - siem_rules_revision: service-role only, moves on every push and only on a push';
end $$;

rollback;

do $$ begin raise notice 'SIEM RULES REVISION DATABASE TESTS PASSED'; end $$;
