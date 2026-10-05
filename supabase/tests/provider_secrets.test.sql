-- provider_secrets: keys an administrator saves in the app. No client role may read or write the
-- table (not even an administrator); only the service role can, and only the allow-listed names are
-- accepted. Run with `npm run db:test`. One transaction, rolled back.

begin;

-- 1. Neither anon nor authenticated may touch the table.
do $$
declare blocked boolean;
begin
  set local role anon;
  blocked := false;
  begin perform * from public.provider_secrets; exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL anon could read provider_secrets'; end if;
  reset role;

  set local role authenticated;
  blocked := false;
  begin perform * from public.provider_secrets; exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL authenticated could read provider_secrets'; end if;
  blocked := false;
  begin
    insert into public.provider_secrets (name, ciphertext) values ('GROQ_API_KEY', 'v1.a.b.c');
  exception when insufficient_privilege then blocked := true; end;
  if not blocked then raise exception 'FAIL authenticated could write provider_secrets'; end if;
  reset role;

  raise notice 'ok - provider_secrets has no direct access for anon or authenticated';
end $$;

-- 2. The service role can write and read, and the name must be on the allow-list.
do $$
declare n integer; blocked boolean;
begin
  set local role service_role;
  insert into public.provider_secrets (name, ciphertext, last4) values ('GROQ_API_KEY', 'v1.a.b.c', 'wxyz');
  select count(*) into n from public.provider_secrets where name = 'GROQ_API_KEY';
  if n <> 1 then raise exception 'FAIL service_role could not save a key'; end if;

  blocked := false;
  begin
    insert into public.provider_secrets (name, ciphertext) values ('OLLAMA_BASE_URL', 'v1.a.b.c');
  exception when check_violation then blocked := true; end;
  if not blocked then raise exception 'FAIL a name outside the allow-list was accepted'; end if;

  blocked := false;
  begin
    insert into public.provider_secrets (name, ciphertext, last4) values ('OTX_API_KEY', 'v1.a.b.c', 'toolong');
  exception when check_violation then blocked := true; end;
  if not blocked then raise exception 'FAIL a long last4 was accepted'; end if;
  reset role;

  raise notice 'ok - service_role saves keys; only allow-listed names with a short last4 are accepted';
end $$;

rollback;
