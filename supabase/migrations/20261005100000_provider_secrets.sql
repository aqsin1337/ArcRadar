-- Provider keys entered by an administrator in the app (Threat-intelligence, AI and GitHub settings).
--
-- Until now every one of these lived only in the server's environment variables. They can now also
-- be saved from the admin UI. The value is encrypted by the application (AES-256-GCM, key in the
-- SECRETS_ENCRYPTION_KEY server variable) BEFORE it reaches this table, so a database dump or a
-- Supabase dashboard read shows only ciphertext. Clients can never read or write the table: the
-- policy can never match and every privilege is revoked; only the service role (the application's
-- admin client, after an `integrations:manage` check) touches it.

create table public.provider_secrets (
  name text primary key check (
    name in (
      'VIRUSTOTAL_API_KEY',
      'ABUSEIPDB_API_KEY',
      'OTX_API_KEY',
      'NVD_API_KEY',
      'SHODAN_INTERNETDB',
      'GROQ_API_KEY',
      'OPENAI_API_KEY',
      'ANTHROPIC_API_KEY',
      'DEEPSEEK_API_KEY',
      'GITHUB_TOKEN',
      'GITHUB_RULES_REPO',
      'GITHUB_RULES_BRANCH'
    )
  ),
  ciphertext text not null check (char_length(ciphertext) between 1 and 4000),
  -- Last characters of a secret, so the page can say which one is saved without revealing it.
  last4 text check (last4 is null or char_length(last4) <= 4),
  updated_by uuid references auth.users (id) on delete set null,
  updated_at timestamptz not null default now()
);

alter table public.provider_secrets enable row level security;

create policy provider_secrets_no_direct_access on public.provider_secrets
  for all to authenticated, anon
  using (false)
  with check (false);

revoke all on public.provider_secrets from public, anon, authenticated;
grant select, insert, update, delete on public.provider_secrets to service_role;
