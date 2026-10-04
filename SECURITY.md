# Security policy

ArcRadar is a portfolio project. If you find a vulnerability, please report it privately through
GitHub's "Report a vulnerability" button on the repository's Security tab rather than opening a public
issue, and please do not exploit it against the live deployment beyond what is needed to show the issue.

Useful background for a reviewer:

- Authorization is enforced in Postgres row-level security. Start with `supabase/migrations` and the SQL
  tests in `supabase/tests`.
- Secrets (service-role key, provider keys, API keys) are server-only. Only the hash of an API key is
  stored.
- The audit log is append-only, including for the service role.
- Details of the hardening work (rate limiting, CSP, cookies, SSRF review) are in
  `docs/ARCRADAR_PROGRESS.md` under Phase 11.
