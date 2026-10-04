/**
 * One rule per route class, deliberately conservative and not admin-configurable (the same
 * narrowing decision Phase 10 made for the dedup window): a portfolio deployment on free-tier
 * provider quotas needs a floor, not a dial. Add a class here when a new endpoint needs one; do
 * not reuse another class's key prefix, or two unrelated endpoints would share a bucket.
 */
export type RateLimitRule = { limit: number; windowSeconds: number };

export const RATE_LIMITS = {
  /** Sign-in, sign-up, password reset: defends against credential stuffing and enumeration by
   * volume, keyed by IP (these run before a session exists). Matches Supabase Auth's own
   * `sign_in_sign_ups` limit (`supabase/config.toml`, 30 per 5 minutes per IP) rather than adding a
   * stricter, second bottleneck: this is a redundant, independent layer in front of it (useful, for
   * example, if a hosted project's own limiter is ever misconfigured or disabled), not a tighter one. */
  authByIp: { limit: 30, windowSeconds: 300 } satisfies RateLimitRule,
  /** Asking an AI provider for an analysis: real, metered cost per call, keyed by the caller. */
  aiByUser: { limit: 30, windowSeconds: 3600 } satisfies RateLimitRule,
  /** Creating an alert by hand: each insert also runs the dedup/detection-rule trigger. */
  alertWriteByUser: { limit: 60, windowSeconds: 60 } satisfies RateLimitRule,
  /** "Import now" for the public threat feeds: several downloads and a bulk write per call. */
  feedImportByUser: { limit: 6, windowSeconds: 600 } satisfies RateLimitRule,
  /** Asking the AI to draft a Wazuh rule: metered cost per call, keyed by the caller. */
  wazuhRuleGenerateByUser: { limit: 20, windowSeconds: 3600 } satisfies RateLimitRule,
  /** Committing a rule file to GitHub: an outbound write per call. */
  wazuhRulePushByUser: { limit: 30, windowSeconds: 600 } satisfies RateLimitRule,
  /** A Wazuh Manager's batches: generous (a real sensor delivers steadily, not in bursts), but a
   * cap protects the same trigger from a misbehaving or compromised key. */
  ingestByKey: { limit: 120, windowSeconds: 60 } satisfies RateLimitRule,
} as const;

export type RateLimitClass = keyof typeof RATE_LIMITS;
