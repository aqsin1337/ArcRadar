import type { FailureReason, ProviderAttempt, SkipReason } from "./types";

const SKIPPED: Record<SkipReason, string> = {
  not_permitted:
    "Live lookups are for analysts and administrators, so this provider was not asked.",
  not_public:
    "Private, reserved and documentation addresses and names are never sent to an external provider.",
  has_credentials:
    "URLs that contain a user name or password are never sent to an external provider.",
};

const FAILED: Record<Exclude<FailureReason, "rate_limited">, string> = {
  auth: "Rejected the API key. An administrator should check the key that is configured.",
  timeout: "Did not answer in time.",
  unavailable: "Could not be reached, or is unavailable right now.",
  bad_response: "Answered in a format ArcRadar could not read.",
};

/** One plain sentence about what happened when a provider was asked (or why it was not). */
export function describeAttempt(attempt: ProviderAttempt): string {
  if (attempt.status === "ok") return "Answered.";
  if (attempt.status === "not_found") return "Has no record of this value.";
  if (attempt.status === "skipped") return SKIPPED[attempt.reason];
  if (attempt.reason === "rate_limited") {
    return attempt.retry_after_seconds
      ? `Rate limit reached. Try again in about ${attempt.retry_after_seconds} seconds.`
      : "Rate limit reached. Try again later.";
  }
  return FAILED[attempt.reason];
}
