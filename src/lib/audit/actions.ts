/**
 * Audit action names. The database only requires the shape `word(.word)*` (lowercase and
 * underscores); this list is the vocabulary the application actually writes. Add new actions here
 * as features arrive so the trail stays searchable.
 */
export const AUDIT_ACTIONS = [
  "auth.login",
  "auth.login_failed",
  "auth.logout",
  "auth.signup",
  "auth.email_link_session",
  "auth.password_reset_requested",
  "auth.password_changed",
  "authz.denied",
  "indicator.created",
  "indicator.updated",
  "indicator.deleted",
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];
