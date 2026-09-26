import { isIP } from "node:net";

const MAX_USER_AGENT_LENGTH = 500; // matches the audit_logs.user_agent check constraint

export type RequestMeta = { ip: string | null; userAgent: string | null };

/**
 * Best-effort client address for the audit trail. `x-real-ip` is set by the trusted edge (Vercel,
 * or nginx locally) and preferred; the first `x-forwarded-for` hop is the fallback. Values that are
 * not valid IP literals are dropped because the column is `inet`. Do not use this for security
 * decisions: without a trusted proxy the header can be forged.
 */
export function getClientIp(headers: Headers): string | null {
  const candidates = [headers.get("x-real-ip"), headers.get("x-forwarded-for")?.split(",")[0]];
  for (const candidate of candidates) {
    const value = candidate?.trim();
    if (value && isIP(value) !== 0) return value;
  }
  return null;
}

export function getRequestMeta(request: { headers: Headers } | undefined): RequestMeta {
  if (!request) return { ip: null, userAgent: null };
  const userAgent = request.headers.get("user-agent")?.trim();
  return {
    ip: getClientIp(request.headers),
    userAgent: userAgent ? userAgent.slice(0, MAX_USER_AGENT_LENGTH) : null,
  };
}
