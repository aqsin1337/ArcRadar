import { beforeEach, describe, expect, it, vi } from "vitest";
import { RATE_LIMITS } from "@/lib/rate-limit/constants";
import { enforceRateLimit, ipSubject, userSubject } from "@/lib/rate-limit/service";
import { createAdminClient } from "@/lib/supabase/admin";

vi.mock("@/lib/supabase/admin", () => ({ createAdminClient: vi.fn() }));
vi.mock("@/lib/log", () => ({ logError: vi.fn(), logWarn: vi.fn() }));

function mockRpc(result: { data?: unknown; error?: unknown }) {
  const single = vi.fn().mockResolvedValue(result);
  const rpc = vi.fn(() => ({ single }));
  vi.mocked(createAdminClient).mockReturnValue({ rpc } as never);
  return { rpc, single };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("enforceRateLimit", () => {
  it("resolves quietly when the bucket allows the request", async () => {
    const { rpc } = mockRpc({ data: { allowed: true, retry_after_seconds: 0 }, error: null });
    await expect(enforceRateLimit("authByIp", "203.0.113.9")).resolves.toBeUndefined();
    expect(rpc).toHaveBeenCalledWith("check_rate_limit", {
      p_key: "authByIp:203.0.113.9",
      p_limit: RATE_LIMITS.authByIp.limit,
      p_window_seconds: RATE_LIMITS.authByIp.windowSeconds,
    });
  });

  it("prefixes the key with the route class, so two classes never share a bucket", async () => {
    const { rpc } = mockRpc({ data: { allowed: true, retry_after_seconds: 0 }, error: null });
    await enforceRateLimit("aiByUser", "user-1");
    expect(rpc).toHaveBeenCalledWith(
      "check_rate_limit",
      expect.objectContaining({
        p_key: "aiByUser:user-1",
      }),
    );
  });

  it("throws a 429 with Retry-After once the bucket is over its limit", async () => {
    mockRpc({ data: { allowed: false, retry_after_seconds: 42 }, error: null });
    const failure = enforceRateLimit("aiByUser", "user-1");
    await expect(failure).rejects.toMatchObject({ status: 429, code: "RATE_LIMITED" });
    await failure.catch((error: { headers?: Record<string, string> }) => {
      expect(error.headers?.["Retry-After"]).toBe("42");
    });
  });

  it("falls back to the rule's own window when retry_after_seconds is missing", async () => {
    mockRpc({ data: { allowed: false, retry_after_seconds: null }, error: null });
    await enforceRateLimit("authByIp", "1.2.3.4").catch(
      (error: { headers?: Record<string, string> }) => {
        expect(error.headers?.["Retry-After"]).toBe(String(RATE_LIMITS.authByIp.windowSeconds));
      },
    );
  });

  it("fails open (never throws) when the database call itself errors", async () => {
    mockRpc({ data: null, error: new Error("connection refused") });
    await expect(enforceRateLimit("authByIp", "1.2.3.4")).resolves.toBeUndefined();
  });

  it("fails open when the admin client cannot even be created", async () => {
    vi.mocked(createAdminClient).mockImplementation(() => {
      throw new Error("SUPABASE_SERVICE_ROLE_KEY missing");
    });
    await expect(enforceRateLimit("authByIp", "1.2.3.4")).resolves.toBeUndefined();
  });
});

describe("subject builders", () => {
  it("ipSubject reads the client IP, or falls back to a shared 'unknown' bucket", () => {
    expect(ipSubject({ headers: new Headers({ "x-real-ip": "203.0.113.9" }) })).toBe("203.0.113.9");
    expect(ipSubject({ headers: new Headers() })).toBe("unknown");
  });

  it("userSubject reads the caller's id, or falls back when there is no session", () => {
    expect(userSubject({ user: { id: "u1" } })).toBe("u1");
    expect(userSubject(undefined)).toBe("anonymous");
  });
});
