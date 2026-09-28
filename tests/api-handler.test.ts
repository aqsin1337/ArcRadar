import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { apiErrors } from "@/lib/api/errors";
import { protectedRoute, publicRoute } from "@/lib/api/handler";
import { assertSameOrigin } from "@/lib/api/origin";
import { ok } from "@/lib/api/response";
import { toApiError, unwrap } from "@/lib/api/supabase-errors";
import { EnvError } from "@/lib/env/parse";
import { writeAuditLog } from "@/lib/audit/write";
import { enforceRateLimit } from "@/lib/rate-limit/service";
import { createClient } from "@/lib/supabase/server";
import { USER_ID, apiRequest, fakeSupabase } from "./helpers/supabase";

vi.mock("@/lib/supabase/server", () => ({ createClient: vi.fn() }));
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: vi.fn().mockResolvedValue(true) }));
vi.mock("@/lib/rate-limit/service", () => ({
  enforceRateLimit: vi.fn().mockResolvedValue(undefined),
}));

const createClientMock = vi.mocked(createClient);
const auditMock = vi.mocked(writeAuditLog);
const rateLimitMock = vi.mocked(enforceRateLimit);

function mockSupabase(options?: Parameters<typeof fakeSupabase>[0]) {
  const supabase = fakeSupabase(options);
  createClientMock.mockResolvedValue(supabase as never);
  return supabase;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "error").mockImplementation(() => {});
  mockSupabase();
});

describe("publicRoute", () => {
  it("wraps the response with no-store and a request id", async () => {
    const route = publicRoute(async () => ok({ hello: "world" }));
    const response = await route(apiRequest("/api/x"));
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
    expect(await response.json()).toEqual({ success: true, data: { hello: "world" }, error: null });
  });

  it("passes route params to the handler", async () => {
    const route = publicRoute<{ id: string }>(async ({ params }) => ok(params));
    const response = await route(apiRequest("/api/x/7"), { params: Promise.resolve({ id: "7" }) });
    expect((await response.json()).data).toEqual({ id: "7" });
  });

  it("maps a thrown ApiError to its status, code, details and headers", async () => {
    const route = publicRoute(async () => {
      throw apiErrors.rateLimited(30);
    });
    const response = await route(apiRequest("/api/x"));
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("30");
    expect((await response.json()).error.code).toBe("RATE_LIMITED");
  });

  it("maps a ZodError to 422 with issues", async () => {
    const route = publicRoute(async () => {
      z.object({ a: z.string() }).parse({});
      return ok(null);
    });
    const response = await route(apiRequest("/api/x"));
    const body = await response.json();
    expect(response.status).toBe(422);
    expect(body.error.code).toBe("VALIDATION_ERROR");
    expect(body.error.details.issues[0].path).toBe("a");
  });

  it("hides unexpected errors behind a generic 500 and logs them", async () => {
    const route = publicRoute(async () => {
      throw new Error('relation "secret_table" does not exist');
    });
    const response = await route(apiRequest("/api/x"));
    const text = await response.text();
    expect(response.status).toBe(500);
    expect(text).toContain("INTERNAL_ERROR");
    expect(text).not.toContain("secret_table");
    expect(console.error).toHaveBeenCalled();
  });

  it("answers 503 when required environment variables are missing", async () => {
    createClientMock.mockRejectedValue(new EnvError(["NEXT_PUBLIC_SUPABASE_URL"], "public"));
    const response = await publicRoute(async () => ok(null))(apiRequest("/api/x"));
    const text = await response.text();
    expect(response.status).toBe(503);
    expect(text).not.toContain("NEXT_PUBLIC_SUPABASE_URL");
  });

  it("checks the rate limit, keyed by whatever `subject` computes, before the handler runs", async () => {
    const handler = vi.fn(async () => ok(null));
    const subject = vi.fn(() => "203.0.113.9");
    const route = publicRoute(handler, { rateLimit: { routeClass: "authByIp", subject } });
    await route(apiRequest("/api/x"));
    expect(rateLimitMock).toHaveBeenCalledWith("authByIp", "203.0.113.9");
    expect(handler).toHaveBeenCalledOnce();
  });

  it("returns 429 and never calls the handler once the rate limit throws", async () => {
    rateLimitMock.mockRejectedValueOnce(apiErrors.rateLimited(30));
    const handler = vi.fn(async () => ok(null));
    const route = publicRoute(handler, {
      rateLimit: { routeClass: "authByIp", subject: () => "203.0.113.9" },
    });
    const response = await route(apiRequest("/api/x"));
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("30");
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("same-origin check", () => {
  const route = publicRoute(async () => ok({ done: true }));

  it("rejects a cross-origin unsafe request with 403 before running the handler", async () => {
    const handler = vi.fn(async () => ok(null));
    const response = await publicRoute(handler)(
      apiRequest("/api/x", {
        method: "POST",
        body: {},
        headers: { origin: "https://evil.example" },
      }),
    );
    expect(response.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
  });

  it("allows the same origin, and requests without an Origin header", async () => {
    const same = apiRequest("/api/x", {
      method: "POST",
      body: {},
      headers: { origin: "http://localhost:3000" },
    });
    expect((await route(same)).status).toBe(200);
    expect((await route(apiRequest("/api/x", { method: "POST", body: {} }))).status).toBe(200);
  });

  it("does not check safe methods, and rejects opaque origins", () => {
    expect(() =>
      assertSameOrigin(apiRequest("/api/x", { headers: { origin: "https://evil.example" } })),
    ).not.toThrow();
    expect(() =>
      assertSameOrigin(apiRequest("/api/x", { method: "DELETE", headers: { origin: "null" } })),
    ).toThrow();
  });

  it("uses x-forwarded-host when a proxy sets it", () => {
    const request = apiRequest("/api/x", {
      method: "POST",
      body: {},
      headers: { origin: "https://arcradar.example", "x-forwarded-host": "arcradar.example" },
    });
    expect(() => assertSameOrigin(request)).not.toThrow();
  });
});

describe("protectedRoute", () => {
  const handler = vi.fn(async () => ok({ secret: true }));
  const route = protectedRoute({ permissions: ["audit:read"] }, handler);

  it("returns 401 without a session", async () => {
    mockSupabase({
      user: null,
      userError: { name: "AuthSessionMissingError", message: "x", status: 400 },
    });
    const response = await route(apiRequest("/api/x"));
    expect(response.status).toBe(401);
    expect((await response.json()).error.code).toBe("UNAUTHENTICATED");
    expect(handler).not.toHaveBeenCalled();
  });

  it("returns 503, not 401, when the auth backend is down", async () => {
    mockSupabase({ user: null, userError: { message: "fetch failed", status: 0 } });
    const response = await route(apiRequest("/api/x"));
    expect(response.status).toBe(503);
  });

  it("returns 403 ACCOUNT_DISABLED when the profile is missing or inactive", async () => {
    for (const profile of [null, { display_name: null, role_name: "analyst", is_active: false }]) {
      mockSupabase({ profile });
      const response = await route(apiRequest("/api/x"));
      expect(response.status).toBe(403);
      expect((await response.json()).error.code).toBe("ACCOUNT_DISABLED");
    }
  });

  it("fails closed for a role this build does not know", async () => {
    mockSupabase({ profile: { display_name: null, role_name: "auditor", is_active: true } });
    expect((await route(apiRequest("/api/x"))).status).toBe(403);
  });

  it("returns 403 and audits the denial when a permission is missing", async () => {
    const response = await route(apiRequest("/api/x")); // analysts lack audit:read
    expect(response.status).toBe(403);
    expect(handler).not.toHaveBeenCalled();
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "authz.denied",
        userId: USER_ID,
        entityId: "/api/x",
        metadata: expect.objectContaining({ role: "analyst", method: "GET" }),
      }),
      expect.anything(),
    );
  });

  it("runs the handler with the auth context when permitted", async () => {
    mockSupabase({ profile: { display_name: "Root", role_name: "admin", is_active: true } });
    const response = await route(apiRequest("/api/x"));
    expect(response.status).toBe(200);
    expect(handler).toHaveBeenCalledOnce();
    const [{ auth }] = handler.mock.calls[0] as unknown as [
      { auth: { profile: { role: string } } },
    ];
    expect(auth.profile.role).toBe("admin");
    expect(auditMock).not.toHaveBeenCalled();
  });

  it("only needs a session when no permission is required", async () => {
    const open = protectedRoute({}, async ({ auth }) => ok({ id: auth.user.id }));
    mockSupabase({ profile: { display_name: null, role_name: "viewer", is_active: true } });
    expect((await (await open(apiRequest("/api/x"))).json()).data).toEqual({ id: USER_ID });
  });

  it("rate-limits by the signed-in caller, after the permission check, before the handler", async () => {
    mockSupabase({ profile: { display_name: "Root", role_name: "admin", is_active: true } });
    const handler = vi.fn(async () => ok(null));
    const route = protectedRoute(
      {
        permissions: ["audit:read"],
        rateLimit: { routeClass: "aiByUser", subject: ({ auth }) => auth!.user.id },
      },
      handler,
    );
    await route(apiRequest("/api/x"));
    expect(rateLimitMock).toHaveBeenCalledWith("aiByUser", USER_ID);
    expect(handler).toHaveBeenCalledOnce();
  });

  it("never checks the rate limit when the permission check already failed", async () => {
    const route = protectedRoute(
      {
        permissions: ["audit:read"],
        rateLimit: { routeClass: "aiByUser", subject: ({ auth }) => auth!.user.id },
      },
      async () => ok(null),
    ); // analysts lack audit:read
    await route(apiRequest("/api/x"));
    expect(rateLimitMock).not.toHaveBeenCalled();
  });
});

describe("Supabase error mapping", () => {
  it("maps expected Postgres failures to client errors", () => {
    const status = (code: string) => toApiError({ code, message: "m" }).status;
    expect(status("PGRST116")).toBe(404);
    expect(status("42501")).toBe(403);
    expect(status("23505")).toBe(409);
    expect(status("23503")).toBe(409);
    expect(status("23514")).toBe(422);
    expect(status("22P02")).toBe(422);
    expect(status("PGRST301")).toBe(401);
  });

  it("hides unknown errors behind a 500 and never echoes the message", () => {
    const error = toApiError({ code: "XX000", message: "password=hunter2 in relation foo" });
    expect(error.status).toBe(500);
    expect(error.message).not.toContain("hunter2");
  });

  it("unwrap returns data or throws the mapped error", () => {
    expect(unwrap({ data: [1], error: null })).toEqual([1]);
    expect(() => unwrap({ data: null, error: { code: "23505", message: "dup" } })).toThrow(
      /already exists/,
    );
  });
});
