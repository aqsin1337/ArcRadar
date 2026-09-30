import { beforeEach, describe, expect, it, vi } from "vitest";
import { GET as auditLogs } from "@/app/api/audit-logs/route";
import { getClientIp, getRequestMeta } from "@/lib/audit/request-meta";
import { REDACTED, sanitizeMetadata } from "@/lib/audit/sanitize";
import { writeAuditLog } from "@/lib/audit/write";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";
import { apiRequest, fakeSupabase } from "./helpers/supabase";

vi.mock("@/lib/supabase/admin", () => ({ createAdminClient: vi.fn() }));
vi.mock("@/lib/supabase/server", () => ({ createClient: vi.fn() }));

describe("sanitizeMetadata", () => {
  it("redacts secret-looking keys at any depth", () => {
    const clean = sanitizeMetadata({
      email: "a@b.io",
      password: "hunter2",
      nested: { access_token: "t", Authorization: "Bearer x", api_key: "k", ok: 1 },
      list: [{ refresh_token: "r" }],
    });
    expect(clean).toEqual({
      email: "a@b.io",
      password: REDACTED,
      nested: { access_token: REDACTED, Authorization: REDACTED, api_key: REDACTED, ok: 1 },
      list: [{ refresh_token: REDACTED }],
    });
  });

  it("caps long strings, long arrays, deep nesting and total size", () => {
    const clean = sanitizeMetadata({
      long: "x".repeat(2000),
      many: Array.from({ length: 200 }, (_, i) => i),
      deep: { a: { b: { c: { d: { e: 1 } } } } },
    }) as { long: string; many: unknown[]; deep: unknown };
    expect(clean.long.length).toBeLessThan(600);
    expect(clean.many).toHaveLength(50);
    expect(JSON.stringify(clean.deep)).toContain("[truncated]");

    const huge = Object.fromEntries(
      Array.from({ length: 200 }, (_, i) => [`k${i}`, "y".repeat(400)]),
    );
    expect(sanitizeMetadata(huge)).toEqual({ truncated: true });
  });

  it("handles missing and non-JSON values", () => {
    expect(sanitizeMetadata(undefined)).toEqual({});
    expect(sanitizeMetadata({ a: undefined, n: Number.NaN, s: Symbol("x") })).toEqual({
      a: null,
      n: null,
      s: "Symbol(x)",
    });
  });
});

describe("request metadata", () => {
  it("prefers x-real-ip and falls back to the first forwarded hop", () => {
    expect(
      getClientIp(new Headers({ "x-real-ip": "203.0.113.9", "x-forwarded-for": "198.51.100.1" })),
    ).toBe("203.0.113.9");
    expect(getClientIp(new Headers({ "x-forwarded-for": "198.51.100.1, 10.0.0.1" }))).toBe(
      "198.51.100.1",
    );
    expect(getClientIp(new Headers({ "x-forwarded-for": "2001:db8::1" }))).toBe("2001:db8::1");
  });

  it("drops values that are not IP literals (the column is inet)", () => {
    expect(getClientIp(new Headers({ "x-real-ip": "1.2.3.4; DROP TABLE" }))).toBeNull();
    expect(getClientIp(new Headers({ "x-forwarded-for": "unknown" }))).toBeNull();
    expect(getClientIp(new Headers())).toBeNull();
  });

  it("truncates the user agent to the column limit", () => {
    const { userAgent } = getRequestMeta({
      headers: new Headers({ "user-agent": "a".repeat(900) }),
    });
    expect(userAgent).toHaveLength(500);
    expect(getRequestMeta(undefined)).toEqual({ ip: null, userAgent: null });
  });
});

describe("writeAuditLog", () => {
  const insert = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(createAdminClient).mockReturnValue({ from: vi.fn(() => ({ insert })) } as never);
  });

  it("inserts a sanitized row with request details", async () => {
    insert.mockResolvedValue({ error: null });
    const ok = await writeAuditLog(
      {
        action: "auth.login",
        userId: "u1",
        entityType: "user",
        entityId: "u1",
        metadata: { password: "nope", note: "fine" },
      },
      { headers: new Headers({ "x-real-ip": "203.0.113.9", "user-agent": "vitest" }) },
    );

    expect(ok).toBe(true);
    expect(insert).toHaveBeenCalledWith({
      action: "auth.login",
      user_id: "u1",
      entity_type: "user",
      entity_id: "u1",
      ip_address: "203.0.113.9",
      user_agent: "vitest",
      metadata: { password: REDACTED, note: "fine" },
    });
  });

  it("returns false instead of throwing when the database rejects the write", async () => {
    insert.mockResolvedValue({ error: new Error("connection refused") });
    await expect(writeAuditLog({ action: "auth.logout" })).resolves.toBe(false);

    vi.mocked(createAdminClient).mockImplementation(() => {
      throw new Error("SUPABASE_SERVICE_ROLE_KEY missing");
    });
    await expect(writeAuditLog({ action: "auth.logout" })).resolves.toBe(false);
  });
});

describe("GET /api/audit-logs", () => {
  function mockUser(role: string) {
    const supabase = fakeSupabase({
      profile: { display_name: null, role_name: role, is_active: true },
    });
    vi.mocked(createClient).mockResolvedValue(supabase as never);
    return supabase;
  }

  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(createAdminClient).mockReturnValue({
      from: vi.fn(() => ({ insert: vi.fn().mockResolvedValue({ error: null }) })),
    } as never);
  });

  it("is forbidden for analysts and viewers", async () => {
    for (const role of ["soc_l2", "viewer"]) {
      mockUser(role);
      expect((await auditLogs(apiRequest("/api/audit-logs"))).status).toBe(403);
    }
  });

  it("validates the query before reading, for admins", async () => {
    mockUser("admin");
    const response = await auditLogs(apiRequest("/api/audit-logs?page_size=1000"));
    expect(response.status).toBe(422);
  });

  it("returns a paginated page for admins", async () => {
    const supabase = mockUser("admin");
    const rows = [
      { id: 2, action: "auth.login" },
      { id: 1, action: "auth.logout" },
    ];
    const range = vi.fn().mockResolvedValue({ data: rows, error: null, count: 42 });
    const chain = {
      eq: vi.fn().mockReturnThis(),
      gte: vi.fn().mockReturnThis(),
      lte: vi.fn().mockReturnThis(),
      order: vi.fn().mockReturnThis(),
      range,
    };
    const originalFrom = supabase.from;
    supabase.from = vi.fn((table: string) =>
      table === "audit_logs" ? { select: vi.fn(() => chain) } : originalFrom(),
    ) as never;

    const response = await auditLogs(
      apiRequest("/api/audit-logs?page=2&page_size=20&action=auth.login"),
    );
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(chain.eq).toHaveBeenCalledWith("action", "auth.login");
    expect(range).toHaveBeenCalledWith(20, 39);
    expect(body.data.items).toEqual(rows);
    expect(body.data.pagination).toEqual({ page: 2, page_size: 20, total: 42, total_pages: 3 });
  });
});
