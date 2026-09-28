import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { GET } from "@/app/api/health/route";

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

function configureSupabase() {
  vi.stubEnv("NEXT_PUBLIC_SUPABASE_URL", "http://127.0.0.1:54321");
  vi.stubEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY", "anon-key");
}

describe("GET /api/health", () => {
  it("reports ok when Supabase answers", async () => {
    configureSupabase();
    const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      success: true,
      data: { app: "arcradar", status: "ok", supabase: "ok" },
      error: null,
    });
    expect(fetchMock.mock.calls[0][0]).toBe("http://127.0.0.1:54321/auth/v1/health");
  });

  it("returns 503 when Supabase is unreachable", async () => {
    configureSupabase();
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("connect ECONNREFUSED")));

    const response = await GET();
    const body = await response.json();
    expect(response.status).toBe(503);
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("DEPENDENCY_UNAVAILABLE");
    expect(body.error.details.supabase).toBe("unreachable");
  });

  it("returns 503 and does not call out when Supabase is not configured", async () => {
    vi.stubEnv("NEXT_PUBLIC_SUPABASE_URL", "");
    vi.stubEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY", "");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET();
    expect(response.status).toBe(503);
    expect((await response.json()).error.details.supabase).toBe("not_configured");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never leaks configuration values", async () => {
    configureSupabase();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })));
    const text = await (await GET()).text();
    expect(text).not.toContain("anon-key");
    expect(text).not.toContain("127.0.0.1");
  });
});
