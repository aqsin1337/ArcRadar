import { NextRequest, NextResponse } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { apiFetch, parseEnvelope } from "@/lib/api/client";
import { isPublicPath, loginPathFor } from "@/lib/auth/routes";
import { isActivePath, NAV_GROUPS, visibleNavGroups } from "@/lib/nav";
import { permissionsForRole } from "@/lib/rbac/permissions";
import { firstParam } from "@/lib/search-params";
import { DEFAULT_THEME, parseTheme } from "@/lib/theme";
import { fieldErrorsFromZod, formText } from "@/lib/validation/form";
import { PASSWORD_RULES } from "@/lib/validation/auth";

const updateSession = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase/session", () => ({ updateSession }));

describe("parseEnvelope", () => {
  it("returns data for a success envelope", () => {
    expect(parseEnvelope(200, { success: true, data: { a: 1 }, error: null })).toEqual({
      ok: true,
      data: { a: 1 },
    });
  });

  it("maps a validation error to per-field messages (first message wins)", () => {
    const result = parseEnvelope(422, {
      success: false,
      data: null,
      error: {
        code: "VALIDATION_ERROR",
        message: "The request contains invalid data.",
        details: {
          issues: [
            { path: "email", message: "Enter a valid email address." },
            { path: "email", message: "second" },
            { path: "password", message: "Too short." },
          ],
        },
      },
    });
    expect(result).toMatchObject({
      ok: false,
      status: 422,
      code: "VALIDATION_ERROR",
      fieldErrors: { email: "Enter a valid email address.", password: "Too short." },
    });
  });

  it("uses friendly copy for infrastructure errors instead of the server text", () => {
    const limited = parseEnvelope(429, {
      success: false,
      data: null,
      error: { code: "RATE_LIMITED", message: "Too many requests. Try again later." },
    });
    expect(limited).toMatchObject({ ok: false, code: "RATE_LIMITED" });
    expect((limited as { message: string }).message).toMatch(/wait a few minutes/i);
  });

  it("keeps the server message for expected errors (for example bad credentials)", () => {
    const result = parseEnvelope(401, {
      success: false,
      data: null,
      error: { code: "INVALID_CREDENTIALS", message: "Invalid email or password." },
    });
    expect(result).toMatchObject({ ok: false, message: "Invalid email or password." });
  });

  it("treats a non-envelope body as an outage for 5xx and a bad response otherwise", () => {
    expect(parseEnvelope(502, null)).toMatchObject({ ok: false, code: "DEPENDENCY_UNAVAILABLE" });
    expect(parseEnvelope(200, { hello: "world" })).toMatchObject({
      ok: false,
      code: "BAD_RESPONSE",
    });
    expect(parseEnvelope(404, "<html>")).toMatchObject({ ok: false, code: "BAD_RESPONSE" });
  });
});

describe("apiFetch", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("posts JSON with same-origin credentials and parses the envelope", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(Response.json({ success: true, data: { signed_out: true }, error: null }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await apiFetch("/api/auth/logout", { method: "POST" });
    expect(result).toEqual({ ok: true, data: { signed_out: true } });
    const [path, init] = fetchMock.mock.calls[0];
    expect(path).toBe("/api/auth/logout");
    expect(init).toMatchObject({ method: "POST", credentials: "same-origin", cache: "no-store" });
  });

  it("sends a JSON body with a content type", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(Response.json({ success: true, data: null, error: null }));
    vi.stubGlobal("fetch", fetchMock);
    await apiFetch("/api/auth/login", { body: { email: "a@b.io" } });
    const init = fetchMock.mock.calls[0][1];
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "content-type": "application/json" });
    expect(init.body).toBe('{"email":"a@b.io"}');
  });

  it("never throws: a network failure becomes a NETWORK_ERROR result", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    expect(await apiFetch("/api/x")).toMatchObject({ ok: false, status: 0, code: "NETWORK_ERROR" });
  });

  it("survives a proxy error page that is not JSON", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("<h1>502 Bad Gateway</h1>", { status: 502 })),
    );
    expect(await apiFetch("/api/x")).toMatchObject({ ok: false, code: "DEPENDENCY_UNAVAILABLE" });
  });
});

describe("route classification", () => {
  it("lets signed-out visitors reach the auth pages, the callback and the API", () => {
    for (const path of [
      "/",
      "/login",
      "/signup",
      "/forgot-password",
      "/auth/callback",
      "/api/auth/me",
      "/api/health",
    ]) {
      expect(isPublicPath(path), path).toBe(true);
    }
  });

  it("protects app pages, unknown paths and reset-password (needs the recovery session)", () => {
    for (const path of [
      "/dashboard",
      "/alerts",
      "/reset-password",
      "/nope",
      "/loginx",
      "/login/extra",
    ]) {
      expect(isPublicPath(path), path).toBe(false);
    }
  });

  it("ignores a trailing slash", () => {
    expect(isPublicPath("/login/")).toBe(true);
    expect(isPublicPath("/dashboard/")).toBe(false);
  });

  it("builds an encoded login redirect that keeps the query string", () => {
    expect(loginPathFor("/dashboard")).toBe("/login?next=%2Fdashboard");
    expect(loginPathFor("/alerts", "?status=new&page=2")).toBe(
      "/login?next=%2Falerts%3Fstatus%3Dnew%26page%3D2",
    );
  });
});

describe("proxy", () => {
  async function run(path: string, signedIn: boolean | null) {
    const { proxy } = await import("@/proxy");
    const response = NextResponse.next();
    response.cookies.set("sb-test-auth-token", "refreshed");
    updateSession.mockResolvedValue({ response, signedIn });
    return proxy(new NextRequest(`http://localhost:3000${path}`));
  }

  it("redirects a visitor with no session away from a protected page, keeping refreshed cookies", async () => {
    const result = await run("/dashboard?tab=1", false);
    expect(result.status).toBe(307);
    const location = new URL(result.headers.get("location")!);
    expect(location.pathname).toBe("/login");
    expect(location.searchParams.get("next")).toBe("/dashboard?tab=1");
    expect(result.cookies.get("sb-test-auth-token")?.value).toBe("refreshed");
  });

  it("does not redirect public pages, API routes, signed-in users or unknown session state", async () => {
    expect((await run("/login", false)).headers.get("location")).toBeNull();
    expect((await run("/api/audit-logs", false)).headers.get("location")).toBeNull();
    expect((await run("/dashboard", true)).headers.get("location")).toBeNull();
    expect((await run("/dashboard", null)).headers.get("location")).toBeNull();
  });

  it("never bounces a signed-in user off the login page (that could loop with the layout guard)", async () => {
    expect((await run("/login", true)).headers.get("location")).toBeNull();
  });
});

describe("navigation", () => {
  it("shows every group to an admin, including the audit log", () => {
    const groups = visibleNavGroups(permissionsForRole("admin"));
    const labels = groups.flatMap((group) => group.items.map((item) => item.label));
    expect(labels).toContain("Audit log");
    expect(labels).toContain("Settings");
    expect(groups.flatMap((g) => g.items)).toHaveLength(NAV_GROUPS.flatMap((g) => g.items).length);
  });

  it("hides what a viewer may not use, and drops emptied groups", () => {
    const groups = visibleNavGroups(permissionsForRole("viewer"));
    const labels = groups.flatMap((group) => group.items.map((item) => item.label));
    expect(labels).not.toContain("Audit log");
    expect(labels).not.toContain("API keys");
    expect(labels).not.toContain("Integrations");
    expect(labels).toContain("Alerts");
    expect(groups.map((g) => g.label)).not.toContain("Administration");
  });

  it("gives analysts integrations and their own API keys but not the audit log", () => {
    const labels = visibleNavGroups(permissionsForRole("analyst")).flatMap((g) =>
      g.items.map((i) => i.label),
    );
    expect(labels).toEqual(expect.arrayContaining(["Integrations", "API keys"]));
    expect(labels).not.toContain("Audit log");
  });

  it("accepts arrays of permissions too", () => {
    const groups = visibleNavGroups(["alerts:read"]);
    expect(groups.flatMap((g) => g.items.map((i) => i.label))).toEqual(["Overview", "Alerts"]);
  });

  it("keeps only real pages marked live and every href unique", () => {
    const items = NAV_GROUPS.flatMap((g) => g.items);
    expect(items.filter((i) => i.status === "live").map((i) => i.href)).toEqual([
      "/dashboard",
      "/indicators",
    ]);
    expect(new Set(items.map((i) => i.href)).size).toBe(items.length);
  });

  it("marks a page and its children active, but not a sibling with a shared prefix", () => {
    expect(isActivePath("/alerts", "/alerts")).toBe(true);
    expect(isActivePath("/alerts/123", "/alerts")).toBe(true);
    expect(isActivePath("/alerts-archive", "/alerts")).toBe(false);
  });
});

describe("small helpers", () => {
  it("only accepts known themes (the cookie is user input)", () => {
    expect(parseTheme("light")).toBe("light");
    expect(parseTheme("dark")).toBe("dark");
    for (const bad of ["<script>", "", undefined, null, "LIGHT"]) {
      expect(parseTheme(bad as string | undefined)).toBe(DEFAULT_THEME);
    }
  });

  it("takes the first search param value", () => {
    expect(firstParam("a")).toBe("a");
    expect(firstParam(["a", "b"])).toBe("a");
    expect(firstParam(undefined)).toBeUndefined();
  });

  it("collects the first Zod message per top-level field", () => {
    const schema = z.object({ a: z.string().min(3, "short"), b: z.string() });
    const result = schema.safeParse({ a: "x", b: 1 });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(fieldErrorsFromZod(result.error)).toMatchObject({ a: "short" });
      expect(Object.keys(fieldErrorsFromZod(result.error)).sort()).toEqual(["a", "b"]);
    }
  });

  it("reads form text and treats missing or file fields as empty", () => {
    const form = new FormData();
    form.set("name", "Ada");
    form.set("file", new Blob(["x"]), "x.txt");
    expect(formText(form, "name")).toBe("Ada");
    expect(formText(form, "file")).toBe("");
    expect(formText(form, "missing")).toBe("");
  });

  it("password rules agree with what the policy accepts", () => {
    const passes = (value: string) => PASSWORD_RULES.every((rule) => rule.test(value));
    expect(passes("ArcRadar-Demo-1!")).toBe(true);
    expect(passes("short1A")).toBe(false);
    expect(passes("alllowercase1")).toBe(false);
  });
});

beforeEach(() => vi.clearAllMocks());
