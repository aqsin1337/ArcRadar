import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiErrors } from "@/lib/api/errors";
import { EnvError } from "@/lib/env/parse";

const requireAuth = vi.hoisted(() => vi.fn());
const createClient = vi.hoisted(() => vi.fn());
vi.mock("@/lib/auth/context", () => ({ requireAuth }));
vi.mock("@/lib/supabase/server", () => ({ createClient }));

// `cache()` only memoizes inside a React server render; here it passes straight through.
async function loadGetPageAuth() {
  return (await import("@/lib/auth/session")).getPageAuth;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "error").mockImplementation(() => {});
  createClient.mockResolvedValue({});
});

describe("getPageAuth", () => {
  it("returns the auth context for a valid session", async () => {
    requireAuth.mockResolvedValue({ user: { id: "u1" } });
    const result = await (await loadGetPageAuth())();
    expect(result).toEqual({ status: "ok", auth: { user: { id: "u1" } } });
  });

  it("maps expected failures to a status the pages can branch on", async () => {
    const cases: [unknown, string][] = [
      [apiErrors.unauthenticated(), "signed_out"],
      [apiErrors.accountDisabled(), "disabled"],
      [apiErrors.forbidden(), "disabled"],
      [apiErrors.unavailable(), "unavailable"],
      [apiErrors.internal(), "unavailable"],
      [new EnvError(["NEXT_PUBLIC_SUPABASE_URL"], "public"), "unavailable"],
      [new Error("boom"), "unavailable"],
    ];
    for (const [error, status] of cases) {
      requireAuth.mockRejectedValue(error);
      const result = await (await loadGetPageAuth())();
      expect(result.status, String(error)).toBe(status);
    }
  });

  it("lets Next.js control-flow errors through instead of swallowing them", async () => {
    // What `cookies()` throws while Next tries to prerender a page: it means "render me per request".
    const dynamicUsage = Object.assign(new Error("Dynamic server usage"), {
      digest: "DYNAMIC_SERVER_USAGE",
    });
    createClient.mockRejectedValue(dynamicUsage);
    await expect((await loadGetPageAuth())()).rejects.toBe(dynamicUsage);

    // And a redirect thrown from inside the guarded call.
    const redirect = Object.assign(new Error("NEXT_REDIRECT"), {
      digest: "NEXT_REDIRECT;replace;/login;307;",
    });
    createClient.mockResolvedValue({});
    requireAuth.mockRejectedValue(redirect);
    await expect((await loadGetPageAuth())()).rejects.toBe(redirect);
  });
});
