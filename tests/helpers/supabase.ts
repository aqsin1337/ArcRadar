import { NextRequest } from "next/server";
import { vi } from "vitest";

export const USER_ID = "3f2b8c1e-8d0a-4c53-9f5d-2b6a7c9e1d10";

type AuthErrorLike = { name?: string; message: string; status?: number; code?: string };

type FakeOptions = {
  user?: { id: string; email: string } | null;
  userError?: AuthErrorLike | null;
  profile?: { display_name: string | null; role_name: string; is_active: boolean } | null;
  profileError?: { code?: string; message: string } | null;
  /** What the account_state() function answers when the profile is hidden. Default: disabled. */
  accountState?: "pending" | "disabled" | "none";
};

/**
 * A stand-in for the user-scoped Supabase client with only what the guards and auth service touch.
 * Every auth method is a vi.fn() so tests can override results and assert calls.
 */
export function fakeSupabase(options: FakeOptions = {}) {
  const user =
    options.user === undefined ? { id: USER_ID, email: "analyst@arcradar.test" } : options.user;
  const profile =
    options.profile === undefined
      ? { display_name: "Analyst", role_name: "soc_l2", is_active: true }
      : options.profile;

  return {
    auth: {
      getUser: vi
        .fn()
        .mockResolvedValue(
          options.userError
            ? { data: { user: null }, error: options.userError }
            : { data: { user }, error: null },
        ),
      signInWithPassword: vi.fn().mockResolvedValue({ data: { user, session: {} }, error: null }),
      signUp: vi.fn().mockResolvedValue({
        data: { user: { id: USER_ID, identities: [{}] }, session: null },
        error: null,
      }),
      signOut: vi.fn().mockResolvedValue({ error: null }),
      resetPasswordForEmail: vi.fn().mockResolvedValue({ data: {}, error: null }),
      updateUser: vi.fn().mockResolvedValue({ data: { user }, error: null }),
      exchangeCodeForSession: vi.fn().mockResolvedValue({ data: { user }, error: null }),
    },
    rpc: vi.fn().mockResolvedValue({ data: options.accountState ?? "disabled", error: null }),
    from: vi.fn(() => ({
      select: () => ({
        eq: () => ({
          maybeSingle: () =>
            Promise.resolve({ data: profile, error: options.profileError ?? null }),
        }),
      }),
    })),
  };
}

export function apiRequest(
  path: string,
  init: { method?: string; body?: unknown; headers?: Record<string, string> } = {},
) {
  const headers: Record<string, string> = { ...init.headers };
  let body: string | undefined;
  if (init.body !== undefined) {
    headers["content-type"] ??= "application/json";
    body = typeof init.body === "string" ? init.body : JSON.stringify(init.body);
  }
  return new NextRequest(`http://localhost:3000${path}`, {
    method: init.method ?? (body === undefined ? "GET" : "POST"),
    headers: { host: "localhost:3000", ...headers },
    body,
  });
}
