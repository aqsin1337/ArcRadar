import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { POST as forgotPassword } from "@/app/api/auth/forgot-password/route";
import { POST as login } from "@/app/api/auth/login/route";
import { POST as logout } from "@/app/api/auth/logout/route";
import { GET as me } from "@/app/api/auth/me/route";
import { POST as signup } from "@/app/api/auth/signup/route";
import { POST as updatePassword } from "@/app/api/auth/update-password/route";
import { GET as callback } from "@/app/auth/callback/route";
import { writeAuditLog } from "@/lib/audit/write";
import { createClient } from "@/lib/supabase/server";
import { USER_ID, apiRequest, fakeSupabase } from "./helpers/supabase";

vi.mock("@/lib/supabase/server", () => ({ createClient: vi.fn() }));
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: vi.fn().mockResolvedValue(true) }));

const auditMock = vi.mocked(writeAuditLog);
const VALID_PASSWORD = "ArcRadar-Demo-1!";

let supabase: ReturnType<typeof fakeSupabase>;

function mockSupabase(options?: Parameters<typeof fakeSupabase>[0]) {
  supabase = fakeSupabase(options);
  vi.mocked(createClient).mockResolvedValue(supabase as never);
  return supabase;
}

function post(path: string, body: unknown) {
  return apiRequest(path, { method: "POST", body });
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv("NEXT_PUBLIC_SUPABASE_URL", "http://127.0.0.1:54321");
  vi.stubEnv("NEXT_PUBLIC_SUPABASE_ANON_KEY", "anon-key");
  vi.stubEnv("NEXT_PUBLIC_APP_URL", "http://localhost:3000");
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  mockSupabase();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("POST /api/auth/login", () => {
  const credentials = { email: "Analyst@ArcRadar.test", password: VALID_PASSWORD };

  it("signs in, returns session info without tokens, and audits", async () => {
    const response = await login(post("/api/auth/login", credentials));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(supabase.auth.signInWithPassword).toHaveBeenCalledWith({
      email: "analyst@arcradar.test",
      password: VALID_PASSWORD,
    });
    expect(body.data.user).toEqual({ id: USER_ID, email: "analyst@arcradar.test" });
    expect(body.data.profile.role).toBe("analyst");
    expect(body.data.permissions).toContain("indicators:write");
    expect(body.data.permissions).not.toContain("audit:read");
    expect(JSON.stringify(body)).not.toMatch(/access_token|refresh_token/);
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({ action: "auth.login", userId: USER_ID }),
      expect.anything(),
    );
  });

  it("answers 401 with a generic message for bad credentials and audits the failure", async () => {
    supabase.auth.signInWithPassword.mockResolvedValue({
      data: { user: null, session: null },
      error: { message: "Invalid login credentials", status: 400, code: "invalid_credentials" },
    });
    const response = await login(post("/api/auth/login", credentials));
    const body = await response.json();

    expect(response.status).toBe(401);
    expect(body.error.code).toBe("INVALID_CREDENTIALS");
    expect(body.error.message).toBe("Invalid email or password.");
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "auth.login_failed",
        metadata: { email: "analyst@arcradar.test", reason: "invalid_credentials" },
      }),
      expect.anything(),
    );
  });

  it("does not audit or blame the caller when Supabase rate-limits or is down", async () => {
    supabase.auth.signInWithPassword.mockResolvedValue({
      data: { user: null },
      error: { message: "slow down", status: 429, code: "over_request_rate_limit" },
    });
    expect((await login(post("/api/auth/login", credentials))).status).toBe(429);

    supabase.auth.signInWithPassword.mockResolvedValue({
      data: { user: null },
      error: { message: "fetch failed", status: 0 },
    });
    expect((await login(post("/api/auth/login", credentials))).status).toBe(503);
    expect(auditMock).not.toHaveBeenCalled();
  });

  it("reports an unconfirmed email after a correct password", async () => {
    supabase.auth.signInWithPassword.mockResolvedValue({
      data: { user: null },
      error: { message: "x", status: 400, code: "email_not_confirmed" },
    });
    const response = await login(post("/api/auth/login", credentials));
    expect((await response.json()).error.code).toBe("EMAIL_NOT_CONFIRMED");
  });

  it("signs out again when the account is disabled", async () => {
    mockSupabase({ profile: { display_name: null, role_name: "viewer", is_active: false } });
    const response = await login(post("/api/auth/login", credentials));

    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("ACCOUNT_DISABLED");
    expect(supabase.auth.signOut).toHaveBeenCalledWith({ scope: "local" });
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "auth.login_failed",
        metadata: { reason: "account_disabled" },
      }),
      expect.anything(),
    );
  });

  it("rejects malformed input before touching Supabase", async () => {
    for (const body of [{}, { email: "nope", password: "x" }, { ...credentials, role: "admin" }]) {
      const response = await login(post("/api/auth/login", body));
      expect(response.status).toBe(422);
    }
    const wrongType = apiRequest("/api/auth/login", {
      method: "POST",
      body: "email=a",
      headers: { "content-type": "text/plain" },
    });
    expect((await login(wrongType)).status).toBe(415);
    expect(supabase.auth.signInWithPassword).not.toHaveBeenCalled();
  });
});

describe("POST /api/auth/logout", () => {
  it("signs out the current session and audits it", async () => {
    const response = await logout(post("/api/auth/logout", undefined));
    expect(response.status).toBe(200);
    expect(supabase.auth.signOut).toHaveBeenCalledWith({ scope: "local" });
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({ action: "auth.logout", userId: USER_ID }),
      expect.anything(),
    );
  });

  it("succeeds without a session and writes no audit entry", async () => {
    mockSupabase({ user: null, userError: { message: "no session", status: 400 } });
    const response = await logout(apiRequest("/api/auth/logout", { method: "POST" }));
    expect(response.status).toBe(200);
    expect(auditMock).not.toHaveBeenCalled();
  });
});

describe("POST /api/auth/signup", () => {
  const body = { email: "new@arcradar.test", password: VALID_PASSWORD, display_name: " Nova " };

  it("registers, never leaves the caller signed in, and audits", async () => {
    supabase.auth.signUp.mockResolvedValue({
      data: { user: { id: USER_ID, identities: [{}] }, session: { access_token: "t" } },
      error: null,
    });
    const response = await signup(post("/api/auth/signup", body));

    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({
      success: true,
      data: { registered: true },
      error: null,
    });
    expect(supabase.auth.signUp).toHaveBeenCalledWith(
      expect.objectContaining({
        email: "new@arcradar.test",
        options: expect.objectContaining({ data: { display_name: "Nova" } }),
      }),
    );
    expect(supabase.auth.signOut).toHaveBeenCalledWith({ scope: "local" });
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({ action: "auth.signup", userId: USER_ID }),
      expect.anything(),
    );
  });

  it("gives an existing email the identical response (no account enumeration)", async () => {
    const fresh = await (await signup(post("/api/auth/signup", body))).json();

    supabase.auth.signUp.mockResolvedValue({
      data: { user: null, session: null },
      error: { message: "User already registered", status: 422, code: "user_already_exists" },
    });
    const duplicate = await signup(post("/api/auth/signup", body));
    expect(duplicate.status).toBe(201);
    expect(await duplicate.json()).toEqual(fresh);
  });

  it("does not audit an obfuscated duplicate (empty identities)", async () => {
    supabase.auth.signUp.mockResolvedValue({
      data: { user: { id: USER_ID, identities: [] }, session: null },
      error: null,
    });
    expect((await signup(post("/api/auth/signup", body))).status).toBe(201);
    expect(auditMock).not.toHaveBeenCalled();
  });

  it("refuses to accept a role, and enforces the password policy", async () => {
    expect((await signup(post("/api/auth/signup", { ...body, role_name: "admin" }))).status).toBe(
      422,
    );
    expect((await signup(post("/api/auth/signup", { ...body, password: "weakpass" }))).status).toBe(
      422,
    );
    expect(supabase.auth.signUp).not.toHaveBeenCalled();
  });
});

describe("POST /api/auth/forgot-password", () => {
  it("always answers sent, even when the email is unknown", async () => {
    supabase.auth.resetPasswordForEmail.mockResolvedValue({
      data: null,
      error: { message: "user not found", status: 404, code: "user_not_found" },
    });
    const response = await forgotPassword(post("/api/auth/forgot-password", { email: "x@y.io" }));
    expect(response.status).toBe(200);
    expect((await response.json()).data).toEqual({ sent: true });
    expect(supabase.auth.resetPasswordForEmail).toHaveBeenCalledWith(
      "x@y.io",
      expect.objectContaining({
        redirectTo: expect.stringContaining("/auth/callback?next=/reset-password"),
      }),
    );
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({ action: "auth.password_reset_requested" }),
      expect.anything(),
    );
  });

  it("reports rate limiting", async () => {
    supabase.auth.resetPasswordForEmail.mockResolvedValue({
      data: null,
      error: { message: "slow", status: 429, code: "over_email_send_rate_limit" },
    });
    expect(
      (await forgotPassword(post("/api/auth/forgot-password", { email: "x@y.io" }))).status,
    ).toBe(429);
  });
});

describe("POST /api/auth/update-password", () => {
  it("requires a session", async () => {
    mockSupabase({ user: null, userError: { message: "no session", status: 400 } });
    const response = await updatePassword(
      post("/api/auth/update-password", { password: VALID_PASSWORD }),
    );
    expect(response.status).toBe(401);
    expect(supabase.auth.updateUser).not.toHaveBeenCalled();
  });

  it("changes the password, revokes other sessions and audits", async () => {
    const response = await updatePassword(
      post("/api/auth/update-password", { password: VALID_PASSWORD }),
    );
    expect(response.status).toBe(200);
    expect(supabase.auth.updateUser).toHaveBeenCalledWith({ password: VALID_PASSWORD });
    expect(supabase.auth.signOut).toHaveBeenCalledWith({ scope: "others" });
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({ action: "auth.password_changed", userId: USER_ID }),
      expect.anything(),
    );
    expect(JSON.stringify(auditMock.mock.calls)).not.toContain(VALID_PASSWORD);
  });

  it("rejects a weak or unchanged password with 422", async () => {
    expect(
      (await updatePassword(post("/api/auth/update-password", { password: "short" }))).status,
    ).toBe(422);

    supabase.auth.updateUser.mockResolvedValue({
      data: {},
      error: { message: "same", status: 422, code: "same_password" },
    });
    const response = await updatePassword(
      post("/api/auth/update-password", { password: VALID_PASSWORD }),
    );
    expect(response.status).toBe(422);
    expect(supabase.auth.signOut).not.toHaveBeenCalled();
  });
});

describe("GET /api/auth/me", () => {
  it("returns the user, role and permissions", async () => {
    mockSupabase({ profile: { display_name: "Root", role_name: "admin", is_active: true } });
    const body = await (await me(apiRequest("/api/auth/me"))).json();
    expect(body.data.profile).toEqual({ display_name: "Root", role: "admin" });
    expect(body.data.permissions).toContain("audit:read");
  });

  it("is 401 when signed out", async () => {
    mockSupabase({ user: null, userError: { message: "no session", status: 400 } });
    expect((await me(apiRequest("/api/auth/me"))).status).toBe(401);
  });
});

describe("GET /auth/callback", () => {
  const get = (query: string) =>
    callback(new NextRequest(`http://localhost:3000/auth/callback${query}`));

  it("exchanges the code and redirects to a same-site next path", async () => {
    const response = await get("?code=abc&next=/reset-password");
    expect(response.status).toBe(307);
    expect(new URL(response.headers.get("location")!).pathname).toBe("/reset-password");
    expect(supabase.auth.exchangeCodeForSession).toHaveBeenCalledWith("abc");
    expect(auditMock).toHaveBeenCalledWith(
      expect.objectContaining({ action: "auth.email_link_session", userId: USER_ID }),
      expect.anything(),
    );
  });

  it("never redirects off-site", async () => {
    const response = await get("?code=abc&next=//evil.example");
    const location = new URL(response.headers.get("location")!);
    expect(location.host).toBe("localhost:3000");
    expect(location.pathname).toBe("/");
  });

  it("sends a missing or rejected code to the login page with an error", async () => {
    expect(new URL((await get("")).headers.get("location")!).search).toBe("?error=invalid_link");

    supabase.auth.exchangeCodeForSession.mockResolvedValue({
      data: { user: null },
      error: { message: "invalid", status: 400 },
    });
    const response = await get("?code=used");
    expect(new URL(response.headers.get("location")!).pathname).toBe("/login");
  });
});
