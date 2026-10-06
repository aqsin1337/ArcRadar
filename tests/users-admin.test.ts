import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  findUsers: vi.fn(),
  findProfileForAdmin: vi.fn(),
  countActiveAdmins: vi.fn(),
  updateProfileForAdmin: vi.fn().mockResolvedValue(undefined),
  createAccountForAdmin: vi.fn(),
  deleteAccountForAdmin: vi.fn().mockResolvedValue(undefined),
}));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));
vi.mock("@/lib/users/repository", () => repo);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const { createUser, isUserId, updateUser } = await import("@/lib/users/service");
const { createUserSchema, updateUserSchema } = await import("@/lib/users/schema");
const { apiErrors } = await import("@/lib/api/errors");

const request = { headers: new Headers() };
const admin = (id = "admin-1"): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id, email: "admin@arcradar.test" },
  profile: { display_name: "Admin", role: "admin" },
  permissions: permissionsForRole("admin"),
});

const TARGET = "33333333-3333-4333-8333-333333333333";

beforeEach(() => {
  vi.clearAllMocks();
  repo.updateProfileForAdmin.mockResolvedValue(undefined);
  repo.deleteAccountForAdmin.mockResolvedValue(undefined);
  repo.createAccountForAdmin.mockResolvedValue({
    id: TARGET,
    created_at: "2026-10-07T00:00:00Z",
  });
  repo.countActiveAdmins.mockResolvedValue(5); // plenty, unless a test says otherwise
});

describe("updateUserSchema", () => {
  it("needs at least one field and only known roles", () => {
    expect(updateUserSchema.safeParse({}).success).toBe(false);
    expect(updateUserSchema.safeParse({ role_name: "superuser" }).success).toBe(false);
    expect(updateUserSchema.safeParse({ role_name: "soc_l2" }).success).toBe(true);
    expect(updateUserSchema.safeParse({ is_active: false }).success).toBe(true);
    expect(updateUserSchema.safeParse({ role_name: "admin", extra: 1 }).success).toBe(false);
  });
});

describe("isUserId", () => {
  it("rejects anything that is not a UUID", () => {
    expect(isUserId("not-a-uuid")).toBe(false);
    expect(isUserId(TARGET)).toBe(true);
  });
});

describe("updateUser", () => {
  it("refuses a malformed id as not-found, without touching the database", async () => {
    await expect(updateUser(admin(), "nope", { is_active: false }, request)).rejects.toMatchObject({
      status: 404,
    });
    expect(repo.findProfileForAdmin).not.toHaveBeenCalled();
  });

  it("never lets an administrator change their own account here", async () => {
    await expect(
      updateUser(admin(TARGET), TARGET, { role_name: "viewer" }, request),
    ).rejects.toMatchObject({ status: 409 });
    expect(repo.updateProfileForAdmin).not.toHaveBeenCalled();
  });

  it("404s when the target account does not exist", async () => {
    repo.findProfileForAdmin.mockResolvedValue(null);
    await expect(updateUser(admin(), TARGET, { is_active: false }, request)).rejects.toMatchObject({
      status: 404,
    });
  });

  it("changes a role and audits it, only when the role actually changes", async () => {
    repo.findProfileForAdmin.mockResolvedValue({
      role_name: "viewer",
      is_active: true,
      approved_at: "2026-01-01T00:00:00Z",
    });
    await updateUser(admin(), TARGET, { role_name: "soc_l2" }, request);
    expect(repo.updateProfileForAdmin).toHaveBeenCalledWith(TARGET, {
      role_name: "soc_l2",
      is_active: undefined,
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "user.role_changed",
        entityId: TARGET,
        metadata: { from: "viewer", to: "soc_l2" },
      }),
      request,
    );

    audit.mockClear();
    repo.findProfileForAdmin.mockResolvedValue({
      role_name: "soc_l2",
      is_active: true,
      approved_at: "2026-01-01T00:00:00Z",
    });
    await updateUser(admin(), TARGET, { role_name: "soc_l2" }, request);
    expect(audit).not.toHaveBeenCalled();
  });

  it("approving a waiting account is audited as an approval with the chosen role", async () => {
    repo.findProfileForAdmin.mockResolvedValue({
      role_name: "viewer",
      is_active: false,
      approved_at: null,
    });
    await updateUser(admin(), TARGET, { role_name: "soc_l1", is_active: true }, request);
    expect(repo.updateProfileForAdmin).toHaveBeenCalledWith(TARGET, {
      role_name: "soc_l1",
      is_active: true,
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "user.approved", metadata: { role: "soc_l1" } }),
      request,
    );
  });

  it("activates and deactivates with the right action name", async () => {
    repo.findProfileForAdmin.mockResolvedValue({
      role_name: "viewer",
      is_active: true,
      approved_at: "2026-01-01T00:00:00Z",
    });
    await updateUser(admin(), TARGET, { is_active: false }, request);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "user.deactivated" }),
      request,
    );

    audit.mockClear();
    repo.findProfileForAdmin.mockResolvedValue({
      role_name: "viewer",
      is_active: false,
      approved_at: "2026-01-01T00:00:00Z",
    });
    await updateUser(admin(), TARGET, { is_active: true }, request);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ action: "user.activated" }),
      request,
    );
  });

  it("refuses to leave the workspace with no active administrator", async () => {
    repo.findProfileForAdmin.mockResolvedValue({
      role_name: "admin",
      is_active: true,
      approved_at: "2026-01-01T00:00:00Z",
    });
    repo.countActiveAdmins.mockResolvedValue(1); // the target is the only one
    await expect(
      updateUser(admin(), TARGET, { role_name: "viewer" }, request),
    ).rejects.toMatchObject({ status: 409 });
    await expect(updateUser(admin(), TARGET, { is_active: false }, request)).rejects.toMatchObject({
      status: 409,
    });
    expect(repo.updateProfileForAdmin).not.toHaveBeenCalled();
  });

  it("allows demoting the last administrator's role as long as another stays an active admin", async () => {
    repo.findProfileForAdmin.mockResolvedValue({
      role_name: "admin",
      is_active: true,
      approved_at: "2026-01-01T00:00:00Z",
    });
    repo.countActiveAdmins.mockResolvedValue(2);
    await updateUser(admin(), TARGET, { role_name: "soc_l2" }, request);
    expect(repo.updateProfileForAdmin).toHaveBeenCalled();
  });

  it("does not run the last-admin check for someone who was never an active admin", async () => {
    repo.findProfileForAdmin.mockResolvedValue({
      role_name: "viewer",
      is_active: true,
      approved_at: "2026-01-01T00:00:00Z",
    });
    repo.countActiveAdmins.mockResolvedValue(0); // must not matter here
    await updateUser(admin(), TARGET, { is_active: false }, request);
    expect(repo.updateProfileForAdmin).toHaveBeenCalled();
  });
});

describe("createUserSchema", () => {
  const valid = {
    email: " New.Analyst@Example.com ",
    password: "Str0ngPassword",
    display_name: " Leyla ",
    role_name: "soc_l1",
  };

  it("normalizes the email and the name, and needs every field", () => {
    expect(createUserSchema.parse(valid)).toEqual({
      email: "new.analyst@example.com",
      password: "Str0ngPassword",
      display_name: "Leyla",
      role_name: "soc_l1",
    });
    for (const field of Object.keys(valid)) {
      const body: Record<string, unknown> = { ...valid };
      delete body[field];
      expect(createUserSchema.safeParse(body).success, field).toBe(false);
    }
  });

  it("holds the password to the sign-up policy and refuses unknown roles or extra fields", () => {
    expect(createUserSchema.safeParse({ ...valid, password: "short1A" }).success).toBe(false);
    expect(createUserSchema.safeParse({ ...valid, password: "alllowercase123" }).success).toBe(
      false,
    );
    expect(createUserSchema.safeParse({ ...valid, role_name: "root" }).success).toBe(false);
    expect(createUserSchema.safeParse({ ...valid, is_active: true }).success).toBe(false);
    expect(createUserSchema.safeParse({ ...valid, display_name: "   " }).success).toBe(false);
  });
});

describe("createUser", () => {
  const input = {
    email: "leyla@example.com",
    password: "Str0ngPassword",
    display_name: "Leyla",
    role_name: "soc_l1" as const,
  };

  it("makes the sign-in, activates it with the chosen role and returns the new row", async () => {
    const created = await createUser(admin(), input, request);

    expect(repo.createAccountForAdmin).toHaveBeenCalledWith({
      email: "leyla@example.com",
      password: "Str0ngPassword",
      display_name: "Leyla",
    });
    expect(repo.updateProfileForAdmin).toHaveBeenCalledWith(TARGET, {
      role_name: "soc_l1",
      is_active: true,
    });
    expect(created).toEqual({
      id: TARGET,
      email: "leyla@example.com",
      display_name: "Leyla",
      role: "soc_l1",
      is_active: true,
      pending: false,
      created_at: "2026-10-07T00:00:00Z",
      last_sign_in_at: null,
    });
  });

  it("audits who made the account and its role, and never the password", async () => {
    await createUser(admin("admin-9"), input, request);
    expect(audit).toHaveBeenCalledTimes(1);
    const [entry] = audit.mock.calls[0];
    expect(entry).toMatchObject({
      action: "user.created",
      userId: "admin-9",
      entityType: "profile",
      entityId: TARGET,
      metadata: { role: "soc_l1" },
    });
    expect(JSON.stringify(entry)).not.toContain("Str0ngPassword");
  });

  it("removes the half-made sign-in when the role cannot be given, and reports the failure", async () => {
    repo.updateProfileForAdmin.mockRejectedValue(apiErrors.internal());
    await expect(createUser(admin(), input, request)).rejects.toMatchObject({ status: 500 });
    expect(repo.deleteAccountForAdmin).toHaveBeenCalledWith(TARGET);
    expect(audit).not.toHaveBeenCalled();
  });

  it("changes nothing when the email already has an account", async () => {
    repo.createAccountForAdmin.mockRejectedValue(
      apiErrors.conflict("An account with this email already exists."),
    );
    await expect(createUser(admin(), input, request)).rejects.toMatchObject({ status: 409 });
    expect(repo.updateProfileForAdmin).not.toHaveBeenCalled();
    expect(repo.deleteAccountForAdmin).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });
});
