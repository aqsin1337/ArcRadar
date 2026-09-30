import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  findUsers: vi.fn(),
  findProfileForAdmin: vi.fn(),
  countActiveAdmins: vi.fn(),
  updateProfileForAdmin: vi.fn().mockResolvedValue(undefined),
}));
const audit = vi.hoisted(() => vi.fn().mockResolvedValue(true));
vi.mock("@/lib/users/repository", () => repo);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));

const { isUserId, updateUser } = await import("@/lib/users/service");
const { updateUserSchema } = await import("@/lib/users/schema");

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
