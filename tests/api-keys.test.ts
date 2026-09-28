import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import { MAX_ACTIVE_KEYS_PER_USER } from "@/lib/api-keys/constants";
import { API_KEY_PATTERN, bearerToken, generateApiKey, hashApiKey } from "@/lib/api-keys/keys";
import { createApiKeySchema } from "@/lib/api-keys/schema";
import type { ApiKeyRow } from "@/lib/api-keys/types";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  countUsableKeys: vi.fn(),
  findKeyByHash: vi.fn(),
  findVisibleApiKey: vi.fn(),
  insertApiKey: vi.fn(),
  listApiKeys: vi.fn(),
  revokeApiKeyRow: vi.fn(),
  touchLastUsed: vi.fn(),
}));
const audit = vi.hoisted(() => vi.fn());
vi.mock("@/lib/api-keys/repository", () => repo);
vi.mock("@/lib/audit/write", () => ({ writeAuditLog: audit }));
vi.mock("@/lib/log", () => ({ logWarn: vi.fn(), logError: vi.fn() }));

const { createApiKey, keyStatus, listApiKeys, revokeApiKey, verifyApiKey } =
  await import("@/lib/api-keys/service");

const NOW = new Date("2026-09-27T12:00:00.000Z");
const DAY = 24 * 60 * 60 * 1000;
const ADMIN = "3f0d3a86-5a53-4c8e-8f7e-1f2d3c4b5a69";
const KEY_ID = "0b8f4f3e-2f4e-4c55-9e0a-6a1a3a4b5c6d";
const request = { headers: new Headers() };

const auth = (role: "admin" | "analyst" | "viewer"): AuthContext => ({
  supabase: {} as AuthClient,
  user: { id: ADMIN, email: `${role}@arcradar.test` },
  profile: { display_name: role, role },
  permissions: permissionsForRole(role),
});

const row = (overrides: Partial<ApiKeyRow> = {}): ApiKeyRow => ({
  id: KEY_ID,
  user_id: ADMIN,
  name: "Wazuh lab",
  key_prefix: "arc_AbCd",
  scopes: ["ingest:wazuh"],
  last_used_at: null,
  expires_at: new Date(NOW.getTime() + 30 * DAY).toISOString(),
  revoked_at: null,
  created_at: NOW.toISOString(),
  ...overrides,
});

async function failureOf(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("expected the call to fail");
}

describe("generating and hashing keys", () => {
  it("makes a 256-bit key that starts with arc_, and stores only its SHA-256 hash", () => {
    const { key, prefix, hash } = generateApiKey();
    expect(key).toMatch(API_KEY_PATTERN);
    expect(key).toHaveLength(47);
    expect(prefix).toBe(key.slice(0, 8));
    expect(prefix.startsWith("arc_")).toBe(true);
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
    expect(hash).toBe(hashApiKey(key));
    expect(hash).not.toContain(key.slice(4));
  });

  it("never repeats", () => {
    const keys = new Set(Array.from({ length: 200 }, () => generateApiKey().key));
    expect(keys.size).toBe(200);
  });

  it("hashes with plain SHA-256 (a known vector)", () => {
    expect(hashApiKey("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("recognizes the shape of a key and nothing else", () => {
    const { key } = generateApiKey();
    expect(API_KEY_PATTERN.test(key)).toBe(true);
    for (const bad of [
      "",
      "arc_",
      `arc_${"a".repeat(42)}`,
      `arc_${"a".repeat(44)}`,
      `ARC_${"a".repeat(43)}`,
      `arc_${"a".repeat(42)}!`,
      ` ${key}`,
    ]) {
      expect(API_KEY_PATTERN.test(bad)).toBe(false);
    }
  });
});

describe("bearerToken", () => {
  it("reads the token of a Bearer header, whatever the case of the scheme", () => {
    expect(bearerToken("Bearer abc")).toBe("abc");
    expect(bearerToken("bearer abc")).toBe("abc");
    expect(bearerToken("BEARER   abc  ")).toBe("abc");
  });

  it("returns null for anything else", () => {
    for (const header of [
      null,
      "",
      "Bearer",
      "Bearer ",
      "Basic abc",
      "abc",
      "Bearer a b",
      "Token abc",
    ]) {
      expect(bearerToken(header)).toBeNull();
    }
  });
});

describe("createApiKeySchema", () => {
  it("takes a name, scopes and an optional lifetime, dropping duplicate scopes", () => {
    expect(
      createApiKeySchema.parse({ name: "  Wazuh lab ", scopes: ["ingest:wazuh", "ingest:wazuh"] }),
    ).toEqual({
      name: "Wazuh lab",
      scopes: ["ingest:wazuh"],
    });
    expect(
      createApiKeySchema.parse({ name: "x", scopes: ["ingest:wazuh"], expires_in_days: null })
        .expires_in_days,
    ).toBeNull();
    expect(
      createApiKeySchema.parse({ name: "x", scopes: ["ingest:wazuh"], expires_in_days: 30 })
        .expires_in_days,
    ).toBe(30);
  });

  it("refuses an empty name or scope list, an unknown scope, a bad lifetime and any field the server owns", () => {
    const ok = { name: "x", scopes: ["ingest:wazuh"] };
    for (const bad of [
      { ...ok, name: "   " },
      { ...ok, name: "x".repeat(101) },
      { ...ok, scopes: [] },
      { ...ok, scopes: ["admin:everything"] },
      { name: "x" },
      { ...ok, expires_in_days: 0 },
      { ...ok, expires_in_days: 366 },
      { ...ok, expires_in_days: 1.5 },
      { ...ok, expires_in_days: "30" },
      { ...ok, user_id: ADMIN },
      { ...ok, key_hash: "a".repeat(64) },
      { ...ok, key_prefix: "arc_" },
    ]) {
      expect(createApiKeySchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe("keyStatus", () => {
  it("is revoked, expired or active, in that order of precedence", () => {
    expect(keyStatus(row(), NOW)).toBe("active");
    expect(keyStatus(row({ expires_at: null }), NOW)).toBe("active");
    expect(keyStatus(row({ expires_at: NOW.toISOString() }), NOW)).toBe("expired");
    expect(keyStatus(row({ expires_at: new Date(NOW.getTime() - 1).toISOString() }), NOW)).toBe(
      "expired",
    );
    expect(keyStatus(row({ revoked_at: NOW.toISOString() }), NOW)).toBe("revoked");
    expect(
      keyStatus(
        row({
          revoked_at: NOW.toISOString(),
          expires_at: new Date(NOW.getTime() - DAY).toISOString(),
        }),
        NOW,
      ),
    ).toBe("revoked");
  });
});

describe("createApiKey", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
    repo.countUsableKeys.mockResolvedValue(0);
    repo.insertApiKey.mockImplementation(async (input) =>
      row({
        ...input,
        id: KEY_ID,
        last_used_at: null,
        revoked_at: null,
        created_at: NOW.toISOString(),
      }),
    );
  });

  it("gives an administrator a key, shown once, and stores only the hash", async () => {
    const { key, api_key } = await createApiKey(
      auth("admin"),
      { name: "Wazuh lab", scopes: ["ingest:wazuh"] },
      request,
      NOW,
    );

    expect(key).toMatch(API_KEY_PATTERN);
    const stored = repo.insertApiKey.mock.calls[0][0];
    expect(stored).toMatchObject({
      user_id: ADMIN,
      name: "Wazuh lab",
      scopes: ["ingest:wazuh"],
      key_prefix: key.slice(0, 8),
      key_hash: hashApiKey(key),
    });
    expect(JSON.stringify(stored)).not.toContain(key);
    expect(api_key).toMatchObject({ id: KEY_ID, status: "active", key_prefix: key.slice(0, 8) });
    expect(JSON.stringify(api_key)).not.toContain(key);
    expect(api_key).not.toHaveProperty("key_hash");
  });

  it("expires after a year unless told otherwise, in a set number of days, or never", async () => {
    await createApiKey(auth("admin"), { name: "a", scopes: ["ingest:wazuh"] }, request, NOW);
    expect(repo.insertApiKey.mock.calls[0][0].expires_at).toBe(
      new Date(NOW.getTime() + 365 * DAY).toISOString(),
    );
    await createApiKey(
      auth("admin"),
      { name: "b", scopes: ["ingest:wazuh"], expires_in_days: 7 },
      request,
      NOW,
    );
    expect(repo.insertApiKey.mock.calls[1][0].expires_at).toBe(
      new Date(NOW.getTime() + 7 * DAY).toISOString(),
    );
    await createApiKey(
      auth("admin"),
      { name: "c", scopes: ["ingest:wazuh"], expires_in_days: null },
      request,
      NOW,
    );
    expect(repo.insertApiKey.mock.calls[2][0].expires_at).toBeNull();
  });

  it("audits who made which key, without the key", async () => {
    const { key } = await createApiKey(
      auth("admin"),
      { name: "Wazuh lab", scopes: ["ingest:wazuh"] },
      request,
      NOW,
    );
    const entry = audit.mock.calls[0][0];
    expect(entry).toMatchObject({
      action: "api_key.created",
      userId: ADMIN,
      entityType: "api_key",
      entityId: KEY_ID,
    });
    expect(entry.metadata).toMatchObject({
      name: "Wazuh lab",
      scopes: ["ingest:wazuh"],
      key_prefix: key.slice(0, 8),
    });
    expect(JSON.stringify(entry)).not.toContain(key);
    expect(JSON.stringify(entry)).not.toContain(hashApiKey(key));
  });

  it("refuses a role that may not use the scope (403), before anything is stored", async () => {
    for (const role of ["analyst", "viewer"] as const) {
      const error = await failureOf(
        createApiKey(auth(role), { name: "x", scopes: ["ingest:wazuh"] }, request, NOW),
      );
      expect(error).toMatchObject({ status: 403, code: "FORBIDDEN" });
    }
    expect(repo.insertApiKey).not.toHaveBeenCalled();
    expect(audit).not.toHaveBeenCalled();
  });

  it("limits how many usable keys a person has (409)", async () => {
    repo.countUsableKeys.mockResolvedValue(MAX_ACTIVE_KEYS_PER_USER);
    const error = await failureOf(
      createApiKey(auth("admin"), { name: "x", scopes: ["ingest:wazuh"] }, request, NOW),
    );
    expect(error).toMatchObject({ status: 409 });
    expect(repo.insertApiKey).not.toHaveBeenCalled();
  });
});

describe("listing and revoking", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    audit.mockResolvedValue(true);
  });

  it("lists keys with their status and never a secret", async () => {
    repo.listApiKeys.mockResolvedValue([row(), row({ id: "k2", revoked_at: NOW.toISOString() })]);
    const keys = await listApiKeys(auth("admin"), NOW);
    expect(keys.map((key) => key.status)).toEqual(["active", "revoked"]);
    expect(JSON.stringify(keys)).not.toContain("key_hash");
  });

  it("revokes a key the caller can see, and audits it", async () => {
    repo.findVisibleApiKey.mockResolvedValue(row());
    repo.revokeApiKeyRow.mockResolvedValue(row({ revoked_at: NOW.toISOString() }));
    const revoked = await revokeApiKey(auth("admin"), KEY_ID, request, NOW);
    expect(revoked.status).toBe("revoked");
    expect(audit.mock.calls[0][0]).toMatchObject({ action: "api_key.revoked", entityId: KEY_ID });
    expect(audit.mock.calls[0][0].metadata).toMatchObject({
      key_prefix: "arc_AbCd",
      owner_id: ADMIN,
    });
  });

  it("revoking twice is harmless and writes no second audit entry", async () => {
    repo.findVisibleApiKey.mockResolvedValue(row({ revoked_at: NOW.toISOString() }));
    repo.revokeApiKeyRow.mockResolvedValue(null);
    expect((await revokeApiKey(auth("admin"), KEY_ID, request, NOW)).status).toBe("revoked");
    expect(audit).not.toHaveBeenCalled();
  });

  it("answers 404 for a key the caller cannot see (row level security) and for a malformed id", async () => {
    repo.findVisibleApiKey.mockResolvedValue(null);
    expect(await failureOf(revokeApiKey(auth("analyst"), KEY_ID, request, NOW))).toMatchObject({
      status: 404,
    });
    expect(repo.revokeApiKeyRow).not.toHaveBeenCalled();
    repo.findVisibleApiKey.mockClear();
    expect(await failureOf(revokeApiKey(auth("admin"), "nope", request, NOW))).toMatchObject({
      status: 404,
    });
    expect(repo.findVisibleApiKey).not.toHaveBeenCalled();
  });
});

describe("verifyApiKey", () => {
  const { key } = generateApiKey();
  const owned = (
    overrides: Record<string, unknown> = {},
    owner: unknown = { is_active: true, role_name: "admin" },
  ) => ({
    ...row(),
    ...overrides,
    owner,
  });

  beforeEach(() => {
    vi.resetAllMocks();
    repo.findKeyByHash.mockResolvedValue(owned());
    repo.touchLastUsed.mockResolvedValue(undefined);
  });

  it("accepts a good key and says who it acts for", async () => {
    const principal = await verifyApiKey(key, "ingest:wazuh", NOW);
    expect(principal).toEqual({
      keyId: KEY_ID,
      keyName: "Wazuh lab",
      keyPrefix: "arc_AbCd",
      ownerId: ADMIN,
      scopes: ["ingest:wazuh"],
    });
    expect(repo.findKeyByHash).toHaveBeenCalledWith(hashApiKey(key));
    expect(repo.touchLastUsed).toHaveBeenCalledWith(KEY_ID, NOW);
  });

  it("looks the key up by its hash, never by the key itself", async () => {
    await verifyApiKey(key, "ingest:wazuh", NOW);
    expect(JSON.stringify(repo.findKeyByHash.mock.calls)).not.toContain(key);
  });

  it("never asks the database about a token that cannot be a key", async () => {
    for (const token of [null, "", "not-a-key", `arc_${"a".repeat(10)}`]) {
      expect(await failureOf(verifyApiKey(token, "ingest:wazuh", NOW))).toMatchObject({
        status: 401,
      });
    }
    expect(repo.findKeyByHash).not.toHaveBeenCalled();
  });

  it("gives every reason a key is unusable the same 401, so nothing can be learned from it", async () => {
    const cases: [string, unknown][] = [
      ["unknown", null],
      ["revoked", owned({ revoked_at: NOW.toISOString() })],
      ["expired", owned({ expires_at: new Date(NOW.getTime() - 1000).toISOString() })],
      ["owner disabled", owned({}, { is_active: false, role_name: "admin" })],
      ["owner deleted", owned({}, null)],
      ["owner demoted below the scope", owned({}, { is_active: true, role_name: "analyst" })],
      ["owner with an unknown role", owned({}, { is_active: true, role_name: "root" })],
    ];
    const seen = new Set<string>();
    for (const [name, found] of cases) {
      repo.findKeyByHash.mockResolvedValue(found);
      const error = await failureOf(verifyApiKey(key, "ingest:wazuh", NOW));
      expect(error, name).toMatchObject({
        status: 401,
        code: "UNAUTHENTICATED",
        message: "The API key is not valid.",
      });
      expect(error.headers).toEqual({ "WWW-Authenticate": 'Bearer realm="ArcRadar"' });
      seen.add(JSON.stringify([error.status, error.code, error.message]));
    }
    expect(seen.size).toBe(1);
    expect(repo.touchLastUsed).not.toHaveBeenCalled();
  });

  it("a valid key without the scope is 403", async () => {
    repo.findKeyByHash.mockResolvedValue(owned({ scopes: [] }));
    expect(await failureOf(verifyApiKey(key, "ingest:wazuh", NOW))).toMatchObject({
      status: 403,
      code: "FORBIDDEN",
    });
    expect(repo.touchLastUsed).not.toHaveBeenCalled();
  });

  it("a key that never expires keeps working", async () => {
    repo.findKeyByHash.mockResolvedValue(owned({ expires_at: null }));
    await expect(verifyApiKey(key, "ingest:wazuh", new Date("2099-01-01"))).resolves.toBeDefined();
  });

  it("does not fail a request because the last-used stamp could not be written", async () => {
    repo.touchLastUsed.mockRejectedValue(new Error("database is busy"));
    await expect(verifyApiKey(key, "ingest:wazuh", NOW)).resolves.toMatchObject({ keyId: KEY_ID });
  });
});
