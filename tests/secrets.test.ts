import { randomBytes } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import type { ServerEnv } from "@/lib/env/server";
import { SECRET_CATALOG, SECRET_NAMES, valueSchemaFor } from "@/lib/secrets/catalog";
import { decryptSecret, encryptSecret, parseEncryptionKey } from "@/lib/secrets/crypto";
import { permissionsForRole } from "@/lib/rbac/permissions";

const repo = vi.hoisted(() => ({
  findStoredSecrets: vi.fn(),
  upsertStoredSecret: vi.fn(),
  deleteStoredSecret: vi.fn(),
}));
vi.mock("@/lib/secrets/repository", () => repo);
const audit = vi.hoisted(() => ({ writeAuditLog: vi.fn() }));
vi.mock("@/lib/audit/write", () => audit);

const { getEffectiveEnv, listSecrets, removeSecret, saveSecret } =
  await import("@/lib/secrets/service");

const KEY_B64 = randomBytes(32).toString("base64");
const KEY = parseEncryptionKey(KEY_B64)!;
const baseEnv = (extra: Partial<ServerEnv> = {}): ServerEnv =>
  ({
    SUPABASE_SERVICE_ROLE_KEY: "service",
    SECRETS_ENCRYPTION_KEY: KEY_B64,
    ...extra,
  }) as ServerEnv;

const auth: AuthContext = {
  supabase: {} as AuthClient,
  user: { id: "admin-1", email: "admin@arcradar.test" },
  profile: { display_name: "admin", role: "admin" },
  permissions: permissionsForRole("admin"),
};
const request = { headers: new Headers() };

const stored = (name: string, plain: string, last4: string | null = null) => ({
  name,
  ciphertext: encryptSecret(plain, name, KEY),
  last4,
  updated_at: "2026-10-05T10:00:00.000Z",
});

beforeEach(() => vi.clearAllMocks());

describe("secret encryption", () => {
  it("round-trips and never stores the plain text", () => {
    const sealed = encryptSecret("sk-live-abcdef123456", "OPENAI_API_KEY", KEY);
    expect(sealed).not.toContain("abcdef123456");
    expect(decryptSecret(sealed, "OPENAI_API_KEY", KEY)).toBe("sk-live-abcdef123456");
  });

  it("uses a fresh nonce each time", () => {
    expect(encryptSecret("same-value-1", "GROQ_API_KEY", KEY)).not.toBe(
      encryptSecret("same-value-1", "GROQ_API_KEY", KEY),
    );
  });

  it("refuses a value moved under another name, a tampered value and a wrong key", () => {
    const sealed = encryptSecret("sk-live-abcdef123456", "OPENAI_API_KEY", KEY);
    expect(() => decryptSecret(sealed, "GROQ_API_KEY", KEY)).toThrow();
    const [v, iv, tag, body] = sealed.split(".");
    const flipped = `${v}.${iv}.${tag}.${body!.slice(0, -2)}${body!.endsWith("AA") ? "BB" : "AA"}`;
    expect(() => decryptSecret(flipped, "OPENAI_API_KEY", KEY)).toThrow();
    expect(() => decryptSecret(sealed, "OPENAI_API_KEY", randomBytes(32))).toThrow();
  });

  it("accepts only a 32-byte key", () => {
    expect(parseEncryptionKey(undefined)).toBeNull();
    expect(parseEncryptionKey(randomBytes(16).toString("base64"))).toBeNull();
    expect(parseEncryptionKey(KEY_B64)).not.toBeNull();
  });
});

describe("catalog", () => {
  it("covers exactly the names the database allows", () => {
    expect(SECRET_CATALOG.map((entry) => entry.name).sort()).toEqual([...SECRET_NAMES].sort());
  });

  it("validates each kind of value", () => {
    expect(valueSchemaFor("secret", "OPENAI_API_KEY").safeParse("short").success).toBe(false);
    expect(valueSchemaFor("secret", "OPENAI_API_KEY").safeParse("has space inside").success).toBe(
      false,
    );
    expect(valueSchemaFor("secret", "OPENAI_API_KEY").safeParse(" sk-abcdefgh12 ").data).toBe(
      "sk-abcdefgh12",
    );
    expect(
      valueSchemaFor("text", "GITHUB_RULES_REPO").safeParse("aqsin1337/wazuh_rules").success,
    ).toBe(true);
    expect(valueSchemaFor("text", "GITHUB_RULES_REPO").safeParse("../etc/passwd").success).toBe(
      false,
    );
    expect(valueSchemaFor("flag", "SHODAN_INTERNETDB").safeParse("true").success).toBe(true);
    expect(valueSchemaFor("flag", "SHODAN_INTERNETDB").safeParse("yes").success).toBe(false);
  });

  it("does not let an administrator set the Ollama address", () => {
    expect(SECRET_NAMES).not.toContain("OLLAMA_BASE_URL");
  });
});

describe("getEffectiveEnv", () => {
  it("lays saved keys over the server environment", async () => {
    const env = await getEffectiveEnv({
      base: () => baseEnv({ GROQ_API_KEY: "from-server-1234", OTX_API_KEY: "otx-from-server" }),
      load: async () => [stored("GROQ_API_KEY", "from-app-5678")],
    });
    expect(env.GROQ_API_KEY).toBe("from-app-5678");
    expect(env.OTX_API_KEY).toBe("otx-from-server");
  });

  it("uses the environment alone when no encryption key is set", async () => {
    const load = vi.fn();
    const env = await getEffectiveEnv({
      base: () => baseEnv({ SECRETS_ENCRYPTION_KEY: undefined, GROQ_API_KEY: "from-server-1234" }),
      load,
    });
    expect(env.GROQ_API_KEY).toBe("from-server-1234");
    expect(load).not.toHaveBeenCalled();
  });

  it("falls back to the environment when the database cannot be read", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const env = await getEffectiveEnv({
      base: () => baseEnv({ GROQ_API_KEY: "from-server-1234" }),
      load: async () => {
        throw new Error("down");
      },
    });
    expect(env.GROQ_API_KEY).toBe("from-server-1234");
  });

  it("skips a row that cannot be decrypted and keeps the others", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const wrongKeyRow = {
      name: "OPENAI_API_KEY",
      ciphertext: encryptSecret("x-secret-value", "OPENAI_API_KEY", randomBytes(32)),
      last4: "alue",
      updated_at: "2026-10-05T10:00:00.000Z",
    };
    const env = await getEffectiveEnv({
      base: () => baseEnv({ OPENAI_API_KEY: "from-server-1234" }),
      load: async () => [wrongKeyRow, stored("GROQ_API_KEY", "from-app-5678")],
    });
    expect(env.OPENAI_API_KEY).toBe("from-server-1234");
    expect(env.GROQ_API_KEY).toBe("from-app-5678");
  });
});

describe("listSecrets", () => {
  it("shows where each setting comes from and never a saved secret", async () => {
    const overview = await listSecrets({
      base: () => baseEnv({ OTX_API_KEY: "otx-from-server", GITHUB_RULES_BRANCH: "main" }),
      load: async () => [
        stored("GROQ_API_KEY", "gsk_very_secret_value", "alue"),
        stored("GITHUB_RULES_REPO", "aqsin1337/wazuh_rules"),
      ],
    });
    const byName = Object.fromEntries(overview.secrets.map((s) => [s.name, s]));
    expect(overview.encryption_ready).toBe(true);
    expect(byName.GROQ_API_KEY).toMatchObject({ source: "app", last4: "alue", value: null });
    expect(byName.OTX_API_KEY).toMatchObject({ source: "server", value: null });
    expect(byName.OPENAI_API_KEY).toMatchObject({ source: "none" });
    expect(byName.GITHUB_RULES_REPO).toMatchObject({
      source: "app",
      value: "aqsin1337/wazuh_rules",
    });
    expect(byName.GITHUB_RULES_BRANCH).toMatchObject({ source: "server", value: "main" });
    expect(JSON.stringify(overview)).not.toContain("gsk_very_secret_value");
    expect(JSON.stringify(overview)).not.toContain("otx-from-server");
  });

  it("reports that saving is not ready without an encryption key", async () => {
    const overview = await listSecrets({
      base: () => baseEnv({ SECRETS_ENCRYPTION_KEY: undefined }),
      load: async () => [],
    });
    expect(overview.encryption_ready).toBe(false);
  });
});

describe("saveSecret / removeSecret", () => {
  it("stores the value encrypted, keeps the last four characters and audits without the value", async () => {
    await saveSecret(auth, "OPENAI_API_KEY", " sk-live-abcdef123456 ", request, baseEnv());
    const row = repo.upsertStoredSecret.mock.calls[0]![0];
    expect(row.name).toBe("OPENAI_API_KEY");
    expect(row.last4).toBe("3456");
    expect(row.updated_by).toBe("admin-1");
    expect(row.ciphertext).not.toContain("abcdef");
    expect(decryptSecret(row.ciphertext, "OPENAI_API_KEY", KEY)).toBe("sk-live-abcdef123456");
    const entry = audit.writeAuditLog.mock.calls[0]![0];
    expect(entry).toMatchObject({ action: "secret.saved", entityId: "OPENAI_API_KEY" });
    expect(JSON.stringify(entry)).not.toContain("abcdef");
  });

  it("keeps no last4 for a non-secret setting", async () => {
    await saveSecret(auth, "GITHUB_RULES_REPO", "aqsin1337/wazuh_rules", request, baseEnv());
    expect(repo.upsertStoredSecret.mock.calls[0]![0].last4).toBeNull();
  });

  it("rejects an unknown name, a bad value, and a server with no encryption key", async () => {
    await expect(
      saveSecret(auth, "OLLAMA_BASE_URL", "http://x", request, baseEnv()),
    ).rejects.toMatchObject({
      status: 404,
    });
    await expect(
      saveSecret(auth, "OPENAI_API_KEY", "short", request, baseEnv()),
    ).rejects.toBeInstanceOf(ApiError);
    await expect(
      saveSecret(
        auth,
        "OPENAI_API_KEY",
        "sk-live-abcdef123456",
        request,
        baseEnv({ SECRETS_ENCRYPTION_KEY: undefined }),
      ),
    ).rejects.toMatchObject({ status: 503 });
    expect(repo.upsertStoredSecret).not.toHaveBeenCalled();
    expect(audit.writeAuditLog).not.toHaveBeenCalled();
  });

  it("removes a saved key and audits it", async () => {
    await removeSecret(auth, "GROQ_API_KEY", request);
    expect(repo.deleteStoredSecret).toHaveBeenCalledWith("GROQ_API_KEY");
    expect(audit.writeAuditLog.mock.calls[0]![0]).toMatchObject({ action: "secret.removed" });
    await expect(removeSecret(auth, "NOPE", request)).rejects.toMatchObject({ status: 404 });
  });
});
