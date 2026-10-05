import "server-only";
import { apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthContext } from "@/lib/auth/context";
import { getServerEnv, type ServerEnv } from "@/lib/env/server";
import { logError } from "@/lib/log";
import {
  SECRET_CATALOG,
  type SecretDefinition,
  type SecretName,
  secretDefinition,
  valueSchemaFor,
} from "./catalog";
import { decryptSecret, encryptSecret, parseEncryptionKey } from "./crypto";
import {
  deleteStoredSecret,
  findStoredSecrets,
  upsertStoredSecret,
  type StoredSecret,
} from "./repository";

type RequestLike = { headers: Headers };

export type SecretSource = "app" | "server" | "none";

export type SecretView = SecretDefinition & {
  source: SecretSource;
  /** The end of a saved secret, never the secret. */
  last4: string | null;
  /** Shown only for non-secret settings (a repository, a branch) and the on/off flag. */
  value: string | null;
  updated_at: string | null;
};

export type SecretsOverview = { encryption_ready: boolean; secrets: SecretView[] };

/** The overlay of keys saved in the app on top of the server's environment. */
export type SecretsDeps = {
  base: () => ServerEnv;
  load: () => Promise<StoredSecret[]>;
};

const defaultSecretsDeps = (): SecretsDeps => ({ base: getServerEnv, load: findStoredSecrets });

function decryptAll(
  rows: StoredSecret[],
  base: ServerEnv,
): { values: Map<string, string>; stored: Map<string, StoredSecret> } {
  const key = parseEncryptionKey(base.SECRETS_ENCRYPTION_KEY);
  const values = new Map<string, string>();
  const stored = new Map<string, StoredSecret>();
  for (const row of rows) {
    stored.set(row.name, row);
    if (!key) continue;
    try {
      values.set(row.name, decryptSecret(row.ciphertext, row.name, key));
    } catch (error) {
      // A wrong key or a damaged row: this one setting falls back to the environment.
      logError("secrets.decrypt_failed", error, { name: row.name });
    }
  }
  return { values, stored };
}

/**
 * The server environment with the keys an administrator saved in the app laid over it (the app wins;
 * removing a saved key falls back to the server variable). This is what every provider registry,
 * the AI settings and the GitHub push read. It never throws: if the database cannot be reached the
 * environment alone is used, so a lookup keeps working with whatever the server has.
 */
export async function getEffectiveEnv(
  deps: SecretsDeps = defaultSecretsDeps(),
): Promise<ServerEnv> {
  const base = deps.base();
  if (!parseEncryptionKey(base.SECRETS_ENCRYPTION_KEY)) return base;
  try {
    const { values } = decryptAll(await deps.load(), base);
    const overlay: Record<string, string> = {};
    for (const [name, value] of values) overlay[name] = value;
    return { ...base, ...overlay };
  } catch (error) {
    logError("secrets.load_failed", error);
    return base;
  }
}

export async function listSecrets(
  deps: SecretsDeps = defaultSecretsDeps(),
): Promise<SecretsOverview> {
  const base = deps.base();
  const ready = parseEncryptionKey(base.SECRETS_ENCRYPTION_KEY) !== null;
  const rows = await deps.load();
  const { values, stored } = ready
    ? decryptAll(rows, base)
    : { values: new Map<string, string>(), stored: new Map(rows.map((r) => [r.name, r])) };

  const secrets = SECRET_CATALOG.map((definition): SecretView => {
    const row = stored.get(definition.name);
    const fromServer = Boolean(base[definition.name]);
    const savedValue = values.get(definition.name);
    const source: SecretSource = savedValue !== undefined ? "app" : fromServer ? "server" : "none";
    const shown =
      source === "app" ? savedValue : source === "server" ? base[definition.name] : null;
    return {
      ...definition,
      source,
      last4: source === "app" ? (row?.last4 ?? null) : null,
      value: definition.kind === "secret" ? null : (shown ?? null),
      updated_at: source === "app" ? (row?.updated_at ?? null) : null,
    };
  });
  return { encryption_ready: ready, secrets };
}

function requireDefinition(name: string): SecretDefinition {
  const definition = secretDefinition(name);
  if (!definition) throw apiErrors.notFound("Unknown setting.");
  return definition;
}

export async function saveSecret(
  auth: AuthContext,
  name: string,
  value: unknown,
  request: RequestLike,
  base: ServerEnv = getServerEnv(),
): Promise<void> {
  const definition = requireDefinition(name);
  const key = parseEncryptionKey(base.SECRETS_ENCRYPTION_KEY);
  if (!key) {
    throw apiErrors.unavailable(
      "Saving keys from the app needs SECRETS_ENCRYPTION_KEY on the server (32 random bytes, base64).",
    );
  }
  const parsed = valueSchemaFor(definition.kind, definition.name).safeParse(value);
  if (!parsed.success) {
    throw apiErrors.validation({
      issues: [{ path: "value", message: parsed.error.issues[0]?.message ?? "Invalid value." }],
    });
  }

  await upsertStoredSecret({
    name: definition.name,
    ciphertext: encryptSecret(parsed.data, definition.name, key),
    last4: definition.kind === "secret" ? parsed.data.slice(-4) : null,
    updated_by: auth.user.id,
  });
  // The value itself is never written to the audit trail.
  await writeAuditLog(
    {
      action: "secret.saved",
      userId: auth.user.id,
      entityType: "secret",
      entityId: definition.name,
    },
    request,
  );
}

export async function removeSecret(
  auth: AuthContext,
  name: string,
  request: RequestLike,
): Promise<void> {
  const definition = requireDefinition(name);
  await deleteStoredSecret(definition.name);
  await writeAuditLog(
    {
      action: "secret.removed",
      userId: auth.user.id,
      entityType: "secret",
      entityId: definition.name,
    },
    request,
  );
}

export type { SecretName };
