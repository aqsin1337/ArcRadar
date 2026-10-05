import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM for provider keys at rest. The ciphertext is bound to the setting's name (as
 * additional authenticated data), so a stored value cannot be copied under another name and still
 * decrypt. Format: `v1.<iv>.<tag>.<ciphertext>`, each part base64url.
 */

const VERSION = "v1";

export function parseEncryptionKey(value: string | undefined): Buffer | null {
  if (!value) return null;
  const key = Buffer.from(value, "base64");
  return key.length === 32 ? key : null;
}

export function encryptSecret(plain: string, name: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(name));
  const body = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv, tag, body]
    .map((part, i) => (i === 0 ? part : b64(part as Buffer)))
    .join(".");
}

export function decryptSecret(stored: string, name: string, key: Buffer): string {
  const [version, iv, tag, body] = stored.split(".");
  if (version !== VERSION || !iv || !tag || !body) throw new Error("Unrecognized secret format.");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "base64url"));
  decipher.setAAD(Buffer.from(name));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(body, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

const b64 = (buffer: Buffer) => buffer.toString("base64url");
