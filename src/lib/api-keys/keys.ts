import { createHash, randomBytes } from "node:crypto";
import { API_KEY_PREFIX } from "./constants";

/** `arc_` plus 32 random bytes as base64url (43 characters): 256 bits, so guessing is not an attack. */
export const API_KEY_PATTERN = /^arc_[A-Za-z0-9_-]{43}$/;

/** Only this hash is stored; the key itself is shown once, at creation. */
export const hashApiKey = (key: string): string =>
  createHash("sha256").update(key, "utf8").digest("hex");

export function generateApiKey(): { key: string; prefix: string; hash: string } {
  const key = `${API_KEY_PREFIX}${randomBytes(32).toString("base64url")}`;
  return { key, prefix: key.slice(0, 8), hash: hashApiKey(key) };
}

/** The bearer token of an `Authorization` header, or null when there is none. */
export function bearerToken(header: string | null): string | null {
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header ?? "");
  return match ? match[1] : null;
}
