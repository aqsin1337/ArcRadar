import type { Row } from "@/types/domain";

export type ApiKeyRow = Pick<
  Row<"api_keys">,
  | "id"
  | "user_id"
  | "name"
  | "key_prefix"
  | "scopes"
  | "last_used_at"
  | "expires_at"
  | "revoked_at"
  | "created_at"
>;

export type ApiKeyStatus = "active" | "expired" | "revoked";

/** What the API shows about a key (never the key or its hash). */
export type ApiKeyView = ApiKeyRow & { status: ApiKeyStatus };

/** Who a verified key acts for. */
export type ApiKeyPrincipal = {
  keyId: string;
  keyName: string;
  keyPrefix: string;
  ownerId: string;
  scopes: string[];
};
