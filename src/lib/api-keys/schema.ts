import { z } from "zod";
import { API_KEY_SCOPES, MAX_KEY_LIFETIME_DAYS } from "./constants";

/**
 * Body of POST /api/api-keys. `expires_in_days` defaults to a year; `null` means the key never
 * expires. The body is strict: the owner, the hash and the prefix are the server's to set.
 */
export const createApiKeySchema = z.strictObject({
  name: z
    .string()
    .trim()
    .min(1, "Enter a name for the key.")
    .max(100, "The name can have at most 100 characters."),
  scopes: z
    .array(z.enum(API_KEY_SCOPES, { error: "That is not a scope a key can have." }))
    .min(1, "Choose at least one scope.")
    .max(10, "Too many scopes.")
    .transform((scopes) => [...new Set(scopes)]),
  expires_in_days: z
    .union([
      z
        .number({ error: "Enter a number of days." })
        .int("Enter a whole number of days.")
        .min(1, "A key lasts at least one day.")
        .max(MAX_KEY_LIFETIME_DAYS, `A key lasts at most ${MAX_KEY_LIFETIME_DAYS} days.`),
      z.null(),
    ])
    .optional(),
});

export const apiKeyIdSchema = z.uuid({ error: "The API key id is not valid." });

export type CreateApiKeyInput = z.output<typeof createApiKeySchema>;
