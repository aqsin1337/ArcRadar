import { z } from "zod";
import { emailSchema, newPasswordSchema } from "@/lib/validation/auth";
import { ROLE_NAMES } from "@/types/domain";

const roleSchema = z.enum(ROLE_NAMES, { error: "Not a role ArcRadar knows." });

/** Body of PATCH /api/users/:id. At least one field, so an empty body is a plain validation error. */
export const updateUserSchema = z
  .strictObject({
    role_name: roleSchema.optional(),
    is_active: z.boolean().optional(),
  })
  .refine((value) => value.role_name !== undefined || value.is_active !== undefined, {
    error: "Give a role, an active status, or both.",
  });

export type UpdateUserInput = z.output<typeof updateUserSchema>;

/**
 * Body of POST /api/users: an administrator makes an account for a teammate. The password follows the
 * same policy as sign-up, and the role is required (there is no "default" role to fall into here).
 */
export const createUserSchema = z.strictObject({
  email: emailSchema,
  password: newPasswordSchema,
  display_name: z
    .string()
    .trim()
    .min(1, "Enter a name.")
    .max(100, "The name can have at most 100 characters."),
  role_name: roleSchema,
});

export type CreateUserInput = z.output<typeof createUserSchema>;

export const userIdSchema = z.uuid({ error: "The user id is not valid." });
