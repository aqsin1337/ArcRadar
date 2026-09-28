import { z } from "zod";
import { ROLE_NAMES } from "@/types/domain";

/** Body of PATCH /api/users/:id. At least one field, so an empty body is a plain validation error. */
export const updateUserSchema = z
  .strictObject({
    role_name: z.enum(ROLE_NAMES, { error: "Not a role ArcRadar knows." }).optional(),
    is_active: z.boolean().optional(),
  })
  .refine((value) => value.role_name !== undefined || value.is_active !== undefined, {
    error: "Give a role, an active status, or both.",
  });

export type UpdateUserInput = z.output<typeof updateUserSchema>;

export const userIdSchema = z.uuid({ error: "The user id is not valid." });
