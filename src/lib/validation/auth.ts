import { z } from "zod";

// bcrypt (used by Supabase Auth) ignores everything after 72 bytes, so longer passwords are refused.
const MAX_PASSWORD_LENGTH = 72;

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(254, "Email is too long.")
  .pipe(z.email("Enter a valid email address."));

/**
 * Mirrors the Supabase Auth password policy in supabase/config.toml (minimum_password_length = 10,
 * password_requirements = lower_upper_letters_digits). A hosted project must be configured the same
 * way in the dashboard; these rules only give early, friendly errors. The signup and reset forms
 * render `label` as a live checklist, and the schema reports `message`.
 */
export const PASSWORD_RULES = [
  {
    id: "length",
    label: "At least 10 characters",
    message: "Password must be at least 10 characters.",
    test: (value: string) => value.length >= 10,
  },
  {
    id: "lower",
    label: "A lowercase letter",
    message: "Password must contain a lowercase letter.",
    test: (value: string) => /[a-z]/.test(value),
  },
  {
    id: "upper",
    label: "An uppercase letter",
    message: "Password must contain an uppercase letter.",
    test: (value: string) => /[A-Z]/.test(value),
  },
  {
    id: "digit",
    label: "A digit",
    message: "Password must contain a digit.",
    test: (value: string) => /[0-9]/.test(value),
  },
] as const;

export const newPasswordSchema = z
  .string()
  .max(MAX_PASSWORD_LENGTH, `Password must be at most ${MAX_PASSWORD_LENGTH} characters.`)
  .superRefine((value, context) => {
    for (const rule of PASSWORD_RULES) {
      if (!rule.test(value)) context.addIssue({ code: "custom", message: rule.message });
    }
  });

export const loginSchema = z.strictObject({
  email: emailSchema,
  // No policy check on login: older passwords must still work. Just bound the size.
  password: z.string().min(1, "Password is required.").max(MAX_PASSWORD_LENGTH),
});

export const signupSchema = z.strictObject({
  email: emailSchema,
  password: newPasswordSchema,
  display_name: z.string().trim().min(1).max(100).optional(),
});

export const forgotPasswordSchema = z.strictObject({ email: emailSchema });

export const updatePasswordSchema = z.strictObject({ password: newPasswordSchema });

export type LoginInput = z.output<typeof loginSchema>;
export type SignupInput = z.output<typeof signupSchema>;
