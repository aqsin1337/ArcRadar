import type { RoleName } from "@/types/domain";

export type AdminUser = {
  id: string;
  email: string | null;
  display_name: string | null;
  role: RoleName;
  is_active: boolean;
  /** Signed up but never approved: waiting for an administrator to choose a role and activate. */
  pending: boolean;
  created_at: string;
  last_sign_in_at: string | null;
};
