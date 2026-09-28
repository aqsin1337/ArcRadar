import type { RoleName } from "@/types/domain";

export type AdminUser = {
  id: string;
  email: string | null;
  display_name: string | null;
  role: RoleName;
  is_active: boolean;
  created_at: string;
  last_sign_in_at: string | null;
};
