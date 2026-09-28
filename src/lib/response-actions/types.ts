import type { DataOrigin } from "@/types/domain";

export type ResponseActionStatus = "recommended" | "acknowledged" | "completed" | "skipped";
export type ResponseActionSource = "ai" | "analyst";

/** A catalog entry: a reusable, curated response action (a small playbook item). */
export type ResponseAction = {
  id: string;
  title: string;
  description: string | null;
  category: string | null;
  origin: DataOrigin;
  created_by_name: string | null;
  created_at: string;
  updated_at: string;
};

/** One recommendation or execution of a catalog action against a specific alert. */
export type ResponseActionLogEntry = {
  id: string;
  action_id: string;
  action_title: string;
  action_category: string | null;
  status: ResponseActionStatus;
  source: ResponseActionSource;
  notes: string | null;
  performed_by_name: string | null;
  performed_at: string | null;
  created_by_name: string | null;
  created_at: string;
};
