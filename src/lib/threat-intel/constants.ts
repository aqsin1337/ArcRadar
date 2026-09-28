import { Constants } from "@/types/database";
import type { CampaignStatus } from "@/types/domain";

export const CAMPAIGN_STATUSES = Constants.public.Enums.campaign_status;

export const CAMPAIGN_STATUS_LABELS: Record<CampaignStatus, string> = {
  active: "Active",
  dormant: "Dormant",
  concluded: "Concluded",
};

/** Columns each list can be sorted by. Records without a date always sort last. */
export const ACTOR_SORT_FIELDS = ["name", "last_seen", "first_seen", "updated_at"] as const;
export const CAMPAIGN_SORT_FIELDS = ["name", "last_seen", "first_seen", "status"] as const;
export const MALWARE_SORT_FIELDS = ["name", "malware_type", "updated_at"] as const;
export const TECHNIQUE_SORT_FIELDS = ["id", "name"] as const;

export const SORT_LABELS: Record<string, string> = {
  name: "Name",
  id: "Technique id",
  last_seen: "Last seen",
  first_seen: "First seen",
  updated_at: "Last updated",
  status: "Status",
  malware_type: "Type",
};

/** How many linked indicators a detail page lists; the rest are reachable through the total. */
export const LINKED_INDICATOR_LIMIT = 25;

/** The MITRE ATT&CK technique id pattern (T1566, T1078.001), as the database enforces it. */
export const TECHNIQUE_ID = /^T[0-9]{4}(\.[0-9]{3})?$/;
