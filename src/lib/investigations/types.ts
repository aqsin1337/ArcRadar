import type { IndicatorTag } from "@/lib/indicators/types";
import type {
  AlertStatus,
  DataOrigin,
  IndicatorType,
  Investigation,
  InvestigationStatus,
  Severity,
  Verdict,
} from "@/types/domain";

export type Person = { id: string; display_name: string | null };

/** A row of the investigation list: the record, its analyst and tags, and how much is attached. */
export type InvestigationListItem = Investigation & {
  analyst: Person | null;
  tags: IndicatorTag[];
  indicator_count: number;
  alert_count: number;
};

export type LinkedIndicator = {
  id: string;
  type: IndicatorType;
  value: string;
  verdict: Verdict;
  severity: Severity;
  origin: DataOrigin;
  added_at: string;
  added_by_name: string | null;
};

export type LinkedAlert = {
  id: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  origin: DataOrigin;
  added_at: string;
  added_by_name: string | null;
};

export type InvestigationNote = {
  id: string;
  /** `system` notes are the status history, written by the server. */
  kind: "note" | "system";
  body: string;
  author_id: string | null;
  author_name: string | null;
  created_at: string;
  updated_at: string;
};

export type InvestigationEvidence = {
  id: string;
  title: string;
  location: string;
  description: string | null;
  added_by_name: string | null;
  created_at: string;
};

export type InvestigationTimelineEntry = {
  at: string;
  kind: "opened" | "note" | "system" | "evidence" | "indicator" | "alert";
  title: string;
  detail: string | null;
  actor: string | null;
};

export type InvestigationDetail = Investigation & {
  analyst: Person | null;
  tags: IndicatorTag[];
  created_by_name: string | null;
  indicators: LinkedIndicator[];
  alerts: LinkedAlert[];
  /** Ordinary notes and system notes together, oldest first. */
  notes: InvestigationNote[];
  evidence: InvestigationEvidence[];
  timeline: InvestigationTimelineEntry[];
};

export type ChecklistItem = {
  id: string;
  text: string;
  done: boolean;
  /** `ai` when an AI checklist suggestion seeded it, `analyst` when someone typed it in. */
  source: "ai" | "analyst";
  created_by_name: string | null;
  created_at: string;
  done_by_name: string | null;
  done_at: string | null;
};

export type InvestigationStatusCount = { status: InvestigationStatus; total: number };

export type InvestigationStats = { total: number; by_status: InvestigationStatusCount[] };
