import type {
  InvestigationEvidence,
  InvestigationNote,
  InvestigationTimelineEntry,
  LinkedAlert,
  LinkedIndicator,
} from "./types";

type Source = {
  created_at: string;
  created_by_name: string | null;
  notes: InvestigationNote[];
  evidence: InvestigationEvidence[];
  indicators: LinkedIndicator[];
  alerts: LinkedAlert[];
};

/**
 * Everything that happened in an investigation, newest first: it was opened, notes and status
 * changes were written, evidence, indicators and alerts were attached. Status changes are the
 * `system` notes the server records, so the history is exactly what was recorded.
 */
export function buildInvestigationTimeline(source: Source): InvestigationTimelineEntry[] {
  const entries: InvestigationTimelineEntry[] = [
    {
      at: source.created_at,
      kind: "opened",
      title: "Investigation opened",
      detail: null,
      actor: source.created_by_name,
    },
  ];

  for (const note of source.notes) {
    entries.push(
      note.kind === "system"
        ? {
            at: note.created_at,
            kind: "system",
            title: note.body,
            detail: null,
            actor: note.author_name,
          }
        : {
            at: note.created_at,
            kind: "note",
            title: "Note added",
            detail: note.body,
            actor: note.author_name,
          },
    );
  }
  for (const item of source.evidence) {
    entries.push({
      at: item.created_at,
      kind: "evidence",
      title: "Evidence added",
      detail: item.title,
      actor: item.added_by_name,
    });
  }
  for (const indicator of source.indicators) {
    entries.push({
      at: indicator.added_at,
      kind: "indicator",
      title: "Indicator attached",
      detail: indicator.value,
      actor: indicator.added_by_name,
    });
  }
  for (const alert of source.alerts) {
    entries.push({
      at: alert.added_at,
      kind: "alert",
      title: "Alert attached",
      detail: alert.title,
      actor: alert.added_by_name,
    });
  }

  return entries.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
}
