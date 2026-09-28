import type { AiAnalysisKind } from "./types";

/**
 * Prompt templates, one per analysis kind. Bumping `AI_PROMPT_VERSION` (and recording the new
 * number here) is a deliberate act: the version is stored on every analysis, so a prompt change stays
 * visible in old rows and re-runs are comparable to what they replace, the same idea as a report being
 * an immutable snapshot rather than a live view.
 */
export const AI_PROMPT_VERSION = 1;

/** What the alert page hands over — only fields the caller can already read on the alert itself,
 * never anything fetched specially for the AI feature. */
export type AlertPromptContext = {
  title: string;
  description: string | null;
  severity: string;
  status: string;
  source: string;
  origin: string;
  createdAt: string;
  indicator: { type: string; value: string; verdict: string } | null;
  asset: { name: string; os: string | null } | null;
  techniques: { id: string; name: string | null }[];
  event: { title: string; type: string; severity: string } | null;
};

/** What the investigation page hands over, for the checklist kind. */
export type InvestigationPromptContext = {
  title: string;
  description: string | null;
  status: string;
  priority: string;
  tags: string[];
  indicators: { type: string; value: string; verdict: string }[];
  alerts: { title: string; severity: string; status: string }[];
  notes: string[];
};

/** What the indicator page hands over, for the verdict-recommendation kind. */
export type IndicatorPromptContext = {
  type: string;
  value: string;
  verdict: string;
  severity: string;
  status: string;
  confidence: number;
  source: string;
  description: string | null;
  tags: string[];
  threatActors: string[];
  campaigns: string[];
  malware: string[];
};

export const AI_MAX_OUTPUT_TOKENS: Record<AiAnalysisKind, number> = {
  threat_summary: 500,
  attack_vector: 700,
  severity_validation: 400,
  response_actions: 700,
  false_positive_score: 350,
  investigation_checklist: 500,
  verdict_recommendation: 350,
};

const SHARED_SYSTEM = `You are a SOC analyst's assistant inside ArcRadar, an incident-response, alert-triage
and case-management platform. You are given one record's own data and asked for one specific kind of
analysis.

Rules:
- Base your answer only on the data given below. Never invent a specific fact (an IP, a technique id, a
  file name) that is not present in it; write "unknown" or omit it instead of guessing.
- Your entire reply must be a single JSON object matching the shape described, and nothing else: no
  markdown code fences, no explanation before or after it.
- This is a recommendation for a human analyst to review, never an instruction that gets executed
  automatically.`;

const KIND_INSTRUCTIONS: Record<AiAnalysisKind, string> = {
  threat_summary: `Task: write a short threat summary of this alert for an analyst who has not looked at
it yet.
Reply with: { "summary": string (2-5 sentences), "key_points": string[] (up to 6 short bullet points) }`,
  attack_vector: `Task: identify which MITRE ATT&CK techniques this alert's data is consistent with, and
explain the likely attack vector in one paragraph. Only list a technique id (like "T1059" or
"T1059.001") when the given data plausibly supports it; an empty list is a correct answer when nothing
does.
Reply with: { "techniques": [{ "id": string, "name": string, "confidence": number (0-100) }] (up to 6),
"narrative": string (1-3 sentences) }`,
  severity_validation: `Task: decide whether this alert's current severity looks right given its data, and
suggest one if you disagree.
Reply with: { "agrees": boolean, "suggested_severity": "info"|"low"|"medium"|"high"|"critical",
"reasoning": string (1-3 sentences) }. When you agree, "suggested_severity" repeats the current one.`,
  response_actions: `Task: recommend the immediate response actions an analyst should consider for this
alert. These are recommendations for a human to acknowledge, complete or skip — never actions you are
taking yourself.
Reply with: { "actions": [{ "title": string (short, imperative, e.g. "Isolate the host"), "why": string
(1 sentence), "urgency": "low"|"medium"|"high"|"immediate" }] (1-5 items, most urgent first) }`,
  false_positive_score: `Task: estimate how likely this alert is a false positive, given its data.
Reply with: { "score": number (0 = certainly a real incident, 100 = certainly a false positive),
"reasoning": string (1-3 sentences) }`,
  investigation_checklist: `Task: suggest an investigation checklist for this case: concrete, short next
steps an analyst should work through, given what is already known. Each item is its own step, in a
sensible order; do not repeat something the notes already say is done.
Reply with: { "items": string[] (3-10 short, imperative steps, e.g. "Pull DNS logs for the affected host") }`,
  verdict_recommendation: `Task: recommend a verdict for this indicator, given its own data and what it is
linked to. This is a recommendation only — applying it is a normal, audited edit the analyst makes
themselves, never something you do.
Reply with: { "verdict": "unknown"|"benign"|"suspicious"|"malicious", "confidence": number (0-100),
"reasoning": string (1-3 sentences) }`,
};

function renderAlertContext(alert: AlertPromptContext): string {
  const lines = [
    `Title: ${alert.title}`,
    `Severity: ${alert.severity}`,
    `Status: ${alert.status}`,
    `Source: ${alert.source}`,
    `Origin: ${alert.origin}`,
    `Created: ${alert.createdAt}`,
    `Description: ${alert.description ?? "(none)"}`,
  ];
  if (alert.indicator) {
    lines.push(
      `Related indicator: ${alert.indicator.type} ${alert.indicator.value} (verdict: ${alert.indicator.verdict})`,
    );
  }
  if (alert.asset) {
    lines.push(`Asset: ${alert.asset.name}${alert.asset.os ? ` (${alert.asset.os})` : ""}`);
  }
  if (alert.techniques.length > 0) {
    lines.push(
      `Techniques already tagged: ${alert.techniques.map((t) => t.name ?? t.id).join(", ")}`,
    );
  }
  if (alert.event) {
    lines.push(
      `Source event: "${alert.event.title}" (${alert.event.type}, ${alert.event.severity})`,
    );
  }
  return lines.join("\n");
}

/** Builds the system and user prompt for one analysis kind on one alert. */
export function buildAlertPrompt(
  kind: AiAnalysisKind,
  alert: AlertPromptContext,
): { system: string; user: string } {
  return {
    system: `${SHARED_SYSTEM}\n\n${KIND_INSTRUCTIONS[kind]}`,
    user: `Alert data:\n${renderAlertContext(alert)}`,
  };
}

function renderInvestigationContext(investigation: InvestigationPromptContext): string {
  const lines = [
    `Title: ${investigation.title}`,
    `Status: ${investigation.status}`,
    `Priority: ${investigation.priority}`,
    `Description: ${investigation.description ?? "(none)"}`,
  ];
  if (investigation.tags.length > 0) lines.push(`Tags: ${investigation.tags.join(", ")}`);
  if (investigation.indicators.length > 0) {
    lines.push(
      `Linked indicators: ${investigation.indicators
        .map((i) => `${i.type} ${i.value} (verdict: ${i.verdict})`)
        .join("; ")}`,
    );
  }
  if (investigation.alerts.length > 0) {
    lines.push(
      `Linked alerts: ${investigation.alerts
        .map((a) => `"${a.title}" (${a.severity}, ${a.status})`)
        .join("; ")}`,
    );
  }
  if (investigation.notes.length > 0) {
    lines.push(`Analyst notes so far:\n${investigation.notes.map((n) => `- ${n}`).join("\n")}`);
  }
  return lines.join("\n");
}

/** Builds the system and user prompt for one analysis kind on one investigation. */
export function buildInvestigationPrompt(
  kind: AiAnalysisKind,
  investigation: InvestigationPromptContext,
): { system: string; user: string } {
  return {
    system: `${SHARED_SYSTEM}\n\n${KIND_INSTRUCTIONS[kind]}`,
    user: `Investigation data:\n${renderInvestigationContext(investigation)}`,
  };
}

function renderIndicatorContext(indicator: IndicatorPromptContext): string {
  const lines = [
    `Type: ${indicator.type}`,
    `Value: ${indicator.value}`,
    `Current verdict: ${indicator.verdict}`,
    `Severity: ${indicator.severity}`,
    `Status: ${indicator.status}`,
    `Confidence: ${indicator.confidence}`,
    `Source: ${indicator.source}`,
    `Description: ${indicator.description ?? "(none)"}`,
  ];
  if (indicator.tags.length > 0) lines.push(`Tags: ${indicator.tags.join(", ")}`);
  if (indicator.threatActors.length > 0) {
    lines.push(`Linked threat actors: ${indicator.threatActors.join(", ")}`);
  }
  if (indicator.campaigns.length > 0)
    lines.push(`Linked campaigns: ${indicator.campaigns.join(", ")}`);
  if (indicator.malware.length > 0) lines.push(`Linked malware: ${indicator.malware.join(", ")}`);
  return lines.join("\n");
}

/** Builds the system and user prompt for one analysis kind on one indicator. */
export function buildIndicatorPrompt(
  kind: AiAnalysisKind,
  indicator: IndicatorPromptContext,
): { system: string; user: string } {
  return {
    system: `${SHARED_SYSTEM}\n\n${KIND_INSTRUCTIONS[kind]}`,
    user: `Indicator data:\n${renderIndicatorContext(indicator)}`,
  };
}
