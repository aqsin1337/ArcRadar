"use client";

import {
  ExternalLink,
  FlaskConical,
  GitBranch,
  Pencil,
  Plus,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useState, type ComponentType, type ReactNode } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TextAreaField } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/api/client";
import {
  SIEM_LABELS,
  SIEM_RULE_STATUS_LABELS,
  type SiemId,
  type SiemRuleMode,
  type SiemRuleSeverity,
  type SiemRuleStatus,
} from "@/lib/siem-rules/constants";
import { SPLUNK_SCHEDULES, type SplunkSpec } from "@/lib/siem-rules/dialects/splunk";
import type { FieldCatalog } from "@/lib/siem-rules/catalog";
import type { RuleBacktest, SiemRule } from "@/lib/siem-rules/types";
import { SplunkRuleForm, type SiemRuleFormProps } from "./splunk-rule-form";

const STATUS_TONES: Record<SiemRuleStatus, Tone> = {
  draft: "amber",
  pushed: "green",
  rejected: "slate",
};

const SEVERITY_TONES: Record<SiemRuleSeverity, Tone> = {
  low: "slate",
  medium: "amber",
  high: "orange",
  critical: "red",
};

/** What differs per SIEM on screen: its form, the badges that describe its spec, what the file is called. */
type SiemUi = {
  Form: ComponentType<SiemRuleFormProps>;
  fileLabel: string;
  badges: (rule: SiemRule) => ReactNode;
  askHint: string;
  /** Where the SIEM host picks the rules up from, shown once as a reminder. */
  pullNote: string;
};

const SIEM_UI: Record<SiemId, SiemUi> = {
  splunk: {
    Form: SplunkRuleForm,
    fileLabel: "Splunk savedsearches.conf stanza",
    askHint: "For example: five failed Windows logons from the same address within five minutes.",
    pullNote:
      "ArcRadar only commits the file; a script on the Splunk host pulls the repository and loads approved rules.",
    badges: (rule) => {
      const spec = rule.spec as unknown as SplunkSpec;
      return (
        <>
          <Badge tone="slate">{SPLUNK_SCHEDULES[spec.schedule].label}</Badge>
          {spec.threshold && (
            <Badge tone="orange">
              {spec.threshold.count}× in {spec.threshold.window_minutes} min
              {spec.threshold.by.length > 0 ? " · per " + spec.threshold.by.join(", ") : ""}
            </Badge>
          )}
        </>
      );
    },
  },
};

const WINDOW_LABELS: Record<number, string> = { 24: "Last 24 hours", 168: "Last 7 days" };

function describeBacktest(backtest: RuleBacktest): string {
  if (backtest.error) return `the test could not run: ${backtest.error}`;
  const matches = backtest.matches;
  if (backtest.kind === "threshold") {
    return matches === 0
      ? "would not have fired"
      : `would have fired ${matches}${matches >= 1000 ? "+" : ""} time${matches === 1 ? "" : "s"}`;
  }
  const scanned = backtest.scanned === null ? "" : ` out of ${backtest.scanned} events`;
  return matches === 0
    ? "would not have fired"
    : `would have fired for ${matches} event${matches === 1 ? "" : "s"}${scanned}`;
}

const sampleTime = (time: string) => `${time.slice(0, 16).replace("T", " ")} UTC`;

function describeSample(backtest: RuleBacktest): string {
  // A single-event rule's examples all say the same thing (the conditions): the times are the news.
  if (backtest.kind === "events") {
    const times = backtest.sample.flatMap((item) => (item.time ? [sampleTime(item.time)] : []));
    return times.length > 0 ? `latest at ${times.slice(0, 3).join(", ")}` : "";
  }
  return backtest.sample
    .slice(0, 3)
    .map((item) => {
      const group = item.group ? Object.values(item.group).join(" · ") : "";
      const count = item.count !== undefined ? ` ×${item.count}` : "";
      const time = item.time ? ` (${sampleTime(item.time)})` : "";
      return `${group}${count}${time}`.trim();
    })
    .filter(Boolean)
    .join("; ");
}

/**
 * What Splunk found when it ran the rule's search over past data: the effect of the rule before it goes live.
 * The SIEM host reports this on its own; nothing here asks Splunk anything.
 */
function BacktestPanel({ rule }: { rule: SiemRule }) {
  if (rule.status === "rejected") return null;
  if (rule.status !== "pushed") {
    return (
      <p className="text-xs text-muted" data-testid="backtest">
        Push it in test mode to see how it would have behaved on the real data of the last 24 hours
        and 7 days, before it goes live.
      </p>
    );
  }
  if (rule.backtests.length === 0) {
    return (
      <p className="text-xs text-muted" data-testid="backtest">
        Waiting for Splunk&apos;s test on past data. It starts when Splunk pulls the rule (about a
        minute) and this card updates by itself.
      </p>
    );
  }
  return (
    <div className="space-y-1 rounded-lg border border-border p-3 text-sm" data-testid="backtest">
      <p className="font-medium">Test on real data</p>
      {rule.backtests.map((backtest) => (
        <p key={backtest.window_hours} className="break-words text-muted">
          <span className="text-foreground">
            {WINDOW_LABELS[backtest.window_hours] ?? `${backtest.window_hours} h`}:
          </span>{" "}
          {describeBacktest(backtest)}
          {backtest.sample.length > 0 && !backtest.error
            ? ` · ${backtest.kind === "events" ? "" : "e.g. "}${describeSample(backtest)}`
            : ""}
          {backtest.stale && (
            <span className="text-tone-amber-fg">
              {" "}
              · out of date: the rule changed after this test
            </span>
          )}
        </p>
      ))}
      <p className="text-xs text-muted">
        Measured by Splunk {formatTime(rule.backtests[0].reported_at)}. A rule that counts repeats
        is tested in fixed time slices, so the numbers are close to, not exactly, what the live
        schedule would do.
      </p>
    </div>
  );
}

const SOURCE_LABELS = { manual: "Manual", ai: "AI-generated" } as const;

const formatTime = (iso: string) => `${iso.slice(0, 16).replace("T", " ")} UTC`;

/**
 * The rule workflow for a SIEM other than Wazuh: a person writes a rule (or asks the AI to draft one),
 * reads the file it becomes, then sends it to GitHub, edits it, or rejects it. Nothing here touches the
 * SIEM: its host pulls the repository on its own. The server holds the truth; every action waits for its
 * response and then replaces the local copy of that rule.
 */
export function SiemRulesManager({
  siem,
  rules,
  catalog,
  githubBlobBase,
  githubReady,
  aiReady,
}: {
  siem: SiemId;
  rules: SiemRule[];
  /** The fields the SIEM reported; empty until it has. */
  catalog: FieldCatalog;
  /** `https://github.com/owner/name/blob/branch` when configured, else null. */
  githubBlobBase: string | null;
  githubReady: boolean;
  aiReady: boolean;
}) {
  const ui = SIEM_UI[siem];
  const label = SIEM_LABELS[siem];
  const base = `/api/siem-rules/${siem}`;
  const [items, setItems] = useState(rules);
  const [panel, setPanel] = useState<"none" | "manual" | "ai">("none");
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiError, setAiError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [rejectingId, setRejectingId] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string } | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  // Splunk tests a pushed rule on its own, a minute or two after it pulls it. While a result is missing or out
  // of date, look again every 10 seconds (for at most five minutes) so nobody has to reload the page.
  const waiting = items.some(
    (item) =>
      item.status === "pushed" &&
      (item.backtests.length === 0 || item.backtests.some((backtest) => backtest.stale)),
  );
  useEffect(() => {
    if (!waiting) return;
    const startedAt = Date.now();
    const timer = setInterval(async () => {
      if (Date.now() - startedAt > 5 * 60_000) {
        clearInterval(timer);
        return;
      }
      const result = await apiFetch<SiemRule[]>(base);
      if (!result.ok) return;
      const latest = new Map(result.data.map((rule) => [rule.id, rule]));
      // Only the test results change here: a form being edited is never overwritten.
      setItems((current) =>
        current.map((item) => {
          const fresh = latest.get(item.id);
          return fresh && fresh.updated_at === item.updated_at
            ? { ...item, backtests: fresh.backtests }
            : item;
        }),
      );
    }, 10_000);
    return () => clearInterval(timer);
  }, [waiting, base]);

  const replace = (rule: SiemRule) =>
    setItems((current) => current.map((item) => (item.id === rule.id ? rule : item)));

  async function create(payload: Record<string, unknown>) {
    setPending("create");
    setMessage(null);
    const result = await apiFetch<SiemRule>(base, { body: payload });
    setPending(null);
    if (!result.ok) {
      setFieldErrors(result.fieldErrors);
      setMessage({ tone: "error", text: result.message });
      return;
    }
    setFieldErrors({});
    setItems((current) => [result.data, ...current]);
    setPanel("none");
    setMessage({ tone: "success", text: `Rule ${result.data.rule_key} was saved as a draft.` });
  }

  async function generate() {
    setPending("generate");
    setAiError(null);
    setMessage(null);
    const result = await apiFetch<SiemRule>(`${base}/generate`, { body: { prompt: aiPrompt } });
    setPending(null);
    if (!result.ok) {
      setAiError(result.fieldErrors.prompt ?? result.message);
      return;
    }
    setItems((current) => [result.data, ...current]);
    setAiPrompt("");
    setPanel("none");
    setMessage({
      tone: "success",
      text: `The AI drafted rule ${result.data.rule_key}. Read the file below, then send it to GitHub, edit it or reject it.`,
    });
  }

  async function saveEdit(rule: SiemRule, payload: Record<string, unknown>) {
    setPending(`edit-${rule.id}`);
    setMessage(null);
    const result = await apiFetch<SiemRule>(`${base}/${rule.id}`, {
      method: "PATCH",
      body: payload,
    });
    setPending(null);
    if (!result.ok) {
      setFieldErrors(result.fieldErrors);
      setMessage({ tone: "error", text: result.message });
      return;
    }
    setFieldErrors({});
    replace(result.data);
    setEditingId(null);
  }

  async function push(rule: SiemRule, mode: SiemRuleMode) {
    setPending(`push-${mode}-${rule.id}`);
    setMessage(null);
    const result = await apiFetch<SiemRule>(`${base}/${rule.id}/push?mode=${mode}`, {
      method: "POST",
    });
    setPending(null);
    if (!result.ok) {
      setMessage({ tone: "error", text: result.message });
      return;
    }
    replace(result.data);
    setMessage({
      tone: "success",
      text:
        mode === "test"
          ? `Rule ${rule.rule_key} was committed to GitHub in test mode: Splunk loads it but it does not run or alert. Splunk tests it against past data within a few minutes.`
          : `Rule ${rule.rule_key} was committed to GitHub.`,
    });
  }

  async function reject(rule: SiemRule) {
    setPending(`reject-${rule.id}`);
    setMessage(null);
    const result = await apiFetch<SiemRule>(`${base}/${rule.id}/reject`, {
      body: { reason: rejectReason },
    });
    setPending(null);
    if (!result.ok) {
      setMessage({ tone: "error", text: result.fieldErrors.reason ?? result.message });
      return;
    }
    const withdrawn = rule.status === "pushed";
    replace(result.data);
    setRejectingId(null);
    setRejectReason("");
    if (withdrawn) {
      setMessage({
        tone: "success",
        text: `Rule ${rule.rule_key} was withdrawn: its file was removed from GitHub and Splunk drops the rule within seconds.`,
      });
    }
  }

  async function remove(rule: SiemRule) {
    setPending(`delete-${rule.id}`);
    setMessage(null);
    const result = await apiFetch(`${base}/${rule.id}`, { method: "DELETE" });
    setPending(null);
    if (!result.ok) {
      setMessage({ tone: "error", text: result.message });
      return;
    }
    setItems((current) => current.filter((item) => item.id !== rule.id));
  }

  const busy = pending !== null;
  const { Form } = ui;

  return (
    <div className="space-y-4">
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
      {!githubReady && (
        <Alert tone="warning" title="GitHub is not connected">
          Rules can be drafted, edited and rejected, but &quot;Send to GitHub&quot; stays
          unavailable until a GitHub token and the rules repository are saved on the API keys page
          (see docs/MULTI_SIEM_PLAN.md).
        </Alert>
      )}
      <p className="text-xs text-muted">{ui.pullNote}</p>

      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant={panel === "manual" ? "primary" : "secondary"}
          onClick={() => setPanel(panel === "manual" ? "none" : "manual")}
        >
          <Plus aria-hidden className="size-4" />
          Manual rule
        </Button>
        <Button
          type="button"
          variant={panel === "ai" ? "primary" : "secondary"}
          onClick={() => setPanel(panel === "ai" ? "none" : "ai")}
        >
          <Sparkles aria-hidden className="size-4" />
          Generate with AI
        </Button>
      </div>

      {panel === "manual" && (
        <Card>
          <CardHeader>
            <CardTitle>New {label} rule</CardTitle>
          </CardHeader>
          <CardContent>
            <Form
              rule={null}
              pending={pending === "create"}
              submitLabel="Save as draft"
              serverErrors={fieldErrors}
              catalog={catalog}
              onSubmit={create}
              onCancel={() => setPanel("none")}
            />
          </CardContent>
        </Card>
      )}

      {panel === "ai" && (
        <Card>
          <CardHeader>
            <CardTitle>Generate with AI</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {!aiReady && (
              <Alert tone="warning">
                No AI provider is ready. Set one up on the Integrations page, or write the rule by
                hand.
              </Alert>
            )}
            <TextAreaField
              id={`${siem}-ai-prompt`}
              label="What should the rule detect?"
              hint={ui.askHint}
              value={aiPrompt}
              onChange={(event) => setAiPrompt(event.target.value)}
              maxLength={1000}
              rows={3}
              error={aiError ?? undefined}
            />
            <p className="text-xs text-muted">
              The AI only fills in the rule&apos;s fields; ArcRadar writes the {label} file itself.
              The draft goes through the same checks as a hand-written rule and waits here until you
              send it to GitHub, edit it or reject it.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                loading={pending === "generate"}
                disabled={!aiReady || busy}
                onClick={generate}
              >
                <Sparkles aria-hidden className="size-4" />
                Generate draft
              </Button>
              <Button type="button" variant="ghost" onClick={() => setPanel("none")}>
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {items.length === 0 ? (
        <p className="text-sm text-muted">No {label} rules yet.</p>
      ) : (
        <ul className="space-y-3">
          {items.map((rule) => (
            <li key={rule.id}>
              <Card>
                <CardHeader className="space-y-1">
                  <CardTitle className="text-base">
                    {rule.name}{" "}
                    <span className="font-mono text-xs text-muted">#{rule.rule_key}</span>
                  </CardTitle>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge tone={STATUS_TONES[rule.status]} dot>
                      {SIEM_RULE_STATUS_LABELS[rule.status]}
                    </Badge>
                    {rule.status === "pushed" && rule.mode === "test" && (
                      <Badge tone="violet">Test mode · not alerting</Badge>
                    )}
                    {rule.changed_since_push && <Badge tone="orange">Changed since push</Badge>}
                    <Badge tone={rule.source === "ai" ? "violet" : "slate"}>
                      {SOURCE_LABELS[rule.source]}
                    </Badge>
                    <Badge tone={SEVERITY_TONES[rule.severity]}>
                      {rule.severity.charAt(0).toUpperCase() + rule.severity.slice(1)}
                    </Badge>
                    {ui.badges(rule)}
                    {rule.mitre_ids.map((id) => (
                      <Badge key={id} tone="blue">
                        {id}
                      </Badge>
                    ))}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  {editingId === rule.id ? (
                    <Form
                      rule={rule}
                      pending={pending === `edit-${rule.id}`}
                      submitLabel="Save changes"
                      serverErrors={fieldErrors}
                      catalog={catalog}
                      onSubmit={(payload) => saveEdit(rule, payload)}
                      onCancel={() => setEditingId(null)}
                    />
                  ) : (
                    <>
                      {rule.description && (
                        <p className="text-sm break-words text-muted">{rule.description}</p>
                      )}
                      {rule.source === "ai" && rule.ai_prompt && (
                        <p className="text-xs break-words text-muted">
                          Asked: &quot;{rule.ai_prompt}&quot;
                          {rule.ai_model ? ` · ${rule.ai_provider} / ${rule.ai_model}` : ""}
                        </p>
                      )}
                      <details open={rule.status === "draft"}>
                        <summary className="cursor-pointer text-sm font-medium">
                          {ui.fileLabel}
                        </summary>
                        <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 text-xs">
                          <code>{rule.file.content}</code>
                        </pre>
                      </details>
                      <BacktestPanel rule={rule} />
                      <p className="text-xs text-muted">
                        {rule.status === "pushed" && rule.pushed_at
                          ? `Pushed ${formatTime(rule.pushed_at)}`
                          : `Created ${formatTime(rule.created_at)}`}
                        {rule.created_by_name ? ` · ${rule.created_by_name}` : ""}
                        {rule.status === "rejected" && rule.reject_reason
                          ? ` · rejected: ${rule.reject_reason}`
                          : ""}
                      </p>
                      {rule.status === "pushed" && githubBlobBase && rule.github_path && (
                        <a
                          href={`${githubBlobBase}/${rule.github_path}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
                        >
                          <ExternalLink aria-hidden className="size-3.5" />
                          {rule.github_path}
                        </a>
                      )}

                      {rejectingId === rule.id ? (
                        <div className="space-y-2">
                          {rule.status === "pushed" && (
                            <p className="text-xs text-muted">
                              The rule is on GitHub and Splunk. Withdrawing deletes its file from
                              the repository; Splunk removes the rule when it next pulls (within
                              seconds) and its alerts stop. The rule stays here as rejected.
                            </p>
                          )}
                          <TextAreaField
                            id={`${siem}-reject-${rule.id}`}
                            label="Reason (optional)"
                            value={rejectReason}
                            onChange={(event) => setRejectReason(event.target.value)}
                            maxLength={500}
                            rows={2}
                          />
                          <div className="flex flex-wrap gap-2">
                            <Button
                              type="button"
                              variant="danger"
                              size="sm"
                              loading={pending === `reject-${rule.id}`}
                              disabled={busy || (rule.status === "pushed" && !githubReady)}
                              onClick={() => reject(rule)}
                            >
                              {rule.status === "pushed" ? "Confirm withdraw" : "Confirm reject"}
                            </Button>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => setRejectingId(null)}
                            >
                              <X aria-hidden className="size-4" />
                              Cancel
                            </Button>
                          </div>
                        </div>
                      ) : (
                        <div className="flex flex-wrap gap-2">
                          {rule.status !== "rejected" && (
                            <>
                              <Button
                                type="button"
                                size="sm"
                                loading={pending === `push-live-${rule.id}`}
                                disabled={busy || !githubReady}
                                onClick={() => push(rule, "live")}
                              >
                                <GitBranch aria-hidden className="size-4" />
                                {rule.status !== "pushed"
                                  ? "Send to GitHub"
                                  : rule.mode === "test"
                                    ? "Go live"
                                    : "Send update to GitHub"}
                              </Button>
                              {(rule.status !== "pushed" || rule.mode === "live") && (
                                <Button
                                  type="button"
                                  variant="secondary"
                                  size="sm"
                                  loading={pending === `push-test-${rule.id}`}
                                  disabled={busy || !githubReady}
                                  onClick={() => push(rule, "test")}
                                >
                                  <FlaskConical aria-hidden className="size-4" />
                                  Push as test
                                </Button>
                              )}
                              {rule.status === "pushed" && rule.mode === "test" && (
                                <Button
                                  type="button"
                                  variant="secondary"
                                  size="sm"
                                  loading={pending === `push-test-${rule.id}`}
                                  disabled={busy || !githubReady}
                                  onClick={() => push(rule, "test")}
                                >
                                  Send update (test)
                                </Button>
                              )}
                            </>
                          )}
                          <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            disabled={busy}
                            onClick={() => {
                              setFieldErrors({});
                              setEditingId(rule.id);
                            }}
                          >
                            <Pencil aria-hidden className="size-4" />
                            {rule.status === "rejected" ? "Edit and restore" : "Edit"}
                          </Button>
                          {rule.status !== "rejected" && (
                            <Button
                              type="button"
                              variant="danger"
                              size="sm"
                              disabled={busy}
                              onClick={() => {
                                setRejectReason("");
                                setRejectingId(rule.id);
                              }}
                            >
                              {rule.status === "pushed" ? "Withdraw" : "Reject"}
                            </Button>
                          )}
                          {rule.status !== "pushed" && (
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              aria-label={`Delete ${rule.name}`}
                              loading={pending === `delete-${rule.id}`}
                              disabled={busy}
                              onClick={() => remove(rule)}
                            >
                              <Trash2 aria-hidden className="size-4" />
                              Delete
                            </Button>
                          )}
                        </div>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
