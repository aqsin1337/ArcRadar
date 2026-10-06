"use client";

import { ExternalLink, GitBranch, Pencil, Plus, Sparkles, Trash2, X } from "lucide-react";
import { useState, type ComponentType, type ReactNode } from "react";
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
  type SiemRuleSeverity,
  type SiemRuleStatus,
} from "@/lib/siem-rules/constants";
import { SPLUNK_SCHEDULES, type SplunkSpec } from "@/lib/siem-rules/dialects/splunk";
import type { FieldCatalog } from "@/lib/siem-rules/catalog";
import type { SiemRule } from "@/lib/siem-rules/types";
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

  async function push(rule: SiemRule) {
    setPending(`push-${rule.id}`);
    setMessage(null);
    const result = await apiFetch<SiemRule>(`${base}/${rule.id}/push`, { method: "POST" });
    setPending(null);
    if (!result.ok) {
      setMessage({ tone: "error", text: result.message });
      return;
    }
    replace(result.data);
    setMessage({ tone: "success", text: `Rule ${rule.rule_key} was committed to GitHub.` });
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
    replace(result.data);
    setRejectingId(null);
    setRejectReason("");
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
                              disabled={busy}
                              onClick={() => reject(rule)}
                            >
                              Confirm reject
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
                            <Button
                              type="button"
                              size="sm"
                              loading={pending === `push-${rule.id}`}
                              disabled={busy || !githubReady}
                              onClick={() => push(rule)}
                            >
                              <GitBranch aria-hidden className="size-4" />
                              {rule.status === "pushed"
                                ? "Send update to GitHub"
                                : "Send to GitHub"}
                            </Button>
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
                          {rule.status === "draft" && (
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
                              Reject
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
