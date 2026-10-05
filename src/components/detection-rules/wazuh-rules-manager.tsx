"use client";

import { ExternalLink, GitBranch, Pencil, Plus, Sparkles, Trash2, X } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Badge, type Tone } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, TextField } from "@/components/ui/input";
import { Select, SelectField } from "@/components/ui/select";
import { TextAreaField } from "@/components/ui/textarea";
import { apiFetch } from "@/lib/api/client";
import { fieldErrorsFromZod } from "@/lib/validation/form";
import {
  WAZUH_CONDITION_OP_LABELS,
  WAZUH_CONDITION_OPS,
  WAZUH_FIELD_SUGGESTIONS,
  WAZUH_GROUP_SUGGESTIONS,
  WAZUH_RULE_SOURCE_LABELS,
  WAZUH_RULE_STATUS_LABELS,
  WAZUH_SAME_FIELD_SUGGESTIONS,
  type WazuhRuleStatus,
} from "@/lib/wazuh-rules/constants";
import { createWazuhRuleSchema, updateWazuhRuleSchema } from "@/lib/wazuh-rules/schema";
import type { WazuhRule, WazuhRuleCondition } from "@/lib/wazuh-rules/types";

const STATUS_TONES: Record<WazuhRuleStatus, Tone> = {
  draft: "amber",
  pushed: "green",
  rejected: "slate",
};

const LEVELS = Array.from({ length: 15 }, (_, index) => ({
  value: String(index + 1),
  label: String(index + 1),
}));

type FormState = {
  id: string;
  name: string;
  description: string;
  level: string;
  parent_kind: "group" | "sid";
  parent_value: string;
  conditions: WazuhRuleCondition[];
  mitre: string;
  repeat: boolean;
  frequency: string;
  /** Minutes in the form; the rule stores seconds. */
  minutes: string;
  sameFields: string;
};

const emptyCondition = (): WazuhRuleCondition => ({
  field: "win.eventdata.commandLine",
  op: "contains",
  value: "",
});

const emptyForm = (): FormState => ({
  id: "",
  name: "",
  description: "",
  level: "8",
  parent_kind: "group",
  parent_value: "windows",
  conditions: [emptyCondition()],
  mitre: "",
  repeat: false,
  frequency: "5",
  minutes: "5",
  sameFields: "",
});

const formFromRule = (rule: WazuhRule): FormState => ({
  id: String(rule.id),
  name: rule.name,
  description: rule.description ?? "",
  level: String(rule.level),
  parent_kind: rule.parent_kind,
  parent_value: rule.parent_value,
  conditions: rule.conditions.map((condition) => ({ ...condition })),
  mitre: rule.mitre_ids.join(", "),
  repeat: rule.frequency !== null,
  frequency: String(rule.frequency ?? 5),
  minutes: rule.timeframe === null ? "5" : String(rule.timeframe / 60),
  sameFields: rule.same_fields.join(", "),
});

const mitreList = (text: string) =>
  text
    .split(/[\s,;]+/)
    .map((id) => id.trim())
    .filter(Boolean);

/** Errors for `conditions.N.field` and so on, shown together under the condition builder. */
const conditionErrors = (errors: Record<string, string>) =>
  Object.entries(errors)
    .filter(([path]) => path === "conditions" || path.startsWith("conditions."))
    .map(([, message]) => message);

function RuleForm({
  initial,
  editing,
  pending,
  submitLabel,
  serverErrors,
  onSubmit,
  onCancel,
}: {
  initial: FormState;
  editing: boolean;
  pending: boolean;
  submitLabel: string;
  serverErrors: Record<string, string>;
  onSubmit: (payload: Record<string, unknown>) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState(initial);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const shown = { ...serverErrors, ...errors };
  const set = (patch: Partial<FormState>) => setForm((current) => ({ ...current, ...patch }));
  const idPrefix = editing ? "wr-edit" : "wr-new";

  function updateCondition(index: number, patch: Partial<WazuhRuleCondition>) {
    set({
      conditions: form.conditions.map((condition, i) =>
        i === index ? { ...condition, ...patch } : condition,
      ),
    });
  }

  function submit() {
    const base = {
      name: form.name,
      description: form.description,
      level: Number(form.level),
      parent_kind: form.parent_kind,
      parent_value: form.parent_value,
      conditions: form.conditions,
      mitre_ids: mitreList(form.mitre),
      frequency: form.repeat ? Number(form.frequency) : null,
      timeframe: form.repeat ? Math.round(Number(form.minutes) * 60) : null,
      same_fields: form.repeat ? mitreList(form.sameFields) : [],
    };
    const payload = editing
      ? base
      : { ...base, ...(form.id.trim() === "" ? {} : { id: Number(form.id) }) };
    const parsed = (editing ? updateWazuhRuleSchema : createWazuhRuleSchema).safeParse(payload);
    if (!parsed.success) {
      setErrors(fieldErrorsFromZod(parsed.error));
      return;
    }
    setErrors({});
    onSubmit(payload);
  }

  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-[180px_1fr_110px]">
        {!editing ? (
          <TextField
            id={`${idPrefix}-id`}
            label="Rule id (optional)"
            hint="Empty = next free id"
            inputMode="numeric"
            value={form.id}
            onChange={(event) => set({ id: event.target.value })}
            error={shown.id}
          />
        ) : (
          <TextField id={`${idPrefix}-id`} label="Rule id" value={form.id} disabled readOnly />
        )}
        <TextField
          id={`${idPrefix}-name`}
          label="Name"
          value={form.name}
          onChange={(event) => set({ name: event.target.value })}
          maxLength={200}
          error={shown.name}
        />
        <SelectField
          id={`${idPrefix}-level`}
          label="Level"
          value={form.level}
          onChange={(event) => set({ level: event.target.value })}
          options={LEVELS}
          error={shown.level}
        />
      </div>

      <TextAreaField
        id={`${idPrefix}-description`}
        label="Description (optional)"
        value={form.description}
        onChange={(event) => set({ description: event.target.value })}
        maxLength={2000}
        rows={2}
        error={shown.description}
      />

      <div className="grid gap-3 sm:grid-cols-[180px_1fr]">
        <SelectField
          id={`${idPrefix}-parent-kind`}
          label="Attach to"
          value={form.parent_kind}
          onChange={(event) => set({ parent_kind: event.target.value as "group" | "sid" })}
          options={[
            { value: "group", label: "Rule group" },
            { value: "sid", label: "Parent rule id" },
          ]}
        />
        <div>
          <TextField
            id={`${idPrefix}-parent-value`}
            label={form.parent_kind === "group" ? "Group" : "Parent rule id"}
            list={`${idPrefix}-groups`}
            value={form.parent_value}
            onChange={(event) => set({ parent_value: event.target.value })}
            error={shown.parent_value}
          />
          <datalist id={`${idPrefix}-groups`}>
            {WAZUH_GROUP_SUGGESTIONS.map((group) => (
              <option key={group} value={group} />
            ))}
          </datalist>
        </div>
      </div>

      <div className="space-y-2">
        <p className="text-sm font-medium">Conditions (every one must match)</p>
        <datalist id={`${idPrefix}-fields`}>
          {WAZUH_FIELD_SUGGESTIONS.map((field) => (
            <option key={field} value={field} />
          ))}
        </datalist>
        {form.conditions.map((condition, index) => (
          <div key={index} className="flex flex-wrap items-center gap-2">
            <Input
              aria-label={`Condition ${index + 1} field`}
              list={`${idPrefix}-fields`}
              value={condition.field}
              onChange={(event) => updateCondition(index, { field: event.target.value })}
              className="min-w-56 flex-1"
            />
            <Select
              aria-label={`Condition ${index + 1} comparison`}
              value={condition.op}
              onChange={(event) =>
                updateCondition(index, { op: event.target.value as WazuhRuleCondition["op"] })
              }
              className="w-auto min-w-36"
            >
              {WAZUH_CONDITION_OPS.map((op) => (
                <option key={op} value={op}>
                  {WAZUH_CONDITION_OP_LABELS[op]}
                </option>
              ))}
            </Select>
            <Input
              aria-label={`Condition ${index + 1} value`}
              value={condition.value}
              onChange={(event) => updateCondition(index, { value: event.target.value })}
              maxLength={200}
              className="min-w-40 flex-[2]"
            />
            {(form.conditions.length > 1 || form.repeat) && (
              <button
                type="button"
                aria-label={`Remove condition ${index + 1}`}
                className="shrink-0 rounded-md p-2 text-muted hover:bg-surface-2 hover:text-foreground"
                onClick={() => set({ conditions: form.conditions.filter((_, i) => i !== index) })}
              >
                <Trash2 aria-hidden className="size-4" />
              </button>
            )}
          </div>
        ))}
        {conditionErrors(shown).map((message, index) => (
          <p key={index} className="text-sm text-tone-red-fg">
            {message}
          </p>
        ))}
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={() => set({ conditions: [...form.conditions, emptyCondition()] })}
        >
          <Plus aria-hidden className="size-4" />
          Add condition
        </Button>
      </div>

      <div className="space-y-2 rounded-lg border border-border p-3">
        <label className="flex items-center gap-2 text-sm font-medium">
          <input
            type="checkbox"
            checked={form.repeat}
            onChange={(event) => set({ repeat: event.target.checked })}
            className="size-4 rounded border-input-border"
          />
          Only when it repeats
        </label>
        {form.repeat && (
          <>
            <p className="text-xs text-muted">
              The group or rule above is the single event that is counted (for failed Windows
              logons: group authentication_failed). The rule fires when it happened this many times
              inside the window. Conditions are then optional.
            </p>
            <div className="grid gap-3 sm:grid-cols-[140px_180px_1fr]">
              <TextField
                id={`${idPrefix}-frequency`}
                label="Times"
                inputMode="numeric"
                value={form.frequency}
                onChange={(event) => set({ frequency: event.target.value })}
                error={shown.frequency}
              />
              <TextField
                id={`${idPrefix}-minutes`}
                label="Within (minutes)"
                inputMode="decimal"
                value={form.minutes}
                onChange={(event) => set({ minutes: event.target.value })}
                error={shown.timeframe}
              />
              <TextField
                id={`${idPrefix}-same`}
                label="Same value in (optional)"
                hint="For example win.eventdata.ipAddress: counts per source"
                list={`${idPrefix}-same-fields`}
                value={form.sameFields}
                onChange={(event) => set({ sameFields: event.target.value })}
                error={shown.same_fields}
              />
              <datalist id={`${idPrefix}-same-fields`}>
                {WAZUH_SAME_FIELD_SUGGESTIONS.map((field) => (
                  <option key={field} value={field} />
                ))}
              </datalist>
            </div>
          </>
        )}
      </div>

      <TextField
        id={`${idPrefix}-mitre`}
        label="MITRE ATT&CK techniques (optional)"
        hint="Comma separated, for example T1562.001, T1059.001"
        value={form.mitre}
        onChange={(event) => set({ mitre: event.target.value })}
        error={shown.mitre_ids}
      />

      <div className="flex flex-wrap gap-2">
        <Button type="button" loading={pending} onClick={submit}>
          {submitLabel}
        </Button>
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

const formatTime = (iso: string) => `${iso.slice(0, 16).replace("T", " ")} UTC`;

/**
 * The Wazuh rule workflow: a person writes a rule (or asks the AI to draft one), reads the XML it
 * becomes, and then sends it to GitHub, edits it, or rejects it. Nothing here touches the Wazuh host:
 * the Manager pulls the repository on its own. The server holds the truth; every action waits for its
 * response and then replaces the local copy of that rule.
 */
export function WazuhRulesManager({
  rules,
  githubBlobBase,
  githubReady,
  aiReady,
}: {
  rules: WazuhRule[];
  /** `https://github.com/owner/name/blob/branch` when configured, else null. */
  githubBlobBase: string | null;
  githubReady: boolean;
  aiReady: boolean;
}) {
  const [items, setItems] = useState(rules);
  const [panel, setPanel] = useState<"none" | "manual" | "ai">("none");
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiError, setAiError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [rejectingId, setRejectingId] = useState<number | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string } | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});

  const replace = (rule: WazuhRule) =>
    setItems((current) => current.map((item) => (item.id === rule.id ? rule : item)));

  async function create(payload: Record<string, unknown>) {
    setPending("create");
    setMessage(null);
    const result = await apiFetch<WazuhRule>("/api/wazuh-rules", { body: payload });
    setPending(null);
    if (!result.ok) {
      setFieldErrors(result.fieldErrors);
      setMessage({ tone: "error", text: result.message });
      return;
    }
    setFieldErrors({});
    setItems((current) => [result.data, ...current]);
    setPanel("none");
    setMessage({ tone: "success", text: `Rule ${result.data.id} was saved as a draft.` });
  }

  async function generate() {
    setPending("generate");
    setAiError(null);
    setMessage(null);
    const result = await apiFetch<WazuhRule>("/api/wazuh-rules/generate", {
      body: { prompt: aiPrompt },
    });
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
      text: `The AI drafted rule ${result.data.id}. Read the XML below, then send it to GitHub, edit it or reject it.`,
    });
  }

  async function saveEdit(rule: WazuhRule, payload: Record<string, unknown>) {
    setPending(`edit-${rule.id}`);
    setMessage(null);
    const result = await apiFetch<WazuhRule>(`/api/wazuh-rules/${rule.id}`, {
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

  async function push(rule: WazuhRule) {
    setPending(`push-${rule.id}`);
    setMessage(null);
    const result = await apiFetch<WazuhRule>(`/api/wazuh-rules/${rule.id}/push`, {
      method: "POST",
    });
    setPending(null);
    if (!result.ok) {
      setMessage({ tone: "error", text: result.message });
      return;
    }
    replace(result.data);
    setMessage({ tone: "success", text: `Rule ${rule.id} was committed to GitHub.` });
  }

  async function reject(rule: WazuhRule) {
    setPending(`reject-${rule.id}`);
    setMessage(null);
    const result = await apiFetch<WazuhRule>(`/api/wazuh-rules/${rule.id}/reject`, {
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

  async function remove(rule: WazuhRule) {
    setPending(`delete-${rule.id}`);
    setMessage(null);
    const result = await apiFetch(`/api/wazuh-rules/${rule.id}`, { method: "DELETE" });
    setPending(null);
    if (!result.ok) {
      setMessage({ tone: "error", text: result.message });
      return;
    }
    setItems((current) => current.filter((item) => item.id !== rule.id));
  }

  const busy = pending !== null;

  return (
    <div className="space-y-4">
      {message && <Alert tone={message.tone}>{message.text}</Alert>}
      {!githubReady && (
        <Alert tone="warning" title="GitHub is not connected">
          Rules can be drafted, edited and rejected, but &quot;Send to GitHub&quot; stays
          unavailable until the server has GITHUB_TOKEN and GITHUB_RULES_REPO (see
          docs/WAZUH_RULES.md).
        </Alert>
      )}

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
            <CardTitle>New rule</CardTitle>
          </CardHeader>
          <CardContent>
            <RuleForm
              initial={emptyForm()}
              editing={false}
              pending={pending === "create"}
              submitLabel="Save as draft"
              serverErrors={fieldErrors}
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
              id="wr-ai-prompt"
              label="What should the rule detect?"
              hint="For example: PowerShell trying to turn off Windows Defender real-time protection."
              value={aiPrompt}
              onChange={(event) => setAiPrompt(event.target.value)}
              maxLength={1000}
              rows={3}
              error={aiError ?? undefined}
            />
            <p className="text-xs text-muted">
              The AI only drafts. The draft goes through the same checks as a hand-written rule and
              waits here until you send it to GitHub, edit it or reject it.
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
        <p className="text-sm text-muted">No Wazuh rules yet.</p>
      ) : (
        <ul className="space-y-3">
          {items.map((rule) => (
            <li key={rule.id}>
              <Card>
                <CardHeader className="space-y-1">
                  <CardTitle className="text-base">
                    {rule.name} <span className="font-mono text-xs text-muted">#{rule.id}</span>
                  </CardTitle>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge tone={STATUS_TONES[rule.status]} dot>
                      {WAZUH_RULE_STATUS_LABELS[rule.status]}
                    </Badge>
                    {rule.changed_since_push && <Badge tone="orange">Changed since push</Badge>}
                    <Badge tone={rule.source === "ai" ? "violet" : "slate"}>
                      {WAZUH_RULE_SOURCE_LABELS[rule.source]}
                    </Badge>
                    <Badge tone="slate">Level {rule.level}</Badge>
                    {rule.frequency !== null && rule.timeframe !== null && (
                      <Badge tone="orange">
                        {rule.frequency}× in{" "}
                        {rule.timeframe % 60 === 0
                          ? `${rule.timeframe / 60} min`
                          : `${rule.timeframe} s`}
                        {rule.same_fields.length > 0
                          ? " · same " + rule.same_fields.join(", ")
                          : ""}
                      </Badge>
                    )}
                    {rule.mitre_ids.map((id) => (
                      <Badge key={id} tone="blue">
                        {id}
                      </Badge>
                    ))}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  {editingId === rule.id ? (
                    <RuleForm
                      initial={formFromRule(rule)}
                      editing
                      pending={pending === `edit-${rule.id}`}
                      submitLabel="Save changes"
                      serverErrors={fieldErrors}
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
                          Wazuh rule XML
                        </summary>
                        <pre className="mt-2 overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 text-xs">
                          <code>{rule.xml}</code>
                        </pre>
                      </details>
                      <p className="text-xs text-muted">
                        {rule.triggers > 0
                          ? `Triggered ${rule.triggers} time${rule.triggers === 1 ? "" : "s"}${
                              rule.last_triggered
                                ? ` · last ${formatTime(rule.last_triggered)}`
                                : ""
                            }`
                          : "Not triggered yet"}
                        {rule.status === "pushed" && rule.pushed_at
                          ? ` · pushed ${formatTime(rule.pushed_at)}`
                          : ""}
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
                            id={`wr-reject-${rule.id}`}
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
