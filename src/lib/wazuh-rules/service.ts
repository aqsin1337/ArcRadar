import "server-only";
import { defaultDeps, getAiAvailability, type AiDeps } from "@/lib/ai/service";
import { AiProviderError } from "@/lib/ai/types";
import { apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import { getEffectiveEnv } from "@/lib/secrets/service";
import {
  commitRepoFile,
  GITHUB_TIMEOUT_MS,
  getGithubRulesConfig,
  GithubError,
  type GithubRepoConfig,
} from "@/lib/github/contents";
import { logError, logWarn } from "@/lib/log";
import {
  WAZUH_RULE_ID_MAX,
  WAZUH_RULE_ID_MIN,
  wazuhRuleRepoPath,
  type WazuhRuleSource,
} from "./constants";
import {
  buildWazuhRulePrompt,
  WAZUH_RULE_MAX_OUTPUT_TOKENS,
  WAZUH_RULE_PROMPT_VERSION,
} from "./prompt";
import {
  deleteWazuhRuleRow,
  findWazuhRule,
  findWazuhRules,
  insertWazuhRule,
  nextWazuhRuleId,
  updateWazuhRuleRow,
} from "./repository";
import {
  aiWazuhRuleSchema,
  type AiWazuhRuleDraft,
  type CreateWazuhRuleInput,
  type UpdateWazuhRuleInput,
} from "./schema";
import type { WazuhRule } from "./types";

type RequestLike = { headers: Headers };

/** A malformed id (not an integer, or outside the range) is simply "not found". */
export const isWazuhRuleId = (id: number) =>
  Number.isInteger(id) && id >= WAZUH_RULE_ID_MIN && id <= WAZUH_RULE_ID_MAX;

export type WazuhRuleDeps = {
  ai: () => AiDeps | Promise<AiDeps>;
  githubConfig: () => GithubRepoConfig | null | Promise<GithubRepoConfig | null>;
  fetchImpl?: typeof fetch;
  githubTimeoutMs: number;
  audit: typeof writeAuditLog;
};

export function defaultWazuhRuleDeps(): WazuhRuleDeps {
  return {
    ai: defaultDeps,
    githubConfig: async () => getGithubRulesConfig(await getEffectiveEnv()),
    githubTimeoutMs: GITHUB_TIMEOUT_MS,
    audit: writeAuditLog,
  };
}

/** Whether pushing is possible at all, so the page can say so before someone presses the button. */
export const isGithubConfigured = async (deps = defaultWazuhRuleDeps()) =>
  (await deps.githubConfig()) !== null;

export const listWazuhRules = (supabase: AuthClient): Promise<WazuhRule[]> =>
  findWazuhRules(supabase);

async function requireRule(supabase: AuthClient, id: number): Promise<WazuhRule> {
  if (!isWazuhRuleId(id)) throw apiErrors.notFound("Wazuh rule not found.");
  const rule = await findWazuhRule(supabase, id);
  if (!rule) throw apiErrors.notFound("Wazuh rule not found.");
  return rule;
}

type Provenance = {
  source: WazuhRuleSource;
  ai_prompt?: string;
  ai_provider?: string;
  ai_model?: string;
};

async function createRule(
  auth: AuthContext,
  input: CreateWazuhRuleInput,
  provenance: Provenance,
): Promise<WazuhRule> {
  const id = input.id ?? (await nextWazuhRuleId(auth.supabase));
  return insertWazuhRule(auth.supabase, {
    id,
    name: input.name,
    description: input.description ?? null,
    level: input.level,
    parent_kind: input.parent_kind,
    parent_value: input.parent_value,
    conditions: input.conditions,
    mitre_ids: input.mitre_ids,
    frequency: input.frequency,
    timeframe: input.timeframe,
    same_fields: input.same_fields,
    ...provenance,
  });
}

export async function createWazuhRule(
  auth: AuthContext,
  input: CreateWazuhRuleInput,
  request: RequestLike,
  deps = defaultWazuhRuleDeps(),
): Promise<WazuhRule> {
  const rule = await createRule(auth, input, { source: "manual" });
  await deps.audit(
    {
      action: "wazuh_rule.created",
      userId: auth.user.id,
      entityType: "wazuh_rule",
      entityId: String(rule.id),
      metadata: { id: rule.id, name: rule.name, source: "manual" },
    },
    request,
  );
  return rule;
}

/**
 * Asks the active AI provider to draft a rule from a plain-language description. The answer is
 * validated by the same schema a person's form goes through (an answer that breaks any rule is
 * refused, never stored) and lands as a DRAFT: the AI never pushes anything, an administrator does.
 */
export async function generateWazuhRule(
  auth: AuthContext,
  prompt: string,
  request: RequestLike,
  deps = defaultWazuhRuleDeps(),
): Promise<WazuhRule> {
  const ai = await deps.ai();
  const availability = await getAiAvailability(auth.supabase);
  if (!availability.ready || !availability.active_provider) {
    throw apiErrors.unavailable(
      "No AI provider is configured. Set one up on the Integrations page, or write the rule by hand.",
    );
  }
  const provider = ai.registry.get(availability.active_provider);
  if (!provider) {
    throw apiErrors.unavailable(
      "The active AI provider is no longer configured. Check the Integrations page.",
    );
  }

  const { system, user } = buildWazuhRulePrompt(prompt);
  let result: Awaited<ReturnType<typeof provider.complete>>;
  try {
    result = await provider.complete({
      system,
      user,
      schema: aiWazuhRuleSchema,
      maxOutputTokens: WAZUH_RULE_MAX_OUTPUT_TOKENS,
      signal: AbortSignal.timeout(ai.timeoutMs),
      model: availability.active_model ?? undefined,
    });
  } catch (error) {
    if (error instanceof AiProviderError) {
      logWarn("wazuh_rule.ai_failed", {
        provider: availability.active_provider,
        reason: error.reason,
      });
      if (error.reason === "rate_limited") {
        throw apiErrors.rateLimited(error.retryAfterSeconds ?? undefined);
      }
    } else {
      logError("wazuh_rule.ai_error", error, { provider: availability.active_provider });
    }
    throw apiErrors.unavailable("The AI provider could not answer right now. Try again shortly.");
  }

  const parsed = aiWazuhRuleSchema.safeParse(result.data);
  if (!parsed.success) {
    logWarn("wazuh_rule.ai_invalid", {
      provider: availability.active_provider,
      issues: parsed.error.issues.length,
    });
    throw apiErrors.unavailable(
      "The AI's draft did not pass ArcRadar's checks. Try again, or word the request differently.",
    );
  }
  const draft: AiWazuhRuleDraft = parsed.data;

  const rule = await createRule(
    auth,
    { ...draft, mitre_ids: draft.mitre_ids },
    {
      source: "ai",
      ai_prompt: prompt,
      ai_provider: availability.active_provider,
      ai_model: result.model,
    },
  );
  await deps.audit(
    {
      action: "wazuh_rule.generated",
      userId: auth.user.id,
      entityType: "wazuh_rule",
      entityId: String(rule.id),
      metadata: {
        id: rule.id,
        name: rule.name,
        provider: availability.active_provider,
        model: result.model,
        prompt_version: WAZUH_RULE_PROMPT_VERSION,
      },
    },
    request,
  );
  return rule;
}

export async function getWazuhRule(supabase: AuthClient, id: number): Promise<WazuhRule> {
  return requireRule(supabase, id);
}

/**
 * Editing a rule that was already pushed marks it "changed since push" (the file on GitHub no longer
 * matches); editing a rejected rule brings it back to a draft.
 */
export async function updateWazuhRule(
  auth: AuthContext,
  id: number,
  input: UpdateWazuhRuleInput,
  request: RequestLike,
  deps = defaultWazuhRuleDeps(),
): Promise<WazuhRule> {
  const current = await requireRule(auth.supabase, id);
  const patch: Parameters<typeof updateWazuhRuleRow>[2] = { ...input };
  if (current.status === "pushed") patch.changed_since_push = true;
  if (current.status === "rejected") {
    patch.status = "draft";
    patch.rejected_at = null;
    patch.reject_reason = null;
  }
  const row = await updateWazuhRuleRow(auth.supabase, id, patch);
  if (!row) throw apiErrors.notFound("Wazuh rule not found.");
  await deps.audit(
    {
      action: "wazuh_rule.updated",
      userId: auth.user.id,
      entityType: "wazuh_rule",
      entityId: String(id),
      metadata: { name: row.name, fields: Object.keys(input) },
    },
    request,
  );
  return row;
}

export async function rejectWazuhRule(
  auth: AuthContext,
  id: number,
  reason: string | null,
  request: RequestLike,
  deps = defaultWazuhRuleDeps(),
): Promise<WazuhRule> {
  const current = await requireRule(auth.supabase, id);
  if (current.status !== "draft") {
    throw apiErrors.conflict(
      current.status === "pushed"
        ? "This rule is already on GitHub, so it cannot be rejected."
        : "This rule is already rejected.",
    );
  }
  const row = await updateWazuhRuleRow(auth.supabase, id, {
    status: "rejected",
    rejected_at: new Date().toISOString(),
    reject_reason: reason,
  });
  if (!row) throw apiErrors.notFound("Wazuh rule not found.");
  await deps.audit(
    {
      action: "wazuh_rule.rejected",
      userId: auth.user.id,
      entityType: "wazuh_rule",
      entityId: String(id),
      metadata: { name: row.name, has_reason: reason !== null },
    },
    request,
  );
  return row;
}

/**
 * Commits the rule's generated XML to the rules repository. ArcRadar writes only that file; the
 * Manager pulls the repository itself, so nothing here reaches into the Wazuh host.
 */
export async function pushWazuhRule(
  auth: AuthContext,
  id: number,
  request: RequestLike,
  deps = defaultWazuhRuleDeps(),
): Promise<WazuhRule> {
  const current = await requireRule(auth.supabase, id);
  if (current.status === "rejected") {
    throw apiErrors.conflict("This rule was rejected. Edit it to bring it back to a draft first.");
  }
  const config = await deps.githubConfig();
  if (!config) {
    throw apiErrors.unavailable(
      "GitHub is not configured. An administrator can save a GitHub token and the rules repository on the API keys page.",
    );
  }

  const path = wazuhRuleRepoPath(current.id);
  let commit: Awaited<ReturnType<typeof commitRepoFile>>;
  try {
    commit = await commitRepoFile({
      config,
      path,
      content: current.xml,
      message:
        `${current.status === "pushed" ? "Update" : "Add"} rule ${current.id}: ${current.name}`.slice(
          0,
          200,
        ),
      signal: AbortSignal.timeout(deps.githubTimeoutMs),
      fetchImpl: deps.fetchImpl,
    });
  } catch (error) {
    if (!(error instanceof GithubError)) {
      logError("wazuh_rule.push_error", error, { rule: id });
      throw apiErrors.unavailable("GitHub could not be reached right now. Try again shortly.");
    }
    logWarn("wazuh_rule.push_failed", { rule: id, reason: error.reason });
    if (error.reason === "conflict") throw apiErrors.conflict(error.message);
    if (error.reason === "rate_limited") throw apiErrors.rateLimited();
    throw apiErrors.unavailable(
      error.reason === "auth"
        ? "GitHub refused the token. Check that it can write to the rules repository."
        : error.reason === "not_found"
          ? "The rules repository or branch was not found. Check GITHUB_RULES_REPO."
          : "GitHub could not be reached right now. Try again shortly.",
    );
  }

  const row = await updateWazuhRuleRow(auth.supabase, id, {
    status: "pushed",
    github_path: path,
    github_commit: commit.commitSha ?? current.github_commit,
    pushed_at: new Date().toISOString(),
    pushed_by: auth.user.id,
    changed_since_push: false,
  });
  if (!row) throw apiErrors.notFound("Wazuh rule not found.");
  await deps.audit(
    {
      action: "wazuh_rule.pushed",
      userId: auth.user.id,
      entityType: "wazuh_rule",
      entityId: String(id),
      metadata: {
        name: row.name,
        path,
        commit: commit.commitSha,
        unchanged: commit.unchanged,
        repository: `${config.owner}/${config.repo}`,
        branch: config.branch,
      },
    },
    request,
  );
  return row;
}

export async function deleteWazuhRule(
  auth: AuthContext,
  id: number,
  request: RequestLike,
  deps = defaultWazuhRuleDeps(),
): Promise<void> {
  const current = await requireRule(auth.supabase, id);
  if (current.status === "pushed") {
    throw apiErrors.conflict("This rule is on GitHub, so it cannot be deleted from here.");
  }
  const removed = await deleteWazuhRuleRow(auth.supabase, id);
  if (!removed) throw apiErrors.notFound("Wazuh rule not found.");
  await deps.audit(
    {
      action: "wazuh_rule.deleted",
      userId: auth.user.id,
      entityType: "wazuh_rule",
      entityId: String(id),
      metadata: { name: removed.name },
    },
    request,
  );
}
