import "server-only";
import { defaultDeps, getAiAvailability, type AiDeps } from "@/lib/ai/service";
import { AiProviderError } from "@/lib/ai/types";
import { apiErrors } from "@/lib/api/errors";
import { writeAuditLog } from "@/lib/audit/write";
import type { AuthClient, AuthContext } from "@/lib/auth/context";
import {
  commitRepoFile,
  deleteRepoFile,
  GITHUB_TIMEOUT_MS,
  getGithubRulesConfig,
  GithubError,
  type GithubRepoConfig,
} from "@/lib/github/contents";
import { logError, logWarn } from "@/lib/log";
import { getEffectiveEnv } from "@/lib/secrets/service";
import { SIEM_LABELS, type SiemId, type SiemRuleMode } from "./constants";
import { summarizeCatalog } from "./catalog";
import { findCatalog } from "./catalog-repository";
import { getDialect } from "./dialects";
import {
  deleteSiemRuleRow,
  findSiemRule,
  findSiemRules,
  insertSiemRule,
  nextRuleKey,
  updateSiemRuleRow,
} from "./repository";
import { aiSiemRuleSchema, type CreateSiemRuleInput, type UpdateSiemRuleInput } from "./schema";
import type { SiemRule } from "./types";

type RequestLike = { headers: Headers };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type SiemRuleDeps = {
  ai: () => AiDeps | Promise<AiDeps>;
  githubConfig: () => GithubRepoConfig | null | Promise<GithubRepoConfig | null>;
  fetchImpl?: typeof fetch;
  githubTimeoutMs: number;
  audit: typeof writeAuditLog;
};

export function defaultSiemRuleDeps(): SiemRuleDeps {
  return {
    ai: defaultDeps,
    githubConfig: async () => getGithubRulesConfig(await getEffectiveEnv()),
    githubTimeoutMs: GITHUB_TIMEOUT_MS,
    audit: writeAuditLog,
  };
}

/** What a failed GitHub call means for the caller. Never carries the token or GitHub's own text. */
function githubFailure(error: unknown, siem: SiemId, id: string, what: string): never {
  if (!(error instanceof GithubError)) {
    logError(`siem_rule.${what}_error`, error, { siem, rule: id });
    throw apiErrors.unavailable("GitHub could not be reached right now. Try again shortly.");
  }
  logWarn(`siem_rule.${what}_failed`, { siem, rule: id, reason: error.reason });
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

const notFound = (siem: SiemId) => apiErrors.notFound(`${SIEM_LABELS[siem]} rule not found.`);

export const listSiemRules = (supabase: AuthClient, siem: SiemId): Promise<SiemRule[]> =>
  findSiemRules(supabase, siem);

/** A malformed id is simply "not found". */
async function requireRule(supabase: AuthClient, siem: SiemId, id: string): Promise<SiemRule> {
  if (!UUID.test(id)) throw notFound(siem);
  const rule = await findSiemRule(supabase, siem, id);
  if (!rule) throw notFound(siem);
  return rule;
}

export const getSiemRule = requireRule;

type Provenance = {
  source: "manual" | "ai";
  ai_prompt?: string;
  ai_provider?: string;
  ai_model?: string;
};

async function createRule(
  auth: AuthContext,
  siem: SiemId,
  input: CreateSiemRuleInput,
  provenance: Provenance,
): Promise<SiemRule> {
  const rule_key = input.rule_key ?? (await nextRuleKey(auth.supabase, siem));
  return insertSiemRule(auth.supabase, {
    siem,
    rule_key,
    name: input.name,
    description: input.description ?? null,
    severity: input.severity,
    spec: input.spec,
    mitre_ids: input.mitre_ids,
    ...provenance,
  });
}

export async function createSiemRule(
  auth: AuthContext,
  siem: SiemId,
  input: CreateSiemRuleInput,
  request: RequestLike,
  deps = defaultSiemRuleDeps(),
): Promise<SiemRule> {
  const rule = await createRule(auth, siem, input, { source: "manual" });
  await deps.audit(
    {
      action: "siem_rule.created",
      userId: auth.user.id,
      entityType: "siem_rule",
      entityId: rule.id,
      metadata: { siem, rule_key: rule.rule_key, name: rule.name, source: "manual" },
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
export async function generateSiemRule(
  auth: AuthContext,
  siem: SiemId,
  prompt: string,
  request: RequestLike,
  deps = defaultSiemRuleDeps(),
): Promise<SiemRule> {
  const dialect = getDialect(siem);
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

  const schema = aiSiemRuleSchema(dialect);
  // The AI is told which fields the SIEM really has, when it has reported them.
  const catalog = await findCatalog(auth.supabase, siem);
  const { system, user } = dialect.prompt.build(
    prompt,
    catalog.sources.length > 0 ? summarizeCatalog(catalog) : undefined,
  );
  let result: Awaited<ReturnType<typeof provider.complete>>;
  try {
    result = await provider.complete({
      system,
      user,
      schema,
      maxOutputTokens: dialect.prompt.maxOutputTokens,
      signal: AbortSignal.timeout(ai.timeoutMs),
      model: availability.active_model ?? undefined,
    });
  } catch (error) {
    if (error instanceof AiProviderError) {
      logWarn("siem_rule.ai_failed", {
        siem,
        provider: availability.active_provider,
        reason: error.reason,
      });
      if (error.reason === "rate_limited") {
        throw apiErrors.rateLimited(error.retryAfterSeconds ?? undefined);
      }
    } else {
      logError("siem_rule.ai_error", error, { siem, provider: availability.active_provider });
    }
    throw apiErrors.unavailable("The AI provider could not answer right now. Try again shortly.");
  }

  const parsed = schema.safeParse(result.data);
  if (!parsed.success) {
    logWarn("siem_rule.ai_invalid", {
      siem,
      provider: availability.active_provider,
      issues: parsed.error.issues.length,
    });
    throw apiErrors.unavailable(
      "The AI's draft did not pass ArcRadar's checks. Try again, or word the request differently.",
    );
  }

  const rule = await createRule(auth, siem, parsed.data as CreateSiemRuleInput, {
    source: "ai",
    ai_prompt: prompt,
    ai_provider: availability.active_provider,
    ai_model: result.model,
  });
  await deps.audit(
    {
      action: "siem_rule.generated",
      userId: auth.user.id,
      entityType: "siem_rule",
      entityId: rule.id,
      metadata: {
        siem,
        rule_key: rule.rule_key,
        name: rule.name,
        provider: availability.active_provider,
        model: result.model,
        prompt_version: dialect.prompt.version,
      },
    },
    request,
  );
  return rule;
}

/**
 * Editing a rule that was already pushed marks it "changed since push" (the file on GitHub no longer
 * matches); editing a rejected rule brings it back to a draft.
 */
export async function updateSiemRule(
  auth: AuthContext,
  siem: SiemId,
  id: string,
  input: UpdateSiemRuleInput,
  request: RequestLike,
  deps = defaultSiemRuleDeps(),
): Promise<SiemRule> {
  const current = await requireRule(auth.supabase, siem, id);
  const patch: Parameters<typeof updateSiemRuleRow>[3] = { ...input };
  if (current.status === "pushed") patch.changed_since_push = true;
  if (current.status === "rejected") {
    patch.status = "draft";
    patch.rejected_at = null;
    patch.reject_reason = null;
  }
  const row = await updateSiemRuleRow(auth.supabase, siem, id, patch);
  if (!row) throw notFound(siem);
  await deps.audit(
    {
      action: "siem_rule.updated",
      userId: auth.user.id,
      entityType: "siem_rule",
      entityId: id,
      metadata: { siem, name: row.name, fields: Object.keys(input) },
    },
    request,
  );
  return row;
}

export async function rejectSiemRule(
  auth: AuthContext,
  siem: SiemId,
  id: string,
  reason: string | null,
  request: RequestLike,
  deps = defaultSiemRuleDeps(),
): Promise<SiemRule> {
  const current = await requireRule(auth.supabase, siem, id);
  if (current.status === "rejected") throw apiErrors.conflict("This rule is already rejected.");

  // A rule that is on GitHub is WITHDRAWN: its file is deleted from the repository, so the SIEM host drops the
  // rule the next time it pulls (within seconds, it is woken by the change). Nothing here touches the SIEM.
  let withdrawal: {
    path: string;
    commit: string | null;
    alreadyGone: boolean;
    repository: string;
  } | null = null;
  if (current.status === "pushed") {
    const config = await deps.githubConfig();
    if (!config) {
      throw apiErrors.unavailable(
        "GitHub is not configured, so the rule's file cannot be removed from the repository. An administrator can save a GitHub token and the rules repository on the API keys page.",
      );
    }
    const path = current.github_path ?? current.file.path;
    try {
      const removed = await deleteRepoFile({
        config,
        path,
        message: `Withdraw ${SIEM_LABELS[siem]} rule ${current.rule_key}: ${current.name}`.slice(
          0,
          200,
        ),
        signal: AbortSignal.timeout(deps.githubTimeoutMs),
        fetchImpl: deps.fetchImpl,
      });
      withdrawal = {
        path,
        commit: removed.commitSha,
        alreadyGone: removed.alreadyGone,
        repository: `${config.owner}/${config.repo}`,
      };
    } catch (error) {
      githubFailure(error, siem, id, "withdraw");
    }
  }

  const row = await updateSiemRuleRow(auth.supabase, siem, id, {
    status: "rejected",
    rejected_at: new Date().toISOString(),
    reject_reason: reason,
    ...(withdrawal ? { github_path: null, changed_since_push: false } : {}),
  });
  if (!row) throw notFound(siem);
  await deps.audit(
    {
      action: "siem_rule.rejected",
      userId: auth.user.id,
      entityType: "siem_rule",
      entityId: id,
      metadata: {
        siem,
        name: row.name,
        has_reason: reason !== null,
        ...(withdrawal
          ? {
              withdrawn: true,
              path: withdrawal.path,
              commit: withdrawal.commit,
              already_gone: withdrawal.alreadyGone,
              repository: withdrawal.repository,
            }
          : {}),
      },
    },
    request,
  );
  return row;
}

/**
 * Commits the rule's generated file to the rules repository. ArcRadar writes only that file; the
 * SIEM host pulls the repository itself, so nothing here reaches into the SIEM.
 */
/**
 * Commits the rule's generated file in the given mode. Test mode: the file is loaded by the SIEM but never
 * runs on a schedule and has no action, so it can be backtested without ever alerting; live: the rule as
 * written. Pushing again in the other mode replaces the file.
 */
export async function pushSiemRule(
  auth: AuthContext,
  siem: SiemId,
  id: string,
  mode: SiemRuleMode,
  request: RequestLike,
  deps = defaultSiemRuleDeps(),
): Promise<SiemRule> {
  const current = await requireRule(auth.supabase, siem, id);
  if (current.status === "rejected") {
    throw apiErrors.conflict("This rule was rejected. Edit it to bring it back to a draft first.");
  }
  const config = await deps.githubConfig();
  if (!config) {
    throw apiErrors.unavailable(
      "GitHub is not configured. An administrator can save a GitHub token and the rules repository on the API keys page.",
    );
  }

  // The file for the requested mode, which may differ from the mode the rule was last pushed in.
  const { path, content } = getDialect(siem).render({ ...current, mode });
  let commit: Awaited<ReturnType<typeof commitRepoFile>>;
  try {
    commit = await commitRepoFile({
      config,
      path,
      content,
      message:
        `${current.status === "pushed" ? "Update" : "Add"} ${SIEM_LABELS[siem]} rule ${current.rule_key}${mode === "test" ? " (test mode)" : ""}: ${current.name}`.slice(
          0,
          200,
        ),
      signal: AbortSignal.timeout(deps.githubTimeoutMs),
      fetchImpl: deps.fetchImpl,
    });
  } catch (error) {
    githubFailure(error, siem, id, "push");
  }

  const row = await updateSiemRuleRow(auth.supabase, siem, id, {
    status: "pushed",
    mode,
    github_path: path,
    github_commit: commit.commitSha ?? current.github_commit,
    pushed_at: new Date().toISOString(),
    pushed_by: auth.user.id,
    changed_since_push: false,
  });
  if (!row) throw notFound(siem);
  await deps.audit(
    {
      action: "siem_rule.pushed",
      userId: auth.user.id,
      entityType: "siem_rule",
      entityId: id,
      metadata: {
        siem,
        name: row.name,
        mode,
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

export async function deleteSiemRule(
  auth: AuthContext,
  siem: SiemId,
  id: string,
  request: RequestLike,
  deps = defaultSiemRuleDeps(),
): Promise<void> {
  const current = await requireRule(auth.supabase, siem, id);
  if (current.status === "pushed") {
    throw apiErrors.conflict("This rule is on GitHub, so it cannot be deleted from here.");
  }
  const removed = await deleteSiemRuleRow(auth.supabase, siem, id);
  if (!removed) throw notFound(siem);
  await deps.audit(
    {
      action: "siem_rule.deleted",
      userId: auth.user.id,
      entityType: "siem_rule",
      entityId: id,
      metadata: { siem, name: removed.name },
    },
    request,
  );
}
