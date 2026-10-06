import "server-only";
import type { ServerEnv } from "@/lib/env/server";

/**
 * Commits one file to one GitHub repository through the REST "contents" API. This is the only
 * outbound GitHub call ArcRadar makes, and it follows the same rules as `getJson`/`postJson`: the
 * base address is a literal (never input), the repository comes from a server environment variable
 * that is shape-checked, the path is built from percent-encoded segments, redirects are not
 * followed, there is a deadline and a size cap, and an error never carries the token or a response
 * body. The token needs only "Contents: Read and write" on that one repository.
 */

const API_BASE = "https://api.github.com";
const MAX_RESPONSE_BYTES = 1024 * 1024;
export const GITHUB_TIMEOUT_MS = 15_000;

export type GithubRepoConfig = {
  owner: string;
  repo: string;
  branch: string;
  token: string;
};

export type GithubFailureReason =
  "auth" | "not_found" | "conflict" | "rate_limited" | "timeout" | "unavailable" | "bad_response";

export class GithubError extends Error {
  constructor(
    readonly reason: GithubFailureReason,
    message: string,
  ) {
    super(message);
    this.name = "GithubError";
  }
}

export const REPO_PATTERN = /^([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]{1,100})$/;
export const BRANCH_PATTERN = /^[A-Za-z0-9._/-]{1,100}$/;

/** The rules repository, or null when the token or the repository name is not set (or malformed). */
export function getGithubRulesConfig(
  env: Pick<ServerEnv, "GITHUB_TOKEN" | "GITHUB_RULES_REPO" | "GITHUB_RULES_BRANCH">,
): GithubRepoConfig | null {
  if (!env.GITHUB_TOKEN || !env.GITHUB_RULES_REPO) return null;
  const match = REPO_PATTERN.exec(env.GITHUB_RULES_REPO);
  if (!match) return null;
  const branch = env.GITHUB_RULES_BRANCH ?? "main";
  if (!BRANCH_PATTERN.test(branch) || branch.includes("..")) return null;
  return { owner: match[1], repo: match[2], branch, token: env.GITHUB_TOKEN };
}

const encodePath = (path: string) => path.split("/").map(encodeURIComponent).join("/");

async function readCapped(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    await response.body?.cancel();
    throw new GithubError("bad_response", "GitHub's answer was too large.");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let received = 0;
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new GithubError("bad_response", "GitHub's answer was too large.");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

type CallOptions = {
  config: GithubRepoConfig;
  method: "GET" | "PUT" | "DELETE";
  /** Repository-relative file path, for example `rules/arcradar_100120.xml`. */
  path: string;
  query?: Record<string, string>;
  body?: unknown;
  signal: AbortSignal;
  fetchImpl?: typeof fetch;
};

async function call(options: CallOptions): Promise<{ status: number; json: unknown }> {
  const { config } = options;
  const url = new URL(
    `${API_BASE}/repos/${encodeURIComponent(config.owner)}/${encodeURIComponent(
      config.repo,
    )}/contents/${encodePath(options.path)}`,
  );
  for (const [key, value] of Object.entries(options.query ?? {})) url.searchParams.set(key, value);
  if (url.origin !== API_BASE) {
    throw new GithubError("bad_response", "The GitHub request was refused.");
  }

  const send = options.fetchImpl ?? fetch;
  let response: Response;
  try {
    response = await send(url, {
      method: options.method,
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${config.token}`,
        "x-github-api-version": "2022-11-28",
        "user-agent": "ArcRadar",
        ...(options.body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
      redirect: "manual",
      cache: "no-store",
    });
  } catch {
    if (options.signal.aborted) throw new GithubError("timeout", "GitHub did not answer in time.");
    throw new GithubError("unavailable", "GitHub could not be reached.");
  }

  if (response.status === 404 && options.method === "GET") {
    await response.body?.cancel();
    return { status: 404, json: null };
  }
  if (!response.ok) {
    await response.body?.cancel();
    if (response.status === 401) throw new GithubError("auth", "GitHub rejected the token.");
    if (response.status === 429 || response.headers.get("x-ratelimit-remaining") === "0") {
      throw new GithubError("rate_limited", "GitHub's rate limit was reached.");
    }
    if (response.status === 403) {
      throw new GithubError("auth", "The token is not allowed to write to that repository.");
    }
    if (response.status === 404) {
      throw new GithubError("not_found", "The repository or branch was not found.");
    }
    if (response.status === 409 || response.status === 422) {
      throw new GithubError("conflict", "The file changed on GitHub at the same time. Try again.");
    }
    if (response.status >= 500) throw new GithubError("unavailable", "GitHub is unavailable.");
    throw new GithubError("bad_response", "GitHub refused the request.");
  }

  let text: string;
  try {
    text = await readCapped(response);
  } catch (error) {
    if (error instanceof GithubError) throw error;
    if (options.signal.aborted) throw new GithubError("timeout", "GitHub did not answer in time.");
    throw new GithubError("unavailable", "GitHub's answer could not be read.");
  }
  try {
    return { status: response.status, json: JSON.parse(text) };
  } catch {
    throw new GithubError("bad_response", "GitHub's answer was not valid JSON.");
  }
}

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

export type CommitResult = { commitSha: string | null; unchanged: boolean };

/**
 * Creates the file, or updates it when it already exists (its current blob sha is looked up first,
 * which the API requires). When the content is already identical nothing is committed.
 */
export async function commitRepoFile(params: {
  config: GithubRepoConfig;
  path: string;
  content: string;
  message: string;
  signal: AbortSignal;
  fetchImpl?: typeof fetch;
}): Promise<CommitResult> {
  const { config, path, content, message, signal, fetchImpl } = params;
  const encoded = Buffer.from(content, "utf-8").toString("base64");

  const existing = await call({
    config,
    method: "GET",
    path,
    query: { ref: config.branch },
    signal,
    fetchImpl,
  });
  const current = asRecord(existing.json);
  const sha = existing.status === 200 && typeof current?.sha === "string" ? current.sha : undefined;
  if (
    sha &&
    typeof current?.content === "string" &&
    current.content.replace(/\s/g, "") === encoded
  ) {
    return { commitSha: null, unchanged: true };
  }

  const written = await call({
    config,
    method: "PUT",
    path,
    body: { message, content: encoded, branch: config.branch, ...(sha ? { sha } : {}) },
    signal,
    fetchImpl,
  });
  const commit = asRecord(asRecord(written.json)?.commit);
  if (typeof commit?.sha !== "string") {
    throw new GithubError("bad_response", "GitHub's answer did not name the commit.");
  }
  return { commitSha: commit.sha, unchanged: false };
}

export type DeleteResult = { commitSha: string | null; alreadyGone: boolean };

/**
 * Deletes the file (its current blob sha is looked up first, which the API requires). A file that is not
 * there is not an error: the goal, that it is gone, is already met.
 */
export async function deleteRepoFile(params: {
  config: GithubRepoConfig;
  path: string;
  message: string;
  signal: AbortSignal;
  fetchImpl?: typeof fetch;
}): Promise<DeleteResult> {
  const { config, path, message, signal, fetchImpl } = params;
  const existing = await call({
    config,
    method: "GET",
    path,
    query: { ref: config.branch },
    signal,
    fetchImpl,
  });
  if (existing.status === 404) return { commitSha: null, alreadyGone: true };
  const sha = asRecord(existing.json)?.sha;
  if (typeof sha !== "string") {
    throw new GithubError("bad_response", "GitHub's answer did not name the file.");
  }
  const removed = await call({
    config,
    method: "DELETE",
    path,
    body: { message, sha, branch: config.branch },
    signal,
    fetchImpl,
  });
  const commit = asRecord(asRecord(removed.json)?.commit);
  if (typeof commit?.sha !== "string") {
    throw new GithubError("bad_response", "GitHub's answer did not name the commit.");
  }
  return { commitSha: commit.sha, alreadyGone: false };
}
