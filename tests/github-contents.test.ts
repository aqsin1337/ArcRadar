import { describe, expect, it, vi } from "vitest";
import {
  commitRepoFile,
  getGithubRulesConfig,
  GithubError,
  type GithubRepoConfig,
} from "@/lib/github/contents";

const config: GithubRepoConfig = {
  owner: "aqsin1337",
  repo: "wazuh_rules",
  branch: "main",
  token: "ghp_secret_token_value",
};

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers });

const asFetch = (fn: unknown) => fn as typeof fetch;

const run = (fetchImpl: typeof fetch, content = "<group/>\n") =>
  commitRepoFile({
    config,
    path: "rules/arcradar_100120.xml",
    content,
    message: "Add rule 100120",
    signal: AbortSignal.timeout(5000),
    fetchImpl,
  });

describe("getGithubRulesConfig", () => {
  const env = {
    GITHUB_TOKEN: "t",
    GITHUB_RULES_REPO: "aqsin1337/wazuh_rules",
    GITHUB_RULES_BRANCH: undefined,
  };

  it("needs the token and the repository, and defaults the branch to main", () => {
    expect(getGithubRulesConfig(env)).toMatchObject({
      owner: "aqsin1337",
      repo: "wazuh_rules",
      branch: "main",
    });
    expect(getGithubRulesConfig({ ...env, GITHUB_TOKEN: undefined })).toBeNull();
    expect(getGithubRulesConfig({ ...env, GITHUB_RULES_REPO: undefined })).toBeNull();
  });

  it.each(["not-a-repo", "a/b/c", "../evil/x", "owner/re po", "https://evil.test/x/y"])(
    "refuses the malformed repository %s",
    (repo) => {
      expect(getGithubRulesConfig({ ...env, GITHUB_RULES_REPO: repo })).toBeNull();
    },
  );

  it("refuses a malformed branch", () => {
    expect(getGithubRulesConfig({ ...env, GITHUB_RULES_BRANCH: "a..b" })).toBeNull();
    expect(getGithubRulesConfig({ ...env, GITHUB_RULES_BRANCH: "feature/rules" })).toMatchObject({
      branch: "feature/rules",
    });
  });
});

describe("commitRepoFile", () => {
  it("creates a file that does not exist yet (no sha in the PUT)", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json(404, { message: "Not Found" }))
      .mockResolvedValueOnce(json(201, { commit: { sha: "c0ffee" } }));
    const result = await run(asFetch(fetchImpl));

    expect(result).toEqual({ commitSha: "c0ffee", unchanged: false });
    const [getUrl, getInit] = fetchImpl.mock.calls[0];
    expect(String(getUrl)).toBe(
      "https://api.github.com/repos/aqsin1337/wazuh_rules/contents/rules/arcradar_100120.xml?ref=main",
    );
    expect(getInit.redirect).toBe("manual");
    expect(getInit.headers.authorization).toBe(`Bearer ${config.token}`);
    const put = fetchImpl.mock.calls[1][1];
    expect(put.method).toBe("PUT");
    const body = JSON.parse(put.body);
    expect(body).toMatchObject({ message: "Add rule 100120", branch: "main" });
    expect(body.sha).toBeUndefined();
    expect(Buffer.from(body.content, "base64").toString()).toBe("<group/>\n");
  });

  it("updates an existing file with its current sha", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json(200, { sha: "blob1", content: "b2xk\n" }))
      .mockResolvedValueOnce(json(200, { commit: { sha: "c0ffee" } }));
    await run(asFetch(fetchImpl));
    expect(JSON.parse(fetchImpl.mock.calls[1][1].body).sha).toBe("blob1");
  });

  it("commits nothing when the content is already identical", async () => {
    const same = Buffer.from("<group/>\n").toString("base64");
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json(200, { sha: "blob1", content: `${same}\n` }));
    const result = await run(asFetch(fetchImpl));
    expect(result).toEqual({ commitSha: null, unchanged: true });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it.each([
    [401, {}, "auth"],
    [403, {}, "auth"],
    [403, { "x-ratelimit-remaining": "0" }, "rate_limited"],
    [429, {}, "rate_limited"],
    [409, {}, "conflict"],
    [422, {}, "conflict"],
    [500, {}, "unavailable"],
  ])("maps status %s %j to %s", async (status, headers, reason) => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json(404, {}))
      .mockResolvedValueOnce(json(status, { message: "secret detail" }, headers));
    await expect(run(asFetch(fetchImpl))).rejects.toMatchObject({ reason });
  });

  it("maps a missing repository on write to not_found", async () => {
    // A 404 on the lookup only means "no file yet"; a 404 on the write means the repository or
    // branch is missing.
    const fetchImpl = vi.fn().mockResolvedValue(json(404, {}));
    await expect(run(asFetch(fetchImpl))).rejects.toMatchObject({ reason: "not_found" });
  });

  it("never puts the token or a response body in an error", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json(404, {}))
      .mockResolvedValueOnce(json(401, { message: "Bad credentials ghp_secret_token_value" }));
    try {
      await run(asFetch(fetchImpl));
      throw new Error("expected a failure");
    } catch (error) {
      expect(error).toBeInstanceOf(GithubError);
      expect((error as Error).message).not.toContain("ghp_");
      expect((error as Error).message).not.toContain("Bad credentials");
    }
  });

  it("reports a network failure as unavailable and an abort as a timeout", async () => {
    const down = vi.fn().mockRejectedValue(new Error("ECONNRESET"));
    await expect(run(asFetch(down))).rejects.toMatchObject({ reason: "unavailable" });

    const controller = new AbortController();
    controller.abort();
    const aborted = vi.fn().mockRejectedValue(new Error("aborted"));
    await expect(
      commitRepoFile({
        config,
        path: "rules/x.xml",
        content: "x",
        message: "m",
        signal: controller.signal,
        fetchImpl: asFetch(aborted),
      }),
    ).rejects.toMatchObject({ reason: "timeout" });
  });

  it("encodes each path segment, so a path cannot leave the contents endpoint", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json(404, {}))
      .mockResolvedValueOnce(json(201, { commit: { sha: "c" } }));
    await commitRepoFile({
      config,
      path: "rules/a b?x=1#y.xml",
      content: "x",
      message: "m",
      signal: AbortSignal.timeout(5000),
      fetchImpl: asFetch(fetchImpl),
    });
    const url = new URL(String(fetchImpl.mock.calls[0][0]));
    expect(url.origin).toBe("https://api.github.com");
    expect(url.pathname).toBe("/repos/aqsin1337/wazuh_rules/contents/rules/a%20b%3Fx%3D1%23y.xml");
    expect(url.search).toBe("?ref=main");
  });

  it("refuses an answer that does not name the commit", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(json(404, {}))
      .mockResolvedValueOnce(json(201, { content: {} }));
    await expect(run(asFetch(fetchImpl))).rejects.toMatchObject({ reason: "bad_response" });
  });
});
