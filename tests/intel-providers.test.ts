import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { getJson, parseRetryAfter, pathSegment } from "@/lib/intel/http";
import { AbuseIpdbProvider, reputationFromAbuseScore } from "@/lib/intel/providers/abuseipdb";
import {
  epochToIso,
  findingsFrom,
  reputationFromDetections,
  uniqueStrings,
} from "@/lib/intel/providers/common";
import { DemoProvider } from "@/lib/intel/providers/demo";
import { DEMO_SUBJECTS } from "@/lib/intel/providers/demo-data";
import { VirusTotalProvider } from "@/lib/intel/providers/virustotal";
import { buildRegistry, supportsKind } from "@/lib/intel/registry";
import { isPublicIpv4, isPublicIpv6, isReservedHostname } from "@/lib/intel/target";
import { ProviderError, type LookupContext } from "@/lib/intel/types";

const NOW = new Date("2026-09-26T12:00:00.000Z");
const context = (signal: AbortSignal = new AbortController().signal): LookupContext => ({
  signal,
  now: NOW,
});

/** A fetch stand-in that records what was asked and answers with `respond`. */
function fakeFetch(respond: (url: URL, init: RequestInit) => Response | Promise<Response>) {
  const calls: { url: URL; init: RequestInit }[] = [];
  const impl = vi.fn(async (input: URL | string | Request, init?: RequestInit) => {
    const url = input instanceof URL ? input : new URL(String(input));
    calls.push({ url, init: init ?? {} });
    return respond(url, init ?? {});
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const json = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });

async function failureOf(promise: Promise<unknown>): Promise<ProviderError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ProviderError);
    return error as ProviderError;
  }
  throw new Error("expected the call to fail");
}

const BASE = "https://api.example-provider.test/v1";
const request = (extra: Partial<Parameters<typeof getJson>[0]> & { impl: typeof fetch }) => ({
  baseUrl: BASE,
  path: "/thing",
  headers: { "x-key": "SECRET-KEY-123" },
  signal: new AbortController().signal,
  fetchImpl: extra.impl,
  ...extra,
});

describe("getJson", () => {
  it("sends one GET with the key in a header, never following redirects or caching", async () => {
    const { impl, calls } = fakeFetch(() => json({ hello: "world" }));
    const body = await getJson(request({ impl, query: { ipAddress: "8.8.8.8" } }));

    expect(body).toEqual({ hello: "world" });
    expect(calls).toHaveLength(1);
    const [{ url, init }] = calls;
    expect(url.href).toBe(`${BASE}/thing?ipAddress=8.8.8.8`);
    expect(url.href).not.toContain("SECRET-KEY-123");
    expect(init).toMatchObject({ method: "GET", redirect: "manual", cache: "no-store" });
    expect(init.headers).toMatchObject({ "x-key": "SECRET-KEY-123", accept: "application/json" });
  });

  it("answers null for 404: the provider simply has no record", async () => {
    const { impl } = fakeFetch(() => new Response("{}", { status: 404 }));
    expect(await getJson(request({ impl }))).toBeNull();
  });

  it("lets a provider turn a 404 into a failure (a rejected key), and leaves other 404s as 'no record'", async () => {
    const onNotFound = (headers: Headers) =>
      headers.get("x-reason") === "bad-key" ? new ProviderError("auth", "bad key") : null;

    const badKey = fakeFetch(
      () => new Response("", { status: 404, headers: { "x-reason": "bad-key" } }),
    );
    expect((await failureOf(getJson(request({ impl: badKey.impl, onNotFound })))).reason).toBe(
      "auth",
    );

    const unknown = fakeFetch(() => new Response("", { status: 404 }));
    expect(await getJson(request({ impl: unknown.impl, onNotFound }))).toBeNull();
  });

  it.each([
    [401, "auth"],
    [403, "auth"],
    [429, "rate_limited"],
    [500, "unavailable"],
    [503, "unavailable"],
    [400, "bad_response"],
    [422, "bad_response"],
    [302, "bad_response"],
  ] as const)("maps HTTP %i to %s", async (status, reason) => {
    const { impl } = fakeFetch(
      () =>
        new Response("secret body", { status, headers: { location: "https://elsewhere.test/" } }),
    );
    const error = await failureOf(getJson(request({ impl })));
    expect(error.reason).toBe(reason);
    expect(error.message).not.toContain("secret body");
  });

  it("reads Retry-After from a rate-limit answer", async () => {
    const { impl } = fakeFetch(
      () => new Response("", { status: 429, headers: { "retry-after": "42" } }),
    );
    const error = await failureOf(getJson(request({ impl })));
    expect(error).toMatchObject({ reason: "rate_limited", retryAfterSeconds: 42 });
  });

  it("reports a network failure as unavailable and an aborted deadline as a timeout", async () => {
    const down = fakeFetch(() => {
      throw new TypeError("fetch failed: SECRET-KEY-123");
    });
    const failure = await failureOf(getJson(request({ impl: down.impl })));
    expect(failure.reason).toBe("unavailable");
    expect(failure.message).not.toContain("SECRET-KEY-123");

    const controller = new AbortController();
    const slow = fakeFetch(() => {
      controller.abort();
      throw new DOMException("aborted", "AbortError");
    });
    const timeout = await failureOf(
      getJson(request({ impl: slow.impl, signal: controller.signal })),
    );
    expect(timeout.reason).toBe("timeout");
  });

  it("refuses answers that are not JSON or are too large", async () => {
    const notJson = fakeFetch(() => new Response("<html>oops</html>", { status: 200 }));
    expect((await failureOf(getJson(request({ impl: notJson.impl })))).reason).toBe("bad_response");

    const declared = fakeFetch(
      () => new Response("{}", { status: 200, headers: { "content-length": "5000" } }),
    );
    expect(
      (await failureOf(getJson(request({ impl: declared.impl, maxBytes: 1000 })))).reason,
    ).toBe("bad_response");

    const streamed = fakeFetch(() => new Response(JSON.stringify({ text: "x".repeat(500) })));
    expect((await failureOf(getJson(request({ impl: streamed.impl, maxBytes: 100 })))).reason).toBe(
      "bad_response",
    );
  });

  it("only ever talks to the provider's own https address", async () => {
    const { impl, calls } = fakeFetch(() => json({}));
    // With a base address that has no path, a path such as "@host" would turn into a user name.
    for (const bad of [
      { baseUrl: "https://api.example-provider.test", path: "@evil.test/x" },
      { baseUrl: "http://api.example-provider.test/v1", path: "/thing" },
    ]) {
      const error = await failureOf(getJson(request({ impl, ...bad })));
      expect(error.reason).toBe("bad_response");
    }
    expect(calls).toHaveLength(0);
  });
});

describe("http helpers", () => {
  it("encodes path segments but keeps IPv6 colons readable", () => {
    expect(pathSegment("2001:db8::1")).toBe("2001:db8::1");
    expect(pathSegment("a/b?c#d e")).toBe("a%2Fb%3Fc%23d%20e");
    expect(pathSegment("../secret")).toBe("..%2Fsecret");
  });

  it("parses Retry-After as seconds or as a date, within limits", () => {
    expect(parseRetryAfter("30")).toBe(30);
    expect(parseRetryAfter("0")).toBe(0);
    expect(parseRetryAfter("999999")).toBe(3600);
    expect(parseRetryAfter("Sat, 26 Sep 2026 12:01:00 GMT", NOW.getTime())).toBe(60);
    expect(parseRetryAfter("Sat, 26 Sep 2026 11:00:00 GMT", NOW.getTime())).toBe(0);
    expect(parseRetryAfter("soon")).toBeNull();
    expect(parseRetryAfter(null)).toBeNull();
  });
});

describe("common provider helpers", () => {
  it("is careful with verdicts: nothing flagged is unknown, never benign", () => {
    const stats = (malicious: number, suspicious: number, harmless = 60, undetected = 10) => ({
      malicious,
      suspicious,
      harmless,
      undetected,
    });
    expect(reputationFromDetections(stats(0, 0)).verdict).toBe("unknown");
    expect(reputationFromDetections(stats(0, 0)).summary).toContain("not proof");
    expect(reputationFromDetections(stats(1, 0)).verdict).toBe("suspicious");
    expect(reputationFromDetections(stats(2, 0)).verdict).toBe("suspicious");
    expect(reputationFromDetections(stats(0, 4)).verdict).toBe("suspicious");
    expect(reputationFromDetections(stats(3, 0))).toMatchObject({
      verdict: "malicious",
      summary: "3 of 73 engines flag this as malicious.",
    });
    expect(reputationFromDetections(stats(0, 0, 0, 0)).summary).toContain("no analysis results");
  });

  it("converts epoch seconds, dedupes and orders findings", () => {
    expect(epochToIso(1_700_000_000)).toBe("2023-11-14T22:13:20.000Z");
    expect(epochToIso(null)).toBeNull();
    expect(epochToIso(Number.NaN)).toBeNull();
    expect(uniqueStrings([" a ", "a", "", "b", "c"], 2)).toEqual(["a", "b"]);

    const findings = findingsFrom({
      Zeta: { category: "malicious", result: "Trojan.Z" },
      Beta: { category: "suspicious", result: null },
      Alpha: { category: "malicious" },
      Fine: { category: "harmless", result: "clean" },
      Late: { category: "timeout" },
    });
    expect(findings.map((finding) => finding.engine)).toEqual(["Alpha", "Zeta", "Beta"]);
    expect(findings[2].result).toBeNull();
    expect(findingsFrom({}, 12)).toEqual([]);
    expect(findingsFrom(undefined)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------
// VirusTotal
// ---------------------------------------------------------------------------------------------

const VT_STATS = { malicious: 5, suspicious: 1, harmless: 60, undetected: 20, timeout: 0 };
const VT_RESULTS = {
  "Engine B": { category: "suspicious", result: "Suspicious.Gen", engine_name: "Engine B" },
  "Engine A": { category: "malicious", result: "Trojan.Gen", engine_name: "Engine A" },
  "Engine C": { category: "harmless", result: "clean", engine_name: "Engine C" },
};
const vtAnswer = (attributes: Record<string, unknown>) =>
  json({ data: { type: "x", id: "y", attributes } });

describe("VirusTotalProvider", () => {
  const provider = (impl: typeof fetch) =>
    new VirusTotalProvider({ apiKey: "vt-key", fetchImpl: impl });

  it("reads an IP address report", async () => {
    const { impl, calls } = fakeFetch(() =>
      vtAnswer({
        asn: 64500,
        as_owner: "Fixture Net",
        country: "NL",
        network: "203.0.113.0/24",
        last_analysis_stats: VT_STATS,
        last_analysis_results: VT_RESULTS,
        last_analysis_date: 1_700_000_000,
        tags: ["scanner", "scanner", "tor"],
        reputation: -12,
        unknown_extra_field: { ignored: true },
      }),
    );
    const profile = await provider(impl).lookupIp("203.0.113.10", context());

    expect(calls[0].url.href).toBe("https://www.virustotal.com/api/v3/ip_addresses/203.0.113.10");
    expect(calls[0].init.headers).toMatchObject({ "x-apikey": "vt-key" });
    expect(profile).toMatchObject({
      kind: "ip",
      ip: "203.0.113.10",
      version: 4,
      asn: 64500,
      organization: "Fixture Net",
      country: "NL",
      network: "203.0.113.0/24",
      detections: { malicious: 5, suspicious: 1, harmless: 60, undetected: 20 },
      tags: ["scanner", "tor"],
      last_analysed_at: "2023-11-14T22:13:20.000Z",
      retrieved_at: NOW.toISOString(),
    });
    expect(profile?.reputation).toMatchObject({ verdict: "malicious", confidence: null });
    expect(profile?.findings.map((finding) => finding.engine)).toEqual(["Engine A", "Engine B"]);
  });

  it("keeps IPv6 colons in the request path", async () => {
    const { impl, calls } = fakeFetch(() => vtAnswer({}));
    const profile = await provider(impl).lookupIp("2606:4700:4700::1111", context());
    expect(calls[0].url.pathname).toBe("/api/v3/ip_addresses/2606:4700:4700::1111");
    expect(profile).toMatchObject({ version: 6, detections: null });
    expect(profile?.reputation.verdict).toBe("unknown");
  });

  it("reads a domain report: registrar, dates, nameservers, records and related IPs", async () => {
    const { impl, calls } = fakeFetch(() =>
      vtAnswer({
        registrar: "Fixture Registrar",
        creation_date: 1_600_000_000,
        last_update_date: 1_650_000_000,
        last_dns_records: [
          { type: "A", value: "203.0.113.10", ttl: 300 },
          { type: "AAAA", value: "2001:db8::10", ttl: 300 },
          { type: "NS", value: "ns1.fixture.test", ttl: 3600 },
          { type: "NS", value: "ns2.fixture.test" },
          { type: "MX", value: "mail.fixture.test", ttl: 60 },
        ],
        categories: {
          "Vendor One": "phishing",
          "Vendor Two": "phishing",
          "Vendor Three": "malware",
        },
        last_analysis_stats: { ...VT_STATS, malicious: 0, suspicious: 0 },
      }),
    );
    const profile = await provider(impl).lookupDomain("fixture.test", context());

    expect(calls[0].url.pathname).toBe("/api/v3/domains/fixture.test");
    expect(profile).toMatchObject({
      kind: "domain",
      domain: "fixture.test",
      registrar: "Fixture Registrar",
      created_at: "2020-09-13T12:26:40.000Z",
      updated_at: "2022-04-15T05:20:00.000Z",
      expires_at: null,
      nameservers: ["ns1.fixture.test", "ns2.fixture.test"],
      related_ips: ["203.0.113.10", "2001:db8::10"],
      categories: ["phishing", "malware"],
    });
    expect(profile?.dns_records).toHaveLength(5);
    expect(profile?.dns_records[3]).toEqual({ type: "NS", value: "ns2.fixture.test", ttl: null });
    expect(profile?.reputation.verdict).toBe("unknown");
  });

  it("identifies a URL by its unpadded base64url encoding and never submits it", async () => {
    const url = "https://login.fixture.test/a?b=c&d=é~!";
    const { impl, calls } = fakeFetch(() =>
      vtAnswer({
        last_final_url: "https://login.fixture.test/final",
        title: "Sign in",
        last_http_response_code: 200,
        redirection_chain: ["https://login.fixture.test/a", "https://login.fixture.test/final"],
        first_submission_date: 1_600_000_000,
        categories: { V: "phishing" },
        last_analysis_stats: VT_STATS,
        last_analysis_results: VT_RESULTS,
      }),
    );
    const profile = await provider(impl).lookupUrl(url, context());

    const id = Buffer.from(url, "utf8").toString("base64url");
    expect(id).not.toMatch(/[=+/]/);
    expect(calls).toHaveLength(1);
    expect(calls[0].init.method).toBe("GET");
    expect(calls[0].url.pathname).toBe(`/api/v3/urls/${id}`);
    expect(profile).toMatchObject({
      kind: "url",
      url,
      host: "login.fixture.test",
      final_url: "https://login.fixture.test/final",
      http_status: 200,
      title: "Sign in",
      first_submitted_at: "2020-09-13T12:26:40.000Z",
      categories: ["phishing"],
    });
    expect(profile?.redirect_chain).toHaveLength(2);
  });

  it("reads a file report: hashes, names, type, size, families", async () => {
    const sha256 = "a".repeat(64);
    const { impl, calls } = fakeFetch(() =>
      vtAnswer({
        meaningful_name: "setup.exe",
        names: ["setup.exe", "installer.exe", "setup.exe"],
        size: 123_456,
        type_description: "Win32 EXE",
        md5: "b".repeat(32),
        sha1: "c".repeat(40),
        sha256,
        first_submission_date: 1_600_000_000,
        popular_threat_classification: {
          suggested_threat_label: "trojan.fixture/gen",
          popular_threat_name: [
            { value: "fixture", count: 9 },
            { value: "gen", count: 3 },
          ],
        },
        last_analysis_stats: VT_STATS,
        last_analysis_results: VT_RESULTS,
      }),
    );
    const profile = await provider(impl).lookupHash(sha256, "sha256", context());

    expect(calls[0].url.pathname).toBe(`/api/v3/files/${sha256}`);
    expect(profile).toMatchObject({
      kind: "hash",
      hash: sha256,
      hash_type: "sha256",
      hashes: { md5: "b".repeat(32), sha1: "c".repeat(40), sha256 },
      file_name: "setup.exe",
      file_names: ["setup.exe", "installer.exe"],
      file_type: "Win32 EXE",
      file_size: 123_456,
      malware_families: ["trojan.fixture/gen", "fixture", "gen"],
    });
  });

  it("answers null when VirusTotal has no record", async () => {
    const { impl } = fakeFetch(() => json({ error: { code: "NotFoundError" } }, { status: 404 }));
    expect(await provider(impl).lookupIp("203.0.113.10", context())).toBeNull();
    expect(await provider(impl).lookupHash("a".repeat(32), "md5", context())).toBeNull();
  });

  it("does not trust a malformed answer", async () => {
    const wrongEnvelope = fakeFetch(() => json({ nothing: true }));
    expect(
      (await failureOf(provider(wrongEnvelope.impl).lookupIp("203.0.113.10", context()))).reason,
    ).toBe("bad_response");

    const wrongTypes = fakeFetch(() =>
      vtAnswer({ asn: "not a number", last_analysis_stats: "nope" }),
    );
    expect(
      (await failureOf(provider(wrongTypes.impl).lookupIp("203.0.113.10", context()))).reason,
    ).toBe("bad_response");
  });

  it("passes provider failures through as failures, without leaking the key", async () => {
    const { impl } = fakeFetch(() => new Response("", { status: 401 }));
    const error = await failureOf(provider(impl).lookupDomain("fixture.test", context()));
    expect(error.reason).toBe("auth");
    expect(error.message).not.toContain("vt-key");
  });
});

// ---------------------------------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------------------------------

const abuse = (data: Record<string, unknown>) =>
  json({
    data: {
      ipAddress: "203.0.113.10",
      abuseConfidenceScore: 0,
      countryCode: "DE",
      usageType: "Data Center/Web Hosting/Transit",
      isp: "Fixture Hosting",
      domain: "fixture.test",
      hostnames: ["host.fixture.test"],
      isTor: false,
      totalReports: 0,
      lastReportedAt: null,
      ...data,
    },
  });

describe("AbuseIpdbProvider", () => {
  const provider = (impl: typeof fetch) =>
    new AbuseIpdbProvider({ apiKey: "abuse-key", fetchImpl: impl });

  it("asks the check endpoint with the key in a header and maps the answer", async () => {
    const { impl, calls } = fakeFetch(() =>
      abuse({
        abuseConfidenceScore: 88,
        totalReports: 21,
        lastReportedAt: "2026-09-25T10:00:00+00:00",
        isTor: true,
      }),
    );
    const profile = await provider(impl).lookupIp("203.0.113.10", context());

    expect(calls[0].url.origin + calls[0].url.pathname).toBe(
      "https://api.abuseipdb.com/api/v2/check",
    );
    expect(calls[0].url.searchParams.get("ipAddress")).toBe("203.0.113.10");
    expect(calls[0].url.searchParams.get("maxAgeInDays")).toBe("90");
    expect(calls[0].url.href).not.toContain("abuse-key");
    expect(calls[0].init.headers).toMatchObject({ Key: "abuse-key" });
    expect(profile).toMatchObject({
      kind: "ip",
      ip: "203.0.113.10",
      version: 4,
      organization: "Fixture Hosting",
      isp: "Fixture Hosting",
      usage_type: "Data Center/Web Hosting/Transit",
      country: "DE",
      hostnames: ["host.fixture.test"],
      related_domains: ["fixture.test"],
      report_count: 21,
      last_reported_at: "2026-09-25T10:00:00.000Z",
      tags: ["tor"],
      detections: null,
      retrieved_at: NOW.toISOString(),
    });
    expect(profile?.reputation).toMatchObject({ verdict: "malicious", confidence: 88 });
  });

  it("uses AbuseIPDB's own bands for the verdict", () => {
    expect(reputationFromAbuseScore(0, false, 0).verdict).toBe("unknown");
    expect(reputationFromAbuseScore(24, false, 3).verdict).toBe("unknown");
    expect(reputationFromAbuseScore(25, false, 3)).toMatchObject({
      verdict: "suspicious",
      confidence: 25,
    });
    expect(reputationFromAbuseScore(74, false, 3).verdict).toBe("suspicious");
    expect(reputationFromAbuseScore(75, false, 3)).toMatchObject({
      verdict: "malicious",
      confidence: 75,
    });
    expect(reputationFromAbuseScore(10, true, 0)).toMatchObject({
      verdict: "benign",
      confidence: null,
    });
    expect(reputationFromAbuseScore(50, false, 1).summary).toContain(
      "1 report in the last 90 days",
    );
  });

  it("tolerates missing optional fields and refuses a wrong shape", async () => {
    const sparse = fakeFetch(() =>
      json({ data: { ipAddress: "203.0.113.10", abuseConfidenceScore: 0 } }),
    );
    expect(await provider(sparse.impl).lookupIp("203.0.113.10", context())).toMatchObject({
      country: null,
      hostnames: [],
      report_count: 0,
      last_reported_at: null,
    });

    const wrong = fakeFetch(() => json({ data: { ipAddress: 5 } }));
    expect((await failureOf(provider(wrong.impl).lookupIp("203.0.113.10", context()))).reason).toBe(
      "bad_response",
    );
  });

  it("only answers IP lookups", () => {
    expect(supportsKind(provider(fakeFetch(() => json({})).impl), "ip")).toBe(true);
    for (const kind of ["domain", "url", "hash"] as const) {
      expect(supportsKind(provider(fakeFetch(() => json({})).impl), kind)).toBe(false);
    }
  });
});

describe("buildRegistry", () => {
  it("enables a live provider only when its key is set, and the demo provider always", () => {
    const none = buildRegistry({ VIRUSTOTAL_API_KEY: undefined, ABUSEIPDB_API_KEY: undefined });
    expect(none.external).toHaveLength(0);
    expect(none.demo.info).toMatchObject({ id: "demo", origin: "demo" });

    const both = buildRegistry({ VIRUSTOTAL_API_KEY: "a", ABUSEIPDB_API_KEY: "b" });
    expect(both.external.map((provider) => provider.info.id)).toEqual(["virustotal", "abuseipdb"]);
    expect(both.external.every((provider) => provider.info.origin === "external")).toBe(true);

    const onlyAbuse = buildRegistry({ VIRUSTOTAL_API_KEY: undefined, ABUSEIPDB_API_KEY: "b" });
    expect(onlyAbuse.external.map((provider) => provider.info.id)).toEqual(["abuseipdb"]);
  });

  it("never exposes a key through the provider objects' public surface", () => {
    const registry = buildRegistry({
      VIRUSTOTAL_API_KEY: "vt-secret",
      ABUSEIPDB_API_KEY: "abuse-secret",
    });
    for (const provider of registry.external) {
      expect(JSON.stringify(provider.info)).not.toMatch(/secret/);
    }
  });
});

// ---------------------------------------------------------------------------------------------
// Demo provider
// ---------------------------------------------------------------------------------------------

const REAL_AND_HARMLESS = new Set(["8.8.8.8", "example.com"]);
const seed = readFileSync("supabase/seed.sql", "utf8");

describe("DemoProvider", () => {
  const demo = new DemoProvider();

  it("is labelled demo and answers every subject in its dataset with the right kind of profile", async () => {
    expect(demo.info).toEqual({ id: "demo", name: "Demo dataset", origin: "demo" });

    for (const ip of DEMO_SUBJECTS.ip) {
      expect(await demo.lookupIp(ip, context()), ip).toMatchObject({
        kind: "ip",
        ip,
        retrieved_at: NOW.toISOString(),
      });
    }
    for (const domain of DEMO_SUBJECTS.domain) {
      expect(await demo.lookupDomain(domain, context()), domain).toMatchObject({
        kind: "domain",
        domain,
      });
    }
    for (const url of DEMO_SUBJECTS.url) {
      expect(await demo.lookupUrl(url, context()), url).toMatchObject({ kind: "url", url });
    }
    for (const hash of DEMO_SUBJECTS.hash) {
      const type = hash.length === 32 ? "md5" : hash.length === 40 ? "sha1" : "sha256";
      expect(await demo.lookupHash(hash, type, context()), hash).toMatchObject({
        kind: "hash",
        hash,
        hash_type: type,
      });
    }
  });

  it("honestly has no record of anything else", async () => {
    expect(await demo.lookupIp("203.0.113.190", context())).toBeNull();
    expect(await demo.lookupDomain("unknown.example", context())).toBeNull();
    expect(await demo.lookupUrl("https://unknown.example/x", context())).toBeNull();
    expect(await demo.lookupHash("f".repeat(64), "sha256", context())).toBeNull();
  });

  it("uses only fictional infrastructure, apart from three harmless well-known subjects", () => {
    for (const ip of DEMO_SUBJECTS.ip.filter((value) => !REAL_AND_HARMLESS.has(value))) {
      const routable = ip.includes(":") ? isPublicIpv6(ip) : isPublicIpv4(ip);
      expect(routable, `${ip} must be a documentation address`).toBe(false);
    }
    for (const domain of DEMO_SUBJECTS.domain.filter((value) => !REAL_AND_HARMLESS.has(value))) {
      expect(isReservedHostname(domain), `${domain} must use a reserved name`).toBe(true);
    }
  });

  it("invents no location or attribution for fictional infrastructure", async () => {
    for (const ip of DEMO_SUBJECTS.ip.filter((value) => !REAL_AND_HARMLESS.has(value))) {
      const profile = await demo.lookupIp(ip, context());
      expect(profile, ip).toMatchObject({ country: null, region: null, city: null });
      expect(profile?.organization ?? "", ip).toMatch(/fictional|Demo/i);
    }
  });

  it("lines up with the seeded indicators: every fictional subject is in supabase/seed.sql", () => {
    for (const value of [...DEMO_SUBJECTS.ip, ...DEMO_SUBJECTS.domain, ...DEMO_SUBJECTS.url].filter(
      (subject) => !REAL_AND_HARMLESS.has(subject),
    )) {
      expect(seed, `${value} is not in the seed`).toContain(`'${value}'`);
    }
  });

  it("knows every digest form of a seeded sample hash, and they agree", async () => {
    const sample = (n: number, algorithm: "md5" | "sha1" | "sha256") =>
      createHash(algorithm).update(`arcradar-demo-sample-${n}`, "utf8").digest("hex");
    for (const n of [1, 2, 3, 4, 5, 6, 7, 8]) {
      const profiles = await Promise.all([
        demo.lookupHash(sample(n, "md5"), "md5", context()),
        demo.lookupHash(sample(n, "sha1"), "sha1", context()),
        demo.lookupHash(sample(n, "sha256"), "sha256", context()),
      ]);
      expect(profiles.every(Boolean), `sample ${n}`).toBe(true);
      expect(new Set(profiles.map((profile) => profile?.file_name)).size).toBe(1);
      expect(profiles[0]?.hashes).toEqual({
        md5: sample(n, "md5"),
        sha1: sample(n, "sha1"),
        sha256: sample(n, "sha256"),
      });
    }
    // The seed inserts sample 1 as a sha256, 6 as md5 and 7 as sha1, and both must match the dataset.
    expect(seed).toContain("sha256_of(1)");
    expect(seed).toContain("md5('arcradar-demo-sample-6')");
  });

  it("describes the EICAR test file without calling it malware", async () => {
    const eicar = await demo.lookupHash(
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "sha256",
      context(),
    );
    expect(eicar?.reputation.verdict).toBe("unknown");
    expect(eicar?.reputation.summary).toMatch(/test file/i);
    expect(eicar?.hashes.md5).toBe("44d88612fea8a8f36de82e1278abb02f");
  });

  it("keeps dates relative to the clock it is given", async () => {
    const profile = await demo.lookupIp("198.51.100.23", context());
    expect(profile?.last_reported_at).toBe("2026-09-25T12:00:00.000Z");
    const domain = await demo.lookupDomain("example.com", context());
    expect(domain?.created_at).toBe("1995-08-14T04:00:00.000Z");
  });
});
