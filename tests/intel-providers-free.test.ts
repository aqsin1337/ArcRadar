import { describe, expect, it, vi } from "vitest";
import { OtxProvider, reputationFromPulses } from "@/lib/intel/providers/otx";
import { ShodanProvider, reputationFromExposure } from "@/lib/intel/providers/shodan";
import { buildRegistry, supportsKind } from "@/lib/intel/registry";
import { ProviderError, type LookupContext } from "@/lib/intel/types";

const NOW = new Date("2026-09-30T12:00:00.000Z");
const context: LookupContext = { signal: new AbortController().signal, now: NOW };

function fakeFetch(respond: (url: URL, init: RequestInit) => Response) {
  const calls: { url: URL; init: RequestInit }[] = [];
  const impl = vi.fn(async (input: URL | string | Request, init?: RequestInit) => {
    const url = input instanceof URL ? input : new URL(String(input));
    calls.push({ url, init: init ?? {} });
    return respond(url, init ?? {});
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const json = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), { status: 200, ...init });

describe("reputationFromPulses", () => {
  it("is conservative: nothing found is unknown, never benign", () => {
    expect(reputationFromPulses(0, false).verdict).toBe("unknown");
    expect(reputationFromPulses(1, false).verdict).toBe("suspicious");
    expect(reputationFromPulses(2, false).verdict).toBe("suspicious");
    expect(reputationFromPulses(3, false).verdict).toBe("malicious");
  });

  it("lets the OTX allow-list win over the number of pulses", () => {
    expect(reputationFromPulses(40, true).verdict).toBe("benign");
  });
});

describe("OtxProvider", () => {
  const pulses = [
    { name: "Botnet C2 list", tags: ["botnet", "c2"], malware_families: ["Emotet"] },
    {
      name: "Phishing kit",
      tags: ["phishing", "c2"],
      malware_families: [{ display_name: "Qakbot" }],
    },
    { name: "Scanner", tags: [] },
  ];

  it("sends the key in a header, never in the address, and reads an IPv4 answer", async () => {
    const { impl, calls } = fakeFetch(() =>
      json({
        pulse_info: { count: 3, pulses },
        country_name: "Germany",
        city: "Berlin",
        asn: "AS64500 Example Net",
      }),
    );
    const provider = new OtxProvider({ apiKey: "SECRET-OTX", fetchImpl: impl });
    const profile = await provider.lookupIp("198.51.100.7", context);

    expect(calls).toHaveLength(1);
    expect(calls[0].url.href).toBe(
      "https://otx.alienvault.com/api/v1/indicators/IPv4/198.51.100.7/general",
    );
    expect(calls[0].url.href).not.toContain("SECRET-OTX");
    expect(calls[0].init.headers).toMatchObject({ "X-OTX-API-KEY": "SECRET-OTX" });
    expect(profile).toMatchObject({
      kind: "ip",
      version: 4,
      asn: 64500,
      organization: "Example Net",
      country: "Germany",
      city: "Berlin",
      report_count: 3,
      reputation: { verdict: "malicious" },
      tags: ["botnet", "c2", "phishing"],
    });
    expect(profile?.findings.map((f) => f.result)).toEqual([
      "Botnet C2 list",
      "Phishing kit",
      "Scanner",
    ]);
  });

  it("uses the IPv6 section for an IPv6 address", async () => {
    const { impl, calls } = fakeFetch(() => json({ pulse_info: { count: 0, pulses: [] } }));
    await new OtxProvider({ apiKey: "k", fetchImpl: impl }).lookupIp("2001:db8::1", context);
    expect(calls[0].url.pathname).toBe("/api/v1/indicators/IPv6/2001:db8::1/general");
  });

  it("reads a hash answer with its malware families, and encodes a URL as one path segment", async () => {
    const hash = "a".repeat(64);
    const first = fakeFetch(() => json({ pulse_info: { count: 3, pulses }, type_title: "PE32" }));
    const provider = new OtxProvider({ apiKey: "k", fetchImpl: first.impl });
    const file = await provider.lookupHash(hash, "sha256", context);
    expect(first.calls[0].url.pathname).toBe(`/api/v1/indicators/file/${hash}/general`);
    expect(file).toMatchObject({
      kind: "hash",
      hash_type: "sha256",
      file_type: "PE32",
      malware_families: ["Emotet", "Qakbot"],
      hashes: { sha256: hash, md5: null, sha1: null },
    });

    const second = fakeFetch(() => json({ pulse_info: { count: 1, pulses: [pulses[0]] } }));
    const url = await new OtxProvider({ apiKey: "k", fetchImpl: second.impl }).lookupUrl(
      "http://198.51.100.9/a/b?x=1",
      context,
    );
    expect(second.calls[0].url.pathname).toBe(
      "/api/v1/indicators/url/http:%2F%2F198.51.100.9%2Fa%2Fb%3Fx%3D1/general",
    );
    expect(url).toMatchObject({
      kind: "url",
      host: "198.51.100.9",
      reputation: { verdict: "suspicious" },
    });
  });

  it("calls a domain benign and lists no findings when OTX allow-lists it", async () => {
    const { impl } = fakeFetch(() =>
      json({ pulse_info: { count: 12, pulses }, validation: [{ source: "whitelist" }] }),
    );
    const profile = await new OtxProvider({ apiKey: "k", fetchImpl: impl }).lookupDomain(
      "example.com",
      context,
    );
    expect(profile?.reputation.verdict).toBe("benign");
    expect(profile?.findings).toEqual([]);
  });

  it("answers null for 404 and reports failures without leaking the key or the body", async () => {
    const missing = fakeFetch(() => new Response("{}", { status: 404 }));
    expect(
      await new OtxProvider({ apiKey: "k", fetchImpl: missing.impl }).lookupDomain(
        "a.example",
        context,
      ),
    ).toBeNull();

    const denied = fakeFetch(() => new Response("SECRET body", { status: 403 }));
    await expect(
      new OtxProvider({ apiKey: "SECRET-OTX", fetchImpl: denied.impl }).lookupDomain(
        "a.example",
        context,
      ),
    ).rejects.toMatchObject({ reason: "auth", message: "The provider rejected the API key." });

    const odd = fakeFetch(() => json({ pulse_info: "not an object" }));
    await expect(
      new OtxProvider({ apiKey: "k", fetchImpl: odd.impl }).lookupDomain("a.example", context),
    ).rejects.toBeInstanceOf(ProviderError);
  });
});

describe("reputationFromExposure", () => {
  it("is exposure data, never malicious on its own", () => {
    expect(reputationFromExposure({ ports: 3, vulns: 2, tags: ["cloud"] }).verdict).toBe("unknown");
    expect(reputationFromExposure({ ports: 1, vulns: 0, tags: ["c2"] }).verdict).toBe("suspicious");
    expect(reputationFromExposure({ ports: 1, vulns: 0, tags: ["Malware"] }).verdict).toBe(
      "suspicious",
    );
  });
});

describe("ShodanProvider", () => {
  it("asks InternetDB without any key and maps ports, hostnames, tags and vulnerabilities", async () => {
    const { impl, calls } = fakeFetch(() =>
      json({
        ip: "198.51.100.20",
        ports: [443, 22, 22],
        hostnames: ["host.example"],
        tags: ["cloud"],
        vulns: ["CVE-2021-1234"],
      }),
    );
    const profile = await new ShodanProvider({ fetchImpl: impl }).lookupIp(
      "198.51.100.20",
      context,
    );

    expect(calls[0].url.href).toBe("https://internetdb.shodan.io/198.51.100.20");
    expect(Object.keys(calls[0].init.headers as Record<string, string>)).toEqual(["accept"]);
    expect(profile).toMatchObject({
      kind: "ip",
      open_ports: [22, 443],
      hostnames: ["host.example"],
      tags: ["cloud", "CVE-2021-1234"],
      reputation: { verdict: "unknown" },
    });
  });

  it("answers null when Shodan has nothing on the address", async () => {
    const { impl } = fakeFetch(() => json({ detail: "No information available" }, { status: 404 }));
    expect(
      await new ShodanProvider({ fetchImpl: impl }).lookupIp("198.51.100.21", context),
    ).toBeNull();
  });

  it("only answers IP lookups", () => {
    const provider = new ShodanProvider();
    expect(supportsKind(provider, "ip")).toBe(true);
    for (const kind of ["domain", "url", "hash"] as const) {
      expect(supportsKind(provider, kind)).toBe(false);
    }
  });
});

describe("buildRegistry with the free providers", () => {
  const none = {
    VIRUSTOTAL_API_KEY: undefined,
    ABUSEIPDB_API_KEY: undefined,
    OTX_API_KEY: undefined,
    SHODAN_INTERNETDB: undefined,
  };
  const ids = (env: Parameters<typeof buildRegistry>[0]) =>
    buildRegistry(env).external.map((p) => p.info.id);

  it("has no live provider without keys or switches", () => {
    expect(ids(none)).toEqual([]);
  });

  it("adds OTX with its key and Shodan with its switch", () => {
    expect(ids({ ...none, OTX_API_KEY: "k" })).toEqual(["otx"]);
    expect(ids({ ...none, SHODAN_INTERNETDB: "true" })).toEqual(["shodan"]);
    expect(
      ids({
        VIRUSTOTAL_API_KEY: "k",
        ABUSEIPDB_API_KEY: "k",
        OTX_API_KEY: "k",
        SHODAN_INTERNETDB: "true",
      }),
    ).toEqual(["virustotal", "abuseipdb", "otx", "shodan"]);
  });
});
