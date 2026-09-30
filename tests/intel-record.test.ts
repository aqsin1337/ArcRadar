import { describe, expect, it } from "vitest";
import { recordFromLookup, worstVerdict } from "@/lib/intel/record";
import { parseTarget, type IntelTarget } from "@/lib/intel/target";
import type { IpProfile, ProviderResult } from "@/lib/intel/types";
import type { Verdict } from "@/types/domain";

const target = (kind: Parameters<typeof parseTarget>[0], value: string): IntelTarget => {
  const parsed = parseTarget(kind, value);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.target;
};

const result = (
  id: "virustotal" | "abuseipdb" | "demo",
  verdict: Verdict,
  confidence: number | null = null,
  summary: string | null = `${id} says ${verdict}`,
): ProviderResult => ({
  provider: {
    id,
    name: id,
    origin: id === "demo" ? "demo" : "external",
  },
  profile: {
    kind: "ip",
    ip: "8.8.8.8",
    version: 4,
    reputation: { verdict, confidence, summary },
  } as unknown as IpProfile,
});

describe("worstVerdict", () => {
  it("takes the most serious verdict, and unknown when nobody said anything", () => {
    expect(worstVerdict([])).toBe("unknown");
    expect(worstVerdict([result("virustotal", "benign"), result("abuseipdb", "suspicious")])).toBe(
      "suspicious",
    );
    expect(worstVerdict([result("virustotal", "malicious"), result("abuseipdb", "benign")])).toBe(
      "malicious",
    );
  });
});

describe("recordFromLookup", () => {
  it("records nothing for no answers or for demo answers only", () => {
    expect(recordFromLookup(target("ip", "8.8.8.8"), [])).toBeNull();
    expect(recordFromLookup(target("ip", "8.8.8.8"), [result("demo", "malicious")])).toBeNull();
  });

  it("builds one record from the live answers and ignores a demo one next to them", () => {
    const out = recordFromLookup(target("ip", "8.8.8.8"), [
      result("virustotal", "suspicious"),
      result("abuseipdb", "malicious", 88),
      result("demo", "benign"),
    ]);
    expect(out?.source).toBe("lookup:abuseipdb.virustotal");
    expect(out?.record).toMatchObject({
      type: "ipv4",
      value: "8.8.8.8",
      verdict: "malicious",
      severity: "high",
      confidence: 88,
    });
    expect(out?.record.description).toContain("abuseipdb says malicious");
    expect(out?.record.description).toContain("virustotal says suspicious");
    expect(out?.record.description).not.toContain("demo");
  });

  it("maps every verdict to a severity and a default confidence", () => {
    const of = (verdict: Verdict) =>
      recordFromLookup(target("ip", "8.8.8.8"), [result("virustotal", verdict)])?.record;
    expect(of("malicious")).toMatchObject({ severity: "high", confidence: 80 });
    expect(of("suspicious")).toMatchObject({ severity: "medium", confidence: 55 });
    expect(of("benign")).toMatchObject({ severity: "info", confidence: 60 });
    expect(of("unknown")).toMatchObject({ severity: "low", confidence: 30 });
  });

  it("uses the indicator type of the target, including the hash algorithm", () => {
    const sha = "a".repeat(64);
    expect(
      recordFromLookup(target("hash", sha), [result("virustotal", "unknown")])?.record.type,
    ).toBe("sha256");
    expect(
      recordFromLookup(target("domain", "example.com"), [result("virustotal", "unknown")])?.record
        .type,
    ).toBe("domain");
  });

  it("keeps the description and the source within their limits", () => {
    const long = "x".repeat(9000);
    const out = recordFromLookup(target("ip", "8.8.8.8"), [
      result("virustotal", "malicious", null, long),
    ]);
    expect(out?.record.description?.length).toBeLessThanOrEqual(4000);
    expect(out?.source.length).toBeLessThanOrEqual(60);
    expect(out?.source).toMatch(/^[a-z0-9_:.-]{1,60}$/);
  });
});
