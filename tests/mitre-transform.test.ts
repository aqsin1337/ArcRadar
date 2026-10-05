import { describe, expect, it } from "vitest";
import { chunk, cleanText, tacticName, transformStix } from "../scripts/lib/mitre-transform.mjs";

const ref = (id: string) => [
  { source_name: "mitre-attack", external_id: id, url: `https://attack.mitre.org/${id}` },
];

const bundle = {
  objects: [
    {
      type: "attack-pattern",
      id: "attack-pattern--1",
      name: "Phishing",
      description: "Sends mail. (Citation: Some Report) See [the docs](https://example.test/x).",
      external_references: ref("T1566"),
      kill_chain_phases: [
        { kill_chain_name: "mitre-attack", phase_name: "initial-access" },
        { kill_chain_name: "other-chain", phase_name: "ignored" },
      ],
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--2",
      name: "Spearphishing Attachment",
      external_references: ref("T1566.001"),
      kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "initial-access" }],
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--c2",
      name: "Web Service",
      external_references: ref("T1102"),
      kill_chain_phases: [{ kill_chain_name: "mitre-attack", phase_name: "command-and-control" }],
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--revoked",
      name: "Revoked",
      revoked: true,
      external_references: ref("T1000"),
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--deprecated",
      name: "Deprecated",
      x_mitre_deprecated: true,
      external_references: ref("T1001"),
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--noid",
      name: "No ATT&CK id",
      external_references: [{ source_name: "capec", external_id: "CAPEC-1" }],
    },
    // Not techniques: nothing of these is imported (ArcRadar has no actors, malware or campaigns).
    { type: "malware", id: "malware--1", name: "Emotet" },
    { type: "intrusion-set", id: "intrusion-set--1", name: "APT99" },
    { type: "campaign", id: "campaign--1", name: "Operation Example" },
  ],
};

describe("transformStix", () => {
  const out = transformStix(bundle);

  it("keeps techniques with an ATT&CK id, drops revoked, deprecated and foreign ones", () => {
    expect(out.techniques.map((t) => t.id)).toEqual(["T1102", "T1566", "T1566.001"]);
    expect(out.techniques[1]).toMatchObject({
      name: "Phishing",
      tactics: ["Initial Access"],
      url: "https://attack.mitre.org/T1566",
    });
  });

  it("imports nothing but techniques", () => {
    expect(Object.keys(out)).toEqual(["techniques"]);
  });

  it("writes tactic names the way the matrix does, with a small 'and'", () => {
    expect(out.techniques[0].tactics).toEqual(["Command and Control"]);
  });

  it("cleans citations and markdown links out of descriptions", () => {
    expect(out.techniques[1].description).toBe("Sends mail. See the docs.");
    expect(out.techniques[2].description).toBeNull();
  });

  it("copes with an empty or malformed bundle", () => {
    for (const input of [null, {}, { objects: "no" }, { objects: [] }]) {
      expect(transformStix(input)).toEqual({ techniques: [] });
    }
  });
});

describe("small helpers", () => {
  it("cleanText", () => {
    expect(cleanText("a (Citation: x) b")).toBe("a b");
    expect(cleanText("   ")).toBeNull();
    expect(cleanText(5)).toBeNull();
  });

  it("tacticName", () => {
    expect(tacticName("defense-evasion")).toBe("Defense Evasion");
    expect(tacticName("execution")).toBe("Execution");
    expect(tacticName("command-and-control")).toBe("Command and Control");
  });

  it("chunk", () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 3)).toEqual([]);
  });
});
