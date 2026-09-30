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
    {
      type: "malware",
      id: "malware--1",
      name: "Emotet",
      x_mitre_platforms: ["Windows"],
      description: "d",
    },
    { type: "tool", id: "tool--1", name: "Mimikatz", x_mitre_platforms: ["Windows"] },
    { type: "malware", id: "malware--dup", name: "EMOTET" },
    {
      type: "campaign",
      id: "campaign--1",
      name: "Operation Example",
      first_seen: "2020-01-01T00:00:00.000Z",
      last_seen: "not a date",
    },
    {
      type: "intrusion-set",
      id: "intrusion-set--1",
      name: "APT99",
      aliases: ["APT99", "Blue Fox"],
      description: "A group.",
    },
    { type: "intrusion-set", id: "intrusion-set--revoked", name: "Old Group", revoked: true },
    {
      type: "relationship",
      relationship_type: "uses",
      source_ref: "intrusion-set--1",
      target_ref: "attack-pattern--1",
    },
    {
      type: "relationship",
      relationship_type: "uses",
      source_ref: "intrusion-set--1",
      target_ref: "attack-pattern--revoked",
    },
    {
      type: "relationship",
      relationship_type: "uses",
      source_ref: "intrusion-set--1",
      target_ref: "malware--1",
    },
    {
      type: "relationship",
      relationship_type: "uses",
      source_ref: "intrusion-set--1",
      target_ref: "tool--1",
    },
    {
      type: "relationship",
      relationship_type: "attributed-to",
      source_ref: "campaign--1",
      target_ref: "intrusion-set--1",
    },
    {
      type: "relationship",
      relationship_type: "uses",
      source_ref: "intrusion-set--1",
      target_ref: "malware--1",
      revoked: true,
    },
  ],
};

describe("transformStix", () => {
  const out = transformStix(bundle);

  it("keeps techniques with an ATT&CK id, drops revoked, deprecated and foreign ones", () => {
    expect(out.techniques.map((t) => t.id)).toEqual(["T1566", "T1566.001"]);
    expect(out.techniques[0]).toMatchObject({
      name: "Phishing",
      tactics: ["Initial Access"],
      url: "https://attack.mitre.org/T1566",
    });
  });

  it("cleans citations and markdown links out of descriptions", () => {
    expect(out.techniques[0].description).toBe("Sends mail. See the docs.");
    expect(out.techniques[1].description).toBeNull();
  });

  it("lists malware and tools once per name, whatever the case", () => {
    expect(out.malware.map((m) => [m.name, m.malware_type])).toEqual([
      ["Emotet", "malware"],
      ["Mimikatz", "tool"],
    ]);
    expect(out.malware[0].platforms).toEqual(["Windows"]);
  });

  it("reads campaigns, turning an unreadable date into null", () => {
    expect(out.campaigns).toEqual([
      {
        name: "Operation Example",
        description: null,
        first_seen: "2020-01-01T00:00:00.000Z",
        last_seen: null,
      },
    ]);
  });

  it("builds actors with their techniques, malware and campaigns, and never links what was dropped", () => {
    expect(out.actors).toHaveLength(1);
    expect(out.actors[0]).toMatchObject({
      name: "APT99",
      aliases: ["Blue Fox"],
      technique_ids: ["T1566"],
      malware_names: ["Emotet", "Mimikatz"],
      campaign_names: ["Operation Example"],
    });
  });

  it("copes with an empty or malformed bundle", () => {
    for (const input of [null, {}, { objects: "no" }, { objects: [] }]) {
      expect(transformStix(input)).toEqual({
        techniques: [],
        malware: [],
        campaigns: [],
        actors: [],
      });
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
  });

  it("chunk", () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 3)).toEqual([]);
  });
});
