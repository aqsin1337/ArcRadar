import { describe, expect, it } from "vitest";
import {
  aiWazuhRuleSchema,
  checkRegex,
  createWazuhRuleSchema,
  generateWazuhRuleSchema,
  updateWazuhRuleSchema,
} from "@/lib/wazuh-rules/schema";
import type { WazuhRuleDefinition } from "@/lib/wazuh-rules/types";
import {
  conditionPattern,
  escapeRegex,
  escapeXml,
  renderWazuhRuleXml,
} from "@/lib/wazuh-rules/xml";

const valid = {
  name: "Defender disable attempt",
  level: 12,
  parent_kind: "group" as const,
  parent_value: "windows",
  conditions: [
    {
      field: "win.eventdata.commandLine",
      op: "contains" as const,
      value: "DisableRealtimeMonitoring",
    },
  ],
  mitre_ids: ["T1562.001"],
};

const definition: WazuhRuleDefinition = { id: 100120, ...valid };

describe("renderWazuhRuleXml", () => {
  it("renders the rule with the fixed element set", () => {
    const xml = renderWazuhRuleXml(definition);
    expect(xml).toContain('<rule id="100120" level="12">');
    expect(xml).toContain("<if_group>windows</if_group>");
    expect(xml).toContain(
      '<field name="win.eventdata.commandLine" type="pcre2">(?i)DisableRealtimeMonitoring</field>',
    );
    expect(xml).toContain("<description>Defender disable attempt</description>");
    expect(xml).toContain("<id>T1562.001</id>");
    expect(xml).toContain('<group name="arcradar,">');
  });

  it("uses if_sid for a parent rule id and omits <mitre> when there is no technique", () => {
    const xml = renderWazuhRuleXml({
      ...definition,
      parent_kind: "sid",
      parent_value: "60103",
      mitre_ids: [],
    });
    expect(xml).toContain("<if_sid>60103</if_sid>");
    expect(xml).not.toContain("<mitre>");
  });

  it("escapes the value for the regex it becomes, then for XML", () => {
    const xml = renderWazuhRuleXml({
      ...definition,
      conditions: [{ field: "win.eventdata.image", op: "contains", value: 'a.exe <b> & "c"' }],
    });
    expect(xml).toContain("a\\.exe &lt;b&gt; &amp; &quot;c&quot;");
    expect(xml).not.toContain("<b>");
  });

  it("cannot be made to emit an element the generator does not know", () => {
    const xml = renderWazuhRuleXml({
      ...definition,
      name: "</description><active-response><command>rm -rf</command></active-response>",
    });
    expect(xml).not.toContain("<active-response>");
    expect(xml).not.toContain("<command>");
    expect(xml).toContain("&lt;active-response&gt;");
  });

  it("builds literal, anchored and raw patterns", () => {
    expect(conditionPattern("contains", "a+b")).toBe("(?i)a\\+b");
    expect(conditionPattern("equals", "C:\\x.exe")).toBe("(?i)^C:\\\\x\\.exe$");
    expect(conditionPattern("regex", "Set-Mp.*Disable")).toBe("(?i)Set-Mp.*Disable");
    expect(escapeRegex("(x)")).toBe("\\(x\\)");
    expect(escapeXml('<&>"')).toBe("&lt;&amp;&gt;&quot;");
  });
});

describe("checkRegex", () => {
  it("accepts ordinary patterns", () => {
    expect(checkRegex("Set-MpPreference.*DisableRealtimeMonitoring")).toBeNull();
    expect(checkRegex("(powershell|pwsh)\\.exe")).toBeNull();
    expect(checkRegex("(?:abc)+")).toBeNull();
  });

  it.each([
    ["(a+)+", "nested repetition"],
    ["(.*)*x", "nested repetition"],
    ["(?=x)a", "lookahead"],
    ["(?i)x", "inline flag"],
    ["(a)\\1", "back-reference"],
    ["a++", "stacked repetition"],
    ["a(", "invalid pattern"],
  ])("rejects %s (%s)", (pattern) => {
    expect(checkRegex(pattern)).not.toBeNull();
  });
});

describe("createWazuhRuleSchema", () => {
  it("accepts a valid rule, with the id optional", () => {
    expect(createWazuhRuleSchema.safeParse(valid).success).toBe(true);
    expect(createWazuhRuleSchema.safeParse({ ...valid, id: 100150 }).success).toBe(true);
  });

  it.each([
    ["an id below the reserved floor", { id: 100001 }],
    ["an id above the range", { id: 1000000 }],
    ["a level of 0", { level: 0 }],
    ["a level of 16", { level: 16 }],
    ["an empty name", { name: " " }],
    ["no conditions", { conditions: [] }],
    [
      "a field outside the known prefixes",
      { conditions: [{ field: "full_log", op: "contains", value: "x" }] },
    ],
    ["an unknown comparison", { conditions: [{ field: "win.a", op: "eval", value: "x" }] }],
    ["an unsafe regex", { conditions: [{ field: "win.a", op: "regex", value: "(a+)+" }] }],
    ["a bad technique id", { mitre_ids: ["T12"] }],
    ["an injected group", { parent_value: "windows</if_group><command>" }],
    ["a non-numeric parent rule id", { parent_kind: "sid", parent_value: "abc" }],
    ["an unknown key", { origin: "external" }],
    ["a status", { status: "pushed" }],
  ])("rejects %s", (_label, patch) => {
    expect(createWazuhRuleSchema.safeParse({ ...valid, ...patch }).success).toBe(false);
  });

  it("normalizes and de-duplicates technique ids", () => {
    const parsed = createWazuhRuleSchema.parse({ ...valid, mitre_ids: ["t1562.001", "T1562.001"] });
    expect(parsed.mitre_ids).toEqual(["T1562.001"]);
  });
});

describe("the other schemas", () => {
  it("the AI draft goes through the same rules and carries no id or status", () => {
    expect(aiWazuhRuleSchema.safeParse(valid).success).toBe(true);
    expect(
      aiWazuhRuleSchema.safeParse({
        ...valid,
        conditions: [{ field: "win.a", op: "regex", value: "(a+)+" }],
      }).success,
    ).toBe(false);
  });

  it("an update needs at least one field", () => {
    expect(updateWazuhRuleSchema.safeParse({}).success).toBe(false);
    expect(updateWazuhRuleSchema.safeParse({ level: 9 }).success).toBe(true);
    expect(updateWazuhRuleSchema.safeParse({ id: 100200 }).success).toBe(false);
  });

  it("a generate request needs a real sentence", () => {
    expect(generateWazuhRuleSchema.safeParse({ prompt: "short" }).success).toBe(false);
    expect(
      generateWazuhRuleSchema.safeParse({ prompt: "Detect PowerShell disabling Defender." })
        .success,
    ).toBe(true);
  });
});
