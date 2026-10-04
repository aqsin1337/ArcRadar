import { describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api/errors";
import {
  INDICATOR_TYPES,
  INDICATOR_TYPE_LABELS,
  INDICATOR_TYPE_SHORT_LABELS,
} from "@/lib/indicators/constants";
import { findIndicators, insertIndicator, updateIndicatorRow } from "@/lib/indicators/repository";
import {
  createIndicatorSchema,
  indicatorListQuerySchema,
  parseIndicatorListParams,
  updateIndicatorSchema,
} from "@/lib/indicators/schema";
import {
  VALUE_HINTS,
  canonicalizeIndicatorValue,
  normalizeIndicatorValue,
  validateIndicatorValue,
} from "@/lib/indicators/value";
import { searchQuerySchema } from "@/lib/search/service";
import type { IndicatorType } from "@/types/domain";

const SHA256 = "a".repeat(64);

// The same shapes the database constraint tests use (supabase/tests/security.test.sql).
const VALID: Record<IndicatorType, string[]> = {
  ipv4: ["203.0.113.10", "0.0.0.0"],
  ipv6: ["2001:db8::1", "::1"],
  domain: ["malicious.example", "a-b.c-d.example.co", "xn--80ak6aa92e.example"],
  url: [
    "https://malicious.example/login?x=1#top",
    "http://198.51.100.23/gate.php",
    "http://host:8080",
  ],
  md5: ["d41d8cd98f00b204e9800998ecf8427e", "D41D8CD98F00B204E9800998ECF8427E"],
  sha1: ["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
  sha256: [SHA256],
  email: ["sender@malicious.example", "a.b+c@sub.example.org"],
  cve: ["CVE-2021-44228", "cve-2024-123456"],
  other: ["anything at all", "x"],
};
const INVALID: Record<IndicatorType, string[]> = {
  ipv4: ["999.1.1.1", "10.0.0.1/24", "1.2.3", "example.com", "::1"],
  ipv6: ["2001:db8::1/64", "203.0.113.10", "not:an:ip", "12345"],
  domain: [
    "localhost",
    "-bad.example",
    "bad-.example",
    "has space.example",
    "trailing.dot.example.",
    `${"a".repeat(64)}.example`,
    "http://x.example",
  ],
  url: [
    "example.com/path",
    "ftp://x.example",
    "https://",
    "https://a b.example",
    "javascript:alert(1)",
  ],
  md5: ["abc123", "z".repeat(32), "a".repeat(33)],
  sha1: ["a".repeat(39), "g".repeat(40)],
  sha256: ["a".repeat(63), "z".repeat(64)],
  email: ["no-at-sign", "a@b", "a b@c.example", "a@@b.example"],
  cve: ["CVE-21-44228", "CVE-2021-1", "2021-44228", "CVE-2021-44228x"],
  other: [""],
};

describe("validateIndicatorValue", () => {
  it.each(INDICATOR_TYPES)("accepts well-formed %s values", (type) => {
    for (const value of VALID[type]) expect(validateIndicatorValue(type, value), value).toBeNull();
  });

  it.each(INDICATOR_TYPES)("rejects malformed %s values with that type's message", (type) => {
    for (const value of INVALID[type]) {
      expect(validateIndicatorValue(type, value), value).toBe(VALUE_HINTS[type].error);
    }
  });

  it("has a label, short label and hint for every type", () => {
    for (const type of INDICATOR_TYPES) {
      expect(INDICATOR_TYPE_LABELS[type]).toBeTruthy();
      expect(INDICATOR_TYPE_SHORT_LABELS[type]).toBeTruthy();
      expect(VALUE_HINTS[type].placeholder).toBeTruthy();
    }
  });
});

describe("value canonicalization", () => {
  it("lower-cases hosts, addresses, hashes and emails; upper-cases CVE ids; leaves URLs alone", () => {
    expect(canonicalizeIndicatorValue("domain", "Login.EXAMPLE")).toBe("login.example");
    expect(canonicalizeIndicatorValue("md5", "D41D8CD98F00B204E9800998ECF8427E")).toBe(
      "d41d8cd98f00b204e9800998ecf8427e",
    );
    expect(canonicalizeIndicatorValue("email", "Boss@Example.ORG")).toBe("boss@example.org");
    expect(canonicalizeIndicatorValue("cve", "cve-2021-44228")).toBe("CVE-2021-44228");
    expect(canonicalizeIndicatorValue("url", "https://Example.com/Path")).toBe(
      "https://Example.com/Path",
    );
    expect(canonicalizeIndicatorValue("other", "Mixed Case")).toBe("Mixed Case");
  });

  it("normalizes the duplicate key exactly like the value_normalized column", () => {
    expect(normalizeIndicatorValue("cve", "cve-2021-44228")).toBe("CVE-2021-44228");
    expect(normalizeIndicatorValue("url", "https://Example.com/Path")).toBe(
      "https://Example.com/Path",
    );
    expect(normalizeIndicatorValue("other", "Mixed Case")).toBe("mixed case");
    expect(normalizeIndicatorValue("domain", "A.EXAMPLE")).toBe("a.example");
  });
});

describe("createIndicatorSchema", () => {
  const parse = (input: unknown) => createIndicatorSchema.safeParse(input);

  it("trims, canonicalizes the value and turns a blank description into null", () => {
    const result = parse({ type: "domain", value: "  Login.EXAMPLE ", description: "   " });
    expect(result.success && result.data).toMatchObject({
      value: "login.example",
      description: null,
    });
  });

  it("reports a bad value on the value field", () => {
    const result = parse({ type: "ipv4", value: "999.1.1.1" });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]).toMatchObject({
        path: ["value"],
        message: VALUE_HINTS.ipv4.error,
      });
    }
  });

  it("refuses fields a client must not set (origin, owner, ids, timestamps)", () => {
    for (const extra of [
      { origin: "external" },
      { created_by: "x" },
      { id: "x" },
      { created_at: "x" },
    ]) {
      expect(
        parse({ type: "domain", value: "a.example", ...extra }).success,
        JSON.stringify(extra),
      ).toBe(false);
    }
  });

  it("bounds confidence and requires whole numbers", () => {
    for (const confidence of [-1, 101, 50.5, "50"]) {
      expect(
        parse({ type: "domain", value: "a.example", confidence }).success,
        String(confidence),
      ).toBe(false);
    }
    expect(parse({ type: "domain", value: "a.example", confidence: 0 }).success).toBe(true);
    expect(parse({ type: "domain", value: "a.example", confidence: 100 }).success).toBe(true);
  });

  it("rejects last_seen before first_seen and accepts offsets", () => {
    const early = "2026-01-01T00:00:00Z";
    const late = "2026-02-01T00:00:00+02:00";
    expect(
      parse({ type: "domain", value: "a.example", first_seen: late, last_seen: early }).success,
    ).toBe(false);
    expect(
      parse({ type: "domain", value: "a.example", first_seen: early, last_seen: late }).success,
    ).toBe(true);
    expect(parse({ type: "domain", value: "a.example", first_seen: "yesterday" }).success).toBe(
      false,
    );
  });

  it("de-duplicates tags ignoring case, keeps the first spelling, and enforces the limits", () => {
    const ok = parse({
      type: "domain",
      value: "a.example",
      tags: ["C2", " c2 ", "Phishing", "phishing"],
    });
    expect(ok.success && ok.data.tags).toEqual(["C2", "Phishing"]);

    const tooMany = Array.from({ length: 21 }, (_, index) => `tag${index}`);
    expect(parse({ type: "domain", value: "a.example", tags: tooMany }).success).toBe(false);
    expect(parse({ type: "domain", value: "a.example", tags: ["x".repeat(51)] }).success).toBe(
      false,
    );
    for (const bad of ["", " ", "<script>", "-leading", "a\nb"]) {
      expect(
        parse({ type: "domain", value: "a.example", tags: [bad] }).success,
        JSON.stringify(bad),
      ).toBe(false);
    }
    for (const good of [
      "c2",
      "ransomware",
      "CVE-2021",
      "windows 10",
      "t1566.001",
      "c#",
      "über-tag",
    ]) {
      expect(parse({ type: "domain", value: "a.example", tags: [good] }).success, good).toBe(true);
    }
  });
});

describe("updateIndicatorSchema", () => {
  it("needs at least one field and cannot change identity or provenance", () => {
    expect(updateIndicatorSchema.safeParse({}).success).toBe(false);
    for (const forbidden of [
      { value: "x" },
      { type: "url" },
      { origin: "demo" },
      { created_by: "x" },
    ]) {
      expect(updateIndicatorSchema.safeParse(forbidden).success, JSON.stringify(forbidden)).toBe(
        false,
      );
    }
  });

  it("accepts partial updates, clearing the description and replacing tags", () => {
    const result = updateIndicatorSchema.safeParse({ severity: "low", description: "", tags: [] });
    expect(result.success && result.data).toEqual({ severity: "low", description: null, tags: [] });
  });
});

describe("indicatorListQuerySchema", () => {
  it("applies the defaults", () => {
    expect(indicatorListQuerySchema.parse({})).toEqual({
      page: 1,
      page_size: 25,
      sort: "last_seen",
      order: "desc",
    });
  });

  it("treats blank form values as no filter and trims the search text", () => {
    const query = indicatorListQuerySchema.parse({
      q: "  phishing  ",
      type: "",
      status: "",
      tag: "",
    });
    expect(query).toMatchObject({ q: "phishing" });
    expect(query.type).toBeUndefined();
    expect(query.tag).toBeUndefined();
    expect(indicatorListQuerySchema.parse({ q: "   " }).q).toBe("");
  });

  it("only sorts by known columns and rejects unknown filter values", () => {
    for (const bad of [
      { sort: "password" },
      { sort: "value; drop table" },
      { order: "up" },
      { type: "nope" },
      { severity: "urgent" },
      { origin: "cloud" },
      { page_size: 101 },
      { q: "x".repeat(201) },
    ]) {
      expect(indicatorListQuerySchema.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
    }
  });
});

describe("parseIndicatorListParams (the list page must survive a hand-edited URL)", () => {
  it("parses valid parameters, taking the first of repeated ones", () => {
    const { query, ignoredInvalid } = parseIndicatorListParams({
      type: ["domain", "url"],
      page: "2",
    });
    expect(ignoredInvalid).toBe(false);
    expect(query).toMatchObject({ type: "domain", page: 2 });
  });

  it("falls back to the defaults and says so when something is invalid", () => {
    const { query, ignoredInvalid } = parseIndicatorListParams({ type: "nope", page: "2" });
    expect(ignoredInvalid).toBe(true);
    expect(query).toMatchObject({ page: 1, sort: "last_seen" });
    expect(query.type).toBeUndefined();
  });
});

describe("searchQuerySchema", () => {
  it("needs two characters and caps the group size", () => {
    expect(searchQuerySchema.safeParse({ q: "a" }).success).toBe(false);
    expect(searchQuerySchema.safeParse({ q: " a " }).success).toBe(false);
    expect(searchQuerySchema.parse({ q: " ab " })).toEqual({ q: "ab", limit: 6 });
    expect(searchQuerySchema.safeParse({ q: "ab", limit: 11 }).success).toBe(false);
  });
});

// A stand-in for the query builder: every call returns itself and awaiting yields `result`.
function fakeClient(results: Record<string, unknown>) {
  const calls: string[] = [];
  const builder = (table: string) => {
    const chain: Record<string, unknown> = {};
    for (const method of ["insert", "update", "select", "eq", "single", "maybeSingle"]) {
      chain[method] = (...args: unknown[]) => {
        calls.push(`${table}.${method}(${args.map(String).join(",")})`);
        return method === "single" || method === "maybeSingle"
          ? Promise.resolve(results[`${table}.${method}`] ?? results[table])
          : chain;
      };
    }
    return chain;
  };
  return { client: { from: builder } as never, calls };
}

async function rejection(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("Expected a rejection");
}

describe("repository error mapping", () => {
  vi.spyOn(console, "error").mockImplementation(() => {});

  it("turns a duplicate into a 409 that names the existing indicator", async () => {
    const { client, calls } = fakeClient({
      "indicators.single": {
        data: null,
        error: {
          code: "23505",
          message: 'duplicate key value violates unique constraint "indicators_type_value_key"',
        },
      },
      "indicators.maybeSingle": { data: { id: "existing-id" }, error: null },
    });
    const error = await rejection(
      insertIndicator(client, { type: "domain", value: "Dup.Example" }),
    );
    expect([error.status, error.code]).toEqual([409, "CONFLICT"]);
    expect(error.details).toEqual({ existing_id: "existing-id" });
    // The lookup uses the normalized value, like the database's unique key.
    expect(calls.some((call) => call === "indicators.eq(value_normalized,dup.example)")).toBe(true);
  });

  it("still answers 409 when the existing row cannot be looked up", async () => {
    const { client } = fakeClient({
      "indicators.single": { data: null, error: { code: "23505", message: "dup" } },
      "indicators.maybeSingle": { data: null, error: { code: "42501", message: "denied" } },
    });
    const error = await rejection(
      insertIndicator(client, { type: "domain", value: "dup.example" }),
    );
    expect(error.status).toBe(409);
    expect(error.details).toBeUndefined();
  });

  it("names the field for check-constraint failures instead of a generic message", async () => {
    const seen = fakeClient({
      "indicators.maybeSingle": {
        data: null,
        error: {
          code: "23514",
          message:
            'new row for relation "indicators" violates check constraint "indicators_seen_order"',
        },
      },
    });
    const seenError = await rejection(
      updateIndicatorRow(seen.client, "id", { last_seen: "2000-01-01T00:00:00Z" }),
    );
    expect(seenError.status).toBe(422);
    expect(seenError.details).toEqual({
      issues: [{ path: "last_seen", message: "Last seen cannot be earlier than first seen." }],
    });

    const value = fakeClient({
      "indicators.single": {
        data: null,
        error: { code: "23514", message: 'violates check constraint "indicators_value_valid"' },
      },
    });
    const valueError = await rejection(
      insertIndicator(value.client, { type: "ipv4", value: "1.2.3.4" }),
    );
    expect(valueError.details).toEqual({
      issues: [{ path: "value", message: VALUE_HINTS.ipv4.error }],
    });
  });

  it("maps a row-level-security refusal to 403 and hides unknown database errors", async () => {
    const denied = fakeClient({
      "indicators.single": {
        data: null,
        error: { code: "42501", message: "new row violates row-level security policy" },
      },
    });
    expect(
      (await rejection(insertIndicator(denied.client, { type: "domain", value: "a.example" })))
        .status,
    ).toBe(403);

    const broken = fakeClient({
      "indicators.single": {
        data: null,
        error: { code: "XX000", message: "relation secret_table is broken" },
      },
    });
    const error = await rejection(
      insertIndicator(broken.client, { type: "domain", value: "a.example" }),
    );
    expect(error.status).toBe(500);
    expect(error.message).not.toContain("secret_table");
  });

  it("returns null for an update that matched no visible row", async () => {
    const { client } = fakeClient({ "indicators.maybeSingle": { data: null, error: null } });
    expect(await updateIndicatorRow(client, "id", { severity: "low" })).toBeNull();
  });
});

describe("findIndicators paging", () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const query = indicatorListQuerySchema.parse({ page: 99 });

  // rpc() -> chain of eq/order/range; each awaited range() yields the next canned result.
  function fakeRpc(results: unknown[]) {
    let call = 0;
    const builder: Record<string, unknown> = {};
    builder.eq = () => builder;
    builder.order = () => builder;
    builder.range = () => Promise.resolve(results[call++]);
    return { client: { rpc: () => builder } as never, calls: () => call };
  }

  it("returns no rows but the real total for a page past the end (PostgREST refuses that range)", async () => {
    const { client, calls } = fakeRpc([
      {
        data: null,
        error: { code: "PGRST103", message: "Requested range not satisfiable" },
        count: null,
      },
      { data: [{ id: "x" }], error: null, count: 41 },
    ]);
    expect(await findIndicators(client, query)).toEqual({ rows: [], total: 41 });
    expect(calls()).toBe(2);
  });

  it("returns the page as usual otherwise, and maps other errors", async () => {
    const ok = fakeRpc([{ data: [{ id: "a" }], error: null, count: 3 }]);
    expect(await findIndicators(ok.client, query)).toEqual({ rows: [{ id: "a" }], total: 3 });

    const broken = fakeRpc([
      { data: null, error: { code: "XX000", message: "boom" }, count: null },
    ]);
    await expect(findIndicators(broken.client, query)).rejects.toMatchObject({ status: 500 });
  });
});
