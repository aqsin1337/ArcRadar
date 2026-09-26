import { describe, expect, it } from "vitest";
import { z } from "zod";
import { ApiError } from "@/lib/api/errors";
import { buildPage, paginationQuerySchema, toRange } from "@/lib/api/pagination";
import { parseJsonBody, parseQuery, parseWith } from "@/lib/api/validate";
import { safeRedirectPath } from "@/lib/auth/redirect";
import { auditLogQuerySchema } from "@/lib/audit/query";
import {
  emailSchema,
  forgotPasswordSchema,
  loginSchema,
  newPasswordSchema,
  signupSchema,
} from "@/lib/validation/auth";

function jsonRequest(body: BodyInit | null, headers: Record<string, string> = {}) {
  return new Request("http://localhost/api/x", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
  });
}

async function rejection(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("Expected the promise to reject");
}

describe("parseJsonBody", () => {
  const schema = z.strictObject({ name: z.string().min(2) });

  it("returns validated data", async () => {
    expect(await parseJsonBody(jsonRequest('{"name":"ab"}'), schema)).toEqual({ name: "ab" });
  });

  it("accepts a charset parameter on the content type", async () => {
    const request = jsonRequest('{"name":"ab"}', {
      "content-type": "application/json; charset=utf-8",
    });
    expect(await parseJsonBody(request, schema)).toEqual({ name: "ab" });
  });

  it("rejects other content types with 415", async () => {
    const error = await rejection(
      parseJsonBody(jsonRequest("name=ab", { "content-type": "text/plain" }), schema),
    );
    expect([error.status, error.code]).toEqual([415, "UNSUPPORTED_MEDIA_TYPE"]);
  });

  it("rejects an empty body and malformed JSON with 400", async () => {
    expect((await rejection(parseJsonBody(jsonRequest(""), schema))).status).toBe(400);
    expect((await rejection(parseJsonBody(jsonRequest("{nope"), schema))).status).toBe(400);
  });

  it("rejects an oversized body with 413, by header and by counting", async () => {
    const big = JSON.stringify({ name: "x".repeat(200) });
    const byBytes = await rejection(parseJsonBody(jsonRequest(big), schema, 100));
    expect(byBytes.status).toBe(413);

    const byHeader = await rejection(
      parseJsonBody(jsonRequest('{"name":"ab"}', { "content-length": "999999" }), schema, 100),
    );
    expect(byHeader.status).toBe(413);
  });

  it("reports invalid data as 422 with per-field issues and no submitted values", async () => {
    const error = await rejection(
      parseJsonBody(jsonRequest('{"name":"a","extra":"SECRET-VALUE"}'), schema),
    );
    expect([error.status, error.code]).toEqual([422, "VALIDATION_ERROR"]);
    const details = error.details as { issues: { path: string; message: string }[] };
    expect(details.issues.map((issue) => issue.path).sort()).toEqual(["", "name"]);
    expect(JSON.stringify(details)).not.toContain("SECRET-VALUE");
  });
});

describe("parseQuery / pagination", () => {
  it("applies defaults and coerces numbers", () => {
    const empty = new Request("http://localhost/api/x");
    expect(parseQuery(empty, paginationQuerySchema)).toEqual({ page: 1, page_size: 25 });

    const custom = new Request("http://localhost/api/x?page=3&page_size=10&unknown=1");
    expect(parseQuery(custom, paginationQuerySchema)).toEqual({ page: 3, page_size: 10 });
  });

  it("rejects out-of-range values", () => {
    for (const query of ["page=0", "page_size=101", "page_size=abc", "page=1.5"]) {
      expect(() =>
        parseQuery(new Request(`http://localhost/api/x?${query}`), paginationQuerySchema),
      ).toThrow(ApiError);
    }
  });

  it("collects repeated keys into arrays", () => {
    const schema = z.object({ tag: z.array(z.string()) });
    const request = new Request("http://localhost/api/x?tag=a&tag=b");
    expect(parseQuery(request, schema)).toEqual({ tag: ["a", "b"] });
  });

  it("computes ranges and page metadata", () => {
    expect(toRange({ page: 1, page_size: 25 })).toEqual({ from: 0, to: 24 });
    expect(toRange({ page: 3, page_size: 10 })).toEqual({ from: 20, to: 29 });
    expect(buildPage(["a"], 41, { page: 2, page_size: 20 }).pagination).toEqual({
      page: 2,
      page_size: 20,
      total: 41,
      total_pages: 3,
    });
  });

  it("validates audit log filters", () => {
    const ok = parseWith(auditLogQuerySchema, {
      action: "auth.login",
      user_id: "3f2b8c1e-8d0a-4c53-9f5d-2b6a7c9e1d10",
      from: "2026-09-01T00:00:00Z",
    });
    expect(ok.page).toBe(1);
    for (const bad of [{ action: "Auth Login" }, { user_id: "nope" }, { from: "yesterday" }]) {
      expect(() => parseWith(auditLogQuerySchema, bad)).toThrow(ApiError);
    }
  });
});

describe("auth schemas", () => {
  it("normalizes email and rejects invalid ones", () => {
    expect(emailSchema.parse("  Analyst@ArcRadar.TEST ")).toBe("analyst@arcradar.test");
    expect(emailSchema.safeParse("not-an-email").success).toBe(false);
    expect(emailSchema.safeParse(`${"a".repeat(250)}@x.io`).success).toBe(false);
  });

  it("enforces the password policy on new passwords", () => {
    expect(newPasswordSchema.safeParse("ArcRadar-Demo-1!").success).toBe(true);
    for (const weak of [
      "Short1a",
      "alllowercase123",
      "ALLUPPERCASE123",
      "NoDigitsHereAtAll",
      "A1b".repeat(30),
    ]) {
      expect(newPasswordSchema.safeParse(weak).success, weak).toBe(false);
    }
  });

  it("does not apply the policy at login, only a size bound", () => {
    expect(loginSchema.safeParse({ email: "a@b.io", password: "old" }).success).toBe(true);
    expect(loginSchema.safeParse({ email: "a@b.io", password: "" }).success).toBe(false);
  });

  it("rejects unknown fields so a role cannot be smuggled in", () => {
    const result = signupSchema.safeParse({
      email: "a@b.io",
      password: "ArcRadar-Demo-1!",
      role_name: "admin",
    });
    expect(result.success).toBe(false);
    expect(forgotPasswordSchema.safeParse({ email: "a@b.io", extra: 1 }).success).toBe(false);
  });
});

describe("safeRedirectPath", () => {
  it("keeps same-site paths", () => {
    expect(safeRedirectPath("/reset-password")).toBe("/reset-password");
    expect(safeRedirectPath("/dashboard?tab=1#x")).toBe("/dashboard?tab=1#x");
  });

  it("blocks anything that can leave the site", () => {
    for (const bad of [
      "//evil.com",
      "/\\evil.com",
      "https://evil.com",
      "javascript:alert(1)",
      "evil.com",
      "/ok\nLocation: x",
      "",
      null,
      undefined,
    ]) {
      expect(safeRedirectPath(bad, "/home")).toBe("/home");
    }
  });
});
