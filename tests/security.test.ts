import { describe, expect, it } from "vitest";
import { buildCsp } from "@/lib/security/csp";

describe("buildCsp", () => {
  it("locks scripts and styles to the given nonce, with a same-origin fallback", () => {
    const csp = buildCsp("abc123", true);
    expect(csp).toContain("script-src 'self' 'nonce-abc123' 'strict-dynamic'");
    expect(csp).toContain("style-src 'self' 'nonce-abc123'");
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("never allows unnonced inline content, and never lets a script load as a data: URI", () => {
    const csp = buildCsp("abc123", true);
    expect(csp).not.toContain("unsafe-inline");
    const scriptSrc = csp.split("; ").find((directive) => directive.startsWith("script-src"));
    expect(scriptSrc).not.toContain("data:");
  });

  it("adds 'unsafe-eval' (React's own debug-mode eval) only outside production", () => {
    expect(buildCsp("n", false)).toContain("'unsafe-eval'");
    expect(buildCsp("n", true)).not.toContain("'unsafe-eval'");
  });

  it("only tells the browser to upgrade to https in production (dev and local nginx are plain http)", () => {
    expect(buildCsp("n", true)).toContain("upgrade-insecure-requests");
    expect(buildCsp("n", false)).not.toContain("upgrade-insecure-requests");
  });

  it("never talks to a third-party origin: the browser only ever calls this app's own /api/*", () => {
    const csp = buildCsp("n", true);
    expect(csp).toContain("connect-src 'self'");
    expect(csp).not.toMatch(/https?:\/\//); // no external host is named anywhere in the policy
  });
});
