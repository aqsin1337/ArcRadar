import { describe, expect, it } from "vitest";
import { ApiError } from "@/lib/api/errors";
import { requireTarget } from "@/lib/intel/service";
import {
  detectKind,
  externalSkipReason,
  ipv6Groups,
  isPublicIpv4,
  isPublicIpv6,
  isReservedHostname,
  parseTarget,
  type IntelTarget,
} from "@/lib/intel/target";
import type { IntelKind } from "@/lib/intel/types";

const target = (kind: IntelKind, value: string): IntelTarget => {
  const parsed = parseTarget(kind, value);
  if (!parsed.ok) throw new Error(`fixture ${value} is not a valid ${kind}: ${parsed.error}`);
  return parsed.target;
};

describe("parseTarget", () => {
  it("accepts and canonicalizes an IPv4 and an IPv6 address", () => {
    expect(target("ip", " 203.0.113.10 ")).toMatchObject({
      value: "203.0.113.10",
      version: 4,
      indicatorType: "ipv4",
    });
    expect(target("ip", "2001:DB8::ABCD")).toMatchObject({
      value: "2001:db8::abcd",
      version: 6,
      indicatorType: "ipv6",
    });
  });

  it("rejects malformed addresses and points at the right lookup when it can", () => {
    for (const bad of ["999.1.1.1", "10.0.0.1/24", "1.2.3", "2001:db8::/32", "::g"]) {
      const result = parseTarget("ip", bad);
      expect(result.ok, bad).toBe(false);
    }
    expect(parseTarget("ip", "login.example")).toMatchObject({
      ok: false,
      suggestion: { kind: "domain", value: "login.example" },
    });
    expect(parseTarget("ip", "")).toMatchObject({ ok: false, suggestion: null });
    expect(parseTarget("ip", "9".repeat(3000))).toMatchObject({ ok: false });
  });

  it("lower-cases domains and refuses URLs, paths and trailing dots", () => {
    expect(target("domain", "Login.EXAMPLE")).toMatchObject({
      value: "login.example",
      indicatorType: "domain",
    });
    expect(parseTarget("domain", "https://login.example/x")).toMatchObject({
      ok: false,
      suggestion: { kind: "url" },
    });
    for (const bad of ["localhost", "trailing.dot.example.", "-bad.example", "has space.example"]) {
      expect(parseTarget("domain", bad).ok, bad).toBe(false);
    }
  });

  it("accepts http(s) URLs as typed, extracts the host and flags credentials", () => {
    expect(target("url", "https://Login.Example/Account?x=1#top")).toMatchObject({
      value: "https://Login.Example/Account?x=1#top",
      host: "login.example",
      hasCredentials: false,
    });
    expect(target("url", "http://[2001:db8::1]:8080/a")).toMatchObject({ host: "2001:db8::1" });
    expect(target("url", "https://user:secret@login.example/")).toMatchObject({
      hasCredentials: true,
    });
    for (const bad of [
      "ftp://x.example",
      "javascript:alert(1)",
      "login.example/path",
      "https://",
    ]) {
      expect(parseTarget("url", bad).ok, bad).toBe(false);
    }
  });

  it("recognizes MD5, SHA-1 and SHA-256 by length and lower-cases them", () => {
    expect(target("hash", "D41D8CD98F00B204E9800998ECF8427E")).toMatchObject({
      hashType: "md5",
      value: "d41d8cd98f00b204e9800998ecf8427e",
      indicatorType: "md5",
    });
    expect(target("hash", "a".repeat(40))).toMatchObject({ hashType: "sha1" });
    expect(target("hash", "b".repeat(64))).toMatchObject({ hashType: "sha256" });
    for (const bad of ["abc123", "z".repeat(32), "a".repeat(33), "a".repeat(65)]) {
      expect(parseTarget("hash", bad).ok, bad).toBe(false);
    }
    expect(parseTarget("hash", "203.0.113.10")).toMatchObject({
      ok: false,
      suggestion: { kind: "ip" },
    });
  });
});

describe("detectKind", () => {
  it.each([
    ["203.0.113.10", "ip"],
    ["2001:db8::1", "ip"],
    ["Login.Example", "domain"],
    ["https://login.example/a", "url"],
    ["d41d8cd98f00b204e9800998ecf8427e", "hash"],
    ["DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "hash"],
    ["cve-2021-44228", "cve"],
  ] as const)("%s is a %s", (value, kind) => {
    expect(detectKind(value)?.kind).toBe(kind);
  });

  it("does not mistake a dotted quad for a domain, and says nothing about plain words", () => {
    expect(detectKind("1.2.3.44")?.kind).toBe("ip");
    // Numbers with dots that are not addresses are not domains either: no real TLD is all digits.
    for (const value of ["198.51", "1.2.3.400", "999.1.1.1", "10.0.0"]) {
      expect(detectKind(value), value).toBeNull();
    }
    expect(detectKind("harbor")).toBeNull();
    expect(detectKind("")).toBeNull();
    expect(detectKind("a".repeat(5000))).toBeNull();
  });

  it("canonicalizes what it finds", () => {
    expect(detectKind("CVE-2021-44228")).toEqual({ kind: "cve", value: "CVE-2021-44228" });
    expect(detectKind("LOGIN.EXAMPLE")).toEqual({ kind: "domain", value: "login.example" });
  });
});

describe("public address checks (nothing private or reserved leaves the workspace)", () => {
  it.each([
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "172.15.255.255",
    "172.32.0.1",
    "100.63.255.255",
    "100.128.0.1",
    "192.169.0.1",
  ])("%s is public", (ip) => expect(isPublicIpv4(ip)).toBe(true));

  it.each([
    "0.0.0.0",
    "10.1.2.3",
    "100.64.0.1",
    "100.127.255.255",
    "127.0.0.1",
    "169.254.10.10",
    "172.16.0.1",
    "172.31.255.255",
    "192.0.0.5",
    "192.0.2.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.19.255.255",
    "198.51.100.23",
    "203.0.113.45",
    "224.0.0.1",
    "255.255.255.255",
  ])("%s is not public", (ip) => expect(isPublicIpv4(ip)).toBe(false));

  it.each(["2606:4700:4700::1111", "2a00:1450:4001:81b::200e", "2001:4860:4860::8888"])(
    "%s is public",
    (ip) => expect(isPublicIpv6(ip)).toBe(true),
  );

  it.each([
    "::",
    "::1",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "ff02::1",
    "2001:db8::1",
    "2001:db8:bad:1::5",
    "2001:0:4136:e378::1",
    "2002:c000:204::1",
    "3fff:abc::1",
    "::ffff:192.0.2.1",
  ])("%s is not public", (ip) => expect(isPublicIpv6(ip)).toBe(false));

  it("expands IPv6 addresses to eight groups and rejects malformed ones", () => {
    expect(ipv6Groups("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(ipv6Groups("::")).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(ipv6Groups("2001:DB8::")).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]);
    expect(ipv6Groups("1:2:3:4:5:6:7:8")).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(ipv6Groups("::ffff:192.0.2.1")).toEqual([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201]);
    expect(ipv6Groups("1::2::3")).toBeNull();
    expect(ipv6Groups("1:2:3:4:5:6:7:8:9")).toBeNull();
    expect(ipv6Groups("1:2:3")).toBeNull();
    expect(ipv6Groups("12345::1")).toBeNull();
  });

  it("knows the names that cannot exist on the public DNS", () => {
    for (const host of [
      "a.example",
      "x.test",
      "a.b.invalid",
      "localhost",
      "printer.local",
      "example.com",
      "www.example.com",
      "a.example.org",
      "corp.internal",
      "1.0.0.127.in-addr.arpa",
      "abc.onion",
    ]) {
      expect(isReservedHostname(host), host).toBe(true);
    }
    for (const host of [
      "google.com",
      "notexample.com",
      "example.org.uk",
      "test.example.co.uk",
      "myexample.net",
    ]) {
      expect(isReservedHostname(host), host).toBe(false);
    }
  });
});

describe("externalSkipReason", () => {
  it("lets public subjects go and holds back private, reserved and credentialed ones", () => {
    expect(externalSkipReason(target("ip", "8.8.8.8"))).toBeNull();
    expect(externalSkipReason(target("ip", "10.0.0.5"))).toBe("not_public");
    expect(externalSkipReason(target("ip", "198.51.100.23"))).toBe("not_public");
    expect(externalSkipReason(target("ip", "2001:db8::1"))).toBe("not_public");
    expect(externalSkipReason(target("ip", "2606:4700:4700::1111"))).toBeNull();

    expect(externalSkipReason(target("domain", "google.com"))).toBeNull();
    expect(externalSkipReason(target("domain", "login.example"))).toBe("not_public");

    expect(externalSkipReason(target("url", "https://google.com/search?q=a"))).toBeNull();
    expect(externalSkipReason(target("url", "https://login.example/a"))).toBe("not_public");
    expect(externalSkipReason(target("url", "http://192.168.0.10/admin"))).toBe("not_public");
    expect(externalSkipReason(target("url", "http://[fe80::1]/a"))).toBe("not_public");
    expect(externalSkipReason(target("url", "https://user:pw@google.com/"))).toBe(
      "has_credentials",
    );

    expect(externalSkipReason(target("hash", "a".repeat(64)))).toBeNull();
  });
});

describe("requireTarget", () => {
  it("returns the target, or a 422 naming the value field", () => {
    expect(requireTarget("ip", "8.8.8.8")).toMatchObject({ kind: "ip", value: "8.8.8.8" });
    try {
      requireTarget("ip", "nope");
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ApiError);
      const api = error as ApiError;
      expect(api.status).toBe(422);
      expect(api.details).toEqual({
        issues: [{ path: "value", message: expect.stringContaining("IPv4 or IPv6") }],
      });
    }
  });
});
