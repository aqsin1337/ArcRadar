import { describe, expect, it } from "vitest";
import { EnvError } from "@/lib/env/parse";
import { parsePublicEnv } from "@/lib/env/public";
import { parseServerEnv } from "@/lib/env/server";

describe("parsePublicEnv", () => {
  const valid = {
    NEXT_PUBLIC_SUPABASE_URL: "http://127.0.0.1:54321",
    NEXT_PUBLIC_SUPABASE_ANON_KEY: "anon-key",
  };

  it("accepts valid values and defaults the app URL", () => {
    expect(parsePublicEnv(valid)).toEqual({
      ...valid,
      NEXT_PUBLIC_APP_URL: "http://localhost:3000",
    });
  });

  it("rejects a missing key and a malformed URL, naming only the variables", () => {
    const error = catchError(() =>
      parsePublicEnv({ NEXT_PUBLIC_SUPABASE_URL: "not a url secret-value" }),
    );
    expect(error).toBeInstanceOf(EnvError);
    expect((error as EnvError).variables.sort()).toEqual([
      "NEXT_PUBLIC_SUPABASE_ANON_KEY",
      "NEXT_PUBLIC_SUPABASE_URL",
    ]);
    expect((error as EnvError).message).not.toContain("secret-value");
  });
});

describe("parseServerEnv", () => {
  it("requires the service-role key", () => {
    expect(() => parseServerEnv({})).toThrow(EnvError);
  });

  it("treats empty provider keys as not configured", () => {
    const env = parseServerEnv({
      SUPABASE_SERVICE_ROLE_KEY: "service-key",
      VIRUSTOTAL_API_KEY: "",
      ABUSEIPDB_API_KEY: "   ",
      OTX_API_KEY: "otx-key",
    });
    expect(env.VIRUSTOTAL_API_KEY).toBeUndefined();
    expect(env.ABUSEIPDB_API_KEY).toBeUndefined();
    expect(env.OTX_API_KEY).toBe("otx-key");
    expect(env.SHODAN_API_KEY).toBeUndefined();
  });

  it("works with no external provider keys at all (demo mode)", () => {
    expect(
      parseServerEnv({ SUPABASE_SERVICE_ROLE_KEY: "service-key" }).SUPABASE_SERVICE_ROLE_KEY,
    ).toBe("service-key");
  });
});

function catchError(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("expected the function to throw");
}
