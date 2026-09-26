import { describe, expect, it } from "vitest";
import { fail, ok } from "@/lib/api/response";

describe("API response envelope", () => {
  it("wraps success data", async () => {
    const response = ok({ id: 1 });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ success: true, data: { id: 1 }, error: null });
  });

  it("wraps errors with the given status and code", async () => {
    const response = fail(422, "VALIDATION_ERROR", "Invalid input.", { field: "value" });
    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({
      success: false,
      data: null,
      error: { code: "VALIDATION_ERROR", message: "Invalid input.", details: { field: "value" } },
    });
  });

  it("omits details when none are given", async () => {
    const body = await fail(404, "NOT_FOUND", "Missing.").json();
    expect(body.error).toEqual({ code: "NOT_FOUND", message: "Missing." });
  });
});
