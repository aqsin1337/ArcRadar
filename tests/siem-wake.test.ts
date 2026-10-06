import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/siem-rules/wake-repository", () => ({ readRevision: vi.fn() }));

const { WAKE_MAX_WAIT_SECONDS, waitForPush } = await import("@/lib/siem-rules/wake");

/** A fake clock: sleeping moves time forward, so a 25 s wait takes no real time. */
function clock(revisions: string[]) {
  let time = 0;
  let calls = 0;
  return {
    deps: {
      revision: vi.fn(async () => revisions[Math.min(calls++, revisions.length - 1)]),
      sleep: vi.fn(async (ms: number) => {
        time += ms;
      }),
      now: () => time,
    },
    elapsed: () => time,
  };
}

describe("waitForPush", () => {
  it("answers at once with the current revision when the host has none yet", async () => {
    const { deps, elapsed } = clock(["2026-10-06 10:00:00+00"]);
    const answer = await waitForPush("splunk", null, 25, undefined, deps);
    expect(answer).toEqual({ revision: "2026-10-06 10:00:00+00", changed: false });
    expect(elapsed()).toBe(0);
  });

  it("answers at once when something was pushed since the revision the host saw", async () => {
    const { deps, elapsed } = clock(["rev2"]);
    expect(await waitForPush("splunk", "rev1", 25, undefined, deps)).toEqual({
      revision: "rev2",
      changed: true,
    });
    expect(elapsed()).toBe(0);
  });

  it("waits, and answers the moment a push appears", async () => {
    const { deps, elapsed } = clock(["rev1", "rev1", "rev1", "rev2"]);
    expect(await waitForPush("splunk", "rev1", 25, undefined, deps)).toEqual({
      revision: "rev2",
      changed: true,
    });
    expect(elapsed()).toBe(3000);
  });

  it("gives up after the wait with nothing new, never earlier", async () => {
    const { deps, elapsed } = clock(["rev1"]);
    expect(await waitForPush("splunk", "rev1", 5, undefined, deps)).toEqual({
      revision: "rev1",
      changed: false,
    });
    expect(elapsed()).toBe(5000);
  });

  it("never waits longer than the maximum, however much is asked", async () => {
    const { deps, elapsed } = clock(["rev1"]);
    await waitForPush("splunk", "rev1", 9999, undefined, deps);
    expect(elapsed()).toBe(WAKE_MAX_WAIT_SECONDS * 1000);
  });

  it("does not wait at all for wait=0", async () => {
    const { deps, elapsed } = clock(["rev1"]);
    expect(await waitForPush("splunk", "rev1", 0, undefined, deps)).toEqual({
      revision: "rev1",
      changed: false,
    });
    expect(elapsed()).toBe(0);
  });

  it("stops waiting when the host hangs up", async () => {
    const controller = new AbortController();
    const { deps } = clock(["rev1"]);
    deps.sleep.mockImplementation(async () => controller.abort());
    const answer = await waitForPush("splunk", "rev1", 25, controller.signal, deps);
    expect(answer.changed).toBe(false);
    expect(deps.sleep).toHaveBeenCalledTimes(1);
  });

  it("an empty revision (nothing ever pushed) is a revision like any other", async () => {
    const { deps } = clock(["", "", "2026-10-06 10:00:00+00"]);
    expect(await waitForPush("splunk", "", 25, undefined, deps)).toEqual({
      revision: "2026-10-06 10:00:00+00",
      changed: true,
    });
  });
});
