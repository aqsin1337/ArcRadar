import "server-only";
import type { SiemId } from "./constants";
import { readRevision } from "./wake-repository";

/** The longest one request waits. Short enough for every proxy in between, long enough to be cheap. */
export const WAKE_MAX_WAIT_SECONDS = 25;
const POLL_MS = 1000;

export type WakeDeps = {
  revision: (siem: SiemId) => Promise<string>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
};

const defaultDeps = (): WakeDeps => ({
  revision: readRevision,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  now: () => Date.now(),
});

/**
 * "Tell me when a rule is pushed." The SIEM host keeps one request open: it sends the revision it last saw
 * (`since`) and is answered as soon as the latest push is newer, or after `waitSeconds` with nothing new, and
 * asks again. Without `since` (its first call) it is answered at once with the current revision. This replaces
 * asking on a timer: a push reaches the SIEM host within about a second, and no port of the SIEM is opened.
 */
export async function waitForPush(
  siem: SiemId,
  since: string | null,
  waitSeconds: number,
  signal?: AbortSignal,
  deps: WakeDeps = defaultDeps(),
): Promise<{ revision: string; changed: boolean }> {
  const deadline = deps.now() + Math.max(0, Math.min(waitSeconds, WAKE_MAX_WAIT_SECONDS)) * 1000;
  let revision = await deps.revision(siem);
  if (since === null) return { revision, changed: false };
  if (revision !== since) return { revision, changed: true };
  while (!signal?.aborted && deps.now() < deadline) {
    await deps.sleep(Math.min(POLL_MS, Math.max(0, deadline - deps.now())));
    revision = await deps.revision(siem);
    if (revision !== since) return { revision, changed: true };
  }
  return { revision, changed: false };
}
