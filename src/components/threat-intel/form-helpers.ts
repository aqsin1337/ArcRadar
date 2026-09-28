/** "a, b ,, c" -> ["a", "b", "c"]. The schemas trim and drop duplicates as well. */
export function splitList(text: string): string[] {
  return text
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

export const joinList = (values: readonly string[]) => values.join(", ");

/** A local date-time from the browser -> an ISO timestamp with offset ("" -> null). */
export function toIsoOrNull(local: string): string | null {
  if (!local) return null;
  const date = new Date(local);
  return Number.isNaN(date.getTime()) ? local : date.toISOString();
}

/**
 * The date fields of a form as a request body. On create empty dates are simply left out; on edit only
 * dates the user changed are sent (the field has minute precision, so echoing an untouched value back
 * would drop its seconds), and clearing one sends `null`.
 */
export function dateBody(
  mode: "create" | "edit",
  values: { first_seen: string; last_seen: string },
  initial: { first_seen: string; last_seen: string },
): { first_seen?: string | null; last_seen?: string | null } {
  const body: { first_seen?: string | null; last_seen?: string | null } = {};
  for (const key of ["first_seen", "last_seen"] as const) {
    if (mode === "create") {
      const iso = toIsoOrNull(values[key]);
      if (iso) body[key] = iso;
    } else if (values[key] !== initial[key]) {
      body[key] = toIsoOrNull(values[key]);
    }
  }
  return body;
}
