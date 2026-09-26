/** Joins class names, skipping falsy values. (No Tailwind class merging: variants are written to not clash.) */
export function cn(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}
