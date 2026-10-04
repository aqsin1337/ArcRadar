/** First value of a Next.js search param (which is a string, an array, or missing). */
export function firstParam(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
