import { apiErrors } from "@/lib/api/errors";
import { isSiemId, type SiemId } from "./constants";

/** The `:siem` segment of a route. An unknown SIEM is a plain 404. */
export function requireSiem(value: string): SiemId {
  if (!isSiemId(value)) throw apiErrors.notFound("Unknown SIEM.");
  return value;
}
