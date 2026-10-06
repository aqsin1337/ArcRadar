import type { z } from "zod";
import type { SiemId } from "./constants";
import type { RenderedRuleFile, SiemRuleDefinition } from "./types";

/**
 * One SIEM's rule language. A dialect owns three things and nothing else:
 *  - the shape of `spec` (strict, per-field checks: what a person or the AI may fill in),
 *  - how a validated rule becomes the file the SIEM loads (a fixed template, so no command a caller
 *    or the AI invents can ever appear in it),
 *  - the prompt that teaches the AI the `spec` shape (never the output language itself).
 * Adding a SIEM means adding one dialect and one entry in the registry; the lifecycle (draft, review,
 * push to GitHub, reject, audit) is shared.
 */
export interface RuleDialect {
  readonly siem: SiemId;
  readonly label: string;
  readonly specSchema: z.ZodType<Record<string, unknown>>;
  /** Renders the file. Throws if the result breaks the dialect's own safety check (defense in depth). */
  render(rule: SiemRuleDefinition): RenderedRuleFile;
  readonly prompt: {
    version: number;
    maxOutputTokens: number;
    build(description: string): { system: string; user: string };
  };
}
