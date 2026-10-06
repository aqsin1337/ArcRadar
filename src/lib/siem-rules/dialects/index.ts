import type { RuleDialect } from "../dialect";
import type { SiemId } from "../constants";
import { splunkDialect } from "./splunk";

/** Every SIEM ArcRadar writes rules for. A new SIEM is one dialect module plus one line here. */
const DIALECTS: Record<SiemId, RuleDialect> = {
  splunk: splunkDialect,
};

export const getDialect = (siem: SiemId): RuleDialect => DIALECTS[siem];
