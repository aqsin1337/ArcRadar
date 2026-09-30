import type { Severity } from "@/types/domain";

/** What the workspace's own alerts say about one technique. */
export type Observation = {
  alert_count: number;
  max_severity: Severity;
  /** ISO time of the newest alert that mentions the technique. */
  last_seen: string;
};

export type MatrixTechnique = {
  id: string;
  name: string;
  url: string | null;
  /** Null when no alert of this workspace names the technique (or, for a parent, any sub-technique). */
  observed: Observation | null;
  subtechniques: MatrixTechnique[];
};

export type MatrixTactic = {
  name: string;
  techniques: MatrixTechnique[];
  /** How many of this column's parent techniques were observed. */
  observed_techniques: number;
};

export type Matrix = {
  tactics: MatrixTactic[];
  summary: {
    /** Distinct techniques (a sub-technique counts as its parent) named by at least one alert. */
    observed_techniques: number;
    total_techniques: number;
  };
};

export type ObservedRow = {
  technique_id: string;
  alert_count: number;
  max_severity: Severity;
  last_seen: string;
};

export type CatalogTechnique = {
  id: string;
  name: string;
  tactics: string[];
  url: string | null;
};
