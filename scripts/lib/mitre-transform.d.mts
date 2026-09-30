export const ATTACK_STIX_URL: string;

export type MitreTechnique = {
  id: string;
  name: string;
  tactics: string[];
  description: string | null;
  url: string | null;
};
export type MitreMalware = {
  name: string;
  malware_type: "malware" | "tool";
  platforms: string[];
  description: string | null;
};
export type MitreCampaign = {
  name: string;
  description: string | null;
  first_seen: string | null;
  last_seen: string | null;
};
export type MitreActor = {
  name: string;
  aliases: string[];
  description: string | null;
  first_seen: string | null;
  last_seen: string | null;
  technique_ids: string[];
  malware_names: string[];
  campaign_names: string[];
};

export function cleanText(text: unknown): string | null;
export function tacticName(phase: string): string;
export function transformStix(bundle: unknown): {
  techniques: MitreTechnique[];
  malware: MitreMalware[];
  campaigns: MitreCampaign[];
  actors: MitreActor[];
};
export function chunk<T>(items: T[], size: number): T[][];
