export const ATTACK_STIX_URL: string;

export type MitreTechnique = {
  id: string;
  name: string;
  tactics: string[];
  description: string | null;
  url: string | null;
};

export function cleanText(text: unknown): string | null;
export function tacticName(phase: string): string;
export function transformStix(bundle: unknown): { techniques: MitreTechnique[] };
export function chunk<T>(items: T[], size: number): T[][];
