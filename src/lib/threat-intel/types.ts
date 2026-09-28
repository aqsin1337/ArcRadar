import type { Campaign, Indicator, Malware, MitreTechnique, ThreatActor } from "@/types/domain";

export type ActorRef = Pick<ThreatActor, "id" | "name" | "origin">;
export type MalwareRef = Pick<Malware, "id" | "name" | "malware_type" | "origin">;
export type CampaignRef = Pick<Campaign, "id" | "name" | "status" | "origin" | "last_seen">;
export type TechniqueRef = Pick<MitreTechnique, "id" | "name" | "tactics">;

export type LinkedIndicator = Pick<
  Indicator,
  "id" | "type" | "value" | "verdict" | "severity" | "origin"
>;

/** The first few indicators linked to a record, and how many there are in all. */
export type LinkedIndicators = { items: LinkedIndicator[]; total: number };

export type ActorListItem = ThreatActor & {
  counts: { malware: number; campaigns: number; techniques: number; indicators: number };
};

export type CampaignListItem = Campaign & { counts: { actors: number; indicators: number } };

export type MalwareListItem = Malware & { counts: { actors: number; indicators: number } };

export type ActorDetail = ThreatActor & {
  created_by_name: string | null;
  malware: MalwareRef[];
  campaigns: CampaignRef[];
  techniques: TechniqueRef[];
  indicators: LinkedIndicators;
};

export type CampaignDetail = Campaign & {
  created_by_name: string | null;
  actors: ActorRef[];
  indicators: LinkedIndicators;
};

export type MalwareDetail = Malware & {
  created_by_name: string | null;
  actors: ActorRef[];
  indicators: LinkedIndicators;
};

export type TechniqueDetail = MitreTechnique & { actors: ActorRef[] };

/** What the create and edit forms need to offer as choices. */
export type LinkOptions = {
  actors: ActorRef[];
  malware: Pick<Malware, "id" | "name" | "malware_type">[];
  campaigns: Pick<Campaign, "id" | "name" | "status">[];
  techniques: Pick<MitreTechnique, "id" | "name">[];
};
