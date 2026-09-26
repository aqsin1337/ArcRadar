import type { Indicator, IndicatorType, RelationshipType, DataOrigin, Row } from "@/types/domain";

export type IndicatorTag = Pick<Row<"tags">, "id" | "name" | "color">;

/** A row of the indicator list: the record plus its tags. */
export type IndicatorListItem = Indicator & { tags: IndicatorTag[] };

export type LinkedEntity = { id: string; name: string; origin: DataOrigin };

export type IndicatorRelationship = {
  id: string;
  relationship: RelationshipType;
  /** `outgoing`: this indicator is the source; `incoming`: it is the target. */
  direction: "outgoing" | "incoming";
  other: { id: string; type: IndicatorType; value: string };
};

/** Everything the detail page shows about one indicator. */
export type IndicatorDetail = IndicatorListItem & {
  /** Display name of the user who created it, when they still exist and are visible. */
  created_by_name: string | null;
  threat_actors: LinkedEntity[];
  campaigns: LinkedEntity[];
  malware: LinkedEntity[];
  relationships: IndicatorRelationship[];
};
