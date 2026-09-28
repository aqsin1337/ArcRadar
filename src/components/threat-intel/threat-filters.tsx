"use client";

import { ListFilters, type FilterField } from "@/components/ui/list-filters";
import { DATA_ORIGINS, ORIGIN_LABELS } from "@/lib/indicators/constants";
import {
  ACTOR_SORT_FIELDS,
  CAMPAIGN_SORT_FIELDS,
  CAMPAIGN_STATUSES,
  CAMPAIGN_STATUS_LABELS,
  MALWARE_SORT_FIELDS,
  SORT_LABELS,
  TECHNIQUE_SORT_FIELDS,
} from "@/lib/threat-intel/constants";
import { actorList, campaignList, malwareList, techniqueList } from "@/lib/threat-intel/url";

type State = Record<string, string | number | undefined>;

const sortOf = (fields: readonly string[], defaultField: string) => ({
  fields: fields.map((field) => ({ value: field, label: SORT_LABELS[field] ?? field })),
  defaultField,
});

const ORIGIN_FIELD: FilterField = {
  key: "origin",
  label: "Origin",
  all: "Any origin",
  options: DATA_ORIGINS.map((value) => ({ value, label: ORIGIN_LABELS[value] })),
};

/** A value from the URL that no record has any more stays selectable. */
const withCurrent = (values: string[], current: string | number | undefined) =>
  (typeof current === "string" && current && !values.includes(current)
    ? [current, ...values]
    : values
  ).map((value) => ({ value, label: value }));

export function ActorFilters({ state }: { state: State }) {
  return (
    <ListFilters
      ariaLabel="Search and filter threat actors"
      searchId="actor-search"
      searchLabel="Search threat actors"
      searchPlaceholder="Search by name, alias, motivation, target or description (all words must match)"
      state={state}
      fields={[ORIGIN_FIELD]}
      sort={sortOf(ACTOR_SORT_FIELDS, "name")}
      hrefFor={(current, overrides) => actorList.href(current, overrides)}
      gridClassName="grid-cols-2 sm:grid-cols-3 lg:grid-cols-5"
    />
  );
}

export function CampaignFilters({ state }: { state: State }) {
  return (
    <ListFilters
      ariaLabel="Search and filter campaigns"
      searchId="campaign-search"
      searchLabel="Search campaigns"
      searchPlaceholder="Search by name or description (all words must match)"
      state={state}
      fields={[
        {
          key: "status",
          label: "Status",
          all: "Any status",
          options: CAMPAIGN_STATUSES.map((value) => ({
            value,
            label: CAMPAIGN_STATUS_LABELS[value],
          })),
        },
        ORIGIN_FIELD,
      ]}
      sort={sortOf(CAMPAIGN_SORT_FIELDS, "last_seen")}
      hrefFor={(current, overrides) => campaignList.href(current, overrides)}
      gridClassName="grid-cols-2 sm:grid-cols-3 lg:grid-cols-5"
    />
  );
}

export function MalwareFilters({ state, types }: { state: State; types: string[] }) {
  return (
    <ListFilters
      ariaLabel="Search and filter malware"
      searchId="malware-search"
      searchLabel="Search malware"
      searchPlaceholder="Search by name, type, platform or description (all words must match)"
      state={state}
      fields={[
        { key: "type", label: "Type", all: "Any type", options: withCurrent(types, state.type) },
        ORIGIN_FIELD,
      ]}
      sort={sortOf(MALWARE_SORT_FIELDS, "name")}
      hrefFor={(current, overrides) => malwareList.href(current, overrides)}
      gridClassName="grid-cols-2 sm:grid-cols-3 lg:grid-cols-5"
    />
  );
}

export function TechniqueFilters({ state, tactics }: { state: State; tactics: string[] }) {
  return (
    <ListFilters
      ariaLabel="Search and filter techniques"
      searchId="technique-search"
      searchLabel="Search techniques"
      searchPlaceholder="Search by id, name, tactic or description (all words must match)"
      state={state}
      fields={[
        {
          key: "tactic",
          label: "Tactic",
          all: "Any tactic",
          options: withCurrent(tactics, state.tactic),
        },
      ]}
      sort={sortOf(TECHNIQUE_SORT_FIELDS, "id")}
      hrefFor={(current, overrides) => techniqueList.href(current, overrides)}
      gridClassName="grid-cols-2 sm:grid-cols-3 lg:grid-cols-5"
    />
  );
}
