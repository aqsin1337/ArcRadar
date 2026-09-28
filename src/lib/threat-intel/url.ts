import { createListUrl } from "@/lib/validation/list-url";

export const actorList = createListUrl({
  path: "/threat-actors",
  filterKeys: ["q", "origin"],
  defaultSort: "name",
  defaultOrder: "asc",
});

export const campaignList = createListUrl({
  path: "/campaigns",
  filterKeys: ["q", "status", "origin"],
  defaultSort: "last_seen",
});

export const malwareList = createListUrl({
  path: "/malware",
  filterKeys: ["q", "type", "origin"],
  defaultSort: "name",
  defaultOrder: "asc",
});

export const techniqueList = createListUrl({
  path: "/mitre",
  filterKeys: ["q", "tactic"],
  defaultSort: "id",
  defaultOrder: "asc",
});
