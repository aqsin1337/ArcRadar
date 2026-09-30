// Turns MITRE's ATT&CK STIX bundle (enterprise-attack.json, github.com/mitre-attack/attack-stix-data)
// into the shape public.import_mitre_attack() takes. Pure: no network, no database, so it is tested
// directly (tests/mitre-transform.test.ts). Revoked and deprecated objects are dropped.

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;

export const ATTACK_STIX_URL =
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

const active = (object) => object && !object.revoked && !object.x_mitre_deprecated;

function attackReference(object) {
  return (object.external_references ?? []).find((ref) => ref.source_name === "mitre-attack");
}

/** MITRE's text is full of "(Citation: ...)" markers and markdown links; keep the words. */
export function cleanText(text) {
  if (typeof text !== "string") return null;
  const cleaned = text
    .replace(/\s*\(Citation: [^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\((?:[^)]+)\)/g, "$1")
    .replace(/<\/?code>/g, "")
    .trim();
  return cleaned === "" ? null : cleaned;
}

/** "defense-evasion" -> "Defense Evasion" (how the technique list already writes its tactics). */
export function tacticName(phase) {
  return String(phase)
    .split("-")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

const iso = (value) => {
  if (typeof value !== "string") return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

export function transformStix(bundle) {
  const objects = Array.isArray(bundle?.objects) ? bundle.objects : [];
  const byId = new Map(objects.filter(active).map((object) => [object.id, object]));

  const techniqueIdOf = new Map();
  const techniques = [];
  for (const object of byId.values()) {
    if (object.type !== "attack-pattern") continue;
    const reference = attackReference(object);
    const id = reference?.external_id;
    if (!id || !TECHNIQUE_ID.test(id)) continue;
    techniqueIdOf.set(object.id, id);
    techniques.push({
      id,
      name: object.name,
      tactics: [
        ...new Set(
          (object.kill_chain_phases ?? [])
            .filter((phase) => phase.kill_chain_name === "mitre-attack")
            .map((phase) => tacticName(phase.phase_name)),
        ),
      ],
      description: cleanText(object.description),
      url: reference.url ?? null,
    });
  }

  const malwareNameOf = new Map();
  const malware = [];
  const seenMalware = new Set();
  for (const object of byId.values()) {
    if (object.type !== "malware" && object.type !== "tool") continue;
    if (!object.name) continue;
    malwareNameOf.set(object.id, object.name);
    const key = object.name.toLowerCase();
    if (seenMalware.has(key)) continue;
    seenMalware.add(key);
    malware.push({
      name: object.name,
      malware_type: object.type === "tool" ? "tool" : "malware",
      platforms: object.x_mitre_platforms ?? [],
      description: cleanText(object.description),
    });
  }

  const campaignNameOf = new Map();
  const campaigns = [];
  const seenCampaigns = new Set();
  for (const object of byId.values()) {
    if (object.type !== "campaign" || !object.name) continue;
    campaignNameOf.set(object.id, object.name);
    const key = object.name.toLowerCase();
    if (seenCampaigns.has(key)) continue;
    seenCampaigns.add(key);
    campaigns.push({
      name: object.name,
      description: cleanText(object.description),
      first_seen: iso(object.first_seen),
      last_seen: iso(object.last_seen),
    });
  }

  const actorById = new Map();
  for (const object of byId.values()) {
    if (object.type !== "intrusion-set" || !object.name) continue;
    actorById.set(object.id, {
      name: object.name,
      aliases: (object.aliases ?? []).filter((alias) => alias !== object.name),
      description: cleanText(object.description),
      first_seen: iso(object.first_seen),
      last_seen: iso(object.last_seen),
      technique_ids: new Set(),
      malware_names: new Set(),
      campaign_names: new Set(),
    });
  }

  for (const object of objects) {
    if (object.type !== "relationship" || object.revoked || object.x_mitre_deprecated) continue;
    if (object.relationship_type === "uses") {
      const actor = actorById.get(object.source_ref);
      if (!actor) continue;
      const technique = techniqueIdOf.get(object.target_ref);
      if (technique) actor.technique_ids.add(technique);
      const family = malwareNameOf.get(object.target_ref);
      if (family) actor.malware_names.add(family);
    } else if (object.relationship_type === "attributed-to") {
      const actor = actorById.get(object.target_ref);
      const campaign = campaignNameOf.get(object.source_ref);
      if (actor && campaign) actor.campaign_names.add(campaign);
    }
  }

  const seenActors = new Set();
  const actors = [];
  for (const actor of actorById.values()) {
    const key = actor.name.toLowerCase();
    if (seenActors.has(key)) continue;
    seenActors.add(key);
    actors.push({
      ...actor,
      technique_ids: [...actor.technique_ids].sort(),
      malware_names: [...actor.malware_names].sort(),
      campaign_names: [...actor.campaign_names].sort(),
    });
  }

  techniques.sort((a, b) => a.id.localeCompare(b.id));
  return { techniques, malware, campaigns, actors };
}

/** Splits an array into chunks of at most `size`. */
export function chunk(items, size) {
  const chunks = [];
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
  return chunks;
}
