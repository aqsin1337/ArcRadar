// Turns MITRE's ATT&CK STIX bundle (enterprise-attack.json, github.com/mitre-attack/attack-stix-data)
// into the techniques public.import_mitre_attack() takes. Pure: no network, no database, so it is
// tested directly (tests/mitre-transform.test.ts). Revoked and deprecated techniques are dropped.
// Only the technique catalog is imported (names and tactics, for the matrix): ArcRadar has no threat
// actors, campaigns or malware records.

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

const SMALL_WORDS = new Set(["and", "of", "the"]);

/** "defense-evasion" -> "Defense Evasion", "command-and-control" -> "Command and Control". */
export function tacticName(phase) {
  return String(phase)
    .split("-")
    .map((word, index) =>
      index > 0 && SMALL_WORDS.has(word) ? word : word.charAt(0).toUpperCase() + word.slice(1),
    )
    .join(" ");
}

export function transformStix(bundle) {
  const objects = Array.isArray(bundle?.objects) ? bundle.objects : [];
  const techniques = [];
  for (const object of objects.filter(active)) {
    if (object.type !== "attack-pattern") continue;
    const reference = attackReference(object);
    const id = reference?.external_id;
    if (!id || !TECHNIQUE_ID.test(id)) continue;
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
  techniques.sort((a, b) => a.id.localeCompare(b.id));
  return { techniques };
}

/** Splits an array into chunks of at most `size`. */
export function chunk(items, size) {
  const chunks = [];
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
  return chunks;
}
