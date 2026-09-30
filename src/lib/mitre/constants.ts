/**
 * The ATT&CK Enterprise tactics in the order the matrix shows them (the attack's own order, left to
 * right). A technique's `tactics` are stored as text, so a tactic the catalog names that is not listed
 * here is shown after these rather than dropped.
 */
export const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
] as const;

/** Compares tactic names whatever the casing or spelling of "and" ("Command And Control"). */
export const tacticKey = (name: string) => name.trim().toLowerCase().replace(/\s+/g, " ");

export const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;
