/** Where the project lives. Kept in one place so the landing page never drifts. */
export const GITHUB_URL = "https://github.com/aqsin1337/ArcRadar";

/** The setup guide a visitor follows to run their own copy (the README's quick start). */
export const SETUP_GUIDE_URL = `${GITHUB_URL}#quick-start`;

const doc = (name: string) => `${GITHUB_URL}/blob/main/docs/${name}`;

export const DOCS = {
  database: doc("DEPLOYMENT.md#1-create-the-database"),
  deploy: doc("DEPLOYMENT.md#3-deploy-the-app"),
  team: doc("DEPLOYMENT.md#4-make-the-first-administrator"),
  wazuh: doc("WAZUH_INTEGRATION.md"),
  splunk: doc("SPLUNK_INTEGRATION.md"),
  wazuhRules: doc("WAZUH_RULES.md"),
} as const;
