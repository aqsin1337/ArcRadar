/** The switchable groups of public feeds; each is a row on the Integrations page. */
export const FEED_GROUPS = ["abusech", "cisa_kev"] as const;
export type FeedGroup = (typeof FEED_GROUPS)[number];
