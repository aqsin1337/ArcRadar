export type IntegrationRow = {
  provider: string;
  display_name: string;
  capabilities: string[];
  enabled: boolean;
  /** A server-side key is set (or, for demo/wazuh, is not needed). Independent of `enabled`. */
  configured: boolean;
  last_sync_at: string | null;
};
