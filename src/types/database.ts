export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];

export type Database = {
  graphql_public: {
    Tables: {
      [_ in never]: never;
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      graphql: {
        Args: { extensions?: Json; operationName?: string; query?: string; variables?: Json };
        Returns: Json;
      };
    };
    Enums: {
      [_ in never]: never;
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
  public: {
    Tables: {
      alerts: {
        Row: {
          acknowledged_at: string | null;
          assigned_to: string | null;
          created_at: string;
          created_by: string | null;
          description: string | null;
          event_id: string | null;
          id: string;
          indicator_id: string | null;
          origin: Database["public"]["Enums"]["data_origin"];
          resolved_at: string | null;
          severity: Database["public"]["Enums"]["severity"];
          source: string;
          status: Database["public"]["Enums"]["alert_status"];
          title: string;
          updated_at: string;
        };
        Insert: {
          acknowledged_at?: string | null;
          assigned_to?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          event_id?: string | null;
          id?: string;
          indicator_id?: string | null;
          origin?: Database["public"]["Enums"]["data_origin"];
          resolved_at?: string | null;
          severity?: Database["public"]["Enums"]["severity"];
          source?: string;
          status?: Database["public"]["Enums"]["alert_status"];
          title: string;
          updated_at?: string;
        };
        Update: {
          acknowledged_at?: string | null;
          assigned_to?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          event_id?: string | null;
          id?: string;
          indicator_id?: string | null;
          origin?: Database["public"]["Enums"]["data_origin"];
          resolved_at?: string | null;
          severity?: Database["public"]["Enums"]["severity"];
          source?: string;
          status?: Database["public"]["Enums"]["alert_status"];
          title?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "alerts_assigned_to_fkey";
            columns: ["assigned_to"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "alerts_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "alerts_event_id_fkey";
            columns: ["event_id"];
            isOneToOne: false;
            referencedRelation: "events";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "alerts_indicator_id_fkey";
            columns: ["indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
        ];
      };
      api_keys: {
        Row: {
          created_at: string;
          expires_at: string | null;
          id: string;
          key_hash: string;
          key_prefix: string;
          last_used_at: string | null;
          name: string;
          revoked_at: string | null;
          scopes: string[];
          user_id: string;
        };
        Insert: {
          created_at?: string;
          expires_at?: string | null;
          id?: string;
          key_hash: string;
          key_prefix: string;
          last_used_at?: string | null;
          name: string;
          revoked_at?: string | null;
          scopes?: string[];
          user_id: string;
        };
        Update: {
          created_at?: string;
          expires_at?: string | null;
          id?: string;
          key_hash?: string;
          key_prefix?: string;
          last_used_at?: string | null;
          name?: string;
          revoked_at?: string | null;
          scopes?: string[];
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "api_keys_user_id_fkey";
            columns: ["user_id"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      audit_logs: {
        Row: {
          action: string;
          created_at: string;
          entity_id: string | null;
          entity_type: string | null;
          id: number;
          ip_address: unknown;
          metadata: NonNullable<Json>;
          user_agent: string | null;
          user_id: string | null;
        };
        Insert: {
          action: string;
          created_at?: string;
          entity_id?: string | null;
          entity_type?: string | null;
          id?: never;
          ip_address?: unknown;
          metadata?: NonNullable<Json>;
          user_agent?: string | null;
          user_id?: string | null;
        };
        Update: {
          action?: string;
          created_at?: string;
          entity_id?: string | null;
          entity_type?: string | null;
          id?: never;
          ip_address?: unknown;
          metadata?: NonNullable<Json>;
          user_agent?: string | null;
          user_id?: string | null;
        };
        Relationships: [];
      };
      campaigns: {
        Row: {
          created_at: string;
          created_by: string | null;
          description: string | null;
          first_seen: string | null;
          id: string;
          last_seen: string | null;
          name: string;
          origin: Database["public"]["Enums"]["data_origin"];
          status: Database["public"]["Enums"]["campaign_status"];
          updated_at: string;
        };
        Insert: {
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          first_seen?: string | null;
          id?: string;
          last_seen?: string | null;
          name: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          status?: Database["public"]["Enums"]["campaign_status"];
          updated_at?: string;
        };
        Update: {
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          first_seen?: string | null;
          id?: string;
          last_seen?: string | null;
          name?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          status?: Database["public"]["Enums"]["campaign_status"];
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "campaigns_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      events: {
        Row: {
          created_at: string;
          created_by: string | null;
          description: string | null;
          event_type: string;
          id: string;
          indicator_id: string | null;
          occurred_at: string;
          origin: Database["public"]["Enums"]["data_origin"];
          payload: NonNullable<Json>;
          severity: Database["public"]["Enums"]["severity"];
          source: string;
          title: string;
        };
        Insert: {
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          event_type: string;
          id?: string;
          indicator_id?: string | null;
          occurred_at?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          payload?: NonNullable<Json>;
          severity?: Database["public"]["Enums"]["severity"];
          source?: string;
          title: string;
        };
        Update: {
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          event_type?: string;
          id?: string;
          indicator_id?: string | null;
          occurred_at?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          payload?: NonNullable<Json>;
          severity?: Database["public"]["Enums"]["severity"];
          source?: string;
          title?: string;
        };
        Relationships: [
          {
            foreignKeyName: "events_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "events_indicator_id_fkey";
            columns: ["indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
        ];
      };
      indicator_campaigns: {
        Row: {
          campaign_id: string;
          indicator_id: string;
        };
        Insert: {
          campaign_id: string;
          indicator_id: string;
        };
        Update: {
          campaign_id?: string;
          indicator_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "indicator_campaigns_campaign_id_fkey";
            columns: ["campaign_id"];
            isOneToOne: false;
            referencedRelation: "campaigns";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "indicator_campaigns_indicator_id_fkey";
            columns: ["indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
        ];
      };
      indicator_malware: {
        Row: {
          indicator_id: string;
          malware_id: string;
        };
        Insert: {
          indicator_id: string;
          malware_id: string;
        };
        Update: {
          indicator_id?: string;
          malware_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "indicator_malware_indicator_id_fkey";
            columns: ["indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "indicator_malware_malware_id_fkey";
            columns: ["malware_id"];
            isOneToOne: false;
            referencedRelation: "malware";
            referencedColumns: ["id"];
          },
        ];
      };
      indicator_relationships: {
        Row: {
          created_at: string;
          created_by: string | null;
          id: string;
          relationship: Database["public"]["Enums"]["relationship_type"];
          source_indicator_id: string;
          target_indicator_id: string;
        };
        Insert: {
          created_at?: string;
          created_by?: string | null;
          id?: string;
          relationship?: Database["public"]["Enums"]["relationship_type"];
          source_indicator_id: string;
          target_indicator_id: string;
        };
        Update: {
          created_at?: string;
          created_by?: string | null;
          id?: string;
          relationship?: Database["public"]["Enums"]["relationship_type"];
          source_indicator_id?: string;
          target_indicator_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "indicator_relationships_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "indicator_relationships_source_indicator_id_fkey";
            columns: ["source_indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "indicator_relationships_target_indicator_id_fkey";
            columns: ["target_indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
        ];
      };
      indicator_tags: {
        Row: {
          indicator_id: string;
          tag_id: string;
        };
        Insert: {
          indicator_id: string;
          tag_id: string;
        };
        Update: {
          indicator_id?: string;
          tag_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "indicator_tags_indicator_id_fkey";
            columns: ["indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "indicator_tags_tag_id_fkey";
            columns: ["tag_id"];
            isOneToOne: false;
            referencedRelation: "tags";
            referencedColumns: ["id"];
          },
        ];
      };
      indicator_threat_actors: {
        Row: {
          indicator_id: string;
          threat_actor_id: string;
        };
        Insert: {
          indicator_id: string;
          threat_actor_id: string;
        };
        Update: {
          indicator_id?: string;
          threat_actor_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "indicator_threat_actors_indicator_id_fkey";
            columns: ["indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "indicator_threat_actors_threat_actor_id_fkey";
            columns: ["threat_actor_id"];
            isOneToOne: false;
            referencedRelation: "threat_actors";
            referencedColumns: ["id"];
          },
        ];
      };
      indicators: {
        Row: {
          confidence: number;
          created_at: string;
          created_by: string | null;
          description: string | null;
          first_seen: string;
          id: string;
          last_seen: string;
          origin: Database["public"]["Enums"]["data_origin"];
          severity: Database["public"]["Enums"]["severity"];
          source: string;
          status: Database["public"]["Enums"]["indicator_status"];
          type: Database["public"]["Enums"]["indicator_type"];
          updated_at: string;
          value: string;
          value_normalized: string | null;
          verdict: Database["public"]["Enums"]["verdict"];
        };
        Insert: {
          confidence?: number;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          first_seen?: string;
          id?: string;
          last_seen?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          severity?: Database["public"]["Enums"]["severity"];
          source?: string;
          status?: Database["public"]["Enums"]["indicator_status"];
          type: Database["public"]["Enums"]["indicator_type"];
          updated_at?: string;
          value: string;
          value_normalized?: never;
          verdict?: Database["public"]["Enums"]["verdict"];
        };
        Update: {
          confidence?: number;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          first_seen?: string;
          id?: string;
          last_seen?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          severity?: Database["public"]["Enums"]["severity"];
          source?: string;
          status?: Database["public"]["Enums"]["indicator_status"];
          type?: Database["public"]["Enums"]["indicator_type"];
          updated_at?: string;
          value?: string;
          value_normalized?: never;
          verdict?: Database["public"]["Enums"]["verdict"];
        };
        Relationships: [
          {
            foreignKeyName: "indicators_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      integrations: {
        Row: {
          capabilities: string[];
          config: NonNullable<Json>;
          created_at: string;
          display_name: string;
          enabled: boolean;
          id: string;
          last_sync_at: string | null;
          provider: string;
          updated_at: string;
          updated_by: string | null;
        };
        Insert: {
          capabilities?: string[];
          config?: NonNullable<Json>;
          created_at?: string;
          display_name: string;
          enabled?: boolean;
          id?: string;
          last_sync_at?: string | null;
          provider: string;
          updated_at?: string;
          updated_by?: string | null;
        };
        Update: {
          capabilities?: string[];
          config?: NonNullable<Json>;
          created_at?: string;
          display_name?: string;
          enabled?: boolean;
          id?: string;
          last_sync_at?: string | null;
          provider?: string;
          updated_at?: string;
          updated_by?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "integrations_updated_by_fkey";
            columns: ["updated_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      investigation_alerts: {
        Row: {
          alert_id: string;
          investigation_id: string;
        };
        Insert: {
          alert_id: string;
          investigation_id: string;
        };
        Update: {
          alert_id?: string;
          investigation_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_alerts_alert_id_fkey";
            columns: ["alert_id"];
            isOneToOne: false;
            referencedRelation: "alerts";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "investigation_alerts_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
      investigation_evidence: {
        Row: {
          added_by: string | null;
          created_at: string;
          description: string | null;
          id: string;
          investigation_id: string;
          location: string;
          title: string;
        };
        Insert: {
          added_by?: string | null;
          created_at?: string;
          description?: string | null;
          id?: string;
          investigation_id: string;
          location: string;
          title: string;
        };
        Update: {
          added_by?: string | null;
          created_at?: string;
          description?: string | null;
          id?: string;
          investigation_id?: string;
          location?: string;
          title?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_evidence_added_by_fkey";
            columns: ["added_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "investigation_evidence_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
      investigation_indicators: {
        Row: {
          indicator_id: string;
          investigation_id: string;
        };
        Insert: {
          indicator_id: string;
          investigation_id: string;
        };
        Update: {
          indicator_id?: string;
          investigation_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_indicators_indicator_id_fkey";
            columns: ["indicator_id"];
            isOneToOne: false;
            referencedRelation: "indicators";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "investigation_indicators_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
      investigation_notes: {
        Row: {
          author_id: string | null;
          body: string;
          created_at: string;
          id: string;
          investigation_id: string;
          updated_at: string;
        };
        Insert: {
          author_id?: string | null;
          body: string;
          created_at?: string;
          id?: string;
          investigation_id: string;
          updated_at?: string;
        };
        Update: {
          author_id?: string | null;
          body?: string;
          created_at?: string;
          id?: string;
          investigation_id?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_notes_author_id_fkey";
            columns: ["author_id"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "investigation_notes_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
      investigation_tags: {
        Row: {
          investigation_id: string;
          tag_id: string;
        };
        Insert: {
          investigation_id: string;
          tag_id: string;
        };
        Update: {
          investigation_id?: string;
          tag_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_tags_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "investigation_tags_tag_id_fkey";
            columns: ["tag_id"];
            isOneToOne: false;
            referencedRelation: "tags";
            referencedColumns: ["id"];
          },
        ];
      };
      investigations: {
        Row: {
          analyst_id: string | null;
          closed_at: string | null;
          created_at: string;
          created_by: string | null;
          description: string | null;
          id: string;
          origin: Database["public"]["Enums"]["data_origin"];
          priority: Database["public"]["Enums"]["priority"];
          status: Database["public"]["Enums"]["investigation_status"];
          title: string;
          updated_at: string;
        };
        Insert: {
          analyst_id?: string | null;
          closed_at?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          id?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          priority?: Database["public"]["Enums"]["priority"];
          status?: Database["public"]["Enums"]["investigation_status"];
          title: string;
          updated_at?: string;
        };
        Update: {
          analyst_id?: string | null;
          closed_at?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          id?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          priority?: Database["public"]["Enums"]["priority"];
          status?: Database["public"]["Enums"]["investigation_status"];
          title?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigations_analyst_id_fkey";
            columns: ["analyst_id"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "investigations_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      malware: {
        Row: {
          created_at: string;
          created_by: string | null;
          description: string | null;
          id: string;
          malware_type: string | null;
          name: string;
          origin: Database["public"]["Enums"]["data_origin"];
          platforms: string[];
          updated_at: string;
        };
        Insert: {
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          id?: string;
          malware_type?: string | null;
          name: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          platforms?: string[];
          updated_at?: string;
        };
        Update: {
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          id?: string;
          malware_type?: string | null;
          name?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          platforms?: string[];
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "malware_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      mitre_techniques: {
        Row: {
          description: string | null;
          id: string;
          name: string;
          tactics: string[];
          url: string | null;
        };
        Insert: {
          description?: string | null;
          id: string;
          name: string;
          tactics?: string[];
          url?: string | null;
        };
        Update: {
          description?: string | null;
          id?: string;
          name?: string;
          tactics?: string[];
          url?: string | null;
        };
        Relationships: [];
      };
      permissions: {
        Row: {
          description: string;
          key: string;
        };
        Insert: {
          description: string;
          key: string;
        };
        Update: {
          description?: string;
          key?: string;
        };
        Relationships: [];
      };
      profiles: {
        Row: {
          avatar_url: string | null;
          created_at: string;
          display_name: string | null;
          id: string;
          is_active: boolean;
          role_name: string;
          updated_at: string;
        };
        Insert: {
          avatar_url?: string | null;
          created_at?: string;
          display_name?: string | null;
          id: string;
          is_active?: boolean;
          role_name?: string;
          updated_at?: string;
        };
        Update: {
          avatar_url?: string | null;
          created_at?: string;
          display_name?: string | null;
          id?: string;
          is_active?: boolean;
          role_name?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "profiles_role_name_fkey";
            columns: ["role_name"];
            isOneToOne: false;
            referencedRelation: "roles";
            referencedColumns: ["name"];
          },
        ];
      };
      reports: {
        Row: {
          content: NonNullable<Json>;
          created_at: string;
          created_by: string | null;
          id: string;
          investigation_id: string | null;
          origin: Database["public"]["Enums"]["data_origin"];
          parameters: NonNullable<Json>;
          title: string;
          type: Database["public"]["Enums"]["report_type"];
        };
        Insert: {
          content?: NonNullable<Json>;
          created_at?: string;
          created_by?: string | null;
          id?: string;
          investigation_id?: string | null;
          origin?: Database["public"]["Enums"]["data_origin"];
          parameters?: NonNullable<Json>;
          title: string;
          type: Database["public"]["Enums"]["report_type"];
        };
        Update: {
          content?: NonNullable<Json>;
          created_at?: string;
          created_by?: string | null;
          id?: string;
          investigation_id?: string | null;
          origin?: Database["public"]["Enums"]["data_origin"];
          parameters?: NonNullable<Json>;
          title?: string;
          type?: Database["public"]["Enums"]["report_type"];
        };
        Relationships: [
          {
            foreignKeyName: "reports_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "reports_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
        ];
      };
      role_permissions: {
        Row: {
          permission_key: string;
          role_name: string;
        };
        Insert: {
          permission_key: string;
          role_name: string;
        };
        Update: {
          permission_key?: string;
          role_name?: string;
        };
        Relationships: [
          {
            foreignKeyName: "role_permissions_permission_key_fkey";
            columns: ["permission_key"];
            isOneToOne: false;
            referencedRelation: "permissions";
            referencedColumns: ["key"];
          },
          {
            foreignKeyName: "role_permissions_role_name_fkey";
            columns: ["role_name"];
            isOneToOne: false;
            referencedRelation: "roles";
            referencedColumns: ["name"];
          },
        ];
      };
      roles: {
        Row: {
          created_at: string;
          description: string;
          name: string;
        };
        Insert: {
          created_at?: string;
          description: string;
          name: string;
        };
        Update: {
          created_at?: string;
          description?: string;
          name?: string;
        };
        Relationships: [];
      };
      tags: {
        Row: {
          color: string | null;
          created_at: string;
          id: string;
          name: string;
        };
        Insert: {
          color?: string | null;
          created_at?: string;
          id?: string;
          name: string;
        };
        Update: {
          color?: string | null;
          created_at?: string;
          id?: string;
          name?: string;
        };
        Relationships: [];
      };
      threat_actor_campaigns: {
        Row: {
          campaign_id: string;
          threat_actor_id: string;
        };
        Insert: {
          campaign_id: string;
          threat_actor_id: string;
        };
        Update: {
          campaign_id?: string;
          threat_actor_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "threat_actor_campaigns_campaign_id_fkey";
            columns: ["campaign_id"];
            isOneToOne: false;
            referencedRelation: "campaigns";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "threat_actor_campaigns_threat_actor_id_fkey";
            columns: ["threat_actor_id"];
            isOneToOne: false;
            referencedRelation: "threat_actors";
            referencedColumns: ["id"];
          },
        ];
      };
      threat_actor_malware: {
        Row: {
          malware_id: string;
          threat_actor_id: string;
        };
        Insert: {
          malware_id: string;
          threat_actor_id: string;
        };
        Update: {
          malware_id?: string;
          threat_actor_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "threat_actor_malware_malware_id_fkey";
            columns: ["malware_id"];
            isOneToOne: false;
            referencedRelation: "malware";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "threat_actor_malware_threat_actor_id_fkey";
            columns: ["threat_actor_id"];
            isOneToOne: false;
            referencedRelation: "threat_actors";
            referencedColumns: ["id"];
          },
        ];
      };
      threat_actor_techniques: {
        Row: {
          technique_id: string;
          threat_actor_id: string;
        };
        Insert: {
          technique_id: string;
          threat_actor_id: string;
        };
        Update: {
          technique_id?: string;
          threat_actor_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "threat_actor_techniques_technique_id_fkey";
            columns: ["technique_id"];
            isOneToOne: false;
            referencedRelation: "mitre_techniques";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "threat_actor_techniques_threat_actor_id_fkey";
            columns: ["threat_actor_id"];
            isOneToOne: false;
            referencedRelation: "threat_actors";
            referencedColumns: ["id"];
          },
        ];
      };
      threat_actors: {
        Row: {
          aliases: string[];
          attribution_country: string | null;
          created_at: string;
          created_by: string | null;
          description: string | null;
          first_seen: string | null;
          id: string;
          last_seen: string | null;
          motivation: string | null;
          name: string;
          origin: Database["public"]["Enums"]["data_origin"];
          target_countries: string[];
          target_industries: string[];
          updated_at: string;
        };
        Insert: {
          aliases?: string[];
          attribution_country?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          first_seen?: string | null;
          id?: string;
          last_seen?: string | null;
          motivation?: string | null;
          name: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          target_countries?: string[];
          target_industries?: string[];
          updated_at?: string;
        };
        Update: {
          aliases?: string[];
          attribution_country?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          first_seen?: string | null;
          id?: string;
          last_seen?: string | null;
          motivation?: string | null;
          name?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          target_countries?: string[];
          target_industries?: string[];
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "threat_actors_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      vulnerabilities: {
        Row: {
          created_at: string;
          created_by: string | null;
          cve_id: string;
          cvss_score: number | null;
          cvss_vector: string | null;
          cvss_version: string | null;
          description: string;
          exploit_status: Database["public"]["Enums"]["exploit_status"];
          id: string;
          modified_at: string | null;
          origin: Database["public"]["Enums"]["data_origin"];
          published_at: string | null;
          reference_urls: string[];
          remediation: string | null;
          severity: Database["public"]["Enums"]["severity"];
          title: string;
          updated_at: string;
        };
        Insert: {
          created_at?: string;
          created_by?: string | null;
          cve_id: string;
          cvss_score?: number | null;
          cvss_vector?: string | null;
          cvss_version?: string | null;
          description?: string;
          exploit_status?: Database["public"]["Enums"]["exploit_status"];
          id?: string;
          modified_at?: string | null;
          origin?: Database["public"]["Enums"]["data_origin"];
          published_at?: string | null;
          reference_urls?: string[];
          remediation?: string | null;
          severity?: Database["public"]["Enums"]["severity"];
          title: string;
          updated_at?: string;
        };
        Update: {
          created_at?: string;
          created_by?: string | null;
          cve_id?: string;
          cvss_score?: number | null;
          cvss_vector?: string | null;
          cvss_version?: string | null;
          description?: string;
          exploit_status?: Database["public"]["Enums"]["exploit_status"];
          id?: string;
          modified_at?: string | null;
          origin?: Database["public"]["Enums"]["data_origin"];
          published_at?: string | null;
          reference_urls?: string[];
          remediation?: string | null;
          severity?: Database["public"]["Enums"]["severity"];
          title?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "vulnerabilities_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      vulnerability_affected_products: {
        Row: {
          affected_versions: string | null;
          fixed_version: string | null;
          id: string;
          product: string;
          vendor: string;
          vulnerability_id: string;
        };
        Insert: {
          affected_versions?: string | null;
          fixed_version?: string | null;
          id?: string;
          product: string;
          vendor: string;
          vulnerability_id: string;
        };
        Update: {
          affected_versions?: string | null;
          fixed_version?: string | null;
          id?: string;
          product?: string;
          vendor?: string;
          vulnerability_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "vulnerability_affected_products_vulnerability_id_fkey";
            columns: ["vulnerability_id"];
            isOneToOne: false;
            referencedRelation: "vulnerabilities";
            referencedColumns: ["id"];
          },
        ];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      current_role_name: { Args: Record<PropertyKey, never>; Returns: string };
      escape_like: { Args: { p_text: string }; Returns: string };
      has_permission: { Args: { p_key: string }; Returns: boolean };
      is_valid_indicator: {
        Args: { p_type: Database["public"]["Enums"]["indicator_type"]; p_value: string };
        Returns: boolean;
      };
      search_indicators: {
        Args: { p_query?: string; p_tag?: string };
        Returns: {
          confidence: number;
          created_at: string;
          created_by: string | null;
          description: string | null;
          first_seen: string;
          id: string;
          last_seen: string;
          origin: Database["public"]["Enums"]["data_origin"];
          severity: Database["public"]["Enums"]["severity"];
          source: string;
          status: Database["public"]["Enums"]["indicator_status"];
          type: Database["public"]["Enums"]["indicator_type"];
          updated_at: string;
          value: string;
          value_normalized: string | null;
          verdict: Database["public"]["Enums"]["verdict"];
        }[];
        SetofOptions: {
          from: "*";
          to: "indicators";
          isOneToOne: false;
          isSetofReturn: true;
        };
      };
      set_indicator_tags: {
        Args: { p_indicator_id: string; p_tags: string[] };
        Returns: undefined;
      };
    };
    Enums: {
      alert_status: "new" | "acknowledged" | "investigating" | "resolved" | "false_positive";
      campaign_status: "active" | "dormant" | "concluded";
      data_origin: "demo" | "local" | "external";
      exploit_status: "unknown" | "none" | "poc_available" | "exploited_in_wild";
      indicator_status: "active" | "inactive" | "expired" | "whitelisted" | "under_review";
      indicator_type:
        "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256" | "email" | "cve" | "other";
      investigation_status: "open" | "investigating" | "contained" | "resolved" | "closed";
      priority: "low" | "medium" | "high" | "critical";
      relationship_type:
        "resolves_to" | "communicates_with" | "downloads" | "hosted_on" | "related_to";
      report_type: "investigation" | "indicators" | "alerts" | "vulnerabilities" | "threat_actor";
      severity: "info" | "low" | "medium" | "high" | "critical";
      verdict: "unknown" | "benign" | "suspicious" | "malicious";
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
};

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">;

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">];

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R;
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] & DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R;
      }
      ? R
      : never
    : never;

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I;
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I;
      }
      ? I
      : never
    : never;

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U;
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U;
      }
      ? U
      : never
    : never;

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    keyof DefaultSchema["Enums"] | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never;

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    keyof DefaultSchema["CompositeTypes"] | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends { schema: keyof DatabaseWithoutInternals }
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never;

export const Constants = {
  graphql_public: {
    Enums: {},
  },
  public: {
    Enums: {
      alert_status: ["new", "acknowledged", "investigating", "resolved", "false_positive"],
      campaign_status: ["active", "dormant", "concluded"],
      data_origin: ["demo", "local", "external"],
      exploit_status: ["unknown", "none", "poc_available", "exploited_in_wild"],
      indicator_status: ["active", "inactive", "expired", "whitelisted", "under_review"],
      indicator_type: [
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "md5",
        "sha1",
        "sha256",
        "email",
        "cve",
        "other",
      ],
      investigation_status: ["open", "investigating", "contained", "resolved", "closed"],
      priority: ["low", "medium", "high", "critical"],
      relationship_type: [
        "resolves_to",
        "communicates_with",
        "downloads",
        "hosted_on",
        "related_to",
      ],
      report_type: ["investigation", "indicators", "alerts", "vulnerabilities", "threat_actor"],
      severity: ["info", "low", "medium", "high", "critical"],
      verdict: ["unknown", "benign", "suspicious", "malicious"],
    },
  },
} as const;
