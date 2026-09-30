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
      ai_analyses: {
        Row: {
          content: NonNullable<Json>;
          created_at: string;
          id: string;
          kind: string;
          model: string;
          prompt_version: number;
          provider: string;
          requested_by: string | null;
          subject_id: string;
          subject_type: string;
        };
        Insert: {
          content: NonNullable<Json>;
          created_at?: string;
          id?: string;
          kind: string;
          model: string;
          prompt_version: number;
          provider: string;
          requested_by?: string | null;
          subject_id: string;
          subject_type: string;
        };
        Update: {
          content?: NonNullable<Json>;
          created_at?: string;
          id?: string;
          kind?: string;
          model?: string;
          prompt_version?: number;
          provider?: string;
          requested_by?: string | null;
          subject_id?: string;
          subject_type?: string;
        };
        Relationships: [
          {
            foreignKeyName: "ai_analyses_provider_fkey";
            columns: ["provider"];
            isOneToOne: false;
            referencedRelation: "integrations";
            referencedColumns: ["provider"];
          },
          {
            foreignKeyName: "ai_analyses_requested_by_fkey";
            columns: ["requested_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      ai_settings: {
        Row: {
          active_model: string | null;
          active_provider: string | null;
          id: boolean;
          updated_at: string;
          updated_by: string | null;
        };
        Insert: {
          active_model?: string | null;
          active_provider?: string | null;
          id?: boolean;
          updated_at?: string;
          updated_by?: string | null;
        };
        Update: {
          active_model?: string | null;
          active_provider?: string | null;
          id?: boolean;
          updated_at?: string;
          updated_by?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "ai_settings_active_provider_fkey";
            columns: ["active_provider"];
            isOneToOne: false;
            referencedRelation: "integrations";
            referencedColumns: ["provider"];
          },
          {
            foreignKeyName: "ai_settings_updated_by_fkey";
            columns: ["updated_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      alerts: {
        Row: {
          acknowledged_at: string | null;
          ai_fp_score: number | null;
          asset_id: string | null;
          assigned_to: string | null;
          created_at: string;
          created_by: string | null;
          description: string | null;
          duplicate_count: number;
          duplicate_of: string | null;
          event_id: string | null;
          fingerprint: string | null;
          id: string;
          indicator_id: string | null;
          matched_rule_id: number | null;
          origin: Database["public"]["Enums"]["data_origin"];
          resolved_at: string | null;
          severity: Database["public"]["Enums"]["severity"];
          source: string;
          source_event_id: string | null;
          status: Database["public"]["Enums"]["alert_status"];
          technique_ids: string[];
          title: string;
          updated_at: string;
        };
        Insert: {
          acknowledged_at?: string | null;
          ai_fp_score?: number | null;
          asset_id?: string | null;
          assigned_to?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          duplicate_count?: number;
          duplicate_of?: string | null;
          event_id?: string | null;
          fingerprint?: string | null;
          id?: string;
          indicator_id?: string | null;
          matched_rule_id?: number | null;
          origin?: Database["public"]["Enums"]["data_origin"];
          resolved_at?: string | null;
          severity?: Database["public"]["Enums"]["severity"];
          source?: string;
          source_event_id?: string | null;
          status?: Database["public"]["Enums"]["alert_status"];
          technique_ids?: string[];
          title: string;
          updated_at?: string;
        };
        Update: {
          acknowledged_at?: string | null;
          ai_fp_score?: number | null;
          asset_id?: string | null;
          assigned_to?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          duplicate_count?: number;
          duplicate_of?: string | null;
          event_id?: string | null;
          fingerprint?: string | null;
          id?: string;
          indicator_id?: string | null;
          matched_rule_id?: number | null;
          origin?: Database["public"]["Enums"]["data_origin"];
          resolved_at?: string | null;
          severity?: Database["public"]["Enums"]["severity"];
          source?: string;
          source_event_id?: string | null;
          status?: Database["public"]["Enums"]["alert_status"];
          technique_ids?: string[];
          title?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "alerts_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
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
            foreignKeyName: "alerts_duplicate_of_fkey";
            columns: ["duplicate_of"];
            isOneToOne: false;
            referencedRelation: "alerts";
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
          {
            foreignKeyName: "alerts_matched_rule_id_fkey";
            columns: ["matched_rule_id"];
            isOneToOne: false;
            referencedRelation: "detection_rules";
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
      assets: {
        Row: {
          created_at: string;
          external_id: string;
          first_seen: string;
          id: string;
          ip_address: string | null;
          last_seen: string;
          name: string;
          origin: Database["public"]["Enums"]["data_origin"];
          os: string | null;
          source: string;
          updated_at: string;
        };
        Insert: {
          created_at?: string;
          external_id: string;
          first_seen?: string;
          id?: string;
          ip_address?: string | null;
          last_seen?: string;
          name: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          os?: string | null;
          source: string;
          updated_at?: string;
        };
        Update: {
          created_at?: string;
          external_id?: string;
          first_seen?: string;
          id?: string;
          ip_address?: string | null;
          last_seen?: string;
          name?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          os?: string | null;
          source?: string;
          updated_at?: string;
        };
        Relationships: [];
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
      detection_rules: {
        Row: {
          conditions: NonNullable<Json>;
          created_at: string;
          created_by: string | null;
          description: string | null;
          enabled: boolean;
          id: number;
          name: string;
          origin: Database["public"]["Enums"]["data_origin"];
          priority: number;
          severity: Database["public"]["Enums"]["severity"] | null;
          updated_at: string;
        };
        Insert: {
          conditions: NonNullable<Json>;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          enabled?: boolean;
          id: number;
          name: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          priority?: number;
          severity?: Database["public"]["Enums"]["severity"] | null;
          updated_at?: string;
        };
        Update: {
          conditions?: NonNullable<Json>;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          enabled?: boolean;
          id?: number;
          name?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          priority?: number;
          severity?: Database["public"]["Enums"]["severity"] | null;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "detection_rules_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      events: {
        Row: {
          asset_id: string | null;
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
          source_event_id: string | null;
          title: string;
        };
        Insert: {
          asset_id?: string | null;
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
          source_event_id?: string | null;
          title: string;
        };
        Update: {
          asset_id?: string | null;
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
          source_event_id?: string | null;
          title?: string;
        };
        Relationships: [
          {
            foreignKeyName: "events_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
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
          researched_at: string | null;
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
          researched_at?: string | null;
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
          researched_at?: string | null;
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
          added_at: string;
          added_by: string | null;
          alert_id: string;
          investigation_id: string;
        };
        Insert: {
          added_at?: string;
          added_by?: string | null;
          alert_id: string;
          investigation_id: string;
        };
        Update: {
          added_at?: string;
          added_by?: string | null;
          alert_id?: string;
          investigation_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_alerts_added_by_fkey";
            columns: ["added_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
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
      investigation_checklist_items: {
        Row: {
          created_at: string;
          created_by: string | null;
          done: boolean;
          done_at: string | null;
          done_by: string | null;
          id: string;
          investigation_id: string;
          source: string;
          text: string;
        };
        Insert: {
          created_at?: string;
          created_by?: string | null;
          done?: boolean;
          done_at?: string | null;
          done_by?: string | null;
          id?: string;
          investigation_id: string;
          source: string;
          text: string;
        };
        Update: {
          created_at?: string;
          created_by?: string | null;
          done?: boolean;
          done_at?: string | null;
          done_by?: string | null;
          id?: string;
          investigation_id?: string;
          source?: string;
          text?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_checklist_items_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "investigation_checklist_items_done_by_fkey";
            columns: ["done_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "investigation_checklist_items_investigation_id_fkey";
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
          added_at: string;
          added_by: string | null;
          indicator_id: string;
          investigation_id: string;
        };
        Insert: {
          added_at?: string;
          added_by?: string | null;
          indicator_id: string;
          investigation_id: string;
        };
        Update: {
          added_at?: string;
          added_by?: string | null;
          indicator_id?: string;
          investigation_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "investigation_indicators_added_by_fkey";
            columns: ["added_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
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
          kind: string;
          updated_at: string;
        };
        Insert: {
          author_id?: string | null;
          body: string;
          created_at?: string;
          id?: string;
          investigation_id: string;
          kind?: string;
          updated_at?: string;
        };
        Update: {
          author_id?: string | null;
          body?: string;
          created_at?: string;
          id?: string;
          investigation_id?: string;
          kind?: string;
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
      rate_limit_buckets: {
        Row: {
          bucket_key: string;
          count: number;
          window_start: string;
        };
        Insert: {
          bucket_key: string;
          count?: number;
          window_start: string;
        };
        Update: {
          bucket_key?: string;
          count?: number;
          window_start?: string;
        };
        Relationships: [];
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
      response_action_log: {
        Row: {
          action_id: string;
          alert_id: string | null;
          created_at: string;
          created_by: string | null;
          id: string;
          investigation_id: string | null;
          notes: string | null;
          performed_at: string | null;
          performed_by: string | null;
          source: string;
          status: string;
        };
        Insert: {
          action_id: string;
          alert_id?: string | null;
          created_at?: string;
          created_by?: string | null;
          id?: string;
          investigation_id?: string | null;
          notes?: string | null;
          performed_at?: string | null;
          performed_by?: string | null;
          source: string;
          status?: string;
        };
        Update: {
          action_id?: string;
          alert_id?: string | null;
          created_at?: string;
          created_by?: string | null;
          id?: string;
          investigation_id?: string | null;
          notes?: string | null;
          performed_at?: string | null;
          performed_by?: string | null;
          source?: string;
          status?: string;
        };
        Relationships: [
          {
            foreignKeyName: "response_action_log_action_id_fkey";
            columns: ["action_id"];
            isOneToOne: false;
            referencedRelation: "response_actions";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "response_action_log_alert_id_fkey";
            columns: ["alert_id"];
            isOneToOne: false;
            referencedRelation: "alerts";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "response_action_log_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "response_action_log_investigation_id_fkey";
            columns: ["investigation_id"];
            isOneToOne: false;
            referencedRelation: "investigations";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "response_action_log_performed_by_fkey";
            columns: ["performed_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
      response_actions: {
        Row: {
          category: string | null;
          created_at: string;
          created_by: string | null;
          description: string | null;
          id: string;
          origin: Database["public"]["Enums"]["data_origin"];
          title: string;
          updated_at: string;
        };
        Insert: {
          category?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          id?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          title: string;
          updated_at?: string;
        };
        Update: {
          category?: string | null;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          id?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          title?: string;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "response_actions_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
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
      wazuh_rules: {
        Row: {
          ai_model: string | null;
          ai_prompt: string | null;
          ai_provider: string | null;
          changed_since_push: boolean;
          conditions: NonNullable<Json>;
          created_at: string;
          created_by: string | null;
          description: string | null;
          frequency: number | null;
          github_commit: string | null;
          github_path: string | null;
          id: number;
          level: number;
          mitre_ids: string[];
          name: string;
          origin: Database["public"]["Enums"]["data_origin"];
          parent_kind: string;
          parent_value: string;
          pushed_at: string | null;
          pushed_by: string | null;
          reject_reason: string | null;
          rejected_at: string | null;
          same_fields: string[];
          source: string;
          status: string;
          timeframe: number | null;
          updated_at: string;
        };
        Insert: {
          ai_model?: string | null;
          ai_prompt?: string | null;
          ai_provider?: string | null;
          changed_since_push?: boolean;
          conditions: NonNullable<Json>;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          frequency?: number | null;
          github_commit?: string | null;
          github_path?: string | null;
          id: number;
          level: number;
          mitre_ids?: string[];
          name: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          parent_kind?: string;
          parent_value?: string;
          pushed_at?: string | null;
          pushed_by?: string | null;
          reject_reason?: string | null;
          rejected_at?: string | null;
          same_fields?: string[];
          source: string;
          status?: string;
          timeframe?: number | null;
          updated_at?: string;
        };
        Update: {
          ai_model?: string | null;
          ai_prompt?: string | null;
          ai_provider?: string | null;
          changed_since_push?: boolean;
          conditions?: NonNullable<Json>;
          created_at?: string;
          created_by?: string | null;
          description?: string | null;
          frequency?: number | null;
          github_commit?: string | null;
          github_path?: string | null;
          id?: number;
          level?: number;
          mitre_ids?: string[];
          name?: string;
          origin?: Database["public"]["Enums"]["data_origin"];
          parent_kind?: string;
          parent_value?: string;
          pushed_at?: string | null;
          pushed_by?: string | null;
          reject_reason?: string | null;
          rejected_at?: string | null;
          same_fields?: string[];
          source?: string;
          status?: string;
          timeframe?: number | null;
          updated_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "wazuh_rules_created_by_fkey";
            columns: ["created_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "wazuh_rules_pushed_by_fkey";
            columns: ["pushed_by"];
            isOneToOne: false;
            referencedRelation: "profiles";
            referencedColumns: ["id"];
          },
        ];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      activity_series: {
        Args: { p_days?: number };
        Returns: {
          alerts: number;
          day: string;
          events: number;
        }[];
      };
      alert_severity_counts: {
        Args: Record<PropertyKey, never>;
        Returns: {
          severity: Database["public"]["Enums"]["severity"];
          total: number;
        }[];
      };
      alert_sources: { Args: Record<PropertyKey, never>; Returns: string[] };
      alert_status_counts: {
        Args: Record<PropertyKey, never>;
        Returns: {
          status: Database["public"]["Enums"]["alert_status"];
          total: number;
          unassigned: number;
        }[];
      };
      check_rate_limit: {
        Args: { p_key: string; p_limit: number; p_window_seconds: number };
        Returns: {
          allowed: boolean;
          retry_after_seconds: number;
        }[];
      };
      current_role_name: { Args: Record<PropertyKey, never>; Returns: string };
      detection_rule_matches: {
        Args: { p_alert: Database["public"]["Tables"]["alerts"]["Row"]; p_conditions: Json };
        Returns: boolean;
      };
      escape_like: { Args: { p_text: string }; Returns: string };
      has_permission: { Args: { p_key: string }; Returns: boolean };
      import_external_vulnerabilities: { Args: { p_records: Json }; Returns: Json };
      import_external_vulnerability: { Args: { p: Json }; Returns: string };
      import_mitre_attack: { Args: { p: Json }; Returns: Json };
      indicator_type_counts: {
        Args: Record<PropertyKey, never>;
        Returns: {
          total: number;
          type: Database["public"]["Enums"]["indicator_type"];
        }[];
      };
      indicator_verdict_counts: {
        Args: Record<PropertyKey, never>;
        Returns: {
          total: number;
          verdict: Database["public"]["Enums"]["verdict"];
        }[];
      };
      ingest_telemetry: { Args: { p_records: Json; p_source: string }; Returns: Json };
      investigation_status_counts: {
        Args: Record<PropertyKey, never>;
        Returns: {
          status: Database["public"]["Enums"]["investigation_status"];
          total: number;
        }[];
      };
      is_valid_indicator: {
        Args: { p_type: Database["public"]["Enums"]["indicator_type"]; p_value: string };
        Returns: boolean;
      };
      mitre_observed_techniques: {
        Args: Record<PropertyKey, never>;
        Returns: {
          alert_count: number;
          last_seen: string;
          max_severity: Database["public"]["Enums"]["severity"];
          technique_id: string;
        }[];
      };
      record_external_indicators: { Args: { p_records: Json; p_source: string }; Returns: Json };
      search_alerts: {
        Args: { p_query?: string };
        Returns: {
          acknowledged_at: string | null;
          ai_fp_score: number | null;
          asset_id: string | null;
          assigned_to: string | null;
          created_at: string;
          created_by: string | null;
          description: string | null;
          duplicate_count: number;
          duplicate_of: string | null;
          event_id: string | null;
          fingerprint: string | null;
          id: string;
          indicator_id: string | null;
          matched_rule_id: number | null;
          origin: Database["public"]["Enums"]["data_origin"];
          resolved_at: string | null;
          severity: Database["public"]["Enums"]["severity"];
          source: string;
          source_event_id: string | null;
          status: Database["public"]["Enums"]["alert_status"];
          technique_ids: string[];
          title: string;
          updated_at: string;
        }[];
        SetofOptions: {
          from: "*";
          to: "alerts";
          isOneToOne: false;
          isSetofReturn: true;
        };
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
          researched_at: string | null;
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
      search_investigations: {
        Args: { p_query?: string; p_tag?: string };
        Returns: {
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
        }[];
        SetofOptions: {
          from: "*";
          to: "investigations";
          isOneToOne: false;
          isSetofReturn: true;
        };
      };
      search_mitre_techniques: {
        Args: { p_query?: string };
        Returns: {
          description: string | null;
          id: string;
          name: string;
          tactics: string[];
          url: string | null;
        }[];
        SetofOptions: {
          from: "*";
          to: "mitre_techniques";
          isOneToOne: false;
          isSetofReturn: true;
        };
      };
      search_reports: {
        Args: { p_query?: string };
        Returns: {
          content: NonNullable<Json>;
          created_at: string;
          created_by: string | null;
          id: string;
          investigation_id: string | null;
          origin: Database["public"]["Enums"]["data_origin"];
          parameters: NonNullable<Json>;
          title: string;
          type: Database["public"]["Enums"]["report_type"];
        }[];
        SetofOptions: {
          from: "*";
          to: "reports";
          isOneToOne: false;
          isSetofReturn: true;
        };
      };
      search_vulnerabilities: {
        Args: { p_query?: string };
        Returns: {
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
        }[];
        SetofOptions: {
          from: "*";
          to: "vulnerabilities";
          isOneToOne: false;
          isSetofReturn: true;
        };
      };
      set_indicator_tags: {
        Args: { p_indicator_id: string; p_tags: string[] };
        Returns: undefined;
      };
      set_investigation_tags: {
        Args: { p_investigation_id: string; p_tags: string[] };
        Returns: undefined;
      };
      severity_rank: {
        Args: { p_severity: Database["public"]["Enums"]["severity"] };
        Returns: number;
      };
      telemetry_source_health: {
        Args: Record<PropertyKey, never>;
        Returns: {
          alerts_total: number;
          assets_total: number;
          events_24h: number;
          events_total: number;
          last_event_at: string;
          last_received_at: string;
          origin: Database["public"]["Enums"]["data_origin"];
          source: string;
        }[];
      };
      verdict_rank: {
        Args: { p_verdict: Database["public"]["Enums"]["verdict"] };
        Returns: number;
      };
      vulnerability_severity_counts: {
        Args: Record<PropertyKey, never>;
        Returns: {
          exploited: number;
          severity: Database["public"]["Enums"]["severity"];
          total: number;
        }[];
      };
      wazuh_rule_trigger_stats: {
        Args: Record<PropertyKey, never>;
        Returns: {
          last_triggered: string;
          rule_id: number;
          triggers: number;
        }[];
      };
    };
    Enums: {
      alert_status: "new" | "acknowledged" | "investigating" | "resolved" | "false_positive";
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
