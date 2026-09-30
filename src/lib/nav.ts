import {
  Activity,
  Bell,
  Bug,
  Crosshair,
  FileText,
  Filter,
  FolderSearch,
  Globe,
  Grid3x3,
  Hash,
  KeyRound,
  LayoutDashboard,
  Link2,
  ListChecks,
  Network,
  Plug,
  ScrollText,
  Settings,
  type LucideIcon,
} from "lucide-react";
import type { Permission } from "@/lib/rbac/permissions";

/**
 * The app's navigation, in one place. `live` items link to a real page; `soon` items are shown
 * muted with a "Soon" tag so the shell looks complete while modules are still being built. Flip an
 * item to `live` when its page ships. Items are hidden from users who lack `permission`.
 */
export type NavItem = {
  label: string;
  href: string;
  icon: LucideIcon;
  status: "live" | "soon";
  permission?: Permission;
};

export type NavGroup = { label: string | null; items: NavItem[] };

export const NAV_GROUPS: NavGroup[] = [
  {
    label: null,
    items: [{ label: "Overview", href: "/dashboard", icon: LayoutDashboard, status: "live" }],
  },
  {
    label: "Operations",
    items: [
      { label: "Alerts", href: "/alerts", icon: Bell, status: "live", permission: "alerts:read" },
      {
        label: "Investigations",
        href: "/investigations",
        icon: FolderSearch,
        status: "live",
        permission: "investigations:read",
      },
      {
        label: "Telemetry",
        href: "/telemetry",
        icon: Activity,
        status: "live",
        permission: "events:read",
      },
      {
        label: "Reports",
        href: "/reports",
        icon: FileText,
        status: "live",
        permission: "reports:read",
      },
      {
        label: "Response actions",
        href: "/response-actions",
        icon: ListChecks,
        status: "live",
        permission: "alerts:read",
      },
    ],
  },
  {
    label: "Intelligence",
    items: [
      {
        label: "Indicators",
        href: "/indicators",
        icon: Crosshair,
        status: "live",
        permission: "indicators:read",
      },
      {
        label: "IP intelligence",
        href: "/intelligence/ip",
        icon: Network,
        status: "live",
        permission: "indicators:read",
      },
      {
        label: "Domain intelligence",
        href: "/intelligence/domain",
        icon: Globe,
        status: "live",
        permission: "indicators:read",
      },
      {
        label: "URL analysis",
        href: "/intelligence/url",
        icon: Link2,
        status: "live",
        permission: "indicators:read",
      },
      {
        label: "Hash lookup",
        href: "/intelligence/hash",
        icon: Hash,
        status: "live",
        permission: "indicators:read",
      },
      {
        label: "Vulnerabilities",
        href: "/vulnerabilities",
        icon: Bug,
        status: "live",
        permission: "vulnerabilities:read",
      },
      {
        label: "MITRE ATT&CK",
        href: "/mitre",
        icon: Grid3x3,
        status: "live",
        permission: "threat_intel:read",
      },
    ],
  },
  {
    label: "Administration",
    items: [
      {
        label: "Integrations",
        href: "/integrations",
        icon: Plug,
        status: "live",
        permission: "integrations:read",
      },
      {
        label: "API keys",
        href: "/api-keys",
        icon: KeyRound,
        status: "live",
        permission: "api_keys:manage_own",
      },
      {
        label: "Detection rules",
        href: "/detection-rules",
        icon: Filter,
        status: "live",
        permission: "rules:manage",
      },
      {
        label: "Audit log",
        href: "/audit-log",
        icon: ScrollText,
        status: "live",
        permission: "audit:read",
      },
      {
        label: "Settings",
        href: "/settings",
        icon: Settings,
        status: "live",
        permission: "settings:manage",
      },
    ],
  },
];

/** Keeps only the items (and groups) the caller may see. */
export function visibleNavGroups(permissions: ReadonlySet<string> | readonly string[]): NavGroup[] {
  const has = (permission: Permission) =>
    Array.isArray(permissions)
      ? permissions.includes(permission)
      : (permissions as ReadonlySet<string>).has(permission);

  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.permission || has(item.permission)),
  })).filter((group) => group.items.length > 0);
}

/** True when `pathname` is the item's page or a page below it (`/alerts/123` keeps Alerts active). */
export function isActivePath(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(`${href}/`);
}
