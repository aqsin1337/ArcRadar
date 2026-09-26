import {
  Bell,
  Bug,
  Crosshair,
  FileText,
  FolderSearch,
  Globe,
  Hash,
  KeyRound,
  LayoutDashboard,
  Link2,
  Network,
  Plug,
  ScrollText,
  Settings,
  Skull,
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
      { label: "Alerts", href: "/alerts", icon: Bell, status: "soon", permission: "alerts:read" },
      {
        label: "Investigations",
        href: "/investigations",
        icon: FolderSearch,
        status: "soon",
        permission: "investigations:read",
      },
      {
        label: "Reports",
        href: "/reports",
        icon: FileText,
        status: "soon",
        permission: "reports:read",
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
        status: "soon",
        permission: "indicators:read",
      },
      {
        label: "Domain intelligence",
        href: "/intelligence/domain",
        icon: Globe,
        status: "soon",
        permission: "indicators:read",
      },
      {
        label: "URL analysis",
        href: "/intelligence/url",
        icon: Link2,
        status: "soon",
        permission: "indicators:read",
      },
      {
        label: "Hash lookup",
        href: "/intelligence/hash",
        icon: Hash,
        status: "soon",
        permission: "indicators:read",
      },
      {
        label: "Vulnerabilities",
        href: "/vulnerabilities",
        icon: Bug,
        status: "soon",
        permission: "vulnerabilities:read",
      },
      {
        label: "Threat actors",
        href: "/threat-actors",
        icon: Skull,
        status: "soon",
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
        status: "soon",
        permission: "integrations:read",
      },
      {
        label: "API keys",
        href: "/api-keys",
        icon: KeyRound,
        status: "soon",
        permission: "api_keys:manage_own",
      },
      {
        label: "Audit log",
        href: "/audit-log",
        icon: ScrollText,
        status: "soon",
        permission: "audit:read",
      },
      {
        label: "Settings",
        href: "/settings",
        icon: Settings,
        status: "soon",
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
