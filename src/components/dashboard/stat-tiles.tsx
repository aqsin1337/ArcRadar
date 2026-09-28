import Link from "next/link";
import type { DashboardCounts } from "@/lib/dashboard/types";

function Tile({
  href,
  label,
  value,
  tone,
}: {
  href: string;
  label: string;
  value: number;
  tone?: "red" | "orange";
}) {
  return (
    <Link
      href={href}
      className="flex min-w-0 flex-col justify-between gap-2 rounded-xl border border-border bg-surface p-3 transition-colors hover:bg-surface-2"
    >
      <span className="text-sm text-muted">{label}</span>
      <span
        className={`text-2xl font-semibold tabular-nums tracking-tight ${
          tone === "red" ? "text-tone-red-fg" : tone === "orange" ? "text-tone-orange-fg" : ""
        }`}
      >
        {value}
      </span>
    </Link>
  );
}

export function StatTiles({ counts, days }: { counts: DashboardCounts; days: number }) {
  return (
    <ul className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
      <li className="contents">
        <Tile href="/indicators" label="Total indicators" value={counts.indicators_total} />
      </li>
      <li className="contents">
        <Tile
          href="/indicators?verdict=malicious"
          label="Malicious indicators"
          value={counts.indicators_malicious}
          tone="red"
        />
      </li>
      <li className="contents">
        <Tile
          href="/indicators?verdict=suspicious"
          label="Suspicious indicators"
          value={counts.indicators_suspicious}
          tone="orange"
        />
      </li>
      <li className="contents">
        <Tile
          href="/alerts?status=new"
          label="Active alerts"
          value={counts.alerts_active}
          tone="red"
        />
      </li>
      <li className="contents">
        <Tile
          href="/vulnerabilities?severity=critical"
          label="Critical vulnerabilities"
          value={counts.vulnerabilities_critical}
          tone="red"
        />
      </li>
      <li className="contents">
        <Tile
          href="/investigations"
          label="Open investigations"
          value={counts.investigations_open}
        />
      </li>
      <li className="contents">
        <Tile
          href="/telemetry"
          label={`Events, last ${days} ${days === 1 ? "day" : "days"}`}
          value={counts.events_recent}
        />
      </li>
      <li className="contents">
        <Tile
          href="/alerts"
          label={`Alerts, last ${days} ${days === 1 ? "day" : "days"}`}
          value={counts.alerts_recent}
        />
      </li>
    </ul>
  );
}
