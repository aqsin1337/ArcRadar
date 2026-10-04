import type { ActivityPoint } from "@/lib/dashboard/types";

const WIDTH = 600;
const HEIGHT = 160;
const PAD = 8;

function points(values: number[], max: number): string {
  const step = values.length > 1 ? (WIDTH - PAD * 2) / (values.length - 1) : 0;
  return values
    .map((value, index) => {
      const x = PAD + index * step;
      const y = HEIGHT - PAD - (max === 0 ? 0 : (value / max) * (HEIGHT - PAD * 2));
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

const shortDate = (iso: string) =>
  new Date(`${iso}T00:00:00Z`).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });

/**
 * Alerts and events over the selected window, as two lines on one axis (counts). A legend and a
 * plain-text table sit alongside the drawing, since the lines alone name nothing for a screen reader.
 */
export function ActivityChart({ data }: { data: ActivityPoint[] }) {
  const max = Math.max(1, ...data.map((point) => Math.max(point.alerts, point.events)));
  const alerts = data.map((point) => point.alerts);
  const events = data.map((point) => point.events);

  return (
    <div>
      <div className="flex items-center gap-4 text-xs text-muted">
        <span className="flex items-center gap-1.5">
          <span aria-hidden className="size-2.5 rounded-full bg-tone-red-fg" />
          Alerts
        </span>
        <span className="flex items-center gap-1.5">
          <span aria-hidden className="size-2.5 rounded-full bg-tone-brand-fg" />
          Events
        </span>
      </div>
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={`Alerts and events per day, ${shortDate(data[0]?.day ?? "")} to ${shortDate(
          data.at(-1)?.day ?? "",
        )}. See the table below for exact numbers.`}
        className="mt-2 h-32 w-full"
        preserveAspectRatio="none"
      >
        <line
          x1={PAD}
          y1={HEIGHT - PAD}
          x2={WIDTH - PAD}
          y2={HEIGHT - PAD}
          className="stroke-border"
          strokeWidth={1}
        />
        <polyline
          points={points(events, max)}
          fill="none"
          className="stroke-tone-brand-fg"
          strokeWidth={2}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        <polyline
          points={points(alerts, max)}
          fill="none"
          className="stroke-tone-red-fg"
          strokeWidth={2}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      </svg>
      <div className="flex justify-between text-[11px] text-muted">
        <span>{data[0] ? shortDate(data[0].day) : ""}</span>
        <span>{data.at(-1) ? shortDate(data.at(-1)!.day) : ""}</span>
      </div>

      <details className="mt-2">
        <summary className="cursor-pointer text-xs text-muted">View as a table</summary>
        <div className="mt-2 max-h-40 overflow-y-auto rounded-lg border border-border">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-surface-2">
              <tr>
                <th className="px-2 py-1 font-medium">Day</th>
                <th className="px-2 py-1 font-medium">Alerts</th>
                <th className="px-2 py-1 font-medium">Events</th>
              </tr>
            </thead>
            <tbody>
              {data.map((point) => (
                <tr key={point.day} className="border-t border-border">
                  <td className="px-2 py-1">{point.day}</td>
                  <td className="px-2 py-1 tabular-nums">{point.alerts}</td>
                  <td className="px-2 py-1 tabular-nums">{point.events}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
