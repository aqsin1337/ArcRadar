import { CircleAlert, CircleCheck, Info, TriangleAlert, type LucideIcon } from "lucide-react";
import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";
import { toneClasses, type Tone } from "./badge";

type AlertTone = "info" | "success" | "warning" | "error";

const ALERT_TONES: Record<AlertTone, { tone: Tone; icon: LucideIcon }> = {
  info: { tone: "blue", icon: Info },
  success: { tone: "green", icon: CircleCheck },
  warning: { tone: "amber", icon: TriangleAlert },
  error: { tone: "red", icon: CircleAlert },
};

type AlertProps = Omit<HTMLAttributes<HTMLDivElement>, "title"> & {
  tone?: AlertTone;
  title?: ReactNode;
};

/**
 * Inline message. Errors use role="alert" (announced immediately); everything else uses
 * role="status" (announced politely). Meaning is carried by the icon and text, not color alone.
 */
export function Alert({ tone = "info", title, className, children, ...props }: AlertProps) {
  const { tone: colors, icon: Icon } = ALERT_TONES[tone];
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cn(
        "flex gap-3 rounded-lg border px-3.5 py-3 text-sm",
        toneClasses(colors),
        className,
      )}
      {...props}
    >
      <Icon aria-hidden className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0 space-y-0.5">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className="break-words">{children}</div>}
      </div>
    </div>
  );
}
