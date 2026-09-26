import { Ban, Inbox, ServerCrash, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/cn";
import { toneClasses, type Tone } from "./badge";

type StateProps = {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  icon?: LucideIcon;
  /** Small monospace line, for example an error reference to quote to support. */
  detail?: string;
  className?: string;
};

function StateLayout({
  icon: Icon,
  tone,
  role,
  title,
  description,
  action,
  detail,
  className,
}: StateProps & { icon: LucideIcon; tone: Tone; role?: "alert" | "status" }) {
  return (
    <div
      role={role}
      className={cn(
        "mx-auto flex max-w-md flex-col items-center gap-3 px-4 py-12 text-center",
        className,
      )}
    >
      <span
        className={cn(
          "flex size-12 items-center justify-center rounded-full border",
          toneClasses(tone),
        )}
      >
        <Icon aria-hidden className="size-5" />
      </span>
      <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
      {description && <p className="text-sm text-muted">{description}</p>}
      {detail && (
        <code className="rounded bg-surface-2 px-2 py-1 text-xs text-muted">{detail}</code>
      )}
      {action && <div className="mt-2 flex flex-wrap justify-center gap-2">{action}</div>}
    </div>
  );
}

/** Nothing to show yet (no records, no results). Say what will appear and how to get there. */
export function EmptyState({ icon = Inbox, ...props }: StateProps) {
  return <StateLayout icon={icon} tone="slate" {...props} />;
}

/** Something failed. Say what happened in plain words and offer a way forward (retry, go back). */
export function ErrorState({ icon = ServerCrash, ...props }: StateProps) {
  return <StateLayout icon={icon} tone="red" role="alert" {...props} />;
}

/** The visitor is signed in but lacks the permission for this page. */
export function AccessDenied({
  title = "You don't have access to this page",
  description = "Your role does not include the permission this page needs. Ask an administrator if you think that is a mistake.",
  ...props
}: Partial<StateProps>) {
  return (
    <StateLayout
      icon={Ban}
      tone="amber"
      role="alert"
      title={title}
      description={description}
      {...props}
    />
  );
}
