import type { ReactNode } from "react";

/** Heading block used on every auth page: title, one-line description, then the form. */
export function AuthCard({
  title,
  description,
  children,
  footer,
}: {
  title: string;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="space-y-6">
      <div className="space-y-1.5">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-sm text-muted">{description}</p>}
      </div>
      {children}
      {footer && <div className="text-sm text-muted">{footer}</div>}
    </div>
  );
}
