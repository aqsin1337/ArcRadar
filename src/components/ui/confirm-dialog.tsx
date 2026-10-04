"use client";

import { TriangleAlert } from "lucide-react";
import { useEffect, useId, useRef, type ReactNode } from "react";
import { Alert } from "./alert";
import { Button } from "./button";

type ConfirmDialogProps = {
  open: boolean;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  pending?: boolean;
  /** Shown inside the dialog when the confirmed action failed. */
  error?: string | null;
  onConfirm: () => void;
  onCancel: () => void;
};

/**
 * Confirmation for destructive actions, on the native <dialog> element: focus is trapped, Escape
 * cancels, and the page behind is inert. Focus starts on Cancel so Enter never deletes by accident.
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  pending = false,
  error,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    if (open && !element.open) element.showModal();
    if (!open && element.open) element.close();
  }, [open]);

  return (
    <dialog
      ref={dialog}
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
      // Escape fires "cancel"; route it through our state instead of letting the DOM close it silently.
      onCancel={(event) => {
        event.preventDefault();
        if (!pending) onCancel();
      }}
      onClick={(event) => {
        if (event.target === dialog.current && !pending) onCancel();
      }}
      className="m-auto w-[calc(100%-2rem)] max-w-md rounded-xl border border-border bg-surface p-0 text-foreground shadow-2xl backdrop:bg-black/60"
    >
      <div className="space-y-4 p-5">
        <div className="flex items-start gap-3">
          <span className="flex size-9 shrink-0 items-center justify-center rounded-full border border-tone-red-border bg-tone-red-bg text-tone-red-fg">
            <TriangleAlert aria-hidden className="size-4" />
          </span>
          <div className="min-w-0 space-y-1.5">
            <h2 id={titleId} className="text-base font-semibold">
              {title}
            </h2>
            <div id={descriptionId} className="text-sm break-words text-muted">
              {description}
            </div>
          </div>
        </div>
        {error && <Alert tone="error">{error}</Alert>}
        <div className="flex justify-end gap-2">
          <Button autoFocus variant="secondary" onClick={onCancel} disabled={pending}>
            Cancel
          </Button>
          <Button variant="danger" onClick={onConfirm} loading={pending}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </dialog>
  );
}
