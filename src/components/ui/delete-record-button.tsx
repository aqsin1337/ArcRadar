"use client";

import { Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { apiFetch } from "@/lib/api/client";

/**
 * Delete with a confirmation step, for a threat actor, campaign or malware family. Only render it for
 * users who hold `threat_intel:write`.
 */
export function DeleteRecordButton({
  endpoint,
  listHref,
  noun,
  name,
  consequence,
}: {
  /** The record's API path, for example `/api/campaigns/123`. */
  endpoint: string;
  /** Where to go afterwards, for example `/campaigns`. */
  listHref: string;
  /** "campaign", "threat actor", "malware family". */
  noun: string;
  name: string;
  /** What else disappears with it. */
  consequence: ReactNode;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function confirm() {
    setPending(true);
    setError(null);
    const result = await apiFetch(endpoint, { method: "DELETE" });
    if (!result.ok) {
      setPending(false);
      setError(result.status === 404 ? `This ${noun} no longer exists.` : result.message);
      return;
    }
    router.replace(listHref);
    router.refresh();
  }

  return (
    <>
      <Button variant="danger" onClick={() => setOpen(true)}>
        <Trash2 aria-hidden className="size-4" />
        Delete
      </Button>
      <ConfirmDialog
        open={open}
        title={`Delete this ${noun}?`}
        description={
          <>
            <strong className="font-semibold text-foreground">{name}</strong> will be removed.{" "}
            {consequence} This cannot be undone.
          </>
        }
        confirmLabel={`Delete ${noun}`}
        pending={pending}
        error={error}
        onConfirm={confirm}
        onCancel={() => {
          setOpen(false);
          setError(null);
        }}
      />
    </>
  );
}
