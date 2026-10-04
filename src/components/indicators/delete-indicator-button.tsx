"use client";

import { Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { apiFetch } from "@/lib/api/client";

/** Delete with a confirmation step. Only render it for users who hold `indicators:delete`. */
export function DeleteIndicatorButton({ id, value }: { id: string; value: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function confirm() {
    setPending(true);
    setError(null);
    const result = await apiFetch(`/api/indicators/${id}`, { method: "DELETE" });
    if (!result.ok) {
      setPending(false);
      setError(result.status === 404 ? "This indicator no longer exists." : result.message);
      return;
    }
    router.replace("/indicators");
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
        title="Delete this indicator?"
        description={
          <>
            <code className="break-all text-foreground">{value}</code> will be removed together with
            its tags and relationships. This cannot be undone. Reports and investigations that
            mention it lose the link.
          </>
        }
        confirmLabel="Delete indicator"
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
