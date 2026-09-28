"use client";

import { CloudDownload } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { apiFetch } from "@/lib/api/client";
import type { VulnerabilityDetail } from "@/lib/vulnerabilities/types";

/**
 * Fetches a CVE from the connected provider and records it as external data (or refreshes the
 * external record already there). The server decides whether the caller may, and says why not.
 */
export function ImportCveButton({
  cveId,
  label,
  variant = "primary",
}: {
  cveId: string;
  label: string;
  variant?: "primary" | "secondary";
}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onClick() {
    setPending(true);
    setError(null);
    const result = await apiFetch<VulnerabilityDetail>("/api/vulnerabilities/import", {
      body: { cve_id: cveId },
    });
    if (result.ok) {
      router.push(`/vulnerabilities/${result.data.cve_id}`);
      router.refresh();
    } else {
      setError(result.message);
    }
    setPending(false);
  }

  return (
    <div className="space-y-2">
      <Button type="button" variant={variant} loading={pending} onClick={onClick}>
        <CloudDownload aria-hidden className="size-4" />
        {label}
      </Button>
      {error && <Alert tone="error">{error}</Alert>}
    </div>
  );
}
