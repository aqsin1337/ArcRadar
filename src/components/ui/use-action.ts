"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type { ApiResult } from "@/lib/api/client";

/**
 * Runs one write against the JSON API at a time for a client component: tracks which action is
 * pending (so only its button shows a spinner and the others are disabled), keeps the message of the
 * last failure, and refreshes the server-rendered page after a success. Pass `onSuccess` to do
 * something else first (for example to navigate to the record that was just created).
 */
export function useAction() {
  const router = useRouter();
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run<T>(
    key: string,
    request: () => Promise<ApiResult<T>>,
    onSuccess?: (data: T) => void,
  ): Promise<boolean> {
    if (pending) return false;
    setPending(key);
    setError(null);
    const result = await request();
    setPending(null);
    if (!result.ok) {
      setError(result.message);
      return false;
    }
    if (onSuccess) onSuccess(result.data);
    else router.refresh();
    return true;
  }

  return { pending, error, run, clearError: () => setError(null) };
}
