"use client";

import { createContext, useContext, useMemo, type ReactNode } from "react";
import type { SessionInfo } from "@/lib/auth/context";
import type { Permission } from "@/lib/rbac/permissions";

const SessionContext = createContext<SessionInfo | null>(null);

/**
 * Makes the signed-in user's role and permissions available to Client Components. This only shapes
 * the UI (hide a button, gray out a tab); the API and RLS enforce access on every request.
 */
export function SessionProvider({
  session,
  children,
}: {
  session: SessionInfo;
  children: ReactNode;
}) {
  return <SessionContext value={session}>{children}</SessionContext>;
}

export function useSession(): SessionInfo {
  const session = useContext(SessionContext);
  if (!session) throw new Error("useSession must be used inside <SessionProvider>.");
  return session;
}

/** True when the signed-in user holds `permission`. */
export function useCan(permission: Permission): boolean {
  const { permissions } = useSession();
  return useMemo(() => permissions.includes(permission), [permissions, permission]);
}

/** Renders `children` only for users who hold `permission`. */
export function Can({
  permission,
  children,
  fallback = null,
}: {
  permission: Permission;
  children: ReactNode;
  fallback?: ReactNode;
}) {
  return useCan(permission) ? children : fallback;
}
