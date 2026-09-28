"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { humanize } from "@/components/ui/domain-badges";
import { Select } from "@/components/ui/select";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { useAction } from "@/components/ui/use-action";
import { apiFetch } from "@/lib/api/client";
import { formatRelative } from "@/lib/format";
import { ROLE_NAMES, type RoleName } from "@/types/domain";
import type { AdminUser } from "@/lib/users/types";

/** Every account, with a role and active-status control for everyone except the caller themselves. */
export function UsersTable({
  users,
  selfId,
  now,
}: {
  users: AdminUser[];
  selfId: string;
  now: Date;
}) {
  const { pending, error, run } = useAction();
  const [rows, setRows] = useState(users);

  async function patch(id: string, body: { role_name?: RoleName; is_active?: boolean }) {
    // Optimistic: the role select and the active checkbox are both controlled, so they must reflect
    // the change in the same tick as the click, or React's re-render snaps them straight back.
    const previous = rows.find((u) => u.id === id);
    setRows((current) => current.map((u) => (u.id === id ? { ...u, ...body } : u)));
    const ok = await run(id, () => apiFetch(`/api/users/${id}`, { method: "PATCH", body }));
    if (!ok && previous) {
      setRows((current) => current.map((u) => (u.id === id ? previous : u)));
    }
  }

  return (
    <div className="space-y-3">
      {error && <p className="text-sm text-tone-red-fg">{error}</p>}
      <Table caption="Accounts">
        <THead>
          <Tr>
            <Th>Account</Th>
            <Th>Role</Th>
            <Th>Status</Th>
            <Th className="hidden @lg:table-cell">Last sign-in</Th>
          </Tr>
        </THead>
        <TBody>
          {rows.map((user) => {
            const isSelf = user.id === selfId;
            const busy = pending === user.id;
            return (
              <Tr key={user.id}>
                <Td>
                  <span className="font-medium">{user.display_name ?? user.email ?? user.id}</span>
                  <span className="block text-xs text-muted">{user.email}</span>
                </Td>
                <Td>
                  {isSelf ? (
                    <Badge tone="brand">{humanize(user.role)}</Badge>
                  ) : (
                    <Select
                      aria-label={`Role for ${user.email ?? user.id}`}
                      value={user.role}
                      disabled={busy}
                      onChange={(event) =>
                        patch(user.id, { role_name: event.target.value as RoleName })
                      }
                      className="h-8 w-32 text-xs"
                    >
                      {ROLE_NAMES.map((role) => (
                        <option key={role} value={role}>
                          {humanize(role)}
                        </option>
                      ))}
                    </Select>
                  )}
                </Td>
                <Td>
                  {isSelf ? (
                    <Badge tone="green">Active</Badge>
                  ) : (
                    <label className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={user.is_active}
                        disabled={busy}
                        onChange={(event) => patch(user.id, { is_active: event.target.checked })}
                        className="size-4 rounded border-input-border"
                      />
                      {user.is_active ? "Active" : "Disabled"}
                    </label>
                  )}
                </Td>
                <Td className="hidden @lg:table-cell text-sm text-muted">
                  {user.last_sign_in_at ? formatRelative(user.last_sign_in_at, now) : "Never"}
                </Td>
              </Tr>
            );
          })}
        </TBody>
      </Table>
      <p className="text-xs text-muted">
        You cannot change your own role or active status here, and the last active administrator
        cannot be demoted or disabled.
      </p>
    </div>
  );
}
