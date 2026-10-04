import { ScrollText } from "lucide-react";
import type { Metadata } from "next";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { ListResults } from "@/components/ui/list-results";
import { PageHeader } from "@/components/ui/page-header";
import { Select } from "@/components/ui/select";
import { AccessDenied } from "@/components/ui/states";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { AUDIT_ACTIONS } from "@/lib/audit/actions";
import { auditLogList, parseAuditLogListParams } from "@/lib/audit/query";
import { listAuditLogs } from "@/lib/audit/service";
import { getPageAuthContext } from "@/lib/auth/session";
import { findDisplayNames } from "@/lib/team/repository";
import type { RawParams } from "@/lib/validation/query";

export const metadata: Metadata = { title: "Audit log" };

export default async function AuditLogPage({ searchParams }: PageProps<"/audit-log">) {
  const auth = await getPageAuthContext();
  if (!auth) return null;
  if (!auth.permissions.has("audit:read")) return <AccessDenied />;

  const { query, ignoredInvalid } = parseAuditLogListParams(withFullDayRange(await searchParams));
  const { items, pagination } = await listAuditLogs(auth.supabase, query);
  const names = await findDisplayNames(
    auth.supabase,
    items.map((entry) => entry.user_id),
  );
  const filtered = auditLogList.hasActive(query);

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every security-relevant action, who did it, and when. Append-only: nothing here can be edited or removed."
      />

      <div className="space-y-4">
        {ignoredInvalid && (
          <Alert tone="warning">
            Some options in the address were not valid, so the default view is shown.
          </Alert>
        )}

        <form method="get" className="grid gap-3 sm:grid-cols-4">
          <label className="space-y-1 text-sm">
            <span className="text-muted">Action</span>
            <Select name="action" defaultValue={query.action ?? ""}>
              <option value="">Any action</option>
              {AUDIT_ACTIONS.map((action) => (
                <option key={action} value={action}>
                  {action}
                </option>
              ))}
            </Select>
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-muted">Entity type</span>
            <Input name="entity_type" defaultValue={query.entity_type ?? ""} maxLength={100} />
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-muted">From (UTC date)</span>
            <Input type="date" name="from" defaultValue={query.from?.slice(0, 10) ?? ""} />
          </label>
          <label className="space-y-1 text-sm">
            <span className="text-muted">To (UTC date)</span>
            <Input type="date" name="to" defaultValue={query.to?.slice(0, 10) ?? ""} />
          </label>
          <div className="sm:col-span-4 flex items-center gap-3">
            <button
              type="submit"
              className="rounded-lg border border-input-border px-3 py-1.5 text-sm hover:bg-surface-2"
            >
              Apply
            </button>
            {filtered && (
              <a href="/audit-log" className="text-sm text-muted underline underline-offset-2">
                Clear
              </a>
            )}
          </div>
        </form>

        <ListResults
          pagination={pagination}
          count={items.length}
          filtered={filtered}
          noun={["entry", "entries"]}
          listHref="/audit-log"
          hrefForPage={(page) => auditLogList.href(query, { page })}
          empty={{
            icon: ScrollText,
            title: filtered ? "No entries match" : "Nothing recorded yet",
            description: filtered
              ? "Try a different action, entity type or date range."
              : "Security-relevant actions will appear here as people use ArcRadar.",
          }}
        >
          <Table caption="Audit log">
            <THead>
              <Tr>
                <Th>Action</Th>
                <Th className="hidden @lg:table-cell">When</Th>
                <Th className="hidden @lg:table-cell">Who</Th>
                <Th className="hidden @lg:table-cell">Entity</Th>
                <Th className="hidden @xl:table-cell">From</Th>
              </Tr>
            </THead>
            <TBody>
              {items.map((entry) => (
                <Tr key={entry.id}>
                  <Td>
                    <Badge tone="slate">{entry.action}</Badge>
                    <span className="mt-1 block text-xs text-muted @lg:hidden">
                      {new Date(entry.created_at).toISOString().replace("T", " ").slice(0, 16)} UTC
                    </span>
                    {Object.keys(entry.metadata as object).length > 0 && (
                      <details className="mt-1">
                        <summary className="cursor-pointer text-xs text-muted">Details</summary>
                        <pre className="mt-1 max-w-xs overflow-x-auto rounded bg-surface-2 p-2 text-[11px]">
                          {JSON.stringify(entry.metadata, null, 2)}
                        </pre>
                      </details>
                    )}
                  </Td>
                  <Td className="hidden @lg:table-cell whitespace-nowrap text-xs text-muted">
                    {new Date(entry.created_at).toISOString().replace("T", " ").slice(0, 19)} UTC
                  </Td>
                  <Td className="hidden @lg:table-cell text-sm">
                    {entry.user_id ? (names.get(entry.user_id) ?? entry.user_id) : "System"}
                  </Td>
                  <Td className="hidden @lg:table-cell text-sm text-muted">
                    {entry.entity_type ?? "—"}
                    {entry.entity_id && (
                      <span className="block font-mono text-[11px] [overflow-wrap:anywhere]">
                        {entry.entity_id}
                      </span>
                    )}
                  </Td>
                  <Td className="hidden @xl:table-cell font-mono text-xs text-muted">
                    {entry.ip_address ? String(entry.ip_address) : "—"}
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
        </ListResults>
      </div>
    </>
  );
}

/** The date filter is a plain <input type="date"> (a bare "2026-09-27"); the API wants a full,
 * offset ISO datetime, so "from" becomes the start of that UTC day and "to" the end of it. */
function withFullDayRange(params: RawParams): RawParams {
  const bareDate = /^\d{4}-\d{2}-\d{2}$/;
  const from = firstValue(params.from);
  const to = firstValue(params.to);
  return {
    ...params,
    from: from && bareDate.test(from) ? `${from}T00:00:00Z` : params.from,
    to: to && bareDate.test(to) ? `${to}T23:59:59Z` : params.to,
  };
}

function firstValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
