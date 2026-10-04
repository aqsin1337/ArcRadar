import { Alert } from "@/components/ui/alert";
import type { DataOrigin } from "@/types/domain";

/**
 * The provenance line at the top of a record: demo data is announced as sample data, local data as
 * unverified. External data needs no warning unless the caller gives one (`externalText`).
 */
export function ProvenanceNotice({
  origin,
  externalText,
  className,
}: {
  origin: DataOrigin;
  externalText?: string;
  className?: string;
}) {
  if (origin === "demo") {
    return (
      <Alert tone="warning" className={className}>
        This is demo data: a sample record for demonstration, not live intelligence.
      </Alert>
    );
  }
  if (origin === "local") {
    return (
      <Alert tone="info" className={className}>
        Local data: entered by your team and not verified by an external provider.
      </Alert>
    );
  }
  return externalText ? (
    <Alert tone="info" className={className}>
      {externalText}
    </Alert>
  ) : null;
}
