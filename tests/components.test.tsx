import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button, buttonClasses } from "@/components/ui/button";
import {
  AlertStatusBadge,
  OriginBadge,
  SeverityBadge,
  VerdictBadge,
  humanize,
} from "@/components/ui/domain-badges";
import { TextField } from "@/components/ui/input";
import { PasswordField, PasswordRules } from "@/components/ui/password-field";
import { AccessDenied, EmptyState, ErrorState } from "@/components/ui/states";
import { Table, TBody, THead, Td, Th, Tr } from "@/components/ui/table";
import { cn } from "@/lib/cn";

const html = (node: React.ReactElement) => renderToStaticMarkup(node);

describe("cn", () => {
  it("joins truthy parts only", () => {
    expect(cn("a", false, null, undefined, "b")).toBe("a b");
  });
});

describe("Button", () => {
  it("defaults to type=button so it never submits a form by accident", () => {
    expect(html(<Button>Go</Button>)).toContain('type="button"');
  });

  it("is disabled and aria-busy while loading", () => {
    const markup = html(<Button loading>Save</Button>);
    expect(markup).toContain("disabled");
    expect(markup).toContain('aria-busy="true"');
  });

  it("exposes button styling for links", () => {
    expect(buttonClasses({ variant: "secondary", size: "lg" })).toContain("border-input-border");
  });
});

describe("badges", () => {
  it("humanizes enum values", () => {
    expect(humanize("false_positive")).toBe("False positive");
    expect(html(<AlertStatusBadge status="false_positive" />)).toContain("False positive");
  });

  it("puts the meaning in text, not only in color", () => {
    expect(html(<SeverityBadge severity="critical" />)).toContain("Critical");
    expect(html(<VerdictBadge verdict="malicious" />)).toContain("Malicious");
  });

  it("makes demo data unmistakable: dashed violet outline and an explanatory title", () => {
    const demo = html(<OriginBadge origin="demo" />);
    expect(demo).toContain("Demo data");
    expect(demo).toContain("border-dashed");
    expect(demo).toContain("tone-violet");
    expect(demo).toMatch(/title="[^"]*Not live intelligence/);
    expect(html(<OriginBadge origin="local" />)).not.toContain("border-dashed");
  });

  it("labels external provider data as such", () => {
    expect(html(<OriginBadge origin="external" />)).toContain("External provider");
  });

  it("renders a decorative dot with aria-hidden", () => {
    expect(html(<Badge dot>New</Badge>)).toContain('aria-hidden="true"');
  });
});

describe("form fields", () => {
  it("wires label, hint and error to the input for assistive tech", () => {
    const markup = html(
      <TextField
        id="email"
        label="Email"
        hint="Work address"
        error="Enter a valid email."
        required
      />,
    );
    expect(markup).toContain('for="email"');
    expect(markup).toContain('id="email"');
    expect(markup).toContain('aria-invalid="true"');
    expect(markup).toContain('aria-describedby="email-hint email-error"');
    expect(markup).toContain('id="email-error"');
    expect(markup).toContain('role="alert"');
  });

  it("has no error attributes on a valid field", () => {
    const markup = html(<TextField id="name" label="Name" />);
    expect(markup).not.toContain("aria-invalid");
    expect(markup).not.toContain("aria-describedby");
  });

  it("password field starts hidden with a labelled toggle", () => {
    const markup = html(<PasswordField id="pw" label="Password" />);
    expect(markup).toContain('type="password"');
    expect(markup).toContain('aria-label="Show password"');
    expect(markup).toContain('aria-pressed="false"');
  });

  it("password rules report which requirements are met, in text for screen readers", () => {
    const weak = html(<PasswordRules value="abc" />);
    expect(weak).toContain("At least 10 characters");
    expect(weak).toContain("(not met yet)");
    const strong = html(<PasswordRules value="ArcRadar-Demo-1!" />);
    expect(strong).not.toContain("(not met yet)");
    expect(strong).toContain("(met)");
  });
});

describe("Alert", () => {
  it("announces errors assertively and everything else politely", () => {
    expect(html(<Alert tone="error">Nope</Alert>)).toContain('role="alert"');
    expect(html(<Alert tone="success">Yes</Alert>)).toContain('role="status"');
    expect(html(<Alert>Info</Alert>)).toContain('role="status"');
  });
});

describe("states", () => {
  it("empty state explains what is missing", () => {
    const markup = html(<EmptyState title="No indicators" description="Add one." />);
    expect(markup).toContain("<h2");
    expect(markup).toContain("No indicators");
    expect(markup).not.toContain('role="alert"');
  });

  it("error state is announced and can carry a support reference", () => {
    const markup = html(<ErrorState title="Broke" detail="Reference: abc123" />);
    expect(markup).toContain('role="alert"');
    expect(markup).toContain("Reference: abc123");
  });

  it("access denied has sensible default copy", () => {
    const markup = html(<AccessDenied />);
    expect(markup).toContain("don&#x27;t have access");
    expect(markup).toContain('role="alert"');
  });
});

describe("Table", () => {
  it("is a named, keyboard-scrollable region with proper headers", () => {
    const markup = html(
      <Table caption="Indicators">
        <THead>
          <tr>
            <Th>Value</Th>
          </tr>
        </THead>
        <TBody>
          <Tr>
            <Td>1.2.3.4</Td>
          </Tr>
        </TBody>
      </Table>,
    );
    expect(markup).toContain('aria-label="Indicators"');
    expect(markup).toContain('tabindex="0"');
    expect(markup).toContain('scope="col"');
    expect(markup).toContain("<caption");
  });
});
