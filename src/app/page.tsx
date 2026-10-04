import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Hero, LandingHeader } from "@/components/marketing/hero";
import {
  FinalCta,
  HonestByDesign,
  LandingFooter,
  Pipeline,
  Platform,
  RulesAsCode,
  Security,
  StatsBand,
} from "@/components/marketing/sections";
import { getPageAuth } from "@/lib/auth/session";

export const metadata: Metadata = {
  title: { absolute: "ArcRadar: incident response and threat monitoring" },
  description:
    "Incident-response and case-management platform that complements your SIEM. Wazuh telemetry, threat-intelligence research, MITRE ATT&CK, AI-assisted triage, role-based access and a full audit trail.",
};

/**
 * The public front door. A signed-in visitor goes straight to the app (disabled and unavailable
 * accounts are explained by the app layout); a signed-out one sees the product. Static copy only:
 * nothing here reads workspace data.
 */
export default async function Home() {
  const auth = await getPageAuth();
  if (auth.status !== "signed_out") redirect("/dashboard");

  return (
    <>
      <LandingHeader />
      <main id="main">
        <Hero />
        <StatsBand />
        <Platform />
        <Pipeline />
        <RulesAsCode />
        <Security />
        <HonestByDesign />
        <FinalCta />
      </main>
      <LandingFooter />
    </>
  );
}
