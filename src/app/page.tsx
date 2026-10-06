import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { Hero, LandingHeader } from "@/components/marketing/hero";
import {
  AlertTrace,
  Connections,
  LandingFooter,
  Roles,
  Rules,
  Security,
  Setup,
} from "@/components/marketing/sections";
import { getPageAuth } from "@/lib/auth/session";

export const metadata: Metadata = {
  title: { absolute: "ArcRadar: the case file for every alert your SIEM raises" },
  description:
    "ArcRadar takes alerts from Wazuh and Splunk, researches the indicators inside them, places them on the MITRE ATT&CK matrix and gives analysts a queue, a case file and an audit trail. Detection rules go back to the SIEM as reviewed files in Git.",
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
        <Connections />
        <AlertTrace />
        <Rules />
        <Roles />
        <Security />
        <Setup />
      </main>
      <LandingFooter />
    </>
  );
}
