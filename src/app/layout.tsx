import type { Metadata, Viewport } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import { cookies } from "next/headers";
import { THEME_COOKIE, parseTheme } from "@/lib/theme";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "ArcRadar", template: "%s · ArcRadar" },
  description: "Cybersecurity intelligence and threat monitoring platform.",
  applicationName: "ArcRadar",
};

export const viewport: Viewport = {
  themeColor: "#0a0e14",
  colorScheme: "dark light",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  // The theme lives in a cookie so the server can render the right colors on the first paint.
  const theme = parseTheme((await cookies()).get(THEME_COOKIE)?.value);

  return (
    <html
      lang="en"
      data-theme={theme}
      className={`${GeistSans.variable} ${GeistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full">
        <a href="#main" className="skip-link">
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
