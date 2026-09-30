# Landing Page — Plan (not built yet)

Status: **plan only, approved for planning on 2026-09-28, not started.** This document exists so a
future session can build the page without re-deriving the decisions below. See decision 27 in
`docs/ARCRADAR_PROGRESS.md` and the "No public landing page" line in that file's Known limitations.

## User's note (2026-09-30)

The user pointed out that opening the site sends a visitor straight to the login panel, and that
this is what they mean by "landing page" being missing: a signed-out visitor to `/` should see a
real page first, not the sign-in form. The routing change below (signed out → render the page
instead of `redirect("/login")`) is the core of the request; the rest is content around it.

## Why

Every phase (0-12) built the authenticated product. Nobody ever built the page a stranger sees first.
Today `src/app/page.tsx` does this and nothing else:

```ts
redirect(auth.status === "signed_out" ? "/login" : "/dashboard");
```

A signed-out visitor to `https://arcradar.vercel.app/` never sees what ArcRadar is — they land on a
bare sign-in form. For a portfolio project shown to judges, that first impression matters: the app
needs one real page that explains what it does and why it's technically interesting, before asking
anyone to sign in.

## Scope for this pass

One page, `/`. Not a marketing subsite. No `/about`, `/pricing`, `/contact`, `/blog` — those are
explicitly out of scope unless the user asks to extend this plan. English only, matching the rest of
the app's UI.

## Routing change

`/` is already in `PUBLIC_PAGES` (`src/lib/auth/routes.ts`), so the proxy already lets a signed-out
visitor load it — **no proxy change needed.** Only `src/app/page.tsx` changes:

- Signed in → redirect straight to `/dashboard`, same as today (a returning user should never see
  marketing copy).
- Signed out → render the landing page itself, instead of redirecting to `/login`.

The page needs its own layout: not the `(app)` shell (sidebar, requires auth) and not the `(auth)`
layout (bare centered card). A new self-contained layout for just this page (its own header with the
ArcRadar wordmark + theme toggle + "Sign in" / "Sign up" links, and its own footer) — simplest as a
`<header>`/`<footer>` inside `page.tsx` itself, or a tiny local layout if it grows. No new route group
needed for one page.

## What it must not do

- **No live data.** No dashboard counts, no real alerts, nothing fetched for an anonymous visitor —
  this page is static copy only. (The production project already has no seed/demo data by design; a
  public page must not tempt anyone into adding some just to have numbers to show.)
- **No new dependencies.** Icons from the already-installed `lucide-react`; any illustrative
  graphic is hand-drawn inline SVG/CSS, matching the dashboard charts' precedent (decision 20) rather
  than pulling in an animation or illustration library.
- **Design tokens only** — the semantic tokens in `globals.css`, dark default + light, never a raw hex
  or Tailwind palette color, same rule as the rest of the app.

## Content sections (draft — confirm wording with the user before building)

1. **Header** — wordmark, theme toggle, "Sign in", "Sign up" (sign-up is genuinely open today —
   new accounts start as read-only viewers).
2. **Hero** — product name, one-line pitch, a short supporting sentence, primary CTA "Sign in",
   secondary CTA "View source" (GitHub). Draft pitch: _"An incident-response and case-management
   platform that complements your SIEM — triage alerts, run investigations, and get AI-assisted
   analysis, all with role-based access and a full audit trail."_ — needs the user's sign-off, it's a
   first draft.
3. **Capability grid** — short cards, one per pillar, icon + 1-2 lines: Indicators & Threat
   Intelligence, Alerts & Investigations (case management), AI-Assisted Analysis, Detection Rules &
   Deduplication, Reports, Audit & Role-Based Access.
4. **How data flows in** — a small explainer (sensor/SIEM → ingest → dedup/rules → alert →
   investigation → AI-assisted triage → report), because the Wazuh pipeline is real and working end to
   end and is worth showing, not just claiming.
5. **Screenshots** — 2-3 real captures (dashboard, an alert with the AI analysis card, an indicator
   page) taken from the live app once this is built. Placeholder-shaped sections until then; capturing
   them is part of the build, not this plan.
6. **Engineering highlights** — a short badge/list band aimed at a technical reviewer: Postgres RLS on
   every table, nonce-based CSP with no `unsafe-inline`, rate limiting, an append-only audit log,
   provenance-tracked records (demo/local/external). This is the "why this is a solid build" section
   for judges, not a user-facing sales pitch.
7. **Footer** — GitHub link, "Holberton portfolio project" note, author line, "Built with Next.js,
   Supabase, Vercel."

## Open questions (need the user's answer before or during build)

- **Public demo account?** Today production has no seed data and the only login is the real admin
  account. Do we want a read-only demo login for a judge to click straight into (would mean adding
  some demo-labelled data to production, a real decision, separate from this plan), or is "Sign in" /
  "Sign up" enough?
- **Exact hero wording** — the pitch above is a first draft.
- **Screenshots vs. hand-drawn mockups** for the first version of the page.
- Anything Holberton-specific that must appear (cohort/program name, specific branding rules)?

## Build checklist (for later, not now)

- `src/app/page.tsx` rewritten as described above.
- New presentational components under `src/components/marketing/` (or similar) — plain, no client
  state needed beyond the existing theme toggle.
- Add `/` (signed-out) to `tests/e2e/accessibility.spec.ts`'s axe pass (Phase 11 pattern).
- A Playwright test: signed-out `/` shows marketing content; signed-in `/` redirects to `/dashboard`.
- Update `docs/ARCRADAR_PROGRESS.md`'s "No public landing page" known-limitation line once built.
- No schema change, no new env var, no new dependency expected.
