# ArcRadar

Cybersecurity intelligence and threat-monitoring platform: indicators (IOCs), IP / domain / URL / hash
intelligence, vulnerabilities, threat actors, alerts, investigations and reports.

**Status:** under construction. The foundation (database schema, Row Level Security, demo seed,
Supabase integration, health check) is in place. Authentication flows, the UI and the intelligence
modules are built in later phases; see [docs/ARCRADAR_PROGRESS.md](docs/ARCRADAR_PROGRESS.md).

- Stack: Next.js (App Router) + TypeScript, Supabase (PostgreSQL + Auth), Tailwind CSS.
- Production target: Vercel + Supabase.
- Run it locally: [docs/LOCAL_DEVELOPMENT.md](docs/LOCAL_DEVELOPMENT.md).

The full README (architecture, deployment, API docs, security notes) is written in the final phase.
