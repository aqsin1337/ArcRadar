Men holberton portfolyo ucun proyekt hazirlayiram lokalda hazirlayacayiq sonra vercelde deploy olunmalidi databaza olaraq supabaseden istifade ederiy birde vebserver olacaq nginxnen qoslacayiqda indi ozun seylede nece olmalidisa ele et . buda hazirladigim metapromptlardi bulara bax 

<pasted_content id="4a1b">
You are the lead software architect, senior full-stack engineer, cybersecurity engineer, UI/UX designer, DevOps engineer, QA engineer, and technical writer for this project.

You are working INSIDE an existing local project repository.

The project must become a complete, deployable cybersecurity platform called ArcRadar.

The project is divided into explicit phases.

Do not interpret phrases such as "keep going", "finish everything", or previous instructions as permission to silently execute all remaining phases.

Only the explicit current-phase command authorizes execution of the next phase.

Build a realistic, functional MVP first.

Do not attempt to build an enterprise-scale SIEM/SOAR replacement.

The ArcRadar MVP must prioritize:

CORE MVP:

authentication

RBAC

dashboard

indicators / IOCs

IP intelligence

domain intelligence

URL intelligence

hash intelligence

vulnerabilities

threat actors

alerts

investigations

audit logging

report generation

API key management

provider abstraction

demo mode

database persistence

proper validation

responsive UI

security controls

SECONDARY / EXTENSIBLE:

advanced external provider integrations

advanced correlation engine

background workers

scheduled enrichment

complex event pipelines

advanced analytics

large-scale distributed architecture

enterprise SSO

multi-region deployment

For secondary functionality:

Create clean architecture and extension points where useful, but do not spend the majority of the project implementing enterprise-scale infrastructure that is unnecessary for the MVP.

The application must be genuinely functional, not a fake UI.

================================================== 0.7 DEFINITION OF PHASE COMPLETION

A phase is complete only when:

its intended functionality is implemented

code compiles where applicable

relevant tests or validation were executed

obvious errors are fixed

the project remains runnable

progress is recorded

Do not mark a feature as complete merely because files were created.

================================================== 0.8 PHASE EXECUTION TEMPLATE

For every phase follow this sequence:

A. Read progress state.

B. Inspect only required files.

C. State the phase objective internally.

D. Implement the phase.

E. Validate the phase.

F. Fix issues caused by this phase.

G. Update:
docs/ARCRADAR_PROGRESS.md

H. Give a concise report containing:

completed

important files changed

validation performed

known limitations

next phase

I. STOP.

==================================================

FIRST: ANALYZE THE EXISTING REPOSITORY
==================================================

PHASE 0 ONLY.

Before making major changes:

Inspect the repository structure.

Read, where present:

README

package.json / equivalent dependency files

application source

configuration files

database/schema files

Docker files

environment example files

frontend

backend

API routes

tests

important assets

Determine the current technology stack.

Determine whether the repository contains:

an empty starter

a frontend

a backend

a database

a partial application

an existing full-stack system

Reuse useful existing code.

Do not blindly replace the project.

Identify what already works.

Identify what is missing.

Decide whether the current architecture should be preserved.

Identify the smallest maintainable architecture capable of supporting the MVP.

Create a short architecture plan.

Do NOT implement the whole application in PHASE 0.

Do NOT install large numbers of dependencies in PHASE 0 unless required to determine the architecture.

At the end of PHASE 0:

create/update docs/ARCRADAR_PROGRESS.md

record the existing stack

record architectural decisions

record the implementation phases

STOP.

================================================== 2. PRODUCT

Project name:

ArcRadar

ArcRadar is a modern cybersecurity intelligence and threat-monitoring platform.

The product should feel like a real security product rather than a student CRUD application.

Core concept:

A centralized platform where security teams can monitor:

IP addresses

domains

URLs

hashes

vulnerabilities

threat actors

indicators of compromise (IOCs)

security events

threat intelligence

alerts

investigations

reports

The application should provide a clean SOC/security-operations style experience.

Target users include:

SOC analysts

blue team analysts

threat intelligence analysts

security engineers

cybersecurity students

security teams

================================================== 3. DESIGN DIRECTION

Create a professional cybersecurity SaaS interface.

Visual direction:

dark-first interface

modern SOC / threat-intelligence aesthetic

clean

technical

premium

minimal unnecessary decoration

strong information hierarchy

excellent typography

subtle borders

subtle shadows

cards

charts

tables

badges

status indicators

command-center feeling

Avoid:

generic AI dashboard appearance

excessive gradients

excessive glassmorphism

huge meaningless hero sections

cartoonish cybersecurity graphics

unnecessary animations

template-looking UI

The interface should look like a serious commercial security platform.

Use a consistent design system.

Define:

color tokens

typography

spacing

border radius

shadows

status colors

component variants

responsive breakpoints

Use reusable components rather than duplicated markup.

================================================== 4. APPLICATION STRUCTURE

Create a complete application with at least these areas.

PUBLIC:

Landing page

Features

Integrations

About

Documentation

Contact

Login

Register

AUTHENTICATED:

Dashboard

Threat Intelligence

Indicators

IP Intelligence

Domain Intelligence

URL Intelligence

Hash Intelligence

Vulnerabilities

Threat Actors

Alerts

Investigations

Reports

Integrations

API Keys

Activity / Audit Log

User Profile

Settings

If the existing architecture suggests a better structure, use it while preserving the same functionality.

================================================== 5. LANDING PAGE

Build a polished ArcRadar landing page.

Sections:

Navigation

Hero

Product overview

Threat intelligence capabilities

IOC investigation

Vulnerability intelligence

Threat actor monitoring

Security operations workflow

Integrations

Analytics/dashboard preview

CTA

Footer

The landing page must communicate the actual product.

Do not use fake marketing claims such as:

"99.99% detection"
"100% protection"
"the world's best"

unless there is a real measurable basis.

Use realistic product copy.

================================================== 6. DASHBOARD

Create a real dashboard, not static decorative cards.

Dashboard should include:

total indicators

malicious indicators

suspicious indicators

active alerts

critical vulnerabilities

recent investigations

recent security events

threat activity chart

severity distribution

IOC type distribution

recent indicators table

top threat actors

top malicious IPs/domains

Add:

date/time filtering

severity filtering

search

refresh

useful empty states

loading states

error states

Charts must be based on actual application data.

================================================== 7. IOC / INDICATOR SYSTEM

Implement a proper indicator system.

Supported indicator types:

IPv4

IPv6

Domain

URL

File hash

Email

CVE

other relevant IOC types where appropriate

Each indicator should support:

value

type

severity

confidence

status

source

tags

first seen

last seen

description

relationships

investigation references

created_at

updated_at

Implement:

create

read

update

delete

search

filtering

sorting

pagination

bulk actions where appropriate

Indicator detail page should provide a complete investigation view.

================================================== 8. THREAT INTELLIGENCE

Build a threat intelligence module.

Include:

intelligence feed

IOC enrichment

threat reports

threat actor information

campaigns

malware

TTPs

MITRE ATT&CK references

relationships between entities

Where external intelligence is not configured, provide:

provider abstraction

demo provider

safe local/sample data

Do not pretend local demo data is live threat intelligence.

Clearly distinguish:

Demo

Local

External provider

Last updated

================================================== 9. IP INTELLIGENCE

Create an IP investigation page.

User can enter an IP address.

Show:

IP

version

reputation

confidence

ASN

organization

country

city/region where available

ISP

hostname

reverse DNS

open ports if provider supports it

related domains

related indicators

threat reports

timeline

Create provider abstractions.

For example:

ThreatIntelProvider
IPReputationProvider
DomainReputationProvider
URLReputationProvider

Do not hardcode the whole application around one external API.

================================================== 10. DOMAIN / URL INTELLIGENCE

Domain investigation:

domain

registrar

registration information where available

DNS records

nameservers

related IPs

reputation

threat status

related indicators

timeline

URL investigation:

URL

domain

reputation

detection results

redirects if provider supports them

related indicators

timeline

Use provider abstractions.

================================================== 11. HASH INTELLIGENCE

Support:

MD5

SHA1

SHA256

Hash investigation should show:

hash

hash type

reputation

malware family if available

detection information

file metadata if provider supports it

related indicators

threat reports

timeline

================================================== 12. VULNERABILITY MODULE

Create a vulnerability management/intelligence module.

Support:

CVE

CVSS

severity

affected products

affected versions

description

references

published date

modified date

remediation information

exploit status where available

Implement:

vulnerability list

search

filtering

sorting

vulnerability detail

severity statistics

Create a provider/service abstraction for vulnerability data.

================================================== 13. THREAT ACTORS

Create threat actor profiles.

Each actor may include:

name

aliases

description

origin/attribution if documented

motivation

targeted industries

targeted countries

associated malware

associated campaigns

TTPs

MITRE ATT&CK techniques

indicators

reports

timeline

Do not invent real-world attribution.

Clearly label demo/sample data where necessary.

================================================== 14. ALERTING

Implement an alert system.

Alerts should support:

title

description

severity

source

status

related indicator

related event

created_at

acknowledged_at

resolved_at

Statuses:

New

Acknowledged

Investigating

Resolved

False Positive

Implement:

filtering

searching

sorting

pagination

alert details

status changes

audit logging

================================================== 15. INVESTIGATIONS

Create an investigation workflow.

An investigation should support:

title

description

status

priority

analyst

indicators

alerts

notes

evidence references

timeline

tags

created_at

updated_at

Statuses:

Open

Investigating

Contained

Resolved

Closed

Build an investigation detail page suitable for SOC analyst workflow.

================================================== 16. REPORTING

Implement report generation.

Reports should be able to summarize:

investigation

indicators

alerts

vulnerabilities

threat actor activity

timeline

analyst notes

Provide a clean report preview.

If PDF generation is practical in the existing stack, implement PDF export.

Otherwise implement a print-friendly report system and keep the architecture ready for future PDF generation.

================================================== 17. AUTHENTICATION

==================================================

Use Supabase Auth as the primary authentication system.

At minimum support:

registration

login

logout

session management

protected routes

password reset/change

user profile

authorization

Do NOT unnecessarily implement a second custom authentication system on top of Supabase Auth.

Supabase Auth should handle authentication and identity.

Application-level authorization and RBAC must still be implemented separately.

Do not store plaintext passwords.

Do not expose privileged Supabase credentials to the client.

Use the framework's recommended Supabase client pattern for:

browser/client operations

server-side operations

middleware/route protection where applicable

Validate authenticated sessions on the server for sensitive operations.

================================================== 18. RBAC

Implement role-based access control.

Roles:

Admin

Analyst

Viewer

Example permissions:

Admin:

manage users

manage integrations

manage API keys

manage settings

full access

Analyst:

investigate indicators

manage alerts

create investigations

create reports

Viewer:

read-only access

Do not rely only on frontend hiding.

Authorization must also exist in backend/server logic.

================================================== 18.5 PRODUCTION / DEPLOYMENT ARCHITECTURE

==================================================

ArcRadar is a real deployable web application.

REQUIRED PRODUCTION TARGET:

Vercel for application hosting/deployment

Supabase for PostgreSQL database

Supabase Auth for authentication/session management where appropriate

Supabase Storage only when file/object storage is actually required

Design the application for Vercel + Supabase from the beginning.

Do NOT design around:

a permanently running custom server

a self-hosted production PostgreSQL server

a local-only database

local filesystem persistence

a long-running background worker as a core requirement

a server architecture that cannot run on Vercel

The application must be deployable to Vercel without requiring manual server management.

For local development, use Supabase-compatible tooling or the configured remote Supabase project as appropriate. Do not introduce a second production database.

If the existing framework is already Vercel-compatible, preserve it unless there is a real technical reason not to.

Prefer an architecture such as:

Frontend / App
↓
Vercel-compatible server/API layer
↓
Service layer
↓
Supabase / provider adapters

Operations that require secrets must remain server-side.

Do not expose:

Supabase service-role credentials

external threat-intelligence API keys

other private secrets

to browser/client code.

================================================== 19. DATABASE

==================================================

Use Supabase PostgreSQL as the primary and production database.

Do NOT introduce another production database.

Do NOT use SQLite, MySQL, MongoDB, or a separate self-hosted PostgreSQL instance as the production database.

Design a normalized relational schema in Supabase PostgreSQL.

At minimum model:

User
Role
Permission
Indicator
IndicatorTag
Tag
ThreatActor
Campaign
Malware
Vulnerability
Alert
Investigation
InvestigationNote
Event
Report
Integration
ApiKey
AuditLog

Use proper:

primary keys

foreign keys

indexes

timestamps

constraints

unique constraints where appropriate

relationships

Avoid storing everything as unstructured JSON when relational structure is appropriate.

Use Supabase/PostgreSQL migrations.

The database schema must be reproducible from migrations rather than depending on undocumented manual changes.

Seed the database with realistic SAMPLE data.

Clearly mark seeded data as demo/sample data.

SUPABASE-SPECIFIC REQUIREMENTS

Evaluate and use Row Level Security (RLS) for application tables.

RLS should be enabled wherever appropriate.

Create policies that prevent unauthorized users from accessing or modifying data.

Do not blindly expose database tables to the client.

Use the Supabase anon/publishable client only for operations intended to be safe for the client.

The Supabase service-role key must be server-side only.

Use database constraints and server-side authorization together rather than relying on only the frontend.

ENVIRONMENT VARIABLES

At minimum document the variables needed for the configured Supabase setup, such as:

NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=

SUPABASE_SERVICE_ROLE_KEY=

Also document external provider keys such as:

VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
SHODAN_API_KEY=

Do not hardcode secrets.

Create .env.example.

Clearly distinguish client-safe variables from server-only secrets.

================================================== 20. BACKEND API

Build a clean backend API.

Use consistent:

routing

controllers

services

validation

error handling

authentication middleware

authorization middleware

logging

API responses should be predictable.

Success example:

{
"success": true,
"data": {},
"error": null
}

Error example:

{
"success": false,
"data": null,
"error": {
"code": "VALIDATION_ERROR",
"message": "..."
}
}

Use proper HTTP status codes.

================================================== 21. API DOCUMENTATION

Document the API.

Include:

authentication

endpoints

request examples

response examples

error responses

pagination

filtering

rate limits if implemented

If appropriate, generate OpenAPI documentation.

================================================== 22. EXTERNAL INTEGRATIONS

Design integrations using provider interfaces.

Potential integrations:

VirusTotal

AbuseIPDB

AlienVault OTX

NVD

MITRE ATT&CK

MISP

OpenCTI

Shodan

IMPORTANT:

Do NOT require every API key for the application to start.

The application must work without external API keys.

Use:

environment variables

provider adapters

graceful fallback

mock/demo provider

Example:

VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
SHODAN_API_KEY=

Never commit secrets.

================================================== 23. SEARCH

Implement global search.

Search across:

indicators

IPs

domains

URLs

hashes

CVEs

threat actors

investigations

alerts

Search should recognize indicator types where possible.

Examples:

192.168.1.1 -> IP
example.com -> domain
https://example.com -> URL
SHA256 -> hash
CVE-2026-XXXXX -> vulnerability

Do not claim maliciousness solely from pattern matching.

================================================== 24. AUDIT LOGGING

Track important user actions:

login

logout

indicator created

indicator updated

indicator deleted

investigation created

investigation updated

alert status changed

API key created/revoked

settings changed

administrative actions

Include:

user

action

entity

entity ID

timestamp

IP if available

metadata where appropriate

================================================== 25. API KEYS

Implement user API keys.

Support:

create

list

revoke

last used

created date

expiration if appropriate

Never store raw API secrets in plaintext if the architecture allows secure hashing/storage.

Show the secret only once when created.

================================================== 26. SECURITY REQUIREMENTS

Treat security as a first-class requirement.

Implement:

input validation

output encoding where appropriate

authentication protection

authorization

CSRF protection where relevant

secure cookies where relevant

rate limiting where relevant

security headers

CORS configuration

SQL injection protection

XSS protection

SSRF considerations

safe URL fetching architecture

secret management

safe error messages

audit logging

Do NOT build dangerous functionality that enables arbitrary exploitation of third-party systems.

For URL/IP enrichment functionality, use controlled provider APIs and safe server-side validation.

================================================== 27. FRONTEND QUALITY

Frontend must include:

responsive layout

desktop

tablet

mobile

sidebar

top navigation

breadcrumbs where useful

command/search bar

modals

drawers

dropdowns

toast notifications

loading skeletons

empty states

error states

confirmation dialogs

pagination

filters

sorting

Every important interaction must actually work.

Do not leave buttons that do nothing.

================================================== 28. ACCESSIBILITY

Implement:

semantic HTML

keyboard navigation

visible focus states

accessible labels

ARIA where necessary

sufficient contrast

accessible dialogs

accessible tables

screen-reader-friendly status indicators

================================================== 29. RESPONSIVE DESIGN

Desktop should feel like a professional SOC dashboard.

Mobile should not simply shrink the desktop UI.

Implement:

collapsible sidebar

mobile navigation

responsive tables

responsive cards

responsive charts

touch-friendly controls

================================================== 30. ERROR / LOADING STATES

Every async page should handle:

Loading
Success
Empty
Error

Never show a broken blank screen.

Use useful user-facing messages.

================================================== 31. TESTING

Implement meaningful tests.

At minimum:

authentication tests

authorization tests

indicator CRUD tests

API validation tests

vulnerability tests

alert tests

investigation tests

critical frontend component tests

Run the relevant test suite for the current phase.

Fix failures.

Do not simply write tests that always pass without testing real behavior.

Full test-suite execution should happen during the final QA phase.

================================================== 32. LINT / TYPE CHECK / BUILD

Run validation appropriate to the current phase.

Before final completion, run:

formatter

linter

type checker

unit tests

integration tests where available

production build

Fix errors.

Do not ignore warnings if they indicate actual problems.

Do not repeatedly run expensive full-project validation after tiny unrelated changes unless relevant.

================================================== 33. DEVOPS / DEPLOYMENT

==================================================

Production deployment target:

Vercel
+
Supabase

Provide:

.env.example

Supabase setup instructions

Supabase migration instructions

seed instructions

local development instructions

Vercel deployment instructions

production environment-variable documentation

production build configuration

troubleshooting instructions

Docker is OPTIONAL.

If Docker is used, it should be for local development or supporting infrastructure only.

Do NOT make Docker a prerequisite for Vercel deployment.

Do NOT require a locally running database for production.

Do NOT create unnecessary infrastructure that Vercel + Supabase do not need.

The application must not depend on:

local filesystem persistence

in-memory persistence across requests

a permanently running custom server

a permanently running worker

local PostgreSQL for production

Any asynchronous or background functionality must use a Vercel-compatible or external architecture.

For the MVP, avoid unnecessary background workers and distributed infrastructure.

Do NOT automatically deploy the project.

Do NOT access the user's Vercel or Supabase accounts.

Do NOT ask for cloud credentials unless the user explicitly provides them for a specific task.

The project must be correctly structured and documented so the user can deploy it using their own Vercel and Supabase accounts.

================================================== 34. README

Create a professional README.

Include:

ArcRadar

Description

Features

Architecture

Technology stack

Project structure

Requirements

Installation

Environment variables

Database setup

Migrations

Seed data

Development

Testing

Production build

Docker

API documentation

Security notes

External integrations

Troubleshooting

Contributing

License

Do not write claims that the project does not actually support.

================================================== 35. DATA PROVIDER ARCHITECTURE

This is important.

Never tightly couple the UI to external APIs.

Use a structure similar to:

UI
↓
API
↓
Service layer
↓
Provider interface
↓
External provider / Demo provider

For example:

IPIntelProvider

Methods:

lookupIP()
getReputation()
getRelatedDomains()

Implement:

DemoIPIntelProvider

and external providers where practical.

The same pattern should exist for:

Domain intelligence

URL intelligence

Hash intelligence

Vulnerability intelligence

Threat intelligence

================================================== 36. DEMO MODE

The application must work immediately after installation.

Therefore:

provide realistic seed data

provide demo providers

provide demo dashboard statistics

provide demo alerts

provide demo investigations

provide demo threat actors

provide demo vulnerabilities

Clearly indicate demo/sample information.

Do not represent sample data as live intelligence.

================================================== 36.5 STORAGE

==================================================

If file storage is required for reports or evidence attachments:

prefer Supabase Storage

use secure access policies for private files

do not treat the Vercel filesystem as permanent storage

Do not add file storage unless a real product requirement needs it.

================================================== 37. PERFORMANCE

Optimize for a large amount of security data.

Use:

database indexes

pagination

server-side filtering

debounced search

lazy loading where appropriate

caching where useful

efficient queries

Do not load thousands of records into the browser unnecessarily.

For the MVP, prioritize correct architecture and efficient database access rather than premature distributed-system complexity.

================================================== 38. CODE QUALITY

Follow professional engineering practices.

Prefer:

small reusable components

typed interfaces

clear naming

separation of concerns

service layer

repository/data-access layer where appropriate

centralized validation

centralized error handling

reusable UI components

Avoid:

giant files

duplicated code

magic values

unnecessary abstraction

dead code

commented-out old code

================================================== 39. LOCAL PROJECT STATE / HANDOFF

Maintain:

docs/ARCRADAR_PROGRESS.md

This file exists only to preserve project state across phases.

It should contain:

current phase

completed phases

current implementation status

architecture decisions

important unresolved items

next phase

known limitations

Keep it concise.

Do not use it as a detailed change log.

Also create architecture documentation only when it is actually useful.

Do not generate huge documentation files unnecessarily.

================================================== 40. IMPLEMENTATION PHASES

Use exactly this phased execution model.

PHASE 0 — REPOSITORY ANALYSIS

Tasks:

inspect repository

determine stack

determine existing functionality

identify architecture

identify missing parts

define MVP architecture

define implementation plan

create progress document

NO major implementation.

STOP.

PHASE 1 — FOUNDATION

Tasks:

project structure

core configuration

environment handling

Supabase integration

Supabase client/server utilities appropriate to the framework

database schema foundation in Supabase PostgreSQL

migrations

seed system

initial shared types

base application setup

Vercel-compatible configuration where needed

Do NOT create a second production database.

Validate:

application can start

Supabase configuration is structurally correct

migrations are valid

seed process is valid

environment configuration is documented

Do not require cloud credentials merely to scaffold the architecture.

STOP.

PHASE 2 — BACKEND FOUNDATION

Tasks:

backend structure

API foundation

request validation

centralized error handling

Supabase Auth integration

sessions

server-side session validation

authorization foundation

RBAC

audit logging foundation

Validate:

registration

login

logout

protected route

RBAC checks

validation

STOP.

PHASE 3 — FRONTEND FOUNDATION

Tasks:

design system

app shell

navigation

sidebar

top bar

responsive structure

authentication pages

reusable UI primitives

loading/empty/error states

route protection

Validate:

frontend starts

authentication flow works

responsive navigation works

STOP.

PHASE 4 — CORE SECURITY DATA

Tasks:

indicator system

indicator CRUD

search

filtering

sorting

pagination

indicator details

global search

demo intelligence data

Validate:

create indicator

edit indicator

delete indicator

search

filter

pagination

permissions

STOP.

PHASE 5 — INTELLIGENCE MODULES

Tasks:

IP intelligence

domain intelligence

URL intelligence

hash intelligence

vulnerability module

provider abstractions

demo providers

Validate:

all investigation pages function

provider fallback works

demo mode works without API keys

STOP.

PHASE 6 — THREAT ACTORS / ALERTS / INVESTIGATIONS

Tasks:

threat actors

campaigns

malware

TTPs

MITRE references

alerts

alert workflow

investigations

notes

evidence references

timelines

Validate:

alert lifecycle

investigation lifecycle

relationships between entities

audit events

STOP.

PHASE 7 — DASHBOARD / REPORTING / ADMIN

Tasks:

production dashboard

real application statistics

charts

severity distribution

IOC distribution

reports

report preview

API keys

integrations page

settings

profile

audit log UI

Validate:

dashboard data is dynamic

reports use application data

API key lifecycle works

admin restrictions work

STOP.

PHASE 8 — SECURITY / QUALITY / RESPONSIVENESS

Tasks:

security hardening

headers

CORS

CSRF where applicable

rate limiting where applicable

SSRF protection

secret handling

accessibility

responsive behavior

performance optimization

loading/error/empty states

Validate:

security checks

accessibility checks

responsive checks

performance sanity checks

STOP.

PHASE 9 — DOCUMENTATION / FINAL QA / DEPLOYMENT READINESS

Tasks:

README

.env.example

Supabase setup documentation

Supabase migration documentation

seed documentation

Vercel deployment documentation

API documentation

troubleshooting

full test suite

lint

typecheck

production build

final manual QA

final architecture review

production environment-variable audit

Vercel compatibility review

Supabase RLS/security review

Only during this phase should you perform the full expensive validation pass.

Verify that the application is structurally ready for:

Vercel deployment
+
Supabase production database

Do NOT automatically deploy.

STOP.

================================================== 41. FINAL DEFINITION OF DONE

The project is complete only when:

application starts successfully

frontend works

backend works

database works

migrations work

seed data works

authentication works

RBAC works

dashboard works

indicators work

intelligence pages work

vulnerability module works

threat actor module works

alerts work

investigations work

reports work

API keys work

audit logs work

integrations architecture works

demo mode works without external API keys

loading states work

error states work

responsive design works

security controls are implemented

tests pass

lint passes

typecheck passes

production build passes

README is complete

no secrets are exposed or stored in source files

known limitations are documented

IMPORTANT:

Source-control and repository publishing are completely outside the scope of this project task.

The application must be ready for deployment to:

Vercel + Supabase.

================================================== 42. FINAL REPORT

Only after PHASE 9 is complete, provide a final report.

Include:

What was found in the original repository

Final architecture

Technology stack

Major features implemented

Database structure

API structure

External integrations

Security measures

Tests executed and results

Build result

How to run locally

Demo credentials, if created

Remaining limitations

Do not claim something was implemented or tested unless you actually performed it.

Do not include source-control or repository-publishing status in the final report.

================================================== 43. START RULE

When this prompt is first provided:

EXECUTE PHASE 0 ONLY.

Do not implement the entire application.

Do not continue into PHASE 1.

Do not continue into PHASE 2.

Do not continue into any later phase.

First inspect the repository and understand what already exists.

Create the implementation plan and progress document.

Then STOP and wait for:

CONTINUE PHASE 1

After the user sends that command, execute PHASE 1 ONLY.

Then STOP again.

Continue this same controlled process for each subsequent phase.

Never silently chain phases together.

Never turn one invocation into a full-project implementation session.

The priority is:

CORRECTNESS
→ SECURITY
→ MAINTAINABILITY
→ FUNCTIONALITY
→ VALIDATION
→ CONTEXT EFFICIENCY
</pasted_content id="4a1b">
