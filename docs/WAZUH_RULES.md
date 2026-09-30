# Wazuh detection rules (detection-as-code)

ArcRadar can write Wazuh detection rules, keep them reviewable, and hand the approved ones to the
Wazuh Manager through a Git repository. This page explains the flow, how to set it up, and what it
deliberately does not do.

```
 person or AI            ArcRadar                    GitHub                    Wazuh Manager
 ───────────►  Draft ──► review the XML ──► Send ──► rules/arcradar_<id>.xml ◄── arcradar-apply-rules
                          Edit / Reject      (commit)                              (pulls, tests, restarts)
```

- **Detection rule** (this page): a rule that runs _inside Wazuh_ and decides whether an event becomes an
  alert at all. It arrives in ArcRadar afterwards, like every other Wazuh alert.
- **Severity rule** (the other tab of the same page, `detection_rules`, Phase 10): runs _inside ArcRadar_
  after an alert exists and can only raise its severity. The two are independent.

ArcRadar never connects to the Wazuh host. It only commits a file to a repository; the Manager pulls the
repository itself, on its own schedule. Nothing here executes anything, and rules cannot contain an
active response: the XML is always _generated_ from structured fields, never accepted from a person or
from the AI.

## The workflow (Detection rules page, "Wazuh rules" tab, administrators)

1. **Create a draft**
   - **Manual rule**: name, level (1-15), what to attach to (`if_group` such as `windows`, or a parent
     rule id), one or more conditions (a Wazuh field, `contains` / `equals` / `matches regex`, a value),
     optional MITRE technique ids. Leave the id empty and the next free one (from 100100) is used.
   - **Generate with AI**: describe what to detect in a sentence. The active AI provider drafts the
     fields; the draft goes through exactly the same checks as a hand-written rule (an answer that breaks
     one is refused and nothing is stored). Needs `ai:use` and a ready provider (Integrations page).
2. **Read the XML.** Every rule card shows the file that would be committed, its level, MITRE ids, and
   how many alerts Wazuh has raised through it so far (counted from the alerts ArcRadar received).
3. **Decide**
   - **Send to GitHub**: commits `rules/arcradar_<id>.xml` to the rules repository. The rule becomes
     _Pushed_. Editing a pushed rule marks it _Changed since push_; send it again to update the file.
   - **Edit**: change any field; the XML is regenerated. Editing a rejected rule restores it to a draft.
   - **Reject**: the rule is kept (with an optional reason) but never goes to GitHub.
   - A draft or rejected rule can be deleted. A pushed rule cannot: its file lives on GitHub.
4. **Apply on the Manager** with `arcradar-apply-rules` (below).

Every step is audited (`wazuh_rule.created|generated|updated|rejected|pushed|deleted`).

## Rules that fire on repetition ("5 failed logons in 5 minutes")

Tick **Only when it repeats** on the form (or just say it to the AI: "alert when there are 5 failed logons
in 5 minutes from the same address"). The rule then has:

- **Times** (2-100) and **Within** (minutes; stored as seconds, 1 to 86400) — Wazuh's `frequency` and `timeframe`;
- **Attach to** the group or rule of the _single_ event being counted (failed Windows logons:
  group `authentication_failed`); the file uses `if_matched_group` / `if_matched_sid` instead of
  `if_group` / `if_sid`;
- **Same value in** (optional, up to 3 fields): the counted events must share it, for example
  `win.eventdata.ipAddress` counts per source address (`<same_field>`);
- conditions become optional (the count is the condition). An ordinary rule still needs at least one.

Wazuh counts only events matched by a parent rule with a level above 0, and a parent must load before the
rule (rules from the standard ruleset always do). Verified on the real Manager: with a count of 3 in 60
seconds and `same_field`, the 3rd event from one address fired the rule and two events from another
address did not.

## What a condition becomes

Every condition is a Wazuh `<field name="…" type="pcre2">` test (all conditions must match):

| Comparison      | Pattern written to the file                      |
| --------------- | ------------------------------------------------ |
| `contains "x"`  | `(?i)` + the value with regex characters escaped |
| `equals "x"`    | `(?i)^` + escaped value + `$`                    |
| `matches regex` | `(?i)` + the pattern you typed                   |

A regex is refused if it has lookarounds, inline flags, back-references, a repeated group that itself
repeats, or does not compile. Field names must start with `win.`, `data.`, `syscheck.` or `agent.`.

## Setup

### 1. The repository

Create a repository (for this project: `aqsin1337/wazuh_rules`, public by choice; private also works,
see the note in step 3). It can start empty. ArcRadar creates `rules/arcradar_<id>.xml` on the first push.

### 2. A GitHub token for ArcRadar

GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → Generate:

- **Repository access**: _Only select repositories_ → the rules repository (nothing else).
- **Repository permissions**: **Contents: Read and write** (everything else stays _No access_).
- **Expiration**: pick one you will remember (for example 90 days).

Copy the token (`github_pat_…`) once. Then set three server-side variables (Vercel → Project → Settings →
Environment Variables, or `.env.local` locally):

```
GITHUB_TOKEN=github_pat_…
GITHUB_RULES_REPO=aqsin1337/wazuh_rules
GITHUB_RULES_BRANCH=main
```

The token is a server-only secret, like the AI and intel keys. Without it (or without the repository name)
the page still works for drafting, editing and rejecting; only _Send to GitHub_ is unavailable, and the
page says so.

### 3. The Manager

`deploy/wazuh/apply-arcradar-rules.sh` is installed on the Manager as `/usr/local/sbin/arcradar-apply-rules`:

```bash
sudo install -m 0750 apply-arcradar-rules.sh /usr/local/sbin/arcradar-apply-rules
sudo arcradar-apply-rules --check     # show what would change
sudo arcradar-apply-rules             # apply
```

It clones the repository (over HTTPS, anonymously; for a private repository set `ARCRADAR_RULES_REPO`
to a URL with a read-only deploy key or token), and then:

1. checks every `rules/arcradar_<six digits>.xml` file: the name must match the rule id, exactly one rule,
   and it must not contain `active-response`, `command`, `integration`, `localfile` or any other element
   ArcRadar never generates (a defence against anything ever landing in the repository by another route);
2. copies them to `/var/ossec/etc/rules/` (owner `root:wazuh`, mode 660) and removes any installed
   `arcradar_*.xml` that is no longer in the repository; **no other file is ever touched**;
3. runs Wazuh's own `wazuh-analysisd -t` on the whole ruleset; if Wazuh rejects it, the previous files are
   put back and nothing is restarted;
4. restarts `wazuh-manager` only when something changed.

Run it by hand when you want, or on a schedule (a cron line such as
`*/10 * * * * /usr/local/sbin/arcradar-apply-rules >> /var/log/arcradar-rules.log 2>&1`).

## Verified

- The generated XML was installed on a real Wazuh Manager 4.14.8 through the script: Wazuh accepted and
  loaded it, and a test event containing the condition text fired the rule at level 12 with
  `mitre: T1562.001` while a benign event did not. The script's two refusal paths (an element ArcRadar
  never generates; a file Wazuh itself rejects, level 99) were also exercised and left the Manager
  unchanged. The test rules were removed afterwards.
- Not verified against real GitHub with a real token in the automated tests (the GitHub client is tested
  against faked responses, including error mapping and that the token never appears in an error).

## Limits (on purpose)

- No response action is attached to a rule and nothing is executed. Response stays the human-tracked
  flow of Phase 9.
- One rule per file and a fixed set of elements; repetition is one count, one window and up to three
  same-value fields (no multi-rule correlation, no `different_field`).
- A `Deployed` status (the Manager reporting back that it applied a rule) does not exist: ArcRadar only
  knows a rule was committed. "Triggered N times" is the practical proof that it is live.
- ArcRadar commits to the configured branch directly; there is no pull-request step.
