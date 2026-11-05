#!/usr/bin/env python3
"""Waits for ArcRadar to say "a Wazuh rule was pushed", then pulls and installs it at once.

Instead of asking GitHub on a timer, this keeps one request open to ArcRadar (GET /api/ingest/wazuh/wake). ArcRadar
answers the moment a Wazuh rule is pushed (or after about 25 seconds with "nothing new", and this asks again). On a
push it runs arcradar-apply-rules, which installs the rule and reloads the ruleset in place, so a rule pushed in
ArcRadar is live on the Manager within about ten seconds. Nothing on this machine is opened to the outside: it only
calls ArcRadar, the same way the custom-arcradar integration does, and with the same URL and key.

It runs as a service (arcradar-wazuh-watch.service). The apply cron stays as a slow safety net (a push is applied by
whichever of the two gets there first; both take the same lock, so they never run together).

Settings, all optional (environment variables):
  WAZUH_OSSEC_CONF            default /var/ossec/etc/ossec.conf (the custom-arcradar <integration> block is read)
  ARCRADAR_APPLY_COMMAND      default /usr/local/sbin/arcradar-apply-rules
  ARCRADAR_RULES_LOCK         default /run/arcradar-rules.lock (the lock the apply cron takes)
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OSSEC_CONF = os.environ.get("WAZUH_OSSEC_CONF", "/var/ossec/etc/ossec.conf")
APPLY = os.environ.get("ARCRADAR_APPLY_COMMAND", "/usr/local/sbin/arcradar-apply-rules")
LOCK = os.environ.get("ARCRADAR_RULES_LOCK", "/run/arcradar-rules.lock")
WAIT_SECONDS = 25
REQUEST_TIMEOUT = WAIT_SECONDS + 20
# GitHub shows a fresh commit at once, but if the first pull finds nothing new, look again a few times.
APPLY_ATTEMPTS = 3
APPLY_RETRY_SECONDS = 2
# The apply script waits for a cron run that is already busy instead of skipping the push.
LOCK_WAIT_SECONDS = 240


def log(message):
    sys.stdout.write("%s arcradar-watch: %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), message))
    sys.stdout.flush()


def read_config():
    """The ingest URL and key of the custom-arcradar integration in ossec.conf."""
    with open(OSSEC_CONF, "r", encoding="utf-8") as handle:
        text = handle.read()
    for block in re.findall(r"<integration>(.*?)</integration>", text, re.S):
        if re.search(r"<name>\s*custom-arcradar\s*</name>", block):
            url = re.search(r"<hook_url>\s*(.*?)\s*</hook_url>", block, re.S)
            key = re.search(r"<api_key>\s*(.*?)\s*</api_key>", block, re.S)
            url = url.group(1).rstrip("/") if url else ""
            key = key.group(1) if key else ""
            if not url.endswith("/api/ingest/wazuh") or not key.startswith("arc_"):
                raise SystemExit("the custom-arcradar integration needs a hook_url ending in /api/ingest/wazuh and an api_key")
            return url + "/wake", key
    raise SystemExit("%s has no custom-arcradar integration" % OSSEC_CONF)


def wake(url, key, since):
    query = "?wait=%d" % WAIT_SECONDS
    if since is not None:
        query += "&since=" + urllib.parse.quote(since)
    request = urllib.request.Request(url + query, headers={"authorization": "Bearer " + key})
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.load(response)["data"]


def apply_rules():
    """Runs the apply script until it reports it installed something (or gives up after a few tries)."""
    command = ["flock", "-w", str(LOCK_WAIT_SECONDS), LOCK, APPLY]
    for attempt in range(1, APPLY_ATTEMPTS + 1):
        result = subprocess.run(command, capture_output=True, text=True, timeout=LOCK_WAIT_SECONDS + 300)
        output = (result.stdout + result.stderr).strip()
        if output:
            log("apply: " + output.splitlines()[-1])
        if result.returncode != 0:
            return
        if "applied repository commit" in result.stdout:
            return
        if attempt < APPLY_ATTEMPTS:
            time.sleep(APPLY_RETRY_SECONDS)
    log("apply: nothing new to install after %d tries" % APPLY_ATTEMPTS)


def main():
    url, key = read_config()
    revision = None
    backoff = 2
    log("watching %s" % url)
    while True:
        try:
            answer = wake(url, key, revision)
            backoff = 2
            if revision is None:
                # First answer: remember where we are, and apply once in case a push happened while this was down.
                revision = answer["revision"]
                apply_rules()
            elif answer["changed"]:
                revision = answer["revision"]
                log("a rule was pushed")
                apply_rules()
        except (urllib.error.URLError, OSError, ValueError, KeyError) as error:
            log("could not ask ArcRadar (%s); trying again in %d s" % (error, backoff))
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
        except subprocess.TimeoutExpired:
            log("apply took too long; trying again on the next push")


if __name__ == "__main__":
    sys.exit(main())
