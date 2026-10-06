#!/usr/bin/env python3
"""Waits for ArcRadar to say "a rule was pushed", then pulls and tests it at once.

Instead of asking GitHub on a timer, this keeps one request open to ArcRadar (GET /api/ingest/splunk/wake). ArcRadar
answers the moment a rule is pushed (or after about 25 seconds with "nothing new", and this asks again). On a push it
runs arcradar-apply-splunk-rules, which installs the rule and starts the backtest, so a rule pushed in ArcRadar is
on Splunk and tested within about ten seconds. Nothing on this machine is opened to the outside: it only calls
ArcRadar, the same way the alert action and the sync script do.

It runs as a service (arcradar-splunk-watch.service). The apply cron stays as a slow safety net (a push is applied
by whichever of the two gets there first; the apply script takes a lock, so they never collide).

Settings, all optional (environment variables):
  SPLUNK_HOME                     default /opt/splunk
  ARCRADAR_FORWARD_CONFIG         the alert action's config file with the ArcRadar url and key
  ARCRADAR_APPLY_COMMAND          default /usr/local/sbin/arcradar-apply-splunk-rules
"""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
APP_CONFIG = os.environ.get(
    "ARCRADAR_FORWARD_CONFIG",
    os.path.join(SPLUNK_HOME, "etc", "apps", "arcradar_rules", "local", "arcradar_forward.json"),
)
APPLY = os.environ.get("ARCRADAR_APPLY_COMMAND", "/usr/local/sbin/arcradar-apply-splunk-rules")
WAIT_SECONDS = 25
REQUEST_TIMEOUT = WAIT_SECONDS + 20
# GitHub shows a fresh commit at once, but if the first pull finds nothing new, look again a few times.
APPLY_ATTEMPTS = 4
APPLY_RETRY_SECONDS = 3


def log(message):
    sys.stdout.write("%s arcradar-watch: %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), message))
    sys.stdout.flush()


def read_config():
    with open(APP_CONFIG, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    url = str(config.get("url", "")).rstrip("/")
    key = str(config.get("api_key", "")).strip()
    if not url.endswith("/api/ingest/splunk") or not key.startswith("arc_"):
        raise SystemExit("%s needs a url ending in /api/ingest/splunk and an api_key" % APP_CONFIG)
    return url + "/wake", key


def wake(url, key, since):
    query = "?wait=%d" % WAIT_SECONDS
    if since is not None:
        query += "&since=" + urllib.parse.quote(since)
    request = urllib.request.Request(url + query, headers={"authorization": "Bearer " + key})
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.load(response)["data"]


def apply_rules():
    """Runs the apply script until it reports it installed something (or gives up after a few tries)."""
    for attempt in range(1, APPLY_ATTEMPTS + 1):
        result = subprocess.run([APPLY], capture_output=True, text=True, timeout=300)
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
