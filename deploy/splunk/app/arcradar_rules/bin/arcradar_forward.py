#!/usr/bin/env python3
"""Splunk custom alert action: reports a triggered saved search to ArcRadar.

Splunk runs this once per triggered result (the saved searches ArcRadar writes use
alert.digest_mode = 0) as `arcradar_forward.py --execute` with the alert's JSON on stdin:
sid, search_name, results_link, server_host, result (one row) and configuration (the action's
parameters: rule_key, name, severity, mitre). It POSTs

    { "alerts": [ { sid, search_name, results_link, server_host, result, configuration } ] }

to ArcRadar's /api/ingest/splunk with an API key (scope ingest:splunk). The address and the key are
read from ../local/arcradar_forward.json ({"url": "...", "api_key": "arc_..."}), a file only the
Splunk user can read; they are never part of a saved search.

Delivery. An item that cannot be delivered (ArcRadar unreachable, a 5xx, a 429) is written to a spool
directory and sent again on the next run, oldest first. ArcRadar ignores an item it already has, so
a resend is harmless. An answer that says the item itself is wrong (a 4xx other than 429) is logged
and dropped, never retried forever. At most MAX_SPOOL items are kept.

Needs only the Python that ships with Splunk (standard library).
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_FILE = os.path.join(APP_DIR, "local", "arcradar_forward.json")
SPLUNK_HOME = os.environ.get("SPLUNK_HOME", os.path.dirname(os.path.dirname(os.path.dirname(APP_DIR))))
SPOOL_DIR = os.path.join(SPLUNK_HOME, "var", "spool", "arcradar")
MAX_SPOOL = 500
FLUSH_PER_RUN = 25
TIMEOUT_SECONDS = 20


def log(message):
    # Splunk collects a custom alert action's stderr into its internal logs.
    sys.stderr.write("arcradar_forward: %s\n" % message)
    sys.stderr.flush()


def load_config():
    with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    url = str(config.get("url", "")).strip()
    key = str(config.get("api_key", "")).strip()
    if not url.startswith("https://") and not url.startswith("http://"):
        raise ValueError("url in %s must start with https://" % CONFIG_FILE)
    if not key.startswith("arc_"):
        raise ValueError("api_key in %s is missing or malformed" % CONFIG_FILE)
    return url, key


def build_item(payload):
    result = payload.get("result") or {}
    if not isinstance(result, dict):
        result = {}
    configuration = payload.get("configuration") or {}
    return {
        "sid": str(payload.get("sid", "")),
        "search_name": str(payload.get("search_name", "")),
        "results_link": payload.get("results_link"),
        "server_host": payload.get("server_host"),
        "result": {str(k): v for k, v in result.items()},
        "configuration": {
            "rule_key": configuration.get("rule_key"),
            "name": configuration.get("name"),
            "severity": configuration.get("severity"),
            "mitre": configuration.get("mitre"),
        },
    }


def post(url, key, items):
    """Returns 'ok', 'retry' (try again later) or 'drop' (the request itself is wrong)."""
    body = json.dumps({"alerts": items}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"content-type": "application/json", "authorization": "Bearer " + key},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return "ok" if 200 <= response.status < 300 else "retry"
    except urllib.error.HTTPError as error:
        if error.code in (408, 425, 429) or error.code >= 500:
            log("ArcRadar answered %d; will retry" % error.code)
            return "retry"
        log("ArcRadar answered %d and will not accept this item; dropping it" % error.code)
        return "drop"
    except (urllib.error.URLError, OSError) as error:
        log("could not reach ArcRadar (%s); will retry" % error)
        return "retry"


def spool_files():
    try:
        return sorted(name for name in os.listdir(SPOOL_DIR) if name.endswith(".json"))
    except FileNotFoundError:
        return []


def spool_add(item):
    os.makedirs(SPOOL_DIR, exist_ok=True)
    name = "%020d-%d.json" % (time.time_ns(), os.getpid())
    with open(os.path.join(SPOOL_DIR, name), "w", encoding="utf-8") as handle:
        json.dump(item, handle)
    files = spool_files()
    for old in files[: max(0, len(files) - MAX_SPOOL)]:
        os.remove(os.path.join(SPOOL_DIR, old))
        log("spool is full; dropped the oldest item %s" % old)


def flush_spool(url, key):
    for name in spool_files()[:FLUSH_PER_RUN]:
        path = os.path.join(SPOOL_DIR, name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                item = json.load(handle)
        except (OSError, ValueError):
            os.remove(path)
            continue
        outcome = post(url, key, [item])
        if outcome == "retry":
            return  # ArcRadar is still away: stop, keep the rest in order
        os.remove(path)


def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        log("this script is run by Splunk as an alert action (--execute)")
        return 2
    try:
        payload = json.loads(sys.stdin.read())
        item = build_item(payload)
        url, key = load_config()
    except Exception as error:  # a broken payload or config: say so, do not hide it
        log("cannot start: %s" % error)
        return 1

    flush_spool(url, key)
    outcome = post(url, key, [item])
    if outcome == "retry":
        spool_add(item)
        log("item for %s kept in the spool" % item["search_name"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
