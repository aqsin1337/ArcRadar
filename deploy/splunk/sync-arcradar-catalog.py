#!/usr/bin/env python3
"""Reports to ArcRadar which fields this Splunk really holds, so ArcRadar's rule form can offer the real
index, sourcetype and field names (and the AI can be told them) instead of guessing.

What it does, using Splunk's REST API on this machine only:
  1. finds which (index, sourcetype) pairs received events in the last WINDOW_HOURS (internal indexes,
     whose names start with an underscore, are left out) and keeps the busiest MAX_SOURCES;
  2. for each, looks at a sample of up to SAMPLE_EVENTS events and asks Splunk for a field summary:
     which fields exist, in how many events, how many distinct values, a few example values;
  3. POSTs the result to ArcRadar (POST /api/ingest/splunk/catalog) with the same API key the alert action uses.

It only reads from Splunk (search jobs) and only talks to ArcRadar. ArcRadar replaces its earlier report
for each source it receives, so running it again is harmless. Example values come from real logs: ArcRadar
shows them only to administrators.

Settings, all optional (environment variables):
  SPLUNK_HOME                        default /opt/splunk
  ARCRADAR_SPLUNK_SYNC_AUTH          file with "user:password" of the Splunk account used for the searches
                                     (default /etc/arcradar/splunk-sync, then /etc/arcradar/splunk-admin)
  ARCRADAR_FORWARD_CONFIG            the alert action's config file with the ArcRadar url and key
                                     (default: the arcradar_rules app's local/arcradar_forward.json)
  ARCRADAR_CATALOG_WINDOW_HOURS      default 24
  ARCRADAR_CATALOG_MAX_SOURCES       default 20
  ARCRADAR_CATALOG_SAMPLE_EVENTS     default 1000
Needs only the Python that ships with Splunk or any Python 3.
"""

import base64
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
SPLUNK_URL = "https://127.0.0.1:8089"
APP_CONFIG = os.environ.get(
    "ARCRADAR_FORWARD_CONFIG",
    os.path.join(SPLUNK_HOME, "etc", "apps", "arcradar_rules", "local", "arcradar_forward.json"),
)
WINDOW_HOURS = int(os.environ.get("ARCRADAR_CATALOG_WINDOW_HOURS", "24"))
MAX_SOURCES = int(os.environ.get("ARCRADAR_CATALOG_MAX_SOURCES", "20"))
SAMPLE_EVENTS = int(os.environ.get("ARCRADAR_CATALOG_SAMPLE_EVENTS", "1000"))
MAX_FIELDS = 300

INDEX_PATTERN = re.compile(r"^[a-z0-9_][a-z0-9_-]{0,59}$")
SOURCETYPE_PATTERN = re.compile(r"^[A-Za-z0-9_:./-]{1,80}$")
FIELD_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,79}$")
# Fields Splunk adds to every event: not useful in a rule.
NOISE = {
    "punct", "linecount", "splunk_server", "splunk_server_group", "timestartpos", "timeendpos",
    "eventtype", "tag", "date_second", "date_minute", "date_hour", "date_mday", "date_wday",
    "date_month", "date_year", "date_zone", "index", "source", "sourcetype",
}


def log(message):
    sys.stderr.write("arcradar-catalog: %s\n" % message)


def read_login():
    path = os.environ.get("ARCRADAR_SPLUNK_SYNC_AUTH")
    candidates = [path] if path else ["/etc/arcradar/splunk-sync", "/etc/arcradar/splunk-admin"]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            with open(candidate, "r", encoding="utf-8") as handle:
                user, _, password = handle.read().strip().partition(":")
            if user and password:
                return user, password
    raise SystemExit("no Splunk login found (set ARCRADAR_SPLUNK_SYNC_AUTH or create /etc/arcradar/splunk-sync)")


def read_arcradar():
    with open(APP_CONFIG, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    url = str(config.get("url", "")).rstrip("/")
    key = str(config.get("api_key", "")).strip()
    if not url.endswith("/api/ingest/splunk") or not key.startswith("arc_"):
        raise SystemExit("%s needs a url ending in /api/ingest/splunk and an api_key" % APP_CONFIG)
    return url + "/catalog", key


# Splunk's management port on this machine uses a self-signed certificate.
LOCAL_TLS = ssl.create_default_context()
LOCAL_TLS.check_hostname = False
LOCAL_TLS.verify_mode = ssl.CERT_NONE


def splunk_search(login, spl, earliest):
    """Runs one search to completion and returns its result rows (dicts)."""
    body = urllib.parse.urlencode(
        {"search": spl if spl.startswith("|") else "search " + spl, "exec_mode": "oneshot", "output_mode": "json", "count": "0", "earliest_time": earliest}
    ).encode()
    request = urllib.request.Request(SPLUNK_URL + "/services/search/jobs", data=body, method="POST")
    token = ("%s:%s" % login).encode()
    request.add_header("Authorization", "Basic " + base64.b64encode(token).decode())
    with urllib.request.urlopen(request, timeout=120, context=LOCAL_TLS) as response:
        return json.load(response).get("results", [])


def list_sources(login):
    rows = splunk_search(
        login,
        '| tstats count where index=* by index, sourcetype | search NOT index=_* | sort - count | head %d' % MAX_SOURCES,
        "-%dh" % WINDOW_HOURS,
    )
    sources = []
    for row in rows:
        index, sourcetype = row.get("index", ""), row.get("sourcetype", "")
        if INDEX_PATTERN.match(index) and SOURCETYPE_PATTERN.match(sourcetype):
            sources.append((index, sourcetype))
    return sources


def example_values(raw):
    try:
        items = json.loads(raw) if raw else []
    except ValueError:
        return []
    values = []
    for item in items:
        value = item.get("value") if isinstance(item, dict) else None
        if isinstance(value, str):
            value = " ".join(value.split())[:100]  # one line: a log message can span several
            if value and len(values) < 5:
                values.append(value)
    return values


def describe_source(login, index, sourcetype):
    base = "index=%s sourcetype=%s | head %d" % (index, sourcetype, SAMPLE_EVENTS)
    earliest = "-%dh" % WINDOW_HOURS
    counted = splunk_search(login, base + " | stats count", earliest)
    sampled = int(counted[0].get("count", "0")) if counted else 0
    if sampled < 1:
        return None
    rows = splunk_search(
        login,
        base + " | fieldsummary maxvals=5 | table field count distinct_count values",
        earliest,
    )
    fields = []
    for row in rows:
        name = row.get("field", "")
        if not FIELD_PATTERN.match(name) or name in NOISE or name.startswith("date_"):
            continue
        entry = {"name": name, "count": min(int(row.get("count", "0")), sampled)}
        if row.get("distinct_count", "").isdigit():
            entry["distinct"] = int(row["distinct_count"])
        values = example_values(row.get("values", ""))
        if values:
            entry["values"] = values
        fields.append(entry)
    fields.sort(key=lambda item: -item["count"])
    return {
        "index": index,
        "sourcetype": sourcetype,
        "window_hours": WINDOW_HOURS,
        "events_sampled": sampled,
        "fields": fields[:MAX_FIELDS],
    }


def post(url, key, sources):
    request = urllib.request.Request(
        url,
        data=json.dumps({"sources": sources}).encode(),
        method="POST",
        headers={"content-type": "application/json", "authorization": "Bearer " + key},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def main():
    login = read_login()
    url, key = read_arcradar()
    sources = []
    for index, sourcetype in list_sources(login):
        try:
            described = describe_source(login, index, sourcetype)
        except (urllib.error.URLError, OSError, ValueError) as error:
            log("skipped %s / %s: %s" % (index, sourcetype, error))
            continue
        if described:
            sources.append(described)
    if not sources:
        log("no source with events in the last %d h; nothing to report" % WINDOW_HOURS)
        return 0
    try:
        answer = post(url, key, sources)
    except urllib.error.HTTPError as error:
        log("ArcRadar answered %d: %s" % (error.code, error.read()[:300].decode("utf-8", "replace")))
        return 1
    except (urllib.error.URLError, OSError) as error:
        log("could not reach ArcRadar: %s" % error)
        return 1
    data = answer.get("data", {})
    print("reported %s source(s), %s field(s) to ArcRadar" % (data.get("sources"), data.get("fields")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
