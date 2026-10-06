#!/usr/bin/env python3
"""Reports to ArcRadar what this Splunk really holds and how its rules would have behaved:

  catalog    which (index, sourcetype) pairs have data and which fields their events carry, how often, and a few
             example values, so ArcRadar's rule form can offer real names (and the AI can be told them);
  backtests  for every ArcRadar rule installed here (saved searches named arcradar_<key>), the rule's search run
             over the last 24 hours and 7 days: how often it would have fired, with a few examples, so a person
             sees the effect of a rule before it goes live (and while it is in test mode).

Usage:  arcradar-splunk-sync [--catalog] [--backtests]     (no flag: both)

It uses Splunk's REST API on this machine only, only reads (search jobs), and reports to ArcRadar with the same
API key the alert action uses (POST /api/ingest/splunk/catalog and /backtests). ArcRadar replaces its earlier
report, so running it again is harmless. The example values come from real logs: ArcRadar shows them only to
administrators. A backtest only runs a search that has exactly the shape ArcRadar generates (checked here again
before it is run); anything else is skipped.

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
import datetime
import hashlib
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
BACKTEST_WINDOWS = (24, 168)
MAX_BACKTEST_ROWS = 1000

INDEX_PATTERN = re.compile(r"^[a-z0-9_][a-z0-9_-]{0,59}$")
SOURCETYPE_PATTERN = re.compile(r"^[A-Za-z0-9_:./-]{1,80}$")
FIELD_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,79}$")
RULE_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,60}$")
# Fields Splunk adds to every event: not useful in a rule.
NOISE = {
    "punct", "linecount", "splunk_server", "splunk_server_group", "timestartpos", "timeendpos",
    "eventtype", "tag", "date_second", "date_minute", "date_hour", "date_mday", "date_wday",
    "date_month", "date_year", "date_zone", "index", "source", "sourcetype",
}

# The only shapes a segment of an ArcRadar rule's search can have (the same as ArcRadar and the apply script).
FIELD = r"[A-Za-z_][A-Za-z0-9_.]{0,79}"
BASE_SHAPE = re.compile(r"index=[a-z0-9_][a-z0-9_-]{0,59}( sourcetype=[A-Za-z0-9_:./-]{1,80})?")
REGEX_SHAPE = re.compile(r'regex (%s)="(?:[^"\\]|\\.)*"' % FIELD)
STATS_SHAPE = re.compile(r"stats count( by (%s(?:, %s){0,2}))?" % (FIELD, FIELD))
WHERE_SHAPE = re.compile(r"where count >= ([0-9]{1,4})")


def log(message):
    sys.stderr.write("arcradar-sync: %s\n" % message)


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
    return url, key


# Splunk's management port on this machine uses a self-signed certificate.
LOCAL_TLS = ssl.create_default_context()
LOCAL_TLS.check_hostname = False
LOCAL_TLS.verify_mode = ssl.CERT_NONE


def splunk_request(login, path, data=None):
    request = urllib.request.Request(SPLUNK_URL + path, data=data, method="POST" if data is not None else "GET")
    token = ("%s:%s" % login).encode()
    request.add_header("Authorization", "Basic " + base64.b64encode(token).decode())
    with urllib.request.urlopen(request, timeout=300, context=LOCAL_TLS) as response:
        return json.load(response)


def splunk_search(login, spl, earliest):
    """Runs one search to completion and returns its result rows (dicts)."""
    body = urllib.parse.urlencode(
        {
            "search": spl if spl.startswith("|") else "search " + spl,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "count": "0",
            "earliest_time": earliest,
        }
    ).encode()
    return splunk_request(login, "/services/search/jobs", body).get("results", [])


def post(url, key, payload):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={"content-type": "application/json", "authorization": "Bearer " + key},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


# ---------------------------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------------------------
def list_sources(login):
    rows = splunk_search(
        login,
        "| tstats count where index=* by index, sourcetype | search NOT index=_* | sort - count | head %d" % MAX_SOURCES,
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


def run_catalog(login, base_url, key):
    sources = []
    for index, sourcetype in list_sources(login):
        try:
            described = describe_source(login, index, sourcetype)
        except (urllib.error.URLError, OSError, ValueError) as error:
            log("catalog: skipped %s / %s: %s" % (index, sourcetype, error))
            continue
        if described:
            sources.append(described)
    if not sources:
        log("catalog: no source with events in the last %d h; nothing to report" % WINDOW_HOURS)
        return
    answer = post(base_url + "/catalog", key, {"sources": sources})
    data = answer.get("data", {})
    print("catalog: reported %s source(s), %s field(s) to ArcRadar" % (data.get("sources"), data.get("fields")))


# ---------------------------------------------------------------------------------------------
# backtests
# ---------------------------------------------------------------------------------------------
def split_pipeline(text):
    """Splits on | outside quoted strings (a backslash escapes the next character inside one)."""
    segments, current, quoted, i = [], "", False, 0
    while i < len(text):
        ch = text[i]
        if quoted:
            current += ch
            if ch == "\\":
                current += text[i + 1] if i + 1 < len(text) else ""
                i += 1
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            current += ch
        elif ch == "|":
            segments.append(current.strip())
            current = ""
        else:
            current += ch
        i += 1
    segments.append(current.strip())
    return segments


def parse_rule_search(search):
    """Returns (base, regex_segments, by_fields, limit) of a search with exactly ArcRadar's shape, else raises."""
    base, *steps = split_pipeline(search)
    if not BASE_SHAPE.fullmatch(base):
        raise ValueError("the search does not start with index=<name>")
    regexes, by_fields, limit, saw_stats, saw_where = [], [], None, False, False
    for step in steps:
        if REGEX_SHAPE.fullmatch(step):
            if saw_stats:
                raise ValueError("a regex after the stats")
            regexes.append(step)
        elif STATS_SHAPE.fullmatch(step) and not saw_stats:
            saw_stats = True
            by = STATS_SHAPE.fullmatch(step).group(2)
            by_fields = [name.strip() for name in by.split(",")] if by else []
        elif WHERE_SHAPE.fullmatch(step) and saw_stats and not saw_where:
            saw_where = True
            limit = int(WHERE_SHAPE.fullmatch(step).group(1))
        else:
            raise ValueError("a segment ArcRadar does not generate: %s" % step.split(" ", 1)[0])
    if saw_stats != saw_where:
        raise ValueError("stats and where come together")
    return base, regexes, by_fields, limit


def iso(value):
    """Splunk's _time comes as epoch seconds or as ISO 8601 text (after bin or table); returns UTC ISO or None."""
    try:
        try:
            moment = datetime.datetime.fromtimestamp(float(value), datetime.timezone.utc)
        except (TypeError, ValueError):
            moment = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
        return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def window_minutes(content):
    match = re.fullmatch(r"-(\d{1,5})m", content.get("dispatch.earliest_time", "") or "")
    return int(match.group(1)) if match else 5


def count_of(rows):
    return int(rows[0].get("count", "0")) if rows else 0


def backtest_rule(login, rule_key, content, hours):
    search = content.get("search", "")
    digest = hashlib.sha256(search.encode("utf-8")).hexdigest()
    base, regexes, by_fields, limit = parse_rule_search(search)
    earliest = "-%dh" % hours
    filtered = " | ".join([base] + regexes)
    result = {"rule_key": rule_key, "window_hours": hours, "search_sha256": digest}
    sample = []
    if limit is not None:
        span = window_minutes(content)
        group = ", ".join(["_time"] + by_fields)
        rows = splunk_search(
            login,
            "%s | bin _time span=%dm | stats count by %s | where count >= %d | sort - _time | head %d"
            % (filtered, span, group, limit, MAX_BACKTEST_ROWS),
            earliest,
        )
        scanned = count_of(splunk_search(login, filtered + " | stats count", earliest))
        result.update(kind="threshold", matches=len(rows), scanned=scanned)
        for row in rows[:5]:
            item = {"count": int(row.get("count", "0"))}
            when = iso(row.get("_time"))
            if when:
                item["time"] = when
            if by_fields:
                item["group"] = {name: str(row.get(name, ""))[:200] for name in by_fields}
            sample.append(item)
    else:
        matches = count_of(splunk_search(login, filtered + " | stats count", earliest))
        scanned = count_of(splunk_search(login, base + " | stats count", earliest))
        fields = [REGEX_SHAPE.fullmatch(segment).group(1) for segment in regexes]
        rows = splunk_search(
            login, "%s | head 5 | table %s" % (filtered, ", ".join(["_time"] + fields)), earliest
        )
        result.update(kind="events", matches=matches, scanned=scanned)
        for row in rows:
            item = {"group": {name: str(row.get(name, ""))[:200] for name in fields[:6]}}
            when = iso(row.get("_time"))
            if when:
                item["time"] = when
            sample.append(item)
    result["sample"] = sample
    return result


def list_rules(login):
    path = "/servicesNS/nobody/arcradar_rules/saved/searches?output_mode=json&count=0&search=" + urllib.parse.quote(
        "name=arcradar_*"
    )
    rules = []
    for entry in splunk_request(login, path).get("entry", []):
        name = entry.get("name", "")
        key = name[len("arcradar_"):] if name.startswith("arcradar_") else ""
        if RULE_KEY_PATTERN.match(key):
            rules.append((key, entry.get("content", {})))
    return rules


def run_backtests(login, base_url, key):
    results = []
    for rule_key, content in list_rules(login):
        for hours in BACKTEST_WINDOWS:
            try:
                results.append(backtest_rule(login, rule_key, content, hours))
            except ValueError as error:
                log("backtest: skipped %s: %s" % (rule_key, error))
                break
            except (urllib.error.URLError, OSError) as error:
                digest = hashlib.sha256(content.get("search", "").encode("utf-8")).hexdigest()
                results.append(
                    {
                        "rule_key": rule_key,
                        "window_hours": hours,
                        "kind": "events",
                        "matches": 0,
                        "search_sha256": digest,
                        "error": ("the search failed: %s" % error)[:300],
                        "sample": [],
                    }
                )
    if not results:
        print("backtests: no ArcRadar rule to test")
        return
    answer = post(base_url + "/backtests", key, {"results": results[:200]})
    print("backtests: reported %s result(s) to ArcRadar" % answer.get("data", {}).get("results"))


def main():
    wanted = {arg for arg in sys.argv[1:] if arg in ("--catalog", "--backtests")}
    if not wanted:
        wanted = {"--catalog", "--backtests"}
    login = read_login()
    base_url, key = read_arcradar()
    ok = True
    for flag, action in (("--catalog", run_catalog), ("--backtests", run_backtests)):
        if flag not in wanted:
            continue
        try:
            action(login, base_url, key)
        except urllib.error.HTTPError as error:
            log("%s: ArcRadar or Splunk answered %d: %s" % (flag[2:], error.code, error.read()[:300].decode("utf-8", "replace")))
            ok = False
        except (urllib.error.URLError, OSError) as error:
            log("%s: could not reach ArcRadar or Splunk: %s" % (flag[2:], error))
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
