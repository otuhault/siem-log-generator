"""Fortinet FortiGate against Splunk_TA_fortinet_fortigate, read from disk.

The add-on classifies on `type=` at index time and on `subtype=` — plus, for
`fortigate_event`, on `action=` and `status=` — at search time. So what an event
reaches is decided by three or four fields of the body, and every one of them
has a closed vocabulary the add-on ships: two action lookups and a severity
lookup. The tests below read those files rather than restating them, so an
add-on upgrade fails the suite instead of silently invalidating it.

The trap this file exists to hold shut: `[ftnt_fortigate_auth]` requires
`vendor_status IN(success, failure)`, and the add-on's own sample carries
`status=logout`. A generator that copied the sample would parse perfectly and
land in no datamodel at all.
"""

import collections
import csv
import re
from pathlib import Path

import pytest

from log_generators import REGISTRY
from syslog_framing import SEVERITIES, SyslogFramer
from ta_registry import get_sourcetype_info, get_ta

TA = (Path(__file__).resolve().parents[1] / "TAs"
      / "Splunk_TA_fortinet_fortigate")

pytestmark = pytest.mark.skipif(
    not TA.exists(), reason="Splunk_TA_fortinet_fortigate not present in TAs/"
)

LOG_TYPE = "fortigate"

#: Which registry sourcetype each generator category produces, read off the
#: generator's own METADATA so the two cannot drift.
CATEGORIES = {source["id"]: source["sourcetype"]
              for source in REGISTRY[LOG_TYPE].METADATA["sources"]}


def _stanzas(path):
    out, cur = {}, None
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            out[cur] = {}
        elif cur and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            out[cur][key.strip()] = value.strip()
    return out


@pytest.fixture(scope="module")
def conf():
    return {name: _stanzas(TA / "default" / f"{name}.conf")
            for name in ("props", "eventtypes", "tags", "transforms")}


@pytest.fixture(scope="module")
def lookup_rows():
    """Each shipped lookup as a list of dicts, keys and values stripped."""
    out = {}
    for path in (TA / "lookups").glob("*.csv"):
        with path.open() as handle:
            out[path.stem] = [
                {k.strip(): (v or "").strip() for k, v in row.items()}
                for row in csv.DictReader(handle)
            ]
    return out


def _events(categories, n=400):
    """`n` events from one category, as parsed key=value dicts plus the raw line."""
    generator = REGISTRY[LOG_TYPE](event_categories=list(categories))
    return [(_parse(line), line)
            for line in (generator.generate() for _ in range(n))]


_PAIR = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def _parse(line):
    """What the add-on's `DELIMS = "\\ ,", "="` extraction would produce."""
    return {m.group(1): m.group(2) if m.group(2) is not None else m.group(3)
            for m in _PAIR.finditer(line)}


# ── the index-time fan-out recognises our events ────────────────────────────

def test_every_event_is_recognised_as_a_fortigate_one(conf):
    """[force_sourcetype_fortigate] needs a FortiGate `devid` and a known `type`.

    An event failing that regex stays in whatever sourcetype it arrived as, with
    no extractions at all — the umbrella path breaks silently, and so would a
    deployment that ingests everything as fortigate_log.
    """
    pattern = re.compile(conf["transforms"]["force_sourcetype_fortigate"]["REGEX"])

    for category in CATEGORIES:
        for _, line in _events([category], n=40):
            match = pattern.search(line)
            assert match, f"{category}: not recognised as a FortiGate event"
            expected = CATEGORIES[category]
            assert f"fortigate_{match.group(1)}" == expected, (
                f"{category}: the fan-out would route it to "
                f"fortigate_{match.group(1)}, not {expected}"
            )


def test_the_sourcetypes_we_emit_are_the_canonical_stanzas(conf):
    """`fgt_*` renames into `fortigate_*`, not the other way round: the
    configuration lives on the names we emit."""
    for name in {st["name"] for st in get_ta(LOG_TYPE)["sourcetypes"]}:
        assert name in conf["props"], f"{name} has no stanza in props.conf"
        assert "rename" not in conf["props"][name], (
            f"{name} is an alias stanza; the add-on renames it away"
        )

    legacy = {"fgt_traffic": "fortigate_traffic", "fgt_utm": "fortigate_utm",
              "fgt_event": "fortigate_event", "fgt_anomaly": "fortigate_anomaly"}
    for alias, canonical in legacy.items():
        assert conf["props"][alias]["rename"] == canonical, (
            f"{alias} no longer renames to {canonical} — re-read props.conf "
            f"before trusting the registry"
        )


# ── the eventtypes match, so the tags follow ────────────────────────────────

#: The eventtype search language, reduced to what this add-on actually writes:
#: `field=value`, `field!=value`, `field IN(a, b)`, AND / OR / NOT, parentheses,
#: and adjacency meaning AND. Anything else raises rather than quietly matching.
_TOKEN = re.compile(r'\s*(?:(?P<lparen>\()|(?P<rparen>\))|(?P<comma>,)'
                    r'|(?P<op>!=|=)|(?P<word>"[^"]*"|[^\s()=,!]+))')


def _tokenize(search):
    out, pos = [], 0
    while pos < len(search):
        match = _TOKEN.match(search, pos)
        if not match:
            raise AssertionError(
                f"cannot tokenise eventtype search at {search[pos:]!r}")
        pos = match.end()
        kind = match.lastgroup
        value = match.group(kind)
        out.append((kind, value.strip('"') if kind == "word" else value))
    return out


class _Search:
    """Recursive-descent evaluator over one eventtype search."""

    def __init__(self, tokens, sourcetype, event):
        self.tokens, self.i = tokens, 0
        self.sourcetype, self.event = sourcetype, event

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def take(self):
        token = self.peek()
        self.i += 1
        return token

    def value_of(self, field):
        if field == "sourcetype":
            return self.sourcetype
        actual = self.event.get(field)
        # The add-on aliases action -> vendor_action and status -> vendor_status
        # in props.conf, so an eventtype naming the CIM side means the raw one.
        if actual is None and field.startswith("vendor_"):
            actual = self.event.get(field[len("vendor_"):])
        return actual

    def expr(self):
        result = self.and_expr()
        while self.peek() == ("word", "OR"):
            self.take()
            result = self.and_expr() or result
        return result

    def and_expr(self):
        result = self.unary()
        while True:
            kind, value = self.peek()
            if kind is None or kind == "rparen" or value == "OR":
                return result
            if value == "AND":
                self.take()
            result = self.unary() and result

    def unary(self):
        kind, value = self.peek()
        if value == "NOT":
            self.take()
            return not self.unary()
        if kind == "lparen":
            self.take()
            result = self.expr()
            assert self.take()[0] == "rparen", "unbalanced parenthesis"
            return result
        return self.comparison()

    def comparison(self):
        kind, field = self.take()
        assert kind == "word", f"expected a field name, got {field!r}"
        kind, op = self.peek()
        if kind == "op":
            self.take()
            _, wanted = self.take()
            actual = self.value_of(field)
            return actual == wanted if op == "=" else actual != wanted
        assert op == "IN", f"unsupported operator {op!r} after {field!r}"
        self.take()
        assert self.take()[0] == "lparen", "IN without a list"
        values = []
        while True:
            kind, token = self.take()
            if kind == "rparen":
                break
            if kind == "word":
                values.append(token)
        return self.value_of(field) in values


def _eventtype_matches(search, sourcetype, event):
    """Does this eventtype's search match the event?"""
    return _Search(_tokenize(search), sourcetype, event).expr()

def _tags_for(conf, sourcetype, event):
    """Every tag the add-on would grant this event."""
    tags = set()
    for name, stanza in conf["eventtypes"].items():
        if not _eventtype_matches(stanza.get("search", ""), sourcetype, event):
            continue
        for key, value in conf["tags"].get(f"eventtype={name}", {}).items():
            if value == "enabled":
                tags.add(key)
    return tags


#: The tag set each category has to come away with, and the dataset it buys.
#: Read off tags.conf in the phase-0 pass; asserted here against the add-on.
#: `event_admin` and `event_vpn` are absent because each splits on `action` into
#: two or three different tag sets — they have a test of their own below.
EXPECTED_TAGS = {
    "traffic":       {"network", "communicate"},
    "utm_webfilter": {"web"},
    "utm_ips":       {"ids", "attack"},
    "utm_virus":     {"malware", "attack", "operations"},
    "utm_appctrl":   {"network", "communicate"},
    "event_auth":    {"authentication", "default"},
    "event_config":  {"change", "network"},
    "event_perf":    {"os", "performance", "cpu", "memory"},
    "anomaly":       {"ids", "attack"},
}


@pytest.mark.parametrize("category", sorted(EXPECTED_TAGS))
def test_every_event_of_a_category_earns_its_tags(conf, category):
    sourcetype = CATEGORIES[category]
    for event, line in _events([category], n=120):
        tags = _tags_for(conf, sourcetype, event)
        missing = EXPECTED_TAGS[category] - tags
        assert not missing, f"{category} missing {sorted(missing)}: {line}"


def test_admin_events_are_privileged_or_account_changes(conf):
    """subtype=system splits three ways on `action`, and the add-on tags the
    login and the logout differently — one is Authentication, the other Change."""
    seen = collections.Counter()
    for event, line in _events(["event_admin"], n=300):
        tags = _tags_for(conf, "fortigate_event", event)
        if event["action"] == "login":
            assert {"authentication", "privileged"} <= tags, line
            seen["login"] += 1
        else:
            assert {"change", "account"} <= tags, line
            seen["logout"] += 1
    assert seen["login"] and seen["logout"], f"only one shape emitted: {seen}"


def test_vpn_start_and_end_are_told_apart(conf):
    """Session_Start and Session_End are the same eventtype family separated by
    `action`, so emitting only one half would halve the dataset."""
    seen = collections.Counter()
    for event, line in _events(["event_vpn"], n=400):
        tags = _tags_for(conf, "fortigate_event", event)
        if event["action"] == "tunnel-up":
            assert "start" in tags, line
            seen["start"] += 1
        elif event["action"] == "tunnel-down":
            assert "end" in tags, line
            seen["end"] += 1
        else:
            assert {"authentication", "default"} <= tags, line
            seen["auth"] += 1
    assert all(seen[k] for k in ("start", "end", "auth")), seen


def test_user_authentication_carries_a_status_the_eventtype_accepts(conf):
    """The regression this file exists for: eventtypes.conf:77 needs
    `vendor_status IN(success, failure)` and the shipped sample says `logout`."""
    accepted = {"success", "failure"}
    statuses = collections.Counter()
    for event, line in _events(["event_auth"], n=300):
        assert event["status"] in accepted, (
            f"status={event['status']!r} matches no eventtype: {line}")
        statuses[event["status"]] += 1
    assert len(statuses) == 2, f"only one outcome is ever emitted: {statuses}"


def test_virus_events_are_detections_not_sandbox_submissions(conf):
    """[ftnt_fortigate_virus] excludes vendor_action=analytics, which is what
    both of the add-on's own virus samples carry."""
    for event, line in _events(["utm_virus"], n=120):
        assert event["action"] != "analytics", line
        assert "malware" in _tags_for(conf, "fortigate_utm", event), line


# ── the lookups decide whether a CIM action comes out at all ────────────────

def test_every_traffic_action_is_in_the_action_lookup(lookup_rows):
    known = {row["ftnt_action"] for row in lookup_rows["ftnt_action_info"]}
    for category in ("traffic", "utm_webfilter", "utm_ips", "utm_virus",
                     "utm_appctrl", "anomaly"):
        for event, line in _events([category], n=120):
            assert event["action"] in known, (
                f"{category}: action={event['action']!r} yields no CIM action: {line}")


def test_every_event_action_is_in_the_event_action_lookup(lookup_rows):
    """(subtype, action, status) is the lookup's key; a triple it does not hold
    produces neither `action` nor `change_type`."""
    rows = {(row["subtype"], row["vendor_action"], row["vendor_status"])
            for row in lookup_rows["ftnt_event_action_info"]}
    for category in ("event_auth", "event_admin", "event_vpn", "event_config"):
        for event, line in _events([category], n=150):
            key = (event["subtype"], event["action"],
                   event.get("status", "unknown"))
            assert key in rows, f"{category}: {key} is not in the lookup: {line}"


def test_every_level_is_in_the_severity_lookup(lookup_rows):
    known = {row["level"] for row in lookup_rows["ftnt_severity_info"]}
    for category in CATEGORIES:
        for event, line in _events([category], n=40):
            assert event["level"] in known, line


# ── the wire shape ──────────────────────────────────────────────────────────

def test_the_timestamp_is_at_offset_zero(conf):
    """All four stanzas set TIME_PREFIX = ^ with no lookahead, so anything in
    front of `date=` would be read as the timestamp instead."""
    for name in ("fortigate_traffic", "fortigate_utm", "fortigate_event",
                 "fortigate_anomaly"):
        assert conf["props"][name]["TIME_PREFIX"] == "^", name

    for category in CATEGORIES:
        for _, line in _events([category], n=20):
            assert re.match(r"^date=\d{4}-\d{2}-\d{2} time=\d{2}:\d{2}:\d{2} ",
                            line), line


def test_syslog_framing_adds_a_priority_and_nothing_else():
    """A FortiGate sends `<PRI>` then its payload. Adding a BSD header would
    give TIME_PREFIX = ^ a timestamp with no year to read."""
    framing = get_ta(LOG_TYPE)["syslog_framing"]
    assert framing["header"] == "none"
    framer = SyslogFramer(framing)

    generator = REGISTRY[LOG_TYPE]()
    for _ in range(60):
        line = generator.generate()
        framed = framer.frame(line)
        assert framed.endswith(line), "the payload was rewritten"
        assert re.match(r"^<\d+>date=", framed), framed


def test_the_priority_severity_follows_the_events_own_level(lookup_rows):
    """FortiOS derives the PRI severity from `level=`, whose spelling the
    add-on's severity lookup is the reference for."""
    framer = SyslogFramer(get_ta(LOG_TYPE)["syslog_framing"])
    levels = {row["level"] for row in lookup_rows["ftnt_severity_info"]}
    base = 23 * 8   # local7

    for level in levels:
        line = f'date=2026-09-13 time=11:29:55 level="{level}" type="event"'
        severity = int(re.match(r"^<(\d+)>", framer.frame(line)).group(1)) - base
        assert 0 <= severity <= 7, level
        # `notice` and `debug` are spelled the same on both sides; the rest are
        # aliased. Either way the result has to be a real severity.
        assert severity in SEVERITIES.values()


def test_no_source_is_emitted():
    """Nothing in the add-on classifies on `source`, so inventing one would be
    describing a routing rule that does not exist."""
    for name in {st["name"] for st in get_ta(LOG_TYPE)["sourcetypes"]}:
        info = get_sourcetype_info(LOG_TYPE, name)
        assert not info.get("hec_source"), name
        assert not info.get("hec_source_by_render_format"), name


def test_the_registry_declares_no_umbrella_sourcetype():
    """We know the category, so each event carries its own sourcetype rather
    than leaning on [fortigate_log]'s index-time fan-out."""
    ta = get_ta(LOG_TYPE)
    assert "hec_default_sourcetype" not in ta
    assert "hec_default_sourcetype_by_render_format" not in ta
