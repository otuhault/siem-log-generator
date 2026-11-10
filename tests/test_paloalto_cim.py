"""Palo Alto against the shipped add-on, read from disk.

Two directories are present — 3.0.1 and 4.0.0 — and the newer one is used. Its
field extractions are byte-identical to the older, but it fixed an operator
precedence bug in the eventtypes: `A OR B OR (C AND D) AND cond` let every
traffic subtype match [pan_traffic_start], because AND binds tighter than OR.
4.0.0 parenthesises each sourcetype with its own subtype condition, so what
reaches Network_Traffic now depends on the subtype actually emitted.
"""

import collections
import re
from pathlib import Path

import pytest

from hec_sender import HECSender
from log_generators import REGISTRY
from ta_registry import get_ta

TAS = Path(__file__).resolve().parents[1] / "TAs"


def _locate():
    """The Palo Alto add-on, whatever directory it was unpacked into.

    Pinning a directory name meant the suite skipped itself, silently, the day
    the 4.0.0 tree replaced the 3.0.1 one under the canonical name.
    """
    for candidate in sorted(TAS.glob("*paloalto*")):
        conf = candidate / "default"
        if (conf / "props.conf").exists():
            yield conf


TA = next(_locate(), None)

pytestmark = pytest.mark.skipif(
    TA is None, reason="no Palo Alto add-on in TAs/"
)


def _stanza_body(path, name):
    text = path.read_text(errors="replace")
    match = re.search(r"^\[" + re.escape(name) + r"\]\s*$(.*?)(?=^\[|\Z)",
                      text, re.M | re.S)
    return match.group(1) if match else None


def _fields(transform):
    body = _stanza_body(TA / "transforms.conf", transform)
    raw = re.search(r"FIELDS\s*=\s*(.+?)(?=\n[A-Z_]+\s*=|\Z)", body, re.S).group(1)
    return [f.strip().strip('"') for f in raw.replace("\n", " ").split(",")]


def _sample(category, n=600):
    generator = REGISTRY["paloalto"](log_types=[category])
    return [HECSender._parse_syslog(generator.generate())[1] for _ in range(n)]


# ── the columns our registry pins are the add-on's ──────────────────────────

@pytest.mark.parametrize("sourcetype, transform", [
    ("pan:traffic", "extract_traffic"),
    ("pan:threat", "extract_threat"),
    ("pan:system", "extract_system"),
])
def test_registry_positions_match_the_add_ons_column_order(sourcetype, transform):
    """csv_position is 1-based over the add-on's DELIMS FIELDS list.

    A version bump that reordered a column would silently move every mapping,
    so this checks them rather than trusting them.
    """
    names = _fields(transform)
    info = next(s for s in get_ta("paloalto")["sourcetypes"]
                if s["name"] == sourcetype)

    for field in info["fields"]:
        position = field.get("csv_position")
        if position is None:
            continue
        assert names[position - 1] == field["raw_field"], (
            f"{sourcetype}: position {position} is {names[position - 1]!r}, "
            f"registry says {field['raw_field']!r}"
        )


@pytest.mark.parametrize("category, transform", [
    ("traffic", "extract_traffic"),
    ("threat", "extract_threat"),
    ("system", "extract_system"),
])
def test_the_syslog_header_does_not_shift_the_columns(category, transform):
    """It sits inside future_use1, which is one field either way.

    Keeping the header was the fix for cisco:asa; it must cost Palo Alto
    nothing, since [pan:log] counts commas from the start.
    """
    names = _fields(transform)
    for line in _sample(category, 100):
        values = line.split(",")
        assert values[names.index("log_type")] == category.upper()


# ── which subtypes reach a datamodel ────────────────────────────────────────

def test_the_precedence_fix_is_in_the_shipped_eventtypes():
    """Guard the premise: 4.0.0 conjoins each sourcetype with its condition."""
    body = _stanza_body(TA / "eventtypes.conf", "pan_traffic_start")
    search = " ".join(body.split())
    assert '(sourcetype=pan:traffic AND (log_subtype="start"' in search


def test_traffic_is_mostly_session_records_not_blocks():
    """A firewall writes `end` for every session and deny/drop only for blocks.

    Drawn uniformly, nearly half the traffic was a block — and since the
    precedence fix, a block reaches no datamodel at all.
    """
    subtypes = collections.Counter(line.split(",")[4] for line in _sample("traffic", 3000))
    total = sum(subtypes.values())

    assert subtypes["end"] / total > 0.45, "end should dominate a traffic log"
    assert (subtypes["deny"] + subtypes["drop"]) / total < 0.30
    reached = (subtypes["start"] + subtypes["end"]) / total
    assert reached >= 0.70, f"only {reached:.1%} reaches Network_Traffic"


def test_threat_events_mostly_reach_the_threat_eventtype():
    """[pan_threat] excludes the url and file subtypes."""
    subtypes = collections.Counter(line.split(",")[4] for line in _sample("threat", 2000))
    total = sum(subtypes.values())
    excluded = subtypes["url"] + subtypes["file"]
    assert (total - excluded) / total >= 0.70


def test_the_user_id_field_is_populated_where_the_registry_maps_it():
    """src_user is declared as an A&I field; an empty column would make it decorative."""
    names = _fields("extract_traffic")
    index = names.index("src_user")
    lines = _sample("traffic", 600)
    filled = sum(1 for line in lines if line.split(",")[index].strip())

    assert filled / len(lines) >= 0.15, f"src_user filled on {filled}/{len(lines)}"


# ── the split still works the way the registry assumes ──────────────────────

def test_pan_log_still_fans_out_on_the_fourth_field():
    """hec_default_sourcetype = pan:log relies on this staying true."""
    assert get_ta("paloalto")["hec_default_sourcetype"] == "pan:log"

    body = _stanza_body(TA / "props.conf", "pan:log")
    assert "TRANSFORMS-sourcetype" in body
    for name in ("pan_threat", "pan_traffic", "pan_system"):
        assert name in body

    transform = _stanza_body(TA / "transforms.conf", "pan_traffic")
    assert "MetaData:Sourcetype" in transform
    assert "pan:traffic" in transform


def test_the_add_on_carries_the_precedence_fix():
    """3.0.1 let every traffic subtype match [pan_traffic_start].

    On that version the coverage numbers this suite asserts are meaningless, so
    fail loudly rather than measure against a bug.
    """
    search = " ".join(_stanza_body(TA / "eventtypes.conf", "pan_traffic_start").split())
    assert '(sourcetype=pan:traffic AND (log_subtype="start"' in search, (
        "this looks like Splunk_TA_paloalto_networks 3.0.1 — upgrade to 4.0.0"
    )
