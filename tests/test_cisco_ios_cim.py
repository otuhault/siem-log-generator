"""Cisco IOS against the Cisco Enterprise Networking add-on, read from disk.

This source reaches no CIM datamodel, and that is the add-on's design rather
than a gap on our side: [cisco_ios] grants `cisco network ios`, which is not a
CIM combination. Plenty of operational syslog has no dataset to belong to.

So what these tests check is the part that is ours: that the format is the one
IOS really writes, that every line parses, and that the enrichment lookups fire.
"""

import collections
import csv
import re
from pathlib import Path

import pytest

from log_generators import REGISTRY
from ta_registry import get_sourcetype_info

TA = Path(__file__).resolve().parents[1] / "TAs" / "TA_cisco_catalyst"

pytestmark = pytest.mark.skipif(
    not TA.exists(), reason="TA_cisco_catalyst not present in TAs/"
)

MESSAGE = re.compile(r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>[0-7])-(?P<mnemonic>[A-Z0-9_]+):")


def _stanzas(path):
    out, cur = {}, None
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
            out[cur] = {}
        elif cur and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            out[cur].setdefault(key.strip(), value.strip())
    return out


@pytest.fixture(scope="module")
def conf():
    return {name: _stanzas(TA / "default" / f"{name}.conf")
            for name in ("props", "eventtypes", "tags", "transforms")}


@pytest.fixture(scope="module")
def lines():
    config = REGISTRY["cisco_ios"].SOURCETYPE_CONFIG
    generator = REGISTRY["cisco_ios"](**{config["param_key"]: config["defaults"]})
    return [generator.generate() for _ in range(3000)]


def _to_python(pattern):
    return re.sub(r"\(\?<(?![=!])", "(?P<", pattern)


def _lookup(name):
    with (TA / "lookups" / name).open(errors="replace") as handle:
        return list(csv.DictReader(handle))


# ── no datamodel, said plainly ──────────────────────────────────────────────

def test_the_add_on_grants_no_cim_datamodel(conf):
    """`cisco network ios` is not a CIM combination — Network_Traffic needs
    `communicate`, which nothing here provides for this sourcetype."""
    stanza = conf["tags"].get("eventtype=cisco_ios", {})
    granted = {k for k, v in stanza.items() if v == "enabled"}

    assert granted == {"cisco", "network", "ios"}
    assert "communicate" not in granted

    info = get_sourcetype_info("cisco_ios", "cisco:ios")
    assert info["datamodels"] == [], "a datamodel is claimed that no tag grants"
    assert set(info["tags"]) == granted


def test_the_eventtype_still_matches_this_sourcetype(conf):
    assert "sourcetype=cisco:ios" in conf["eventtypes"]["cisco_ios"]["search"]


# ── the format is the one the add-on parses ─────────────────────────────────

def test_every_line_parses_with_the_general_extraction(conf, lines):
    """extract_cisco_ios-general is what yields facility, mnemonic and the rest."""
    names = [n.strip() for n in
             conf["props"]["cisco:ios"]["REPORT-0cisco_ios-general"].split(",")]
    assert "extract_cisco_ios-general" in names

    pattern = re.compile(_to_python(
        conf["transforms"]["extract_cisco_ios-general"]["REGEX"]))

    for line in lines:
        match = pattern.search(line)
        assert match, f"unparsed: {line[:90]}"
        captured = {k for k, v in match.groupdict().items() if v}
        assert {"facility", "mnemonic", "severity_id", "message_text"} <= captured


def test_the_line_carries_a_sequence_number_and_a_device_time(lines):
    """The IOS header the add-on's event_id and device_time come from."""
    assert all(re.match(r"^\d{6}: \w{3} +\d+ \d{2}:\d{2}:\d{2}\.\d{3}: %", l)
               for l in lines)


# ── the enrichment lookups fire ─────────────────────────────────────────────

def test_most_messages_are_in_the_message_lookup(lines):
    """cisco_ios_messages gives vendor_message_text, explanation and the
    recommended action; a triplet outside it is parsed but not enriched."""
    known = {(r["facility"], r["severity_id"], r["mnemonic"])
             for r in _lookup("cisco_ios_messages.csv")}

    emitted = collections.Counter()
    for line in lines:
        match = MESSAGE.search(line)
        if match:
            emitted[(match["facility"], match["severity"], match["mnemonic"])] += 1

    hit = sum(n for k, n in emitted.items() if k in known)
    share = hit / sum(emitted.values())
    assert share >= 0.60, f"only {share:.1%} of messages are in the lookup"


def test_no_message_misses_the_lookup_only_by_its_severity(lines):
    """A real mnemonic at the wrong severity loses the enrichment for nothing.

    %NTP-6-PEERUNREACH did exactly that; the lookup carries it at 4.
    """
    rows = _lookup("cisco_ios_messages.csv")
    by_mnemonic = collections.defaultdict(set)
    for row in rows:
        by_mnemonic[(row["facility"], row["mnemonic"])].add(row["severity_id"])
    known = {(r["facility"], r["severity_id"], r["mnemonic"]) for r in rows}

    near = set()
    for line in lines:
        match = MESSAGE.search(line)
        if not match:
            continue
        key = (match["facility"], match["severity"], match["mnemonic"])
        if key in known:
            continue
        if (match["facility"], match["mnemonic"]) in by_mnemonic:
            near.add((key, tuple(sorted(by_mnemonic[(key[0], key[2])]))))

    assert not near, f"wrong severity for a known mnemonic: {sorted(near)}"


def test_almost_every_facility_has_a_category(lines):
    """cisco_ios_facility_categories gives vendor_category."""
    known = {r["facility"] for r in _lookup("cisco_ios_facility_categories.csv")}
    emitted = {MESSAGE.search(l)["facility"] for l in lines if MESSAGE.search(l)}

    missing = emitted - known
    assert len(missing) <= 2, f"facilities with no category: {sorted(missing)}"


def test_every_severity_is_a_real_syslog_level(lines):
    known = {r["severity_id"] for r in _lookup("cisco_ios_severity.csv")}
    emitted = {MESSAGE.search(l)["severity"] for l in lines if MESSAGE.search(l)}
    assert emitted <= known, sorted(emitted - known)


# ── the sourcetype covers more than IOS ─────────────────────────────────────

def test_the_same_stanza_handles_xe_and_xr(conf):
    """Which is why there is no separate cisco_xr entry."""
    report = conf["props"]["cisco:ios"]["REPORT-0cisco_ios-general"]
    assert "extract_cisco_ios-general-xe" in report
    assert "extract_cisco_ios-general-xr" in report
