"""Cisco ASA against Splunk_TA_cisco-asa, read from disk.

The add-on extracts per message id — around 182 transforms covering 230 ids —
and every eventtype adds a second condition on top: a message_id set. So what an
event reaches is decided by the id it carries, not by its sourcetype alone. The
id drives the generator's repertoire, not the other way round.
"""

import collections
import re
from pathlib import Path

import pytest

from log_generators import REGISTRY
from ta_registry import get_sourcetype_info

TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_cisco-asa" / "default"

pytestmark = pytest.mark.skipif(
    not TA.exists(), reason="Splunk_TA_cisco-asa not present in TAs/"
)


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
    return {name: _stanzas(TA / f"{name}.conf")
            for name in ("props", "eventtypes", "tags")}


@pytest.fixture(scope="module")
def by_message_id(conf):
    """message_id -> [eventtype], for the eventtypes keyed on cisco:asa."""
    out = collections.defaultdict(list)
    for name, stanza in conf["eventtypes"].items():
        search = stanza.get("search", "")
        if 'sourcetype="cisco:asa"' not in search:
            continue
        for message_id in re.findall(r'"(\d{6})"', search):
            out[message_id].append(name)
    return out


def _emitted(log_type, n=3000):
    config = REGISTRY[log_type].SOURCETYPE_CONFIG
    generator = REGISTRY[log_type](**{config["param_key"]: config["defaults"]})
    counter = collections.Counter()
    for _ in range(n):
        match = re.search(r"%(?:ASA|FTD)-\d-(\d{6})", generator.generate())
        if match:
            counter[match.group(1)] += 1
    return counter


def _extracted_ids(conf):
    """Every message id the add-on has a field extraction for."""
    report = conf["props"]["cisco:asa"]["REPORT-cisco_asa_field_extractions"]
    return set(re.findall(r"(\d{6})", report))


# ── the add-on parses what we emit ──────────────────────────────────────────

def test_most_events_carry_an_id_the_add_on_extracts(conf):
    log_type = "cisco_asa"
    """An id outside the extraction list produces no field at all."""
    known = _extracted_ids(conf)
    emitted = _emitted(log_type)

    covered = sum(n for i, n in emitted.items() if i in known)
    share = covered / sum(emitted.values())
    assert share >= 0.85, (
        f"{log_type}: only {share:.1%} of events carry an extracted id; "
        f"unknown: {sorted(i for i in emitted if i not in known)}"
    )




# ── which datamodels ASA actually reaches ───────────────────────────────────

def _tags_of(conf, eventtype):
    stanza = conf["tags"].get(f"eventtype={eventtype}", {})
    return {k for k, v in stanza.items() if v == "enabled"}


def test_declared_eventtypes_exist_and_grant_the_declared_tags(conf):
    info = get_sourcetype_info("cisco_asa", "cisco:asa")
    granted = set()
    for eventtype in info["eventtypes"]:
        assert eventtype in conf["eventtypes"], f"{eventtype} is gone"
        granted |= _tags_of(conf, eventtype)

    assert set(info["tags"]) == granted, (
        f"registry says {sorted(info['tags'])}, add-on grants {sorted(granted)}"
    )


def test_every_declared_eventtype_is_actually_reached(conf, by_message_id):
    """Declaring one the generator never triggers is a claim, not a mapping."""
    emitted = _emitted("cisco_asa")
    reached = {e for i in emitted for e in by_message_id.get(i, [])}

    for eventtype in get_sourcetype_info("cisco_asa", "cisco:asa")["eventtypes"]:
        assert eventtype in reached, f"{eventtype} is declared but never produced"


def test_the_intrusion_path_fires(conf, by_message_id):
    """It was declared and unreachable: no emitted id was in its set."""
    emitted = _emitted("cisco_asa")
    intrusion = sum(n for i, n in emitted.items()
                    if "cisco_intrusion" in by_message_id.get(i, []))
    share = intrusion / sum(emitted.values())

    assert 0.02 <= share <= 0.25, f"intrusion share is {share:.1%}"
    assert _tags_of(conf, "cisco_intrusion") == {"attack", "ids"}


def test_a_useful_share_of_events_reaches_a_datamodel(by_message_id):
    emitted = _emitted("cisco_asa")
    reached = sum(n for i, n in emitted.items() if by_message_id.get(i))
    share = reached / sum(emitted.values())
    assert share >= 0.70, f"only {share:.1%} of events reach an eventtype"






def test_asa_still_frames_its_own_syslog():
    """It emits a priority, so the delivery format must not offer to add one."""
    from ta_registry import TA_REGISTRY

    for log_type in ("cisco_asa",):
        assert "syslog_framing" not in TA_REGISTRY[log_type]
        config = REGISTRY[log_type].SOURCETYPE_CONFIG
        generator = REGISTRY[log_type](**{config["param_key"]: config["defaults"]})
        assert re.match(r"^<\d+>", generator.generate())


def test_the_event_reaching_splunk_starts_where_the_add_on_looks(conf):
    """[cisco:asa] takes its timestamp from position 0 (TIME_PREFIX = ^).

    HECSender used to remove the whole syslog header, so events arrived as
    `: %ASA-6-302013: …` — no timestamp for the add-on to find, and a stray
    colon no collector produces.
    """
    from hec_sender import HECSender

    assert conf["props"]["cisco:asa"]["TIME_PREFIX"] == "^"
    assert conf["props"]["cisco:asa"]["TIME_FORMAT"] == "%b %d %H:%M:%S"

    config = REGISTRY["cisco_asa"].SOURCETYPE_CONFIG
    generator = REGISTRY["cisco_asa"](**{config["param_key"]: config["defaults"]})

    for _ in range(300):
        host, body = HECSender._parse_syslog(generator.generate())
        assert not body.startswith("<"), "the priority survived"
        assert not body.startswith(":"), f"the header was stripped: {body[:60]}"
        assert re.match(r"^\w{3} +\d{1,2} \d{2}:\d{2}:\d{2} ", body), body[:60]
        assert host and host in body, "the device name left the message"
