"""SSH events must satisfy Splunk_TA_nix, read from disk rather than restated.

The add-on runs two parallel paths for sshd. Only `linux_secure` reaches the
modern one — [sshd_session_start] / [sshd_session_end] and the sshd-session-*
extractions. Everything else falls back to [ssh_open] / [failed_login], which
key on fragile `punct=` values and explicitly exclude linux_secure.

Parsing the shipped .conf keeps these tests honest: if the add-on is upgraded and
a condition changes, they fail instead of quietly asserting last year's contract.
"""

import re
from pathlib import Path

import pytest

from helpers import compile_pcre

from log_generators import REGISTRY
from ta_registry import get_sourcetype_info, get_ta

TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_nix" / "default"

pytestmark = pytest.mark.skipif(
    not TA.exists(), reason="Splunk_TA_nix not present in TAs/"
)


def _stanzas(path):
    """{stanza name: {key: value}} for a .conf file."""
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
            for name in ("eventtypes", "tags", "props", "transforms", "inputs")}


@pytest.fixture(scope="module")
def lines():
    config = REGISTRY["ssh"].SOURCETYPE_CONFIG
    generator = REGISTRY["ssh"](**{config["param_key"]: config["defaults"]})
    return [generator.generate() for _ in range(3000)]


def _tags_of(conf, eventtype):
    stanza = conf["tags"].get(f"eventtype={eventtype}", {})
    return {k for k, v in stanza.items() if v == "enabled"}


# ── the registry describes what the add-on actually does ────────────────────

def test_the_sourcetype_is_the_one_the_add_on_treats_as_modern(conf):
    """linux_secure is not a preference: the modern eventtypes require it."""
    info = get_sourcetype_info("ssh", "linux_secure")
    assert info, "the registry no longer declares linux_secure"

    for eventtype in ("sshd_session_start", "sshd_session_end"):
        search = conf["eventtypes"][eventtype]["search"]
        assert "sourcetype=linux_secure" in search, (
            f"[{eventtype}] no longer requires linux_secure"
        )
    # And the legacy path still refuses it, so there is no third option.
    assert "NOT sourcetype=linux_secure" in conf["eventtypes"]["ssh_open"]["search"]


def test_declared_eventtypes_exist_in_the_add_on(conf):
    for eventtype in get_sourcetype_info("ssh", "linux_secure")["eventtypes"]:
        assert eventtype in conf["eventtypes"], f"{eventtype} is not in eventtypes.conf"


def test_declared_tags_are_the_ones_the_add_on_grants(conf):
    """Tags are granted by the add-on; the registry only mirrors them."""
    info = get_sourcetype_info("ssh", "linux_secure")
    granted = set()
    for eventtype in info["eventtypes"]:
        granted |= _tags_of(conf, eventtype)

    assert granted, "no tag found for any declared eventtype"
    assert set(info["tags"]) == granted, (
        f"registry says {sorted(info['tags'])}, add-on grants {sorted(granted)}"
    )


def test_declared_datamodels_follow_from_those_tags(conf):
    """Authentication comes from `authentication`, Network_Sessions from `network`+`session`."""
    info = get_sourcetype_info("ssh", "linux_secure")
    granted = set()
    for eventtype in info["eventtypes"]:
        granted |= _tags_of(conf, eventtype)

    expected = set()
    if "authentication" in granted:
        expected.add("Authentication")
    if {"network", "session"} <= granted:
        expected.add("Network_Sessions")

    assert set(info["datamodels"]) == expected, (
        f"registry says {sorted(info['datamodels'])}, tags imply {sorted(expected)}"
    )


def test_the_source_is_the_monitored_path(conf):
    """A file monitor, so source is the path — and the add-on does not read it.

    [monitor:///var/log] whitelists `secure` and sets no source of its own, so
    splunkd fills in the file path. That makes the value faithful metadata, not a
    behavioural switch: unlike auditd, no eventtype here keys on source.
    """
    monitor = conf["inputs"].get("monitor:///var/log", {})
    assert "secure" in monitor.get("whitelist", ""), (
        "the add-on no longer collects /var/log/secure by monitor"
    )
    assert "source" not in monitor, "the monitor now sets its own source"

    assert get_sourcetype_info("ssh", "linux_secure")["hec_source"] == "/var/log/secure"
    assert "hec_default_sourcetype" not in get_ta("ssh")


def test_no_eventtype_depends_on_that_source(conf):
    """Guard the claim above: if one starts keying on source, the value matters."""
    for name, stanza in conf["eventtypes"].items():
        if "sshd" in name or name in ("ssh_open", "failed_login"):
            assert "source=" not in stanza.get("search", ""), name


# ── generated events satisfy the add-on's real conditions ───────────────────

def _matches_sshd_authentication(line):
    """[sshd_authentication], transcribed from eventtypes.conf."""
    if "sshd[" not in line and "sshd-session[" not in line:
        return False
    if "possible break-in attempt" in line.lower():
        return False
    low = line.lower()
    verdict = (any(w in low for w in ("accepted", "failed", "failure",
                                      "invalid user", "authentication error"))
               and "from" in low)
    return verdict or any(w in low for w in ("authorized to", "authentication tried",
                                             "login restricted"))


START = ("Failed password for", "Connection closed by invalid user", "Unable to negotiate",
         "session opened for user", "banner exchange", "Could not get shadow information",
         "Accepted password")
END = ("Read error from remote host", "Connection timed out", "Disconnected from user",
       "Connection closed by", "session closed for user")


def _matches_session_start(line):
    return (("sshd[" in line or "sshd-session[" in line)
            and any(s.lower() in line.lower() for s in START))


def _matches_session_end(line):
    return (("sshd[" in line or "sshd-session[" in line)
            and any(s.lower() in line.lower() for s in END)
            and "connection closed by invalid user" not in line.lower())


def test_the_transcribed_conditions_still_match_the_add_on(conf):
    """Guard the transcription above against an add-on upgrade."""
    for signature in START:
        assert signature in conf["eventtypes"]["sshd_session_start"]["search"], signature
    for signature in END:
        assert signature in conf["eventtypes"]["sshd_session_end"]["search"], signature


@pytest.mark.parametrize("name, predicate, floor", [
    ("sshd_authentication", _matches_sshd_authentication, 0.30),
    ("sshd_session_start", _matches_session_start, 0.25),
    ("sshd_session_end", _matches_session_end, 0.08),
])
def test_a_useful_share_of_events_reaches_each_eventtype(lines, name, predicate, floor):
    """Not every sshd line is an auth event — daemon noise is realistic — but a
    generator whose output no datamodel accepts is useless for detection work."""
    share = sum(1 for line in lines if predicate(line)) / len(lines)
    assert share >= floor, f"{name}: only {share:.1%} of events match, floor is {floor:.0%}"


def test_most_events_reach_at_least_one_eventtype(lines):
    covered = sum(1 for line in lines
                  if _matches_sshd_authentication(line)
                  or _matches_session_start(line)
                  or _matches_session_end(line))
    share = covered / len(lines)
    assert share >= 0.65, f"only {share:.1%} of events are CIM-visible"


# ── field extraction ────────────────────────────────────────────────────────

def _auth_transform_regexes(conf):
    """The REGEX of every transform linux_secure lists for authentication."""
    declared = conf["props"]["linux_secure"]["REPORT-0authentication_for_linux_secure"]
    out = {}
    for name in (n.strip() for n in declared.split(",")):
        pattern = conf["transforms"].get(name, {}).get("REGEX")
        if not pattern:
            continue
        try:
            out[name] = compile_pcre(pattern)
        except re.error:
            pass
    return out


def test_the_add_on_declares_the_extractions_we_target(conf):
    regexes = _auth_transform_regexes(conf)
    for name in ("sshd-session-login-failed", "sshd-session-login-accepted",
                 "sshd-session-invalid-user", "sshd-session-disconnect",
                 "sshd-session-read-error-timeout",
                 "sshd-session-banner-exchange-failed",
                 "sshd-session-key-negotiation-failed"):
        assert name in regexes, f"{name} is no longer declared for linux_secure"


def test_each_targeted_extraction_actually_fires(conf, lines):
    """A message shape nothing extracts contributes no CIM field."""
    regexes = _auth_transform_regexes(conf)
    targeted = ("sshd-session-login-failed", "sshd-session-login-accepted",
                "sshd-session-invalid-user", "sshd-session-disconnect",
                "sshd-session-read-error-timeout",
                "sshd-session-banner-exchange-failed",
                "sshd-session-key-negotiation-failed")

    silent = [name for name in targeted
              if not any(regexes[name].search(line) for line in lines)]
    assert not silent, f"no generated event matches: {silent}"


def test_most_events_feed_at_least_one_extraction(conf, lines):
    regexes = _auth_transform_regexes(conf)
    matched = sum(1 for line in lines
                  if any(rx.search(line) for rx in regexes.values()))
    share = matched / len(lines)
    assert share >= 0.70, f"only {share:.1%} of events feed an extraction"


# ── host metadata ───────────────────────────────────────────────────────────

def test_the_host_we_stamp_is_the_dest_the_add_on_extracts(conf, lines):
    """Splunk's `host` and the add-on's `dest` must not be able to disagree.

    [loghost_as_dest] reads dest back out of the syslog header, so the hostname
    is part of the event, not transport. HECSender reads the same header for the
    host metadata, deliberately with the same pattern.
    """
    from hec_sender import HECSender

    dest_pattern = re.compile(conf["transforms"]["loghost_as_dest"]["REGEX"])

    checked = 0
    for line in lines:
        match = dest_pattern.match(line)
        if not match:
            continue
        checked += 1
        host, body = HECSender._parse_syslog(line)
        assert host == match.group(1), f"host {host!r} != dest {match.group(1)!r}"
        assert body == line, "the hostname was stripped — dest would be lost"

    assert checked == len(lines), (
        f"only {checked}/{len(lines)} lines carry a header the add-on can read"
    )


def test_only_the_priority_is_treated_as_transport():
    """A <PRI> goes; everything after it is the message and stays.

    The header is not framing an add-on can spare: [cisco:asa] reads its time
    from position 0, and Splunk_TA_nix reads `dest` from the hostname.
    """
    from hec_sender import HECSender

    host, body = HECSender._parse_syslog(
        "<134>Sep 11 18:03:21 fw-01 pan: THREAT,0,1")

    assert host == "fw-01"
    assert not body.startswith("<134>"), "the priority survived into the event"
    assert body == "Sep 11 18:03:21 fw-01 pan: THREAT,0,1"


def test_the_host_follows_the_environment(tmp_path):
    """With A&I on, the stamped host is one of its entities — the whole point."""
    from environment_manager import EnvironmentManager
    from hec_sender import HECSender

    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env._data["entities"], env._data["accounts"] = {}, {}
    env.create_entity(name="SRV-A", entity_type="server",
                      ip="172.31.7.11", nt_host="SRV-A")
    env.create_entity(name="SRV-B", entity_type="server",
                      ip="172.31.7.12", nt_host="SRV-B")

    config = REGISTRY["ssh"].SOURCETYPE_CONFIG
    generator = REGISTRY["ssh"](**{config["param_key"]: config["defaults"]})
    env.inject_into(generator, "ssh", ratio=100)

    hosts = {HECSender._parse_syslog(generator.generate())[0] for _ in range(300)}

    assert hosts == {"SRV-A", "SRV-B"}, hosts
