"""Shipping a source over syslog means adding the framing a collector needs.

A universal forwarder sends the file's own bytes; SC4S needs a priority to route
on, a program name to pick a sourcetype from, and a hostname to attribute the
event to. `delivery_format` picks between the two, and the framing is added on
the syslog sink only — over HEC it would be stripped straight back off, and for
ssh that header is not transport at all: Splunk_TA_nix reads `dest` out of it.
"""

import re

import pytest

from log_generators import REGISTRY
from log_senders import SenderManager
from syslog_framing import (FACILITIES, SEVERITIES, SyslogFramedGenerator,
                            SyslogFramer, host_pool_for, priority)
from ta_registry import TA_REGISTRY, get_ta

HAS_PRI = re.compile(r"^<(\d+)>")
BSD_HEADER = re.compile(r"^<\d+>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s(\S+)\s")

#: The TAs the registry says need framing added.
FRAMED = sorted(ta for ta, entry in TA_REGISTRY.items() if entry.get("syslog_framing"))


def _build(log_type):
    config = REGISTRY[log_type].SOURCETYPE_CONFIG
    if config.get("multi_instance"):
        return REGISTRY[log_type](**{config["single_param_name"]: config["defaults"][0]})
    return REGISTRY[log_type](**{config["param_key"]: config["defaults"]})


def _framer(log_type):
    return SyslogFramer(get_ta(log_type)["syslog_framing"], host_pool_for(log_type))


# ── who gets the option, and who must not ───────────────────────────────────

def test_only_sources_that_need_framing_declare_it():
    """A TA that emits its own priority must not be framed twice."""
    for log_type in FRAMED:
        generator = _build(log_type)
        lines = [generator.generate() for _ in range(100)]
        assert not any(HAS_PRI.match(line) for line in lines), (
            f"{log_type} already emits a priority but declares syslog_framing"
        )


def test_self_framing_and_non_syslog_sources_declare_none():
    for log_type in ("paloalto", "cisco_asa"):
        generator = _build(log_type)
        assert HAS_PRI.match(generator.generate()), f"{log_type} stopped self-framing"
        assert "syslog_framing" not in TA_REGISTRY[log_type]

    for log_type in ("windows", "active_directory"):
        assert TA_REGISTRY[log_type].get("syslog_viable") is False
        assert "syslog_framing" not in TA_REGISTRY[log_type]


def test_every_declared_facility_and_severity_is_real():
    for log_type in FRAMED:
        framing = TA_REGISTRY[log_type]["syslog_framing"]
        assert framing["facility"] in FACILITIES, log_type
        assert framing["severity"] in SEVERITIES, log_type
        assert priority(framing["facility"], framing["severity"]) is not None


def test_priority_is_facility_times_eight_plus_severity():
    assert priority("authpriv", "info") == 10 * 8 + 6
    assert priority("local7", "notice") == 23 * 8 + 5
    assert priority("nonsense", "info") is None


# ── what the framer does, and refuses to do ─────────────────────────────────

@pytest.mark.parametrize("log_type", FRAMED)
def test_framed_lines_carry_the_declared_priority(log_type):
    framing = TA_REGISTRY[log_type]["syslog_framing"]
    facility = FACILITIES[framing["facility"]]
    fixed = priority(framing["facility"], framing["severity"])
    # A device that derives the severity from the event keeps the facility and
    # varies the rest, so the assertion is on the facility for those.
    per_event = bool(framing.get("severity_field")
                     or framing.get("severity_pattern"))
    framed = SyslogFramedGenerator(_build(log_type), _framer(log_type))

    for _ in range(50):
        match = HAS_PRI.match(framed.generate())
        assert match, "no priority was added"
        value = int(match.group(1))
        if per_event:
            assert value // 8 == facility, f"{log_type} changed facility"
            assert 0 <= value % 8 <= 7
        else:
            assert value == fixed


def test_a_line_that_already_has_a_priority_is_left_alone():
    framer = _framer("auditd")
    already = "<134>Sep 11 18:03:21 fw-01 pan: THREAT,0,1"
    assert framer.frame(already) == already


def test_an_existing_header_is_kept_and_only_the_priority_added():
    """ssh's header is content: Splunk_TA_nix reads dest out of it."""
    framer = _framer("ssh")
    line = "Sep 11 18:03:21 SRV-A sshd[123]: Accepted password for alice from 10.0.0.5 port 22 ssh2"

    framed = framer.frame(line, host="SOMETHING-ELSE")

    assert framed == f"<{framer.priority}>{line}", "the original header was rewritten"
    assert "SRV-A" in framed and "SOMETHING-ELSE" not in framed


def test_a_headerless_line_gets_a_full_header():
    framer = _framer("auditd")
    framed = framer.frame("type=USER_AUTH msg=audit(...)", host="SRV-A")

    match = BSD_HEADER.match(framed)
    assert match, framed
    assert match.group(1) == "SRV-A"
    assert "audispd:" in framed, "the program name SC4S keys on is missing"


def test_the_header_host_is_the_environment_entity(tmp_path):
    """The header must name the same machine as the body, src and account."""
    from environment_manager import EnvironmentManager

    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env._data["entities"], env._data["accounts"] = {}, {}
    env.create_entity(name="SRV-A", entity_type="server",
                      ip="172.31.7.11", nt_host="SRV-A")

    generator = _build("auditd")
    env.inject_into(generator, "auditd", ratio=100)
    framed = SyslogFramedGenerator(generator, _framer("auditd"))

    hosts = set()
    for _ in range(200):
        match = BSD_HEADER.match(framed.generate())
        assert match
        hosts.add(match.group(1))

    assert hosts == {"SRV-A"}, hosts


def test_injection_still_reaches_the_wrapped_generator(tmp_path):
    """The wrapper must not hide the generator it wraps."""
    from environment_manager import EnvironmentManager

    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env._data["entities"], env._data["accounts"] = {}, {}
    env.create_entity(name="SRV-A", entity_type="server",
                      ip="172.31.7.11", nt_host="SRV-A")

    wrapped = SyslogFramedGenerator(_build("auditd"), _framer("auditd"))
    env.inject_into(wrapped, "auditd", ratio=100)

    assert wrapped._ai_entity_roster, "injection did not reach through the wrapper"


# ── framing follows the destination: never over HEC ─────────────────────────

@pytest.mark.parametrize("destination_type, framed", [
    ("syslog", True), ("configuration", False), ("file", True),
])
def test_framing_is_applied_where_the_destination_can_hold_it(destination_type, framed):
    """HEC receives the event itself — a priority would only be stripped again.
    A file can hold either shape, so asking for syslog there is honoured."""
    instances = [_build("auditd")]
    result = SenderManager._apply_delivery_format(
        instances, "auditd", {"delivery_format": "syslog"}, destination_type)

    assert isinstance(result[0], SyslogFramedGenerator) is framed


def test_the_default_format_frames_nothing():
    instances = [_build("auditd")]
    for options in ({}, {"delivery_format": "uf"}):
        result = SenderManager._apply_delivery_format(
            instances, "auditd", options, "syslog")
        assert result is instances


def test_a_self_framing_source_is_never_wrapped():
    """Asking for syslog on Palo Alto must not double its priority."""
    instances = [_build("paloalto")]
    result = SenderManager._apply_delivery_format(
        instances, "paloalto", {"delivery_format": "syslog"}, "syslog")

    assert result is instances


# ── priority-only framing, for a device that sends no BSD header ────────────

def test_fortios_gets_a_priority_and_nothing_else():
    """FortiOS sends `<PRI>date=...` with no timestamp or hostname in between.

    Every stanza of Splunk_TA_fortinet_fortigate sets TIME_PREFIX = ^, so a
    header we invented would be read as the event's own timestamp — losing the
    year and the sub-second the payload carries.
    """
    framer = _framer("fortigate")
    line = 'date=2026-09-13 time=11:29:55 devname="fgt-01" level="notice" type="traffic"'

    framed = framer.frame(line, host="SOMETHING-ELSE")

    assert framed == f"<{framer.priority}>{line}"
    assert not BSD_HEADER.match(framed), "a BSD header was added"


def test_the_priority_severity_follows_the_event_level():
    """FortiOS spells three severities differently from RFC 3164, and the
    add-on's own lookups/ftnt_severity_info.csv is where that vocabulary
    comes from."""
    framer = _framer("fortigate")
    local7 = FACILITIES["local7"]

    def severity_of(level):
        line = f'date=2026-09-13 time=11:29:55 level="{level}" type="event"'
        return int(HAS_PRI.match(framer.frame(line)).group(1)) - local7 * 8

    assert severity_of("alert") == SEVERITIES["alert"]
    assert severity_of("information") == SEVERITIES["info"]
    assert severity_of("critical") == SEVERITIES["crit"]
    assert severity_of("warning") == SEVERITIES["warning"]
    # An unknown spelling falls back to the declared default rather than guessing.
    assert severity_of("wat") == SEVERITIES["notice"]


def test_a_line_with_no_level_falls_back_to_the_declared_severity():
    framer = _framer("fortigate")
    framed = framer.frame('date=2026-09-13 time=11:29:55 type="traffic"')
    assert int(HAS_PRI.match(framed).group(1)) == framer.priority
