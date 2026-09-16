"""Detect Traffic Mirroring, against the Cisco add-on and the detection.

    `cisco_networks` (facility="MIRROR" mnemonic="ETH_SPAN_SESSION_UP")
        OR (facility="SPAN" mnemonic="SESSION_UP")
        OR (facility="SPAN" mnemonic="PKTCAP_START")
        OR (mnemonic="CFGLOG_LOGGEDCMD" command="monitor session*")
    | stats … count BY host facility mnemonic

Another raw search rather than a datamodel one, so what matters is the field
names the add-on produces. `facility` and `mnemonic` come out of
`%FACILITY-SEVERITY-MNEMONIC:` for any line; `command` comes from one exact
extraction, and these tests run both over what the attack sends.
"""

import re
from collections import Counter
from pathlib import Path

import pytest

from helpers import compile_pcre

import log_senders
from attack_generators import (ATTACK_REGISTRY, AttackGeneratorFactory,
                               CiscoTrafficMirroringGenerator, attack_destinations)
from log_generators.registry import REGISTRY
from log_senders import SenderManager

ATTACK = "cisco_traffic_mirroring"
DEFINITION = ATTACK_REGISTRY[ATTACK]
DETECTION = DEFINITION["detection"]
TA = Path(__file__).resolve().parents[1] / "TAs" / "TA_cisco_catalyst" / "default"

needs_ta = pytest.mark.skipif(not TA.exists(), reason="TA_cisco_catalyst not present in TAs/")


# ── the add-on's own extractions ────────────────────────────────────────────

def _transform(name):
    text = (TA / "transforms.conf").read_text(errors="replace")
    body = re.search(r"(?ms)^\[" + re.escape(name) + r"\]\s*$(.*?)(?=^\[|\Z)", text).group(1)
    return compile_pcre(re.search(r"(?m)^REGEX\s*=\s*(.+)$", body).group(1))


def _extract(name):
    props = (TA / "props.conf").read_text(errors="replace")
    return compile_pcre(re.search(r"(?m)^EXTRACT-" + re.escape(name) + r"\s*=\s*(.+)$",
                                   props).group(1))


@pytest.fixture(scope="module")
def add_on():
    """The two extractions the detection depends on, read off the add-on."""
    return {"general": _transform("extract_cisco_ios-general"),
            "cfglog": _extract("cisco_ios-cfglog_loggedcmd")}


def fields(line, add_on):
    """facility, mnemonic and command, the way Splunk_TA_cisco_catalyst makes them."""
    out = {}
    match = add_on["general"].search(line)
    if match:
        out.update({k: v for k, v in match.groupdict().items() if v is not None})
    command = add_on["cfglog"].search(line)
    if command:
        out["command"] = command.group("command")
        out["user"] = command.group("user")
    return out


def matches(f):
    """The detection's where clause, as written."""
    facility, mnemonic = f.get("facility"), f.get("mnemonic")
    if facility == "MIRROR" and mnemonic == "ETH_SPAN_SESSION_UP":
        return True
    if facility == "SPAN" and mnemonic in ("SESSION_UP", "PKTCAP_START"):
        return True
    # command="monitor session*" — Splunk anchors the whole value, so a leading
    # space or a missing extraction is a miss.
    return mnemonic == "CFGLOG_LOGGEDCMD" and bool(
        re.fullmatch(r"monitor session.*", f.get("command") or "", re.S))


def _plan(**options):
    return SenderManager.attack_plan(ATTACK, options, "configuration")


def _rendered(plan):
    generator = AttackGeneratorFactory.get_generator(ATTACK, {})
    out = []
    for event in plan:
        generator.use_identity(event.identity)
        out.append((event.kind,
                    generator.generate() if event.kind == "attack" else generator.generate_noise()))
    return out


# ── the source already carries what the detection reads ─────────────────────

@needs_ta
def test_the_add_on_reads_facility_and_mnemonic_off_the_ordinary_source(add_on):
    """The premise: every cisco:ios line this application emits, attack or not,
    yields the two fields the detection groups by."""
    config = REGISTRY["cisco_ios"].SOURCETYPE_CONFIG
    generator = REGISTRY["cisco_ios"](**{config["param_key"]: list(config["defaults"])})
    for _ in range(400):
        f = fields(generator.generate(), add_on)
        assert f.get("facility") and f.get("mnemonic")


@needs_ta
def test_the_logged_command_of_the_ordinary_source_is_extracted_too(add_on):
    """It was not: the generator wrote one space where the add-on's
    `User:(\\S+)\\s\\slogged command:` needs two, so `user`, `vendor_action` and
    `command` were all lost on every CFGLOG event the baseline sender sent."""
    config = REGISTRY["cisco_ios"].SOURCETYPE_CONFIG
    generator = REGISTRY["cisco_ios"](**{config["param_key"]: list(config["defaults"])})
    seen = parsed = 0
    for _ in range(4000):
        line = generator.generate()
        if "CFGLOG_LOGGEDCMD" not in line:
            continue
        seen += 1
        f = fields(line, add_on)
        if f.get("command"):
            parsed += 1
            assert not f["command"].startswith(" "), line
            assert not matches(f), "the baseline must not trip the detection"
    assert seen, "no logged command was emitted at all"
    assert parsed == seen, f"the add-on parsed {parsed} of {seen} logged commands"


# ── the attack ──────────────────────────────────────────────────────────────

@needs_ta
def test_every_attack_event_satisfies_the_detection(add_on):
    kinds = Counter()
    for _kind, line in _rendered(_plan(attack_events_count=300)):
        f = fields(line, add_on)
        assert matches(f), line
        kinds[(f["facility"], f["mnemonic"])] += 1
    # All four ways mirroring announces itself are exercised.
    assert set(kinds) == {("MIRROR", "ETH_SPAN_SESSION_UP"), ("SPAN", "SESSION_UP"),
                          ("SPAN", "PKTCAP_START"), ("PARSER", "CFGLOG_LOGGEDCMD")}, kinds


@needs_ta
def test_the_monitor_session_command_is_extracted_in_the_shape_the_clause_needs(add_on):
    """Two spaces after the user, nothing after the colon.

    Either mistake still produces a parseable IOS event, which is why this is
    checked against the add-on's own regex and not by eye.
    """
    commands = [fields(line, add_on) for _kind, line in _rendered(_plan(attack_events_count=400))]
    logged = [f for f in commands if f["mnemonic"] == "CFGLOG_LOGGEDCMD"]
    assert logged, "the logged-command branch never fired"
    for f in logged:
        assert f["command"].startswith("monitor session "), repr(f["command"])
        assert f["user"], "the add-on reads the user from the same extraction"


@needs_ta
def test_no_noise_event_satisfies_the_detection(add_on):
    seen = Counter()
    noise = [e for e in _plan(attack_events_count=1, attack_noise=True, attack_noise_count=600)
             if e.kind == "noise"]
    for _kind, line in _rendered(noise):
        f = fields(line, add_on)
        assert matches(f) is False, line
        if f["mnemonic"] == "CFGLOG_LOGGEDCMD":
            seen["a command that is not a monitor session"] += 1
        elif f["facility"] in ("SPAN", "MIRROR"):
            seen["a session going down"] += 1
        elif f["facility"] == "SPANTREE":
            seen["the facility that merely starts with SPAN"] += 1
        else:
            seen["ordinary chatter"] += 1
    assert len(seen) == 4, seen


@needs_ta
def test_spantree_is_not_span(add_on):
    """The clause reads facility="SPAN"; SPANTREE is a different facility, and
    the add-on's regex must not hand one over as the other."""
    line = "009832: Sep 15 22:53:41.625: %SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 10"
    assert fields(line, add_on)["facility"] == "SPANTREE"
    assert not matches(fields(line, add_on))


# ── the one field the form offers ───────────────────────────────────────────

def test_the_device_is_random_typed_or_taken_from_the_environment():
    typed = _plan(attack_events_count=5,
                  attack_identity={"host": {"mode": "custom", "value": "SW-LAB-07"}})
    assert {e.identity["host"] for e in typed} == {"SW-LAB-07"}
    assert {e.host for e in typed} == {"SW-LAB-07"}, "and it is what HEC stamps"

    random_run = _plan(attack_events_count=8)
    assert len({e.identity["host"] for e in random_run}) == 1, "one device for the run"


def test_the_named_device_is_what_a_syslog_destination_carries():
    """cisco:ios leaves with `logging origin-id`: the name in front of the
    message is all a collector can attribute the event to, and the detection
    groups by host."""
    plan = SenderManager.attack_plan(
        ATTACK, {"attack_identity": {"host": {"mode": "custom", "value": "SW-LAB-07"}},
                 "attack_events_count": 6, "attack_noise": True, "attack_noise_count": 6},
        "syslog")
    for event in plan:
        line = event.render()
        assert re.match(r"^<\d+>SW-LAB-07: ", line), line


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager
    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env.create_entity("core switch", "router", nt_host="SW-CORE-99")
    monkeypatch.setattr(log_senders, "_env_manager", env)
    return env


def test_the_ai_device_the_form_resolved_is_used(environment):
    plan = _plan(attack_events_count=5,
                 attack_identity={"host": {"mode": "ai", "value": "SW-CORE-99"}})
    assert {e.identity["host"] for e in plan} == {"SW-CORE-99"}


def test_ai_without_a_value_falls_back_to_the_environment(environment):
    plan = _plan(attack_events_count=5, attack_identity={"host": {"mode": "ai"}})
    assert {e.identity["host"] for e in plan} == {"SW-CORE-99"}


# ── the entry ───────────────────────────────────────────────────────────────

def test_the_api_describes_one_source_one_field_and_no_datamodel():
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    assert api["datamodel"] is None, "this detection reads cisco:ios directly"
    assert api["defaults"] == {"events": 1, "noise_events": 20, "duration": 30}
    assert [f["field"] for f in api["identity_fields"]] == ["host"]
    assert api["identity_fields"][0]["picker"] == "assets"
    assert [s["sourcetype"] for s in api["data_sources"]] == ["cisco:ios"]
    assert [f["sourcetype"] for f in api["data_sources"][0]["formats"]] == ["cisco:ios"]
    # Cisco IOS is a syslog source, so nothing is closed off.
    assert attack_destinations(DEFINITION) == ["file", "configuration", "syslog"]
    assert api["warning"] is None


def test_one_event_is_enough():
    plan = _plan(attack_noise=True)
    assert len([e for e in plan if e.kind == "attack"]) == 1
    assert len([e for e in plan if e.kind == "noise"]) == 20


@needs_ta
def test_a_standalone_render_still_satisfies_the_detection(add_on):
    generator = AttackGeneratorFactory.get_generator(ATTACK, {})
    for _ in range(50):
        assert matches(fields(generator.generate(), add_on))
