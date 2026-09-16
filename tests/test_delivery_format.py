"""Delivery format on every destination: which shapes are offered, what leaves.

A source's events have two legitimate shapes. `uf` is the raw event — what a
forwarder reads from disk, and what Splunk indexes once a collector has taken the
framing off. `syslog` is framed — priority and header, as a device puts it on the
wire. A file can hold either one, so on a Local File destination every source
collected over syslog offers both; HEC only ever receives the event itself; a
syslog destination offers the choice only where there is one to make.

The default is the shape a source already has, so no existing sender's output
changes because this choice now exists.
"""

import re

import pytest

from log_generators import REGISTRY
from log_senders import SenderManager
from syslog_framing import (PriorityStrippedGenerator, SyslogFramedGenerator,
                            delivery_description, offered_delivery_formats)
from ta_registry import TA_REGISTRY, get_ta

HAS_PRI = re.compile(r"^<\d+>")

FRAMING_ADDED = {"apache", "auditd", "cisco_ios", "fortigate", "ssh", "zscaler"}
SELF_FRAMED = {"cisco_asa", "paloalto"}
NOT_SYSLOG = {"active_directory", "windows"}


def _build(log_type):
    config = REGISTRY[log_type].SOURCETYPE_CONFIG
    if config.get("multi_instance"):
        return REGISTRY[log_type](**{config["single_param_name"]: config["defaults"][0]})
    return REGISTRY[log_type](**{config["param_key"]: config["defaults"]})


def _lines(log_type, destination_type, requested=None, n=15):
    options = {} if requested is None else {"delivery_format": requested}
    wrapped = SenderManager._apply_delivery_format([_build(log_type)], log_type,
                                                   options, destination_type)[0]
    return wrapped, [wrapped.generate() for _ in range(n)]


def test_the_three_groups_cover_every_source():
    assert FRAMING_ADDED | SELF_FRAMED | NOT_SYSLOG == set(REGISTRY)


# ── what is offered ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("log_type", sorted(FRAMING_ADDED | SELF_FRAMED))
def test_a_file_offers_both_shapes_for_any_syslog_source(log_type):
    assert offered_delivery_formats(get_ta(log_type), "file") == ["uf", "syslog"]


@pytest.mark.parametrize("log_type", sorted(REGISTRY))
def test_hec_never_offers_a_choice(log_type):
    assert offered_delivery_formats(get_ta(log_type), "configuration") == []


def test_a_syslog_destination_offers_it_only_where_there_is_a_choice():
    offered = {lt for lt in REGISTRY if offered_delivery_formats(get_ta(lt), "syslog")}
    # cisco_ios has no forwarder path, the self-framed two always frame, and
    # Windows is not collected over syslog.
    assert offered == FRAMING_ADDED - {"cisco_ios"}


@pytest.mark.parametrize("log_type", sorted(NOT_SYSLOG))
def test_windows_sources_offer_no_delivery_format_anywhere(log_type):
    description = delivery_description(get_ta(log_type))
    assert all(v == [] for v in description["offered"].values())


# ── what leaves on a Local File ─────────────────────────────────────────────

@pytest.mark.parametrize("log_type", sorted(FRAMING_ADDED | SELF_FRAMED))
def test_the_default_on_a_file_is_the_shape_the_source_already_had(log_type):
    """An existing file sender, with no delivery_format saved, is unchanged."""
    wrapped, lines = _lines(log_type, "file")
    expected_pri = log_type in SELF_FRAMED
    assert all(bool(HAS_PRI.match(line)) is expected_pri for line in lines), lines[0]


@pytest.mark.parametrize("log_type", sorted(FRAMING_ADDED | SELF_FRAMED))
def test_syslog_on_a_file_writes_what_the_wire_carries(log_type):
    _, file_lines = _lines(log_type, "file", "syslog")
    assert all(HAS_PRI.match(line) for line in file_lines), file_lines[0]


@pytest.mark.parametrize("log_type", sorted(FRAMING_ADDED | SELF_FRAMED))
def test_uf_on_a_file_writes_the_raw_event(log_type):
    wrapped, lines = _lines(log_type, "file", "uf")
    assert not any(HAS_PRI.match(line) for line in lines), lines[0]
    if log_type in SELF_FRAMED:
        assert isinstance(wrapped, PriorityStrippedGenerator)


def test_a_self_framed_file_in_uf_keeps_everything_but_the_priority():
    """What a syslog server writes to disk: the header and message, the
    priority consumed on arrival."""
    import random
    random.seed(7)
    framed = _build("cisco_asa").generate()
    random.seed(7)
    stripped = PriorityStrippedGenerator(_build("cisco_asa")).generate()
    assert HAS_PRI.match(framed) and stripped == HAS_PRI.sub("", framed, count=1)


@pytest.mark.parametrize("log_type", sorted(NOT_SYSLOG))
def test_windows_sources_are_never_wrapped(log_type):
    generator = _build(log_type)
    for destination in ("file", "syslog", "configuration"):
        for requested in (None, "uf", "syslog"):
            options = {} if requested is None else {"delivery_format": requested}
            result = SenderManager._apply_delivery_format([generator], log_type, options, destination)
            assert result[0] is generator


# ── the syslog destination keeps its rules ──────────────────────────────────

def test_the_syslog_destination_behaves_as_before():
    _, ios = _lines("cisco_ios", "syslog")
    assert all(HAS_PRI.match(line) for line in ios), "a router is always framed"
    _, ssh = _lines("ssh", "syslog")
    assert not any(HAS_PRI.match(line) for line in ssh), "ssh frames only when asked"
    wrapped, asa = _lines("cisco_asa", "syslog", "uf")
    assert all(HAS_PRI.match(line) for line in asa), "a self-framed source is never stripped for a collector"


# ── attacks ─────────────────────────────────────────────────────────────────

def test_an_attack_source_frames_attack_and_noise_alike(monkeypatch):
    """The wrapper must frame generate_noise() too, or half the file would be
    in one shape and half in the other."""
    from attack_generators import ATTACK_REGISTRY
    attack = "windows_tor_client_execution"
    monkeypatch.setitem(ATTACK_REGISTRY[attack], "data_sources", [
        {"log_type": "ssh", "sourcetype": "linux_secure", "formats": ["xml"]}])

    plan = SenderManager.attack_plan(attack, {
        "attack_sources": [{"log_type": "ssh", "sourcetype": "linux_secure",
                            "delivery_format": "syslog"}],
        "attack_noise": True, "attack_noise_count": 5}, "file")

    lines = [event.render() for event in plan]
    assert len(lines) == 10 and all(HAS_PRI.match(line) for line in lines)


def test_an_attack_on_hec_is_never_framed(monkeypatch):
    from attack_generators import ATTACK_REGISTRY
    attack = "windows_tor_client_execution"
    monkeypatch.setitem(ATTACK_REGISTRY[attack], "data_sources", [
        {"log_type": "ssh", "sourcetype": "linux_secure", "formats": ["xml"]}])
    plan = SenderManager.attack_plan(attack, {
        "attack_sources": [{"log_type": "ssh", "sourcetype": "linux_secure",
                            "delivery_format": "syslog"}]}, "configuration")
    assert not any(HAS_PRI.match(event.render()) for event in plan)


def test_the_api_describes_delivery_formats_per_destination():
    from attack_generators import AttackGeneratorFactory
    tor = AttackGeneratorFactory.get_available_attack_types()["windows_tor_client_execution"]
    assert tor["data_sources"][0]["delivery"]["offered"]["file"] == [], (
        "Windows is not collected over syslog, so its attack offers no delivery format")
