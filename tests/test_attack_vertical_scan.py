"""Internal Vertical Port Scan, against the three firewall add-ons and the detection.

    | tstats … FROM datamodel=Network_Traffic WHERE All_Traffic.src_ip IN (private…)
        BY … src_ip dest_port dest_ip transport rule
    | … | stats
        dc(eval(if(dest_port<1024 AND transport="tcp",dest_port,null))) as privilegedDestTcpPortCount
        dc(eval(if(transport="tcp",dest_port,null)))                    as totalDestTcpPortCount
        (… the same for udp …)
        BY src_ip dest_ip transport gtime
    | eval totalDestPortCount      = totalDestUdpPortCount + totalDestTcpPortCount,
           privilegedDestPortCount = privilegedDestTcpPortCount + privilegedDestUdpPortCount
    | where (totalDestPortCount>=500 AND privilegedDestPortCount>=20)

The BY of the outer stats is one transport, so a scan split across TCP and UDP
would clear neither half; the attack is TCP. As with the horizontal scan, tstats
drops any row missing one of the five BY fields, so every probe must carry a
`rule`. The add-on extractions are reused from the horizontal suite.
"""

import ipaddress
from collections import defaultdict

import pytest

import log_senders
from attack_generators import (ATTACK_REGISTRY, AttackGeneratorFactory,
                               VerticalPortScanGenerator, _distinct_ports)
from hec_sender import HECSender
from log_senders import SenderManager
from test_attack_port_scan import PA, FORTI, ASA, PaloAlto, FortiGate, CiscoASA

ATTACK = "paloalto_vertical_port_scan"
DEFINITION = ATTACK_REGISTRY[ATTACK]
DETECTION = DEFINITION["detection"]
TOTAL = DETECTION["total_ports"]            # 500
PRIVILEGED = DETECTION["privileged_ports"]  # 20
BY = DETECTION["by"]

pytestmark = pytest.mark.skipif(
    not (PA.exists() and FORTI.exists() and ASA.exists()),
    reason="the three firewall add-ons are not all in TAs/")

ALL_SOURCES = [{"log_type": s["log_type"], "sourcetype": s["sourcetype"]}
               for s in DEFINITION["data_sources"]]
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


@pytest.fixture(scope="module")
def add_ons():
    return {"pan:log": PaloAlto(), "fortigate_traffic": FortiGate(), "cisco:asa": CiscoASA()}


def _rows(plan, add_ons):
    rows = []
    for event in plan:
        _host, body = HECSender._parse_syslog(event.render())
        fields = add_ons[event.sourcetype].extract(body, event.sourcetype)
        row = {name: fields.get(name) for name in BY}
        row["kind"], row["sourcetype"] = event.kind, event.sourcetype
        rows.append(row)
    return rows


def _detections(rows):
    """{(src,dest,transport): (total, privileged)} for groups over both thresholds.

    The detection's arithmetic: per (src_ip, dest_ip, transport) hour, distinct
    ports and distinct ports below 1024, summed across transports — but each row
    is one transport, so the sum is that transport's own counts.
    """
    groups = defaultdict(set)
    for row in rows:
        if any(not row[name] for name in BY):
            continue
        if not any(ipaddress.ip_address(row["src_ip"]) in n for n in PRIVATE):
            continue
        groups[(row["src_ip"], row["dest_ip"], row["transport"])].add(int(row["dest_port"]))
    fired = {}
    for key, ports in groups.items():
        privileged = len([p for p in ports if p < 1024])
        if len(ports) >= TOTAL and privileged >= PRIVILEGED:
            fired[key] = (len(ports), privileged)
    return fired


def _plan(**options):
    return SenderManager.attack_plan(ATTACK, {"attack_sources": ALL_SOURCES, **options}, "configuration")


# ── the plan ─────────────────────────────────────────────────────────────────

def test_distinct_ports_splits_privileged_from_the_rest():
    ports = _distinct_ports(500, 20)
    assert len(ports) == 500 and len(set(ports)) == 500
    assert len([p for p in ports if p < 1024]) == 20
    # A clamp: never more privileged than total, nor more than the 1023 that exist.
    assert len([p for p in _distinct_ports(10, 999) if p < 1024]) == 10


def test_the_ports_are_shared_evenly_between_the_selected_sourcetypes():
    """500 ports in total, each probed once, recorded by one firewall or another."""
    plan = _plan(attack_events_count=TOTAL, privileged_ports=PRIVILEGED)
    counts = defaultdict(int)
    for event in plan:
        counts[event.sourcetype] += 1
    assert sum(counts.values()) == TOTAL
    assert set(counts) == {"pan:log", "fortigate_traffic", "cisco:asa"}
    assert max(counts.values()) - min(counts.values()) <= 1, dict(counts)


def test_the_scan_is_one_source_one_dest_over_tcp_with_distinct_ports():
    plan = _plan(attack_events_count=TOTAL, privileged_ports=PRIVILEGED)
    attack = [e.identity for e in plan if e.kind == "attack"]
    assert len(attack) == TOTAL, "the count asked for is the count sent, not once per sourcetype"
    assert len({i["src_ip"] for i in attack}) == 1
    assert len({i["dest_ip"] for i in attack}) == 1
    assert {i["transport"] for i in attack} == {"tcp"}
    assert attack[0]["src_ip"] != attack[0]["dest_ip"]
    ports = {i["dest_port"] for i in attack}
    assert len(ports) == TOTAL and len([p for p in ports if p < 1024]) == PRIVILEGED


# ── the detection ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("source", ALL_SOURCES, ids=lambda s: s["log_type"])
def test_the_scan_fires_the_detection_once_on_each_firewall_alone(add_ons, source):
    options = {"attack_sources": [source], "attack_events_count": TOTAL, "privileged_ports": PRIVILEGED}
    fired = _detections(_rows(SenderManager.attack_plan(ATTACK, options, "configuration"), add_ons))
    assert len(fired) == 1 and list(fired.values()) == [(TOTAL, PRIVILEGED)], fired


def test_one_fewer_port_does_not_fire(add_ons):
    assert _detections(_rows(_plan(attack_events_count=TOTAL - 1, privileged_ports=PRIVILEGED), add_ons)) == {}


def test_too_few_privileged_ports_does_not_fire(add_ons):
    fired = _detections(_rows(_plan(attack_events_count=TOTAL, privileged_ports=PRIVILEGED - 1), add_ons))
    assert fired == {}, "500 ports but only 19 below 1024 must not fire"


def test_noise_never_fires_and_never_adds_to_the_scan(add_ons):
    noise_only = [e for e in _plan(attack_events_count=1, attack_noise=True, attack_noise_count=4000)
                  if e.kind == "noise"]
    assert _detections(_rows(noise_only, add_ons)) == {}

    plan = _plan(attack_events_count=TOTAL, privileged_ports=PRIVILEGED,
                 attack_noise=True, attack_noise_count=200)
    fired = _detections(_rows(plan, add_ons))
    assert list(fired.values()) == [(TOTAL, PRIVILEGED)], fired


def test_noise_ports_per_group_stay_far_below_the_threshold():
    _attacks, noise = VerticalPortScanGenerator.plan_identities(DEFINITION, {}, 10, 5000, {})
    per_group = defaultdict(set)
    for identity in noise:
        per_group[(identity["src_ip"], identity["dest_ip"], identity["transport"])].add(identity["dest_port"])
    assert max(len(p) for p in per_group.values()) < TOTAL


# ── the form's choices ───────────────────────────────────────────────────────

def test_a_typed_source_and_dest_are_used(add_ons):
    plan = _plan(attack_events_count=30, privileged_ports=5, attack_identity={
        "src_ip": {"mode": "custom", "value": "192.168.40.7"},
        "dest_ip": {"mode": "custom", "value": "192.168.40.9"}})
    identities = [e.identity for e in plan]
    assert {i["src_ip"] for i in identities} == {"192.168.40.7"}
    assert {i["dest_ip"] for i in identities} == {"192.168.40.9"}


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager
    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env.create_entity("wks", "endpoint", ip="10.50.1.10")
    env.create_entity("crown-jewel", "server", ip="10.60.2.10")
    monkeypatch.setattr(log_senders, "_env_manager", env)
    return env


def test_the_ai_asset_ip_is_used_as_sent_by_the_form(environment):
    """The form resolves the chosen asset to its IP and sends it as the value."""
    plan = _plan(attack_events_count=40, attack_identity={
        "src_ip": {"mode": "ai", "value": "10.50.1.10"},
        "dest_ip": {"mode": "ai", "value": "10.60.2.10"}})
    identities = [e.identity for e in plan if e.kind == "attack"]
    assert {i["src_ip"] for i in identities} == {"10.50.1.10"}
    assert {i["dest_ip"] for i in identities} == {"10.60.2.10"}


def test_ai_without_a_value_falls_back_to_the_environment(environment):
    plan = _plan(attack_events_count=40, attack_identity={
        "src_ip": {"mode": "ai"}, "dest_ip": {"mode": "ai"}})
    identities = [e.identity for e in plan if e.kind == "attack"]
    assert {i["src_ip"] for i in identities} == {"10.50.1.10"}
    assert {i["dest_ip"] for i in identities} == {"10.60.2.10"}


# ── the API and the destinations ─────────────────────────────────────────────

def test_the_api_describes_the_scan():
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    assert api["destinations"] == ["file", "configuration"]
    assert api["count_label"] == "Total Destination Ports"
    assert [f["field"] for f in api["identity_fields"]] == ["src_ip", "dest_ip"]
    assert all(f["mode"] == "asset" for f in api["identity_fields"])
    assert api["extra_counts"][0]["key"] == "privileged_ports"
    assert api["extra_counts"][0]["default"] == PRIVILEGED
    assert [s["sourcetype"] for s in api["data_sources"]] == ["pan:traffic", "fortigate_traffic", "cisco:asa"]
    assert [s["formats"][0]["sourcetype"] for s in api["data_sources"]] == ["pan:log", "fortigate_traffic", "cisco:asa"]


def test_the_manager_refuses_syslog(tmp_path):
    manager = SenderManager(config_file=str(tmp_path / "senders.json"))
    with pytest.raises(ValueError, match="HEC or to a file only"):
        manager.create_sender("vscan", ATTACK, 0, destination_type="syslog", syslog_host="127.0.0.1")
