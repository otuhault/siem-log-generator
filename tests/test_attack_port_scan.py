"""Internal Horizontal Port Scan, against the three firewall add-ons and the detection.

    | tstats … FROM datamodel=Network_Traffic
        WHERE All_Traffic.src_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
        BY All_Traffic.src_ip All_Traffic.dest_port All_Traffic.dest_ip
           All_Traffic.transport All_Traffic.rule span=1s _time
    | … | stats dc(dest_ip) as totalDestIPCount BY src_ip dest_port gtime transport
    | where totalDestIPCount>=250

tstats drops every row where one BY field is null, so an event that reaches
Network_Traffic without a `rule` is invisible to this detection. Each add-on
builds those five fields its own way; these tests do it the same way, from the
shipped .conf and lookup files, then run the detection's arithmetic over what
the attack sends: the scan fires it exactly once, the noise never does.
"""

import collections
import csv
import ipaddress
import re
from collections import defaultdict
from pathlib import Path

import pytest

from helpers import compile_pcre

import log_senders
from attack_generators import (ATTACK_REGISTRY, AttackGeneratorFactory,
                               HorizontalPortScanGenerator, attack_destinations)
from hec_sender import HECSender
from log_senders import SenderManager

ATTACK = "paloalto_horizontal_port_scan"
DEFINITION = ATTACK_REGISTRY[ATTACK]
THRESHOLD = DEFINITION["detection"]["threshold"]
TAS = Path(__file__).resolve().parents[1] / "TAs"
PA = TAS / "Splunk_TA_paloalto_networks" / "default"
FORTI = TAS / "Splunk_TA_fortinet_fortigate"
ASA = TAS / "Splunk_TA_cisco-asa" / "default"

pytestmark = pytest.mark.skipif(
    not (PA.exists() and FORTI.exists() and ASA.exists()),
    reason="the three firewall add-ons are not all in TAs/")

ALL_SOURCES = [{"log_type": s["log_type"], "sourcetype": s["sourcetype"]}
               for s in DEFINITION["data_sources"]]


def _stanzas(path):
    out, current = {}, None
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
            out[current] = {}
        elif current and "=" in stripped and not stripped.startswith("#"):
            key, value = stripped.split("=", 1)
            out[current][key.strip()] = value.strip()
    return out


# ── each add-on's extraction, read from disk ────────────────────────────────

class PaloAlto:
    def __init__(self):
        transforms = _stanzas(PA / "transforms.conf")
        self.fan_out = re.compile(transforms["pan_traffic"]["REGEX"])
        assert transforms["pan_traffic"]["FORMAT"] == "sourcetype::pan:traffic"
        self.fields = [f.strip().strip('"') for f in transforms["extract_traffic"]["FIELDS"].split(",")]
        props = _stanzas(PA / "props.conf")["pan:traffic"]
        assert props["REPORT-search"] == "extract_traffic"
        eventtypes = _stanzas(PA / "eventtypes.conf")
        tags = _stanzas(PA / "tags.conf")
        assert "sourcetype=pan:traffic" in eventtypes["pan_traffic"]["search"]
        assert tags["eventtype=pan_traffic"] == {"network": "enabled", "communicate": "enabled"}

    def extract(self, raw, sourcetype):
        assert sourcetype == "pan:log"
        assert self.fan_out.search(raw), "not renamed to pan:traffic at index time"
        values = raw.split(",")
        return dict(zip(self.fields, values))


class FortiGate:
    def __init__(self):
        props = _stanzas(FORTI / "default" / "props.conf")["fortigate_traffic"]
        transforms = _stanzas(FORTI / "default" / "transforms.conf")
        assert transforms[props["REPORT-field_extract"]]["DELIMS"] == '"\\ ,", "="'
        self.aliases = {}
        for key, value in props.items():
            if key.startswith("FIELDALIAS-"):
                source, target = re.split(r"\s+as\s+", value.strip(), flags=re.I)
                self.aliases.setdefault(source.strip(), []).append(target.strip())
        lookup = props["LOOKUP-fortigate_traffic_ftnt_protocol_lookup"]
        assert re.fullmatch(r"ftnt_protocol_lookup\s+proto\s+OUTPUT\s+.*\btransport\b.*", lookup), lookup
        filename = transforms["ftnt_protocol_lookup"]["filename"]
        with (FORTI / "lookups" / filename).open() as handle:
            self.transport = {row["proto"].strip(): row["transport"].strip()
                              for row in csv.DictReader(handle)}
        eventtypes = _stanzas(FORTI / "default" / "eventtypes.conf")
        tags = _stanzas(FORTI / "default" / "tags.conf")
        assert "sourcetype=fortigate_traffic" in eventtypes["ftnt_fortigate_traffic"]["search"]
        assert tags["eventtype=ftnt_fortigate_traffic"] == {"network": "enabled", "communicate": "enabled"}

    _PAIR = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

    def extract(self, raw, sourcetype):
        assert sourcetype == "fortigate_traffic"
        fields = {m.group(1): m.group(2) if m.group(2) is not None else m.group(3)
                  for m in self._PAIR.finditer(raw)}
        # FIELDALIAS before LOOKUP, and a lookup OUTPUT overwrites.
        for source, targets in self.aliases.items():
            for target in targets:
                if source in fields:
                    fields[target] = fields[source]
        if fields.get("proto") in self.transport:
            fields["transport"] = self.transport[fields["proto"]]
        return fields


class CiscoASA:
    def __init__(self):
        props = _stanzas(ASA / "props.conf")["cisco:asa"]
        transforms = _stanzas(ASA / "transforms.conf")
        names = [n.strip() for n in props["REPORT-cisco_asa_field_extractions"].split(",")]
        self.regexes = []
        for name in names:
            try:
                self.regexes.append(compile_pcre(transforms[name]["REGEX"]))
            except (KeyError, re.error):
                continue
        # The EVALs this detection depends on, exactly as the add-on ships them.
        assert props["EVAL-rule"] == "coalesce(rule, rule_id)"
        assert props["EVAL-transport"] == "lower(transport)"
        assert props["EVAL-dest_port"].endswith("coalesce(dest_port, service))")
        for field in ("EVAL-src_ip", "EVAL-dest_ip"):
            overridden = re.search(r'message_id IN \(([^)]*)\)', props[field]).group(1)
            assert "106023" not in overridden and "106100" not in overridden, field
        eventtypes = _stanzas(ASA / "eventtypes.conf")
        self.connection_ids = set(re.findall(r'"(\d+)"', eventtypes["cisco_connection"]["search"]))
        tags = _stanzas(ASA / "tags.conf")
        assert tags["eventtype=cisco_connection"] == {"network": "enabled", "communicate": "enabled"}

    def extract(self, raw, sourcetype):
        assert sourcetype == "cisco:asa"
        fields = {}
        for regex in self.regexes:
            match = regex.search(raw)
            if match:
                for key, value in match.groupdict().items():
                    if value is not None:
                        fields.setdefault(key, value)
        assert fields.get("message_id") in self.connection_ids, "not a cisco_connection event"
        fields["rule"] = fields.get("rule") or fields.get("rule_id")
        if fields.get("transport"):
            fields["transport"] = fields["transport"].lower()
        return fields


@pytest.fixture(scope="module")
def add_ons():
    return {"pan:log": PaloAlto(), "fortigate_traffic": FortiGate(), "cisco:asa": CiscoASA()}


BY = DEFINITION["detection"]["by"]
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _rows(plan, add_ons):
    """The All_Traffic rows tstats would return, one per event that has every BY field."""
    rows = []
    for event in plan:
        _host, body = HECSender._parse_syslog(event.render())
        fields = add_ons[event.sourcetype].extract(body, event.sourcetype)
        row = {name: fields.get(name) for name in BY}
        row["kind"], row["sourcetype"] = event.kind, event.sourcetype
        rows.append(row)
    return rows


def _detections(rows):
    """{(src_ip, dest_port, transport): distinct dest_ip} for groups at the threshold."""
    groups = defaultdict(set)
    for row in rows:
        if any(not row[name] for name in BY):
            continue                                   # tstats drops the row
        if not any(ipaddress.ip_address(row["src_ip"]) in n for n in PRIVATE):
            continue                                   # the WHERE clause
        groups[(row["src_ip"], row["dest_port"], row["transport"])].add(row["dest_ip"])
    return {key: len(dests) for key, dests in groups.items() if len(dests) >= THRESHOLD}


def _plan(**options):
    return SenderManager.attack_plan(ATTACK, {"attack_sources": ALL_SOURCES, **options}, "configuration")


# ── every source carries the five BY fields ─────────────────────────────────

def test_every_event_on_every_add_on_has_all_five_by_fields(add_ons):
    rows = _rows(_plan(attack_events_count=60, attack_noise=True, attack_noise_count=200), add_ons)
    assert {r["sourcetype"] for r in rows} == set(add_ons)
    for row in rows:
        missing = [name for name in BY if not row[name]]
        assert not missing, (row["sourcetype"], row["kind"], missing)


# ── the detection ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("source", ALL_SOURCES, ids=lambda s: s["log_type"])
def test_the_scan_fires_the_detection_once_on_each_firewall_alone(add_ons, source):
    options = {"attack_sources": [source], "attack_events_count": THRESHOLD}
    plan = SenderManager.attack_plan(ATTACK, options, "configuration")
    fired = _detections(_rows(plan, add_ons))
    assert len(fired) == 1 and list(fired.values()) == [THRESHOLD], fired


def test_one_fewer_destination_does_not_fire(add_ons):
    assert _detections(_rows(_plan(attack_events_count=THRESHOLD - 1), add_ons)) == {}


def test_noise_never_fires_and_never_adds_to_the_scan(add_ons):
    noise_only = [e for e in _plan(attack_events_count=1, attack_noise=True, attack_noise_count=3000)
                  if e.kind == "noise"]
    assert _detections(_rows(noise_only, add_ons)) == {}

    plan = _plan(attack_events_count=300, attack_noise=True, attack_noise_count=1000)
    fired = _detections(_rows(plan, add_ons))
    # Three firewalls saw the same probes: one group, 300 hosts, not 900 and not more.
    assert list(fired.values()) == [300], fired


def test_the_scan_is_one_source_one_port_and_distinct_destinations():
    plan = _plan(attack_events_count=500)
    attack = [e.identity for e in plan if e.kind == "attack"]
    assert len(attack) == 500, "the count asked for is the count sent, not once per sourcetype"
    assert len({(i["src_ip"], i["dest_port"], i["transport"]) for i in attack}) == 1
    assert len({i["dest_ip"] for i in attack}) == 500
    assert attack[0]["src_ip"] not in {i["dest_ip"] for i in attack}


def test_the_events_are_shared_evenly_between_the_selected_sourcetypes():
    """Each probe is recorded by one firewall, and the split is even."""
    plan = _plan(attack_events_count=300, attack_noise=True, attack_noise_count=300)
    for kind, total in (("attack", 300), ("noise", 300)):
        counts = collections.Counter(e.sourcetype for e in plan if e.kind == kind)
        assert sum(counts.values()) == total, kind
        assert set(counts) == {"pan:log", "fortigate_traffic", "cisco:asa"}, kind
        assert max(counts.values()) - min(counts.values()) <= 1, (kind, counts)

    # Unticking one sourcetype does not change how many events are sent.
    two = _plan(attack_events_count=300, attack_sources=ALL_SOURCES[:2])
    assert len([e for e in two if e.kind == "attack"]) == 300
    assert len({e.sourcetype for e in two}) == 2


# ── the form's choices ───────────────────────────────────────────────────────

def test_a_typed_source_and_port_are_used():
    plan = _plan(attack_events_count=10, target_dest_port=161,
                 attack_identity={"src_ip": {"mode": "custom", "value": "192.168.40.7"}})
    identities = [e.identity for e in plan]
    assert {i["src_ip"] for i in identities} == {"192.168.40.7"}
    assert {(i["dest_port"], i["transport"]) for i in identities} == {(161, "udp")}
    assert all(i["dest_ip"].startswith("192.168.") for i in identities), "swept outside the source's network"


def test_an_invalid_typed_source_falls_back_to_a_private_address():
    plan = _plan(attack_events_count=5, attack_identity={"src_ip": {"mode": "custom", "value": "10.0.0.300"}})
    source = plan[0].identity["src_ip"]
    assert source != "10.0.0.300" and ipaddress.ip_address(source).is_private


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager
    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    for n in range(3):
        env.create_entity(f"ws{n}", "endpoint", ip=f"10.50.1.{10 + n}")
    for n in range(40):
        env.create_entity(f"srv{n}", "server", ip=f"10.60.2.{10 + n}")
    monkeypatch.setattr(log_senders, "_env_manager", env)
    return env


def test_the_environment_source_is_an_endpoint_and_destinations_start_from_the_environment(environment):
    plan = _plan(attack_events_count=100, attack_identity={
        "src_ip": {"mode": "environment"}, "dest_ip": {"environment": True}})
    identities = [e.identity for e in plan if e.kind == "attack"]
    sources = {i["src_ip"] for i in identities}
    assert len(sources) == 1 and sources <= {f"10.50.1.{10 + n}" for n in range(3)}

    destinations = {i["dest_ip"] for i in identities}
    known = {f"10.60.2.{10 + n}" for n in range(40)} | {f"10.50.1.{10 + n}" for n in range(3)}
    assert len(destinations) == 100
    # Every environment host but the scanner, then random ones to reach 100.
    assert len(destinations & known) == len(known) - 1


def test_without_the_environment_nothing_from_it_is_used(environment):
    identities = [e.identity for e in _plan(attack_events_count=100)]
    used = {i["src_ip"] for i in identities} | {i["dest_ip"] for i in identities}
    assert not any(ip.startswith(("10.50.1.", "10.60.2.")) for ip in used)


# ── HEC or a file, never syslog, while several sourcetypes are declared ─────

def test_an_attack_over_several_sourcetypes_is_sent_over_hec_or_to_a_file():
    assert attack_destinations(DEFINITION) == ["file", "configuration"]
    # Windows is not collected over syslog (ta_registry: syslog_viable False), so
    # even a single-source Windows attack is offered a file and HEC only.
    assert attack_destinations(ATTACK_REGISTRY["windows_tor_client_execution"]) == ["file", "configuration"]
    assert attack_destinations(ATTACK_REGISTRY["ssh_bruteforce"]) == ["file", "configuration", "syslog"]
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    assert api["destinations"] == ["file", "configuration"]
    assert all(not any(s["delivery"]["offered"].values()) for s in api["data_sources"]), \
        "one shape for every source: no delivery format to choose"
    assert api["count_label"]
    assert [(f["field"], f["mode"]) for f in api["identity_fields"]] == [("src_ip", "single"), ("dest_ip", "distinct")]


def test_the_manager_refuses_syslog(tmp_path):
    manager = SenderManager(config_file=str(tmp_path / "senders.json"))
    with pytest.raises(ValueError, match="HEC or to a file only"):
        manager.create_sender("scan", ATTACK, 0, destination_type="syslog", syslog_host="127.0.0.1")
    sender_id = manager.create_sender("scan", ATTACK, 0, destination=str(tmp_path / "x.log"),
                                      destination_type="file")
    with pytest.raises(ValueError, match="HEC or to a file only"):
        manager.update_sender(sender_id, {"destination_type": "syslog"})
    assert manager.get_sender(sender_id)["destination_type"] == "file"


def test_a_file_receives_the_events_exactly_as_hec_sends_them(tmp_path, monkeypatch, add_ons):
    """Same bodies as the HEC `event` field: the <PRI> gone, nothing else changed —
    whatever delivery format a saved option asks for."""
    import threading
    sent, planned = [], []
    render, plan = log_senders.AttackEvent.render, SenderManager.attack_plan

    def recording_render(event):
        line = render(event)
        sent.append((line, event.sourcetype))
        return line

    def recording_plan(attack_type, options, destination_type="configuration"):
        planned.append(destination_type)
        return plan(attack_type, options, destination_type)

    monkeypatch.setattr(log_senders.AttackEvent, "render", recording_render)
    monkeypatch.setattr(SenderManager, "attack_plan", staticmethod(recording_plan))
    manager = SenderManager(config_file=str(tmp_path / "senders.json"))
    destination = tmp_path / "scan.log"
    options = {"attack_sources": [dict(s, delivery_format="syslog") for s in ALL_SOURCES],
               "attack_events_count": 20, "attack_duration": 0}
    sender_id = manager.create_sender("scan", ATTACK, 0, options=options,
                                      destination=str(destination), destination_type="file")
    manager._execute_attack(sender_id, manager.get_sender(sender_id), threading.Event())

    lines = destination.read_text().splitlines()
    assert manager.get_sender(sender_id)["attack_status"].startswith("Done")
    assert planned == ["configuration"], "several sources must be planned in the HEC shape"
    assert len(lines) == 20
    assert lines == [HECSender._parse_syslog(line)[1] for line, _ in sent]
    assert not any(line.startswith("<") for line in lines), "a priority reached the file"
    for line, sourcetype in sent:
        body = HECSender._parse_syslog(line)[1]
        assert all(add_ons[sourcetype].extract(body, sourcetype).get(name) for name in BY)



def test_a_standalone_render_is_still_a_valid_probe(add_ons):
    """A preview outside a plan — no identity — must not crash or lose a BY field."""
    for log_type, sourcetype in (("paloalto", "pan:log"), ("fortigate", "fortigate_traffic"),
                                 ("cisco_asa", "cisco:asa")):
        generator = AttackGeneratorFactory.get_generator(ATTACK, {"source_log_type": log_type})
        _host, body = HECSender._parse_syslog(generator.generate())
        fields = add_ons[sourcetype].extract(body, sourcetype)
        assert all(fields.get(name) for name in BY), (log_type, fields)


def test_noise_sources_stay_below_the_threshold_by_construction():
    attacks, noise = HorizontalPortScanGenerator.plan_identities(DEFINITION, {}, 10, 10000, {})
    per_group = defaultdict(set)
    for identity in noise:
        per_group[(identity["src_ip"], identity["dest_port"], identity["transport"])].add(identity["dest_ip"])
    assert max(len(d) for d in per_group.values()) < THRESHOLD
    assert attacks[0]["src_ip"] not in {i["src_ip"] for i in noise}
