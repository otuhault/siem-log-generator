"""Windows Modify Registry to Add or Modify Firewall Rule, against its detection.

    | tstats … FROM datamodel=Endpoint.Registry
      WHERE Registry.registry_path = "*\\System\\CurrentControlSet\\Services
            \\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\\*"
            Registry.action = modified
      BY  action dest process_guid process_id registry_hive registry_path
          registry_key_name registry_value_data registry_value_name
          registry_value_type status user vendor_product

There is no `fillnull` in this one, and a tstats BY drops every row where one
field is null — the trap the port scans hit. So the thirteen BY fields matter as
much as the two WHERE clauses, and these tests check all fifteen conditions.

Twelve of the thirteen hold by construction. The thirteenth, `registry_value_type`,
the add-on leaves empty: it builds the field as `"REG_" + RegistryValueType`, and
RegistryValueType is extracted only from a Details shaped `TYPE (value)` — a DWORD
or a QWORD. A firewall rule is a REG_SZ whose Details is the rule itself,
`v2.26|Action=Allow|…`, so nothing is extracted. Splunk's own True Positive
dataset for this detection (attack_data T1112/firewall_modify_delete) has the
same shape.

That does not stop the search, and this is the part that had to be measured
rather than reasoned about: Splunk_SA_CIM gives the field a default, so it
reaches the datamodel as "unknown" and the BY keeps the row. Counted on a real
install — 217 rows REG_DWORD, 892 unknown. The events stay modelled on that
dataset rather than carrying a `DWORD (0x…)`, which would fill the field with a
firewall rule no Windows ever wrote.
"""

import re
from pathlib import Path

import pytest

import log_senders
from attack_generators import (ATTACK_REGISTRY, AttackGeneratorFactory,
                               FIREWALL_RULES_KEY, attack_destinations)
from log_senders import SenderManager
from test_sysmon_cim import cim_fields, raw_fields

ATTACK = "sysmon_firewall_rule_registry"
DEFINITION = ATTACK_REGISTRY[ATTACK]
SYSMON_TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_microsoft_sysmon" / "default"

needs_ta = pytest.mark.skipif(
    not SYSMON_TA.exists(), reason="Splunk_TA_microsoft_sysmon not present in TAs/")

#: Every field the search groups by. All of them must be non-null or the row is
#: dropped before it is ever counted.
BY_FIELDS = ["action", "dest", "process_guid", "process_id", "registry_hive",
             "registry_path", "registry_key_name", "registry_value_data",
             "registry_value_name", "registry_value_type", "status", "user",
             "vendor_product"]

#: transforms.conf [sysmon-registryvaluetype], then EVAL-registry_value_type.
VALUE_TYPE = re.compile(r"<Data Name='Details'>(\w+)\s\(.+?\)</Data>")


def all_cim_fields(line):
    fields = cim_fields(line)
    found = VALUE_TYPE.search(line)
    fields["registry_value_type"] = "REG_" + found.group(1) if found else None
    return {k: v for k, v in fields.items() if v is not None}


def matches(fields):
    """The two WHERE clauses."""
    return (FIREWALL_RULES_KEY + "\\" in (fields.get("registry_path") or "")
            and fields.get("action") == "modified")


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


# ── the premise: the add-on still builds these the way the tests replay them ─

@needs_ta
def test_the_value_type_still_comes_only_from_a_typed_details():
    """The whole caveat rests on this pair. If either moves, re-measure."""
    transforms = (SYSMON_TA / "transforms.conf").read_text(errors="replace")
    assert r"<Data Name='Details'>(\w+)\s\(.+\)</Data>" in transforms, \
        "the RegistryValueType transform changed"

    props = (SYSMON_TA / "props.conf").read_text(errors="replace")
    eval_line = re.search(r"(?m)^EVAL-registry_value_type\s*=\s*(.+)$", props).group(1)
    assert "RegistryValueType" in eval_line and '"REG_"' in eval_line, eval_line


# ── the two WHERE clauses ───────────────────────────────────────────────────

@needs_ta
def test_every_attack_event_satisfies_both_clauses():
    for _kind, line in _rendered(_plan(attack_events_count=150)):
        fields = all_cim_fields(line)
        assert matches(fields), fields


@needs_ta
def test_no_noise_event_does():
    noise = [e for e in _plan(attack_events_count=1, attack_noise=True, attack_noise_count=200)
             if e.kind == "noise"]
    missed_path = missed_action = ordinary = 0
    for _kind, line in _rendered(noise):
        fields = all_cim_fields(line)
        assert not matches(fields), fields
        path = fields.get("registry_path") or ""
        if FIREWALL_RULES_KEY in path:
            missed_action += 1        # the same key, deleted rather than written
        elif "CurrentControlSet" in path or "CurrentVersion" in path:
            missed_path += 1          # modified, somewhere that is not a rule
        else:
            ordinary += 1
    assert missed_action and missed_path and ordinary, \
        (missed_action, missed_path, ordinary)


# ── the thirteen the search groups by ───────────────────────────────────────

@needs_ta
def test_only_registry_value_type_is_left_to_the_datamodel_to_fill():
    """Twelve come from the event; the thirteenth arrives as CIM's "unknown"."""
    expected_gap = {"registry_value_type"}
    for _kind, line in _rendered(_plan(attack_events_count=150)):
        fields = all_cim_fields(line)
        missing = {name for name in BY_FIELDS if not fields.get(name)}
        assert missing == expected_gap, (missing, line[:200])


@needs_ta
def test_the_empty_one_is_empty_for_the_reason_documented():
    """A firewall rule is a string, so no type is extracted. Pinned so that a
    generator change cannot quietly start writing a typed Details instead."""
    for _kind, line in _rendered(_plan(attack_events_count=60)):
        details = re.search(r"<Data Name='Details'>([^<]*)</Data>", line).group(1)
        assert details.startswith("v2."), details
        assert not VALUE_TYPE.search(line), \
            "a typed Details would make the search fire on a rule Windows never wrote"


def test_the_attack_needs_no_warning():
    """It did carry one, saying the search might not fire. Measured on a real
    install it does: CIM defaults the empty field to "unknown" and the BY keeps
    the row. A warning means the reader must do something; there is nothing."""
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    assert api["warning"] is None


# ── it is Splunk's own dataset, not an invention ────────────────────────────

@needs_ta
def test_the_events_have_the_shape_of_the_published_attack_data():
    """attack_data T1112/firewall_modify_delete: EventID 13, SetValue, svchost
    or netsh, the rule value pipe-delimited under a GUID-named value."""
    for _kind, line in _rendered(_plan(attack_events_count=80)):
        raw = raw_fields(line)
        assert raw["EventCode"] == "13"
        assert raw["EventType"] == "SetValue"
        assert raw["TargetObject"].startswith(FIREWALL_RULES_KEY + "\\")
        assert re.fullmatch(r"\{[0-9A-F-]+\}", raw["TargetObject"].rsplit("\\", 1)[-1])
        assert re.match(r"v2\.\d+\|Action=(Allow|Block)\|Active=TRUE\|Dir=(In|Out)\|",
                        raw["Details"]), raw["Details"]


# ── the form ────────────────────────────────────────────────────────────────

def test_the_endpoint_and_the_user_hold_for_the_whole_run():
    once = _plan(attack_events_count=8)
    assert len({e.identity["dest"] for e in once}) == 1
    assert len({e.identity["user"] for e in once}) == 1

    typed = _plan(attack_events_count=5, attack_identity={
        "dest": {"mode": "custom", "value": "WKS-LAB-07"},
        "user": {"mode": "custom", "value": "svc_legacy"}})
    assert {e.identity["dest"] for e in typed} == {"WKS-LAB-07"}


@needs_ta
def test_the_typed_values_reach_the_event():
    plan = _plan(attack_events_count=4, attack_identity={
        "dest": {"mode": "custom", "value": "WKS-LAB-07"},
        "user": {"mode": "custom", "value": "svc_legacy"}})
    for _kind, line in _rendered(plan):
        assert "<Computer>WKS-LAB-07</Computer>" in line
        assert "svc_legacy" in raw_fields(line)["User"]


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager
    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env.create_entity("laptop", "endpoint", nt_host="WKS-ENV-01")
    env.create_account("env.user", account_type="standard")
    monkeypatch.setattr(log_senders, "_env_manager", env)
    return env


def test_the_ai_values_are_used(environment):
    plan = _plan(attack_events_count=4, attack_identity={
        "dest": {"mode": "ai"}, "user": {"mode": "ai"}})
    assert {e.identity["dest"] for e in plan} == {"WKS-ENV-01"}
    assert {e.identity["user"] for e in plan} == {"env.user"}


def test_the_api_declares_one_sysmon_source_and_no_syslog():
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    assert api["datamodel"] == "Endpoint"
    assert api["defaults"] == {"events": 1, "noise_events": 20, "duration": 30}
    assert [s["sourcetype"] for s in DEFINITION["data_sources"]] == \
        ["XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"]
    assert attack_destinations(DEFINITION) == ["file", "configuration"]


@needs_ta
def test_a_standalone_render_still_satisfies_the_clauses():
    generator = AttackGeneratorFactory.get_generator(ATTACK, {})
    for _ in range(30):
        assert matches(all_cim_fields(generator.generate()))
