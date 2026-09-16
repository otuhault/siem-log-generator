"""Windows Unusual SysWOW64 Process Run System32 Executable, against its detection.

    | tstats … from datamodel=Endpoint.Processes where
        Processes.process_path = "*\\Windows\\SysWOW64\\*"
        AND Processes.process  = "*windows\\system32\\*"

A datamodel search this time, so what matters is the two CIM fields the add-on
builds from one 4688 — and they come from different places, which is the whole
point of the detection: a 32-bit caller asking for `C:\\Windows\\System32\\cmd.exe`
is redirected by WOW64, so `NewProcessName` says SysWOW64 while `CommandLine`
still says System32.

These tests rebuild both fields the way Splunk_TA_windows does, in each
rendering, and evaluate the clause as written. The EVAL definitions are read off
the shipped props.conf so an add-on upgrade that changes them fails here.
"""

import re
from collections import Counter
from pathlib import Path

import pytest

from helpers import compile_pcre

import log_senders
from attack_generators import (ATTACK_REGISTRY, AttackGeneratorFactory,
                               WindowsSysWow64Generator, attack_destinations)
from log_senders import SenderManager

ATTACK = "windows_syswow64_runs_system32"
DEFINITION = ATTACK_REGISTRY[ATTACK]
TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_windows" / "default"

needs_ta = pytest.mark.skipif(not TA.exists(), reason="Splunk_TA_windows not present in TAs/")


# ── the add-on's chain, rebuilt ─────────────────────────────────────────────

def _stanza(name):
    text = (TA / "props.conf").read_text(errors="replace")
    return re.search(r"(?ms)^\[" + re.escape(name) + r"\]\s*$(.*?)(?=^\[|\Z)", text).group(1)


def _transform(name):
    text = (TA / "transforms.conf").read_text(errors="replace")
    body = re.search(r"(?ms)^\[" + re.escape(name) + r"\]\s*$(.*?)(?=^\[|\Z)", text).group(1)
    return compile_pcre(re.search(r"(?m)^REGEX\s*=\s*(.+)$", body).group(1))


#: [process_command_line_process_and_arguments]: the command line's first token.
FIRST_TOKEN = re.compile(r'(^"[^"]+"|[^\s]+)\s*(.*)')


def cim_fields(event, render_format):
    """`process_path` and `process`, as the add-on's EVALs produce them.

    `EVAL-process` takes the command line only when its first token holds a
    backslash; otherwise it rebuilds one from the image path, and the System32
    the detection looks for would never appear.
    """
    if render_format == "xml":
        image = _transform("new_process_for_windows_security_from_xml").search(event)
        command = _transform("process_command_line_for_xml").search(event)
        image = image.group("new_process") if image else None
        command = command.group("Process_Command_Line") if command else None
    else:
        labels = {k.strip().replace(" ", "_"): v.strip()
                  for k, v in re.findall(r"\n\s*([^:\n]+):\s+([^\n]*)", event)}
        image, command = labels.get("New_Process_Name"), labels.get("Process_Command_Line")

    process = None
    if command:
        first = FIRST_TOKEN.match(command).group(1)
        process = command if "\\" in first else None
    return {"process_path": image, "process": process or image}


def matches(fields):
    """The where clause, with tstats' case-insensitive globbing."""
    def like(value, glob):
        pattern = ".*".join(re.escape(part) for part in glob.split("*"))
        return bool(re.fullmatch(pattern, value or "", re.I | re.S))

    return (like(fields["process_path"], r"*\Windows\SysWOW64\*")
            and like(fields["process"], r"*windows\system32\*"))


def _plan(**options):
    return SenderManager.attack_plan(ATTACK, options, "configuration")


def _rendered(plan, render_format="xml"):
    generator = AttackGeneratorFactory.get_generator(ATTACK, {"render_format": render_format})
    out = []
    for event in plan:
        generator.use_identity(event.identity)
        out.append((event.kind,
                    generator.generate() if event.kind == "attack" else generator.generate_noise()))
    return out


# ── the premise: the add-on still builds these two the way we replay them ───

@needs_ta
def test_the_add_on_still_builds_process_and_process_path_from_a_4688():
    """Read off the shipped props.conf, so an upgrade that moves them fails here."""
    for stanza, image_field in (("source::XmlWinEventLog:Security", "new_process"),
                                ("source::WinEventLog:Security", "New_Process_Name")):
        body = _stanza(stanza)
        path_eval = re.search(r"(?m)^EVAL-process_path\s*=\s*(.+)$", body).group(1)
        assert re.match(rf"case\(\s*EventCode==4688\s*,\s*{image_field}\b", path_eval), \
            (stanza, path_eval)

        process_eval = re.search(r"(?m)^EVAL-process\s*=\s*(.+)$", body).group(1)
        assert "Process_Command_Line" in process_eval, stanza
        assert 'match(process_command_line_process,"(\\\\\\)")' in process_eval, \
            f"{stanza}: the command line is no longer gated on a backslash"


# ── the attack ──────────────────────────────────────────────────────────────

@needs_ta
@pytest.mark.parametrize("render_format", ["xml", "classic"])
def test_every_attack_event_satisfies_the_clause(render_format):
    for _kind, line in _rendered(_plan(attack_events_count=200), render_format):
        fields = cim_fields(line, render_format)
        assert matches(fields), fields


@needs_ta
def test_the_two_fields_disagree_on_purpose():
    """That disagreement is the finding: the image was redirected, the command
    line still names what was asked for."""
    for _kind, line in _rendered(_plan(attack_events_count=100), "xml"):
        fields = cim_fields(line, "xml")
        assert "SysWOW64" in fields["process_path"]
        assert "System32" in fields["process"]
        assert fields["process"] != fields["process_path"]


@needs_ta
def test_every_command_line_starts_with_a_path_or_the_field_would_not_carry_it():
    """`EVAL-process` falls back to the image path when the first token has no
    backslash, which would drop the System32 the clause looks for."""
    for _kind, line in _rendered(_plan(attack_events_count=100), "xml"):
        command = _transform("process_command_line_for_xml").search(line) \
            .group("Process_Command_Line")
        assert "\\" in FIRST_TOKEN.match(command).group(1), command


@needs_ta
@pytest.mark.parametrize("render_format", ["xml", "classic"])
def test_no_noise_event_satisfies_the_clause(render_format):
    noise = [e for e in _plan(attack_events_count=1, attack_noise=True, attack_noise_count=400)
             if e.kind == "noise"]
    seen = Counter()
    for _kind, line in _rendered(noise, render_format):
        fields = cim_fields(line, render_format)
        assert not matches(fields), fields
        path, process = fields["process_path"], fields["process"]
        if "SysWOW64" in path:
            seen["a 32-bit image naming no System32 path"] += 1
        elif "System32" in path:
            seen["the 64-bit image doing the same work"] += 1
        else:
            seen["ordinary process creation"] += 1
    # Each clause is missed on its own, and neither together.
    assert len(seen) == 3, seen


# ── the fields the form offers ──────────────────────────────────────────────

def test_the_endpoint_and_the_user_are_random_typed_or_from_the_environment():
    typed = _plan(attack_events_count=5, attack_identity={
        "dest": {"mode": "custom", "value": "WKS-LAB-07"},
        "user": {"mode": "custom", "value": "svc_legacy"}})
    assert {e.identity["dest"] for e in typed} == {"WKS-LAB-07"}
    assert {e.identity["user"] for e in typed} == {"svc_legacy"}

    once = _plan(attack_events_count=8)
    assert len({e.identity["dest"] for e in once}) == 1, "one machine for the run"
    assert len({e.identity["user"] for e in once}) == 1, "one account for the run"


@needs_ta
def test_the_typed_values_reach_the_event():
    plan = _plan(attack_events_count=4, attack_identity={
        "dest": {"mode": "custom", "value": "WKS-LAB-07"},
        "user": {"mode": "custom", "value": "svc_legacy"}})
    for _kind, line in _rendered(plan, "xml"):
        assert "<Computer>WKS-LAB-07</Computer>" in line
        assert "<Data Name='SubjectUserName'>svc_legacy</Data>" in line


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager
    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env.create_entity("laptop", "endpoint", nt_host="WKS-ENV-01")
    env.create_account("env.user", account_type="standard")
    monkeypatch.setattr(log_senders, "_env_manager", env)
    return env


def test_the_ai_values_the_form_resolved_are_used(environment):
    plan = _plan(attack_events_count=4, attack_identity={
        "dest": {"mode": "ai", "value": "WKS-ENV-01"},
        "user": {"mode": "ai", "value": "env.user"}})
    assert {e.identity["dest"] for e in plan} == {"WKS-ENV-01"}
    assert {e.identity["user"] for e in plan} == {"env.user"}


def test_ai_without_a_value_falls_back_to_the_environment(environment):
    plan = _plan(attack_events_count=4, attack_identity={
        "dest": {"mode": "ai"}, "user": {"mode": "ai"}})
    assert {e.identity["dest"] for e in plan} == {"WKS-ENV-01"}
    assert {e.identity["user"] for e in plan} == {"env.user"}


# ── the entry ───────────────────────────────────────────────────────────────

def test_the_api_describes_one_windows_source_in_both_renderings():
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    assert api["datamodel"] == "Endpoint"
    assert api["defaults"] == {"events": 1, "noise_events": 20, "duration": 30}
    assert [f["field"] for f in api["identity_fields"]] == ["dest", "user"]
    assert api["identity_fields"][1]["picker"] == "identities"
    assert [f["sourcetype"] for f in api["data_sources"][0]["formats"]] == \
        ["XmlWinEventLog", "WinEventLog"], "XML first, so it is the default"
    # Windows is not collected over syslog.
    assert attack_destinations(DEFINITION) == ["file", "configuration"]
    assert api["warning"] is None


def test_sysmon_is_not_claimed_without_an_add_on_to_check_it_against():
    """The detection also lists Sysmon EventID 1. Nothing in TAs/ maps a Sysmon
    event to Endpoint.Processes, so declaring the source would be a claim this
    repository cannot verify."""
    sysmon_add_ons = list((TA.parents[1]).glob("*ysmon*")) if TA.parents[1].exists() else []
    assert not sysmon_add_ons, "a Sysmon add-on is present now — the source can be declared"
    assert [s["sourcetype"] for s in DEFINITION["data_sources"]] == ["WinEventLog:Security"]


def test_one_event_is_enough():
    plan = _plan(attack_noise=True)
    assert len([e for e in plan if e.kind == "attack"]) == 1
    assert len([e for e in plan if e.kind == "noise"]) == 20


@needs_ta
@pytest.mark.parametrize("render_format", ["xml", "classic"])
def test_a_standalone_render_still_satisfies_the_clause(render_format):
    generator = AttackGeneratorFactory.get_generator(ATTACK, {"render_format": render_format})
    for _ in range(30):
        assert matches(cim_fields(generator.generate(), render_format))
