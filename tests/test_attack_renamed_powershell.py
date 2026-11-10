"""Windows Renamed Powershell Execution, against its detection.

    | tstats … from datamodel=Endpoint.Processes where
        (Processes.original_file_name = PowerShell.EXE
         Processes.process_name      != powershell.exe)
      OR (pwsh.dll / pwsh.exe) OR (powershell_ise.EXE / powershell_ise.exe)
      by  action dest original_file_name parent_process parent_process_exec
          parent_process_guid parent_process_id parent_process_name
          parent_process_path process process_exec process_guid process_hash
          process_id process_integrity_level process_name process_path user
          user_id vendor_product

The same shape as the SysWOW64 attack: two CIM fields built from different raw
fields, and the finding is that they disagree. `original_file_name` is the
OriginalFileName in the binary's PE header, which renaming the file leaves
untouched; `process_name` is the basename of Image. Copy powershell.exe to
RelTekAudio.exe and they stop matching.

Two conditions the add-on imposes, both checked below. `EVAL-original_file_name`
covers EventCode 1 and 7 only and refuses the value "-", so the field has to
carry a real name. And twenty fields are grouped by with no fillnull, so each
has to be present — nineteen from Sysmon, and user_id from Splunk_TA_windows'
generic [XmlWinEventLog] stanza, which these events reach through the rename.

Modelled on attack_data T1036.003/renamed_powershell, whose three events are a
renamed C:\\ProgramData\\RelTekAudio.exe beside a genuine powershell.exe
carrying the same header — which is the near miss the noise needs.
"""

import re
from pathlib import Path

import pytest

import log_senders
from attack_generators import (ATTACK_REGISTRY, POWERSHELL_IDENTITIES,
                               AttackGeneratorFactory, attack_destinations)
from log_senders import SenderManager
from test_sysmon_cim import PROCESS_BY_FIELDS, process_cim_fields, raw_fields

ATTACK = "sysmon_renamed_powershell"
DEFINITION = ATTACK_REGISTRY[ATTACK]
SYSMON_TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_microsoft_sysmon" / "default"

needs_ta = pytest.mark.skipif(
    not SYSMON_TA.exists(), reason="Splunk_TA_microsoft_sysmon not present in TAs/")

#: The three pairs the search tests, as it spells them.
PAIRS = [(original, real) for original, real, _description in POWERSHELL_IDENTITIES]


def matches(fields):
    """The where clause. tstats compares these case-insensitively."""
    original = (fields.get("original_file_name") or "").lower()
    name = (fields.get("process_name") or "").lower()
    return any(original == want.lower() and name != real.lower() for want, real in PAIRS)


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


# ── the premise: the add-on still builds the two fields this way ────────────

@needs_ta
def test_original_file_name_comes_from_the_header_and_refuses_the_placeholder():
    props = (SYSMON_TA / "props.conf").read_text(errors="replace")
    line = re.search(r"(?m)^EVAL-original_file_name\s*=\s*(.+)$", props).group(1)
    assert "OriginalFileName" in line
    assert '!= "-"' in line, "the add-on no longer refuses the placeholder"
    assert '"1"' in line, "EventCode 1 is no longer covered"


@needs_ta
def test_process_name_is_the_basename_of_image():
    props = (SYSMON_TA / "props.conf").read_text(errors="replace")
    line = re.search(r"(?m)^EVAL-process_name\s*=\s*(.+)$", props).group(1)
    assert "Image" in line and "replace(" in line


# ── the clause ──────────────────────────────────────────────────────────────

@needs_ta
def test_every_attack_event_satisfies_the_clause():
    for _kind, line in _rendered(_plan(attack_events_count=150)):
        assert matches(process_cim_fields(line)), raw_fields(line).get("Image")


@needs_ta
def test_the_two_fields_disagree_on_purpose():
    """The header says PowerShell, the file on disk says something else."""
    for _kind, line in _rendered(_plan(attack_events_count=100)):
        fields = process_cim_fields(line)
        assert fields["original_file_name"].lower().startswith(("powershell", "pwsh"))
        assert not fields["process_name"].lower().startswith(("powershell", "pwsh"))


@needs_ta
def test_no_noise_event_satisfies_it():
    noise = [e for e in _plan(attack_events_count=1, attack_noise=True, attack_noise_count=200)
             if e.kind == "noise"]
    renamed_back, unrelated = 0, 0
    for _kind, line in _rendered(noise):
        fields = process_cim_fields(line)
        assert not matches(fields), fields
        if fields["original_file_name"].lower().startswith(("powershell", "pwsh")):
            renamed_back += 1     # the real binary, under its own name
        else:
            unrelated += 1        # an ordinary process whose header matches
    assert renamed_back and unrelated, (renamed_back, unrelated)


@needs_ta
def test_all_three_binaries_the_search_names_are_exercised():
    seen = {process_cim_fields(line)["original_file_name"]
            for _kind, line in _rendered(_plan(attack_events_count=200))}
    assert seen == {original for original, _real in PAIRS}, seen


# ── the twenty fields it groups by ──────────────────────────────────────────

@needs_ta
def test_every_grouped_field_is_present():
    """No fillnull in this search, so a null would drop the row."""
    assert set(DEFINITION["detection"]["by"]) == set(PROCESS_BY_FIELDS), \
        "the detection's BY list and the fields checked here have drifted apart"
    for _kind, line in _rendered(_plan(attack_events_count=120)):
        fields = process_cim_fields(line)
        missing = [name for name in PROCESS_BY_FIELDS if not fields.get(name)]
        assert not missing, (missing, line[:200])


@needs_ta
def test_the_original_file_name_is_never_the_placeholder():
    for _kind, line in _rendered(_plan(attack_events_count=60, attack_noise=True,
                                       attack_noise_count=60)):
        assert raw_fields(line)["OriginalFileName"] not in ("-", "")


# ── it is Splunk's own dataset, not an invention ────────────────────────────

@needs_ta
def test_the_pair_from_the_published_attack_data_is_reproduced():
    """RelTekAudio.exe under ProgramData carrying OriginalFileName PowerShell.EXE."""
    from attack_generators import RENAMED_POWERSHELL

    assert "C:\\ProgramData\\RelTekAudio.exe" in RENAMED_POWERSHELL
    images = {raw_fields(line)["Image"]
              for _kind, line in _rendered(_plan(attack_events_count=200))}
    assert "C:\\ProgramData\\RelTekAudio.exe" in images


# ── the form ────────────────────────────────────────────────────────────────

def test_the_endpoint_and_the_user_hold_for_the_whole_run():
    once = _plan(attack_events_count=8)
    assert len({e.identity["dest"] for e in once}) == 1
    assert len({e.identity["user"] for e in once}) == 1


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
    assert api["warning"] is None
    assert [s["sourcetype"] for s in DEFINITION["data_sources"]] == \
        ["XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"]
    assert attack_destinations(DEFINITION) == ["file", "configuration"]


@needs_ta
def test_a_standalone_render_still_satisfies_the_clause():
    generator = AttackGeneratorFactory.get_generator(ATTACK, {})
    for _ in range(30):
        assert matches(process_cim_fields(generator.generate()))
