"""Windows AD Privileged Account SID History Addition, against its detection.

    `wineventlog_security` EventCode IN (4742, 4738) NOT SidHistory IN ("%%1793", -)
    | rex field=SidHistory "(^%{|^)(?P<SidHistory>.*?)(}$|$)"
    | eval category="privileged"
    | lookup identity_lookup_expanded category, identity as SidHistory OUTPUT identity_tag as match
    | where isnotnull(match)
    | rename TargetSid as userSid
    | table _time action status host user userSid SidHistory Logon_ID src_user dest

No datamodel here: the detection reads the Security log directly. So these tests
extract the fields the way Splunk_TA_windows does — the XML block extraction for
the XML rendering, Splunk's wel-col-kv label extraction for the classic one —
and evaluate the two conditions the search states.

The third condition cannot be evaluated here: `identity_lookup_expanded` lives in
the reader's Enterprise Security, and no generator can populate it. What the
tests do check is that the SID reaches Splunk unmangled and is the value the form
asked for, which is what makes matching it possible at all.
"""

import re
from collections import Counter
from pathlib import Path

import pytest

from helpers import compile_pcre

import log_senders
from attack_generators import (ATTACK_REGISTRY, PRIVILEGED_SID_DEFAULT, AttackGeneratorFactory,
                               SID_HISTORY_UNSET, WindowsSidHistoryGenerator, attack_destinations)
from log_senders import SenderManager

ATTACK = "windows_ad_sid_history_addition"
DEFINITION = ATTACK_REGISTRY[ATTACK]
DETECTION = DEFINITION["detection"]
TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_windows" / "default"

needs_ta = pytest.mark.skipif(not TA.exists(), reason="Splunk_TA_windows not present in TAs/")


# ── the add-on's extractions, as each rendering offers them ─────────────────

def _transforms():
    out, current = {}, None
    for line in (TA / "transforms.conf").read_text(errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
            out[current] = {}
        elif current and "=" in stripped and not stripped.startswith("#"):
            key, value = stripped.split("=", 1)
            out[current][key.strip()] = value.strip()
    return out


def xml_fields(event):
    """EventData as [eventdata_xml_block] then [eventdata_xml_data] yield it."""
    transforms = _transforms()
    block = compile_pcre(transforms["eventdata_xml_block"]["REGEX"])
    field = compile_pcre(transforms["eventdata_xml_data"]["REGEX"])
    out = {}
    for found in block.finditer(event):
        for match in field.finditer(found.group(1)):
            out[match.group(1)] = match.group(2)
    out["EventCode"] = re.search(r"<EventID>(\d+)</EventID>", event).group(1)
    # REPORT-dest_for_windows_security = …,Computer_as_dest
    out["dest"] = re.search(r"<Computer>([^<]+)</Computer>", event).group(1)
    return out


def classic_fields(event):
    """What Splunk's wel-col-kv makes of the message body, plus the header.

    The label becomes the field name with its spaces underscored — which is why
    `SID History:` cannot answer to `SidHistory`.
    """
    out = {k.strip().replace(" ", "_"): v.strip()
           for k, v in re.findall(r"\n\s*([^:\n]+):\s+([^\n]*)", event)}
    out.update(dict(re.findall(r"(?m)^(\w+)=(.*)$", event)))
    out["dest"] = out.get("ComputerName", "")
    return out


def _generator(render_format="xml", **options):
    return AttackGeneratorFactory.get_generator(ATTACK, {"render_format": render_format, **options})


def _plan(**options):
    return SenderManager.attack_plan(ATTACK, options, "configuration")


def _rendered(plan, render_format="xml"):
    """Every event of a plan, rendered in one format, with its identity."""
    generator = _generator(render_format)
    out = []
    for event in plan:
        generator.use_identity(event.identity)
        line = generator.generate() if event.kind == "attack" else generator.generate_noise()
        out.append((event.kind, line))
    return out


# ── the two conditions the search states ────────────────────────────────────

def matches(fields):
    """EventCode IN (4742, 4738) NOT SidHistory IN ("%%1793", -)."""
    return (fields.get("EventCode") in ("4738", "4742")
            and fields.get("SidHistory") not in (None, "") + tuple(SID_HISTORY_UNSET))


REX = re.compile(r"(^%\{|^)(?P<SidHistory>.*?)(\}$|$)")


def unwrapped(value):
    """The SID the detection's own rex pulls out of SidHistory."""
    return REX.match(value).group("SidHistory")


@needs_ta
def test_every_attack_event_satisfies_the_search():
    for _kind, line in _rendered(_plan(attack_events_count=200), "xml"):
        fields = xml_fields(line)
        assert matches(fields), fields
        assert unwrapped(fields["SidHistory"]).startswith("S-1-5-21-"), fields["SidHistory"]


@needs_ta
def test_no_noise_event_satisfies_the_search():
    noise = [e for e in _plan(attack_events_count=1, attack_noise=True, attack_noise_count=300)
             if e.kind == "noise"]
    seen = Counter()
    for _kind, line in _rendered(noise, "xml"):
        fields = xml_fields(line)
        assert not matches(fields), fields
        seen["excluded event code" if fields["EventCode"] not in ("4738", "4742")
             else "no SID history"] += 1
    # Both near misses are exercised: a neighbouring event code, and the two
    # values Windows writes when nothing was added.
    assert seen["excluded event code"] and seen["no SID history"], seen


@needs_ta
@pytest.mark.parametrize("wrapper", ["bare", "braced"])
def test_the_rex_unwraps_both_shapes_windows_writes(wrapper):
    sid = "S-1-5-21-1004336348-1177238915-682003330-512"
    assert unwrapped(sid if wrapper == "bare" else "%{" + sid + "}") == sid


@needs_ta
def test_both_shapes_actually_occur_in_what_the_attack_sends():
    values = [xml_fields(line)["SidHistory"]
              for _kind, line in _rendered(_plan(attack_events_count=300), "xml")]
    assert any(v.startswith("%{") for v in values) and any(not v.startswith("%{") for v in values)
    assert len({unwrapped(v) for v in values}) == 1, "one planted SID for the whole run"


# ── the classic rendering cannot answer this detection ──────────────────────

@needs_ta
def test_the_classic_rendering_carries_the_value_under_a_name_the_search_cannot_read():
    """Reported by the add-on's own extractions, not by assumption.

    Splunk's wel-col-kv names a field after the message label, so `SID History:`
    becomes `SID_History`. Nothing in Splunk_TA_windows aliases it to
    `SidHistory`, so the detection's `NOT SidHistory IN (…)` never sees it. The
    event is faithful; this detection just cannot match it.
    """
    assert "SidHistory" not in (TA / "props.conf").read_text(errors="replace")
    assert "SidHistory" not in (TA / "transforms.conf").read_text(errors="replace")

    _kind, line = _rendered(_plan(attack_events_count=1), "classic")[0]
    fields = classic_fields(line)
    assert fields["EventCode"] in ("4738", "4742")
    assert unwrapped(fields["SID_History"]).startswith("S-1-5-21-"), "the value is there…"
    assert "SidHistory" not in fields, "…but not under the name the search reads"
    assert not matches(fields)


@needs_ta
def test_the_xml_rendering_is_the_one_that_answers_it():
    _kind, line = _rendered(_plan(attack_events_count=1), "xml")[0]
    assert matches(xml_fields(line))
    assert DEFINITION["data_sources"][0]["formats"][0] == "xml", "XML must be the default"


# ── the fields the detection tables ─────────────────────────────────────────

@needs_ta
def test_the_add_on_maps_src_user_for_4738_but_not_for_4742():
    """Read off the shipped props.conf, so an add-on upgrade shows up here.

    `EVAL-src_user` lists the event codes whose SubjectUserName becomes src_user.
    4738 is in it and 4742 is not, so a computer account change reaches the
    detection's table with that column empty. That is the add-on's mapping, not
    something the generator can fix.
    """
    stanza = re.search(r"(?ms)^\[source::XmlWinEventLog:Security\](.*?)(?=^\[)",
                       (TA / "props.conf").read_text(errors="replace")).group(1)
    src_user = re.search(r"(?m)^EVAL-src_user\s*=\s*(.+)$", stanza).group(1)
    codes = set(re.findall(r"\d{4}", src_user))
    assert "4738" in codes and "4742" not in codes


@needs_ta
def test_the_tabled_fields_are_present_on_a_4738():
    """host, user, userSid, SidHistory, src_user and dest, the add-on's way."""
    plan = _plan(attack_events_count=40, attack_identity={
        "src_user": {"mode": "custom", "value": "adm_dupont"},
        "dest": {"mode": "custom", "value": "DC-CORP-01"}})
    for event in plan:
        fields = xml_fields(_rendered([event], "xml")[0][1])
        if fields["EventCode"] != "4738":
            continue
        assert fields["SubjectUserName"] == "adm_dupont"      # EVAL-src_user
        assert fields["TargetUserName"]                        # EVAL-user
        assert fields["TargetSid"].startswith("S-1-5-21-")     # rename TargetSid as userSid
        assert fields["dest"].startswith("DC-CORP-01")         # Computer_as_dest
        assert re.fullmatch(r"0x[0-9A-F]+", fields["SubjectLogonId"])
        assert event.host == "DC-CORP-01"                      # stamped over HEC


# ── the form's choices ──────────────────────────────────────────────────────

def test_random_host_follows_the_destination():
    """One domain controller logs its own change."""
    for _ in range(20):
        identity = _plan(attack_events_count=1)[0].identity
        assert identity["host"] == identity["dest"]


def test_each_field_can_be_typed():
    plan = _plan(attack_events_count=5, attack_identity={
        "host": {"mode": "custom", "value": "DC-HQ-02"},
        "dest": {"mode": "custom", "value": "DC01"},
        "src_user": {"mode": "custom", "value": "svc_adsync"}})
    for event in plan:
        assert event.identity["host"] == "DC-HQ-02"
        assert event.identity["dest"] == "DC01"
        assert event.identity["src_user"] == "svc_adsync"
        assert event.host == "DC-HQ-02"


@needs_ta
def test_the_planted_sid_is_the_same_one_every_run_unless_it_is_typed():
    """Fixed by default, so the row added to an identities lookup keeps matching.

    It is the privileged principal being impersonated — a group, typically —
    not the account doing the planting, so it is nobody's SubjectUserSid.
    """
    for _ in range(3):
        plan = _plan(attack_events_count=20)
        assert {e.identity["privileged_sid"] for e in plan} == {PRIVILEGED_SID_DEFAULT}
        for _kind, line in _rendered(plan, "xml"):
            fields = xml_fields(line)
            assert unwrapped(fields["SidHistory"]) == PRIVILEGED_SID_DEFAULT
            assert fields["SubjectUserSid"] != PRIVILEGED_SID_DEFAULT


@needs_ta
def test_a_typed_sid_is_planted_and_a_malformed_one_falls_back():
    mine = "S-1-5-21-99-88-77-519"
    plan = _plan(attack_events_count=5, attack_identity={"sid_history": {"value": mine}})
    for _kind, line in _rendered(plan, "xml"):
        assert unwrapped(xml_fields(line)["SidHistory"]) == mine

    junk = _plan(attack_events_count=5, attack_identity={"sid_history": {"value": "nonsense"}})
    assert {e.identity["privileged_sid"] for e in junk} == {PRIVILEGED_SID_DEFAULT}


def test_the_warning_hands_over_the_very_sid_the_field_will_send():
    """The steps are only usable while the two cannot drift apart."""
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    warning = api["warning"]
    field = next(f for f in api["identity_fields"] if f["field"] == "sid_history")

    assert warning["code"] == field["default"] == PRIVILEGED_SID_DEFAULT
    assert "`identity`" in warning["text"] and "`category`" in warning["text"]
    assert "privileged" in warning["text"]
    assert warning["text"][0].islower(), "it continues the form's 'Before you run this —' lead"
    assert field["mode"] == "text", "a plain pre-filled input, not a Random/A&I choice"
    # A warning means the reader has to do something the generator cannot. Only
    # this attack is in that position: it needs an ES lookup populated by hand.
    # The firewall-rule one carried one for a while, on the theory that a field
    # Sysmon leaves empty would stop its search; CIM defaults that field, so it
    # does not, and the warning went. Listing them makes a second an explicit
    # decision rather than a drift.
    warned = {key for key, a in AttackGeneratorFactory.get_available_attack_types().items()
              if a.get("warning")}
    assert warned == {ATTACK}, warned


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager
    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env.create_entity("dc-lab", "domain_controller", nt_host="DC-LAB-01")
    env.create_account("adm.lab", account_type="admin")
    monkeypatch.setattr(log_senders, "_env_manager", env)
    return env


def test_the_ai_value_the_form_resolved_is_used(environment):
    plan = _plan(attack_events_count=5, attack_identity={
        "dest": {"mode": "ai", "value": "DC-LAB-01"},
        "src_user": {"mode": "ai", "value": "adm.lab"}})
    for event in plan:
        assert event.identity["dest"] == "DC-LAB-01"
        assert event.identity["src_user"] == "adm.lab"


def test_ai_without_a_value_falls_back_to_the_environment(environment):
    plan = _plan(attack_events_count=5, attack_identity={
        "dest": {"mode": "ai"}, "src_user": {"mode": "ai"}})
    for event in plan:
        assert event.identity["dest"] == "DC-LAB-01"
        assert event.identity["src_user"] == "adm.lab"


# ── the entry ────────────────────────────────────────────────────────────────

def test_it_is_a_windows_attack_with_no_syslog_and_no_datamodel():
    api = AttackGeneratorFactory.get_available_attack_types()[ATTACK]
    assert api["destinations"] == ["file", "configuration"], "Windows is not collected over syslog"
    assert api["datamodel"] is None, "this detection reads the raw Security log"
    assert api["defaults"] == {"events": 1, "noise_events": 20, "duration": 30}
    assert [f["sourcetype"] for f in api["data_sources"][0]["formats"]] == \
        ["XmlWinEventLog", "WinEventLog"]
    assert [f["field"] for f in api["identity_fields"]] == \
        ["host", "src_user", "dest", "sid_history"]
    assert api["identity_fields"][1]["picker"] == "identities"
    assert attack_destinations(DEFINITION) == ["file", "configuration"]


def test_one_event_is_enough_and_the_noise_is_twenty():
    plan = _plan(attack_noise=True)
    assert len([e for e in plan if e.kind == "attack"]) == 1
    assert len([e for e in plan if e.kind == "noise"]) == 20


@needs_ta   # xml_fields() reads the add-on's transforms.conf
def test_a_standalone_render_is_still_a_well_formed_event():
    for render_format in ("xml", "classic"):
        line = _generator(render_format).generate()
        assert "4738" in line or "4742" in line
        if render_format == "xml":
            assert matches(xml_fields(line))
