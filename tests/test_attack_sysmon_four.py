"""Four Sysmon attacks, each against the clauses of its own detection.

One per remaining group, so between them they exercise every datamodel the
Sysmon source reaches:

  Executables Or Script Creation In Temp Path   EventID 11  Endpoint.Filesystem
  Ngrok Reverse Proxy on Network                EventID 22  Network_Resolution
  Windows Registry SIP Provider Modification    EventID 13  Endpoint.Registry
  Windows Network Connection From Suspect Loc.  EventID 3   Network_Traffic

Each detection's WHERE is rebuilt here from the CIM fields the add-on produces,
and each attack must satisfy it while no noise event does. Where a field is not
one Sysmon writes — `action` on a file creation, `registry_value_name`,
`answer_count`, `app` — the test says which EVAL derives it, because that is
what the events have to feed.
"""

import re
from pathlib import Path

import pytest

from attack_generators import ATTACK_REGISTRY, AttackGeneratorFactory, attack_destinations
from log_senders import SenderManager
from test_sysmon_cim import file_cim_fields, raw_fields

SYSMON_TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_microsoft_sysmon" / "default"
needs_ta = pytest.mark.skipif(
    not SYSMON_TA.exists(), reason="Splunk_TA_microsoft_sysmon not present in TAs/")


def plan(attack, **options):
    return SenderManager.attack_plan(attack, options, "configuration")


def rendered(attack, **options):
    generator = AttackGeneratorFactory.get_generator(attack, {})
    out = []
    for event in plan(attack, **options):
        generator.use_identity(event.identity)
        out.append((event.kind,
                    generator.generate() if event.kind == "attack" else generator.generate_noise()))
    return out


def like(value, glob):
    """A Splunk wildcard comparison, case-insensitive as tstats does it."""
    pattern = ".*".join(re.escape(part) for part in glob.split("*"))
    return bool(re.fullmatch(pattern, value or "", re.I | re.S))


def directive(name):
    props = (SYSMON_TA / "props.conf").read_text(errors="replace")
    found = re.search(r"(?m)^" + re.escape(name) + r"\s*=\s*((?:.*\\\n)*.*)$", props)
    return re.sub(r"\\\n\s*", " ", found.group(1)) if found else None


# ══ Executables Or Script Creation In Temp Path ═════════════════════════════

TEMP_ATTACK = "sysmon_temp_path_executable"
TEMP_EXTENSIONS = ["*.bat", "*.cmd", "*.com", "*.dll", "*.exe", "*.js", "*.msc",
                   "*.pif", "*.ps1", "*.sys", "*.vbe", "*.vbs"]
TEMP_PATHS_GLOB = ["*:\\Temp\\*", "*:\\Windows\\Temp\\*", "*\\AppData\\Local\\Temp\\*"]


def temp_matches(fields):
    return (fields.get("action") == "created"
            and any(like(fields.get("file_name"), g) for g in TEMP_EXTENSIONS)
            and any(like(fields.get("file_path"), g) for g in TEMP_PATHS_GLOB)
            and not like(fields.get("file_path"), "*\\__PSScriptPolicyTest_*"))


@needs_ta
def test_the_action_on_a_file_creation_is_still_the_timestamp_comparison():
    """The first clause rests on it: created only when the two agree."""
    line = directive("EVAL-action")
    assert 'EventCode = "11" AND UtcTime==CreationUtcTime' in line, line
    assert 'EventCode = "11" AND UtcTime!=CreationUtcTime' in line, line


@needs_ta
def test_every_temp_drop_satisfies_its_three_clauses():
    for _kind, line in rendered(TEMP_ATTACK, attack_events_count=150):
        fields = file_cim_fields(line)
        assert temp_matches(fields), fields


@needs_ta
def test_the_temp_noise_misses_one_clause_at_a_time():
    noise = [e for e in plan(TEMP_ATTACK, attack_events_count=1, attack_noise=True,
                             attack_noise_count=250) if e.kind == "noise"]
    generator = AttackGeneratorFactory.get_generator(TEMP_ATTACK, {})
    seen = set()
    for event in noise:
        generator.use_identity(event.identity)
        fields = file_cim_fields(generator.generate_noise())
        assert not temp_matches(fields), fields
        if fields["action"] != "created":
            seen.add("an overwrite, so modified")
        elif like(fields["file_path"], "*\\__PSScriptPolicyTest_*"):
            seen.add("the file the search excludes")
        elif not any(like(fields["file_name"], g) for g in TEMP_EXTENSIONS):
            seen.add("harmless extension")
        else:
            seen.add("executable, ordinary path")
    assert len(seen) == 4, seen


@needs_ta
def test_every_extension_the_search_lists_can_occur():
    names = {file_cim_fields(line)["file_name"].rsplit(".", 1)[-1].lower()
             for _kind, line in rendered(TEMP_ATTACK, attack_events_count=400)}
    assert names <= {g.lstrip("*.") for g in TEMP_EXTENSIONS}
    assert len(names) >= 5, names


# ══ Ngrok Reverse Proxy on Network ══════════════════════════════════════════

NGROK_ATTACK = "sysmon_ngrok_dns"
NGROK_GLOBS = ["*.ngrok.com", "*.ngrok.io", "ngrok.*.tunnel.com", "korgn.*.lennut.com"]
DNS_ANSWER = re.compile(r"(type:\s+(?P<record_type_id>\d+)\s+|)(?P<answer>[^;]+);")


def dns_fields(event):
    raw = raw_fields(event)
    answers = [m.group("answer") for m in DNS_ANSWER.finditer(raw.get("QueryResults", ""))]
    return {
        "query": raw.get("QueryName"),
        "answer": answers,
        "answer_count": len(answers),
        "query_count": 1,
        "reply_code_id": raw.get("QueryStatus"),
        "src": raw.get("Computer"),          # EVAL-src takes Computer for EventCode 22
        "vendor_product": "Microsoft Sysmon",
    }


@needs_ta
def test_src_on_a_dns_event_is_the_computer_not_an_address():
    assert '"19","20","21","22"' in directive("EVAL-src")


@needs_ta
def test_every_ngrok_query_matches_one_of_the_globs():
    for _kind, line in rendered(NGROK_ATTACK, attack_events_count=150):
        fields = dns_fields(line)
        assert any(like(fields["query"], g) for g in NGROK_GLOBS), fields["query"]


@needs_ta
def test_the_tunnel_answers_survive_the_repeating_match():
    """answer and answer_count are grouped by, and neither is a field Sysmon
    writes — both come out of QueryResults."""
    counts = set()
    for _kind, line in rendered(NGROK_ATTACK, attack_events_count=200):
        fields = dns_fields(line)
        assert fields["answer"], line[:160]
        assert fields["answer_count"] == len(fields["answer"])
        counts.add(fields["answer_count"])
    assert counts >= {1, 2}, f"a tunnel resolving to several addresses never occurred: {counts}"


@needs_ta
def test_no_ngrok_noise_matches_including_the_lookalikes():
    noise = [e for e in plan(NGROK_ATTACK, attack_events_count=1, attack_noise=True,
                             attack_noise_count=250) if e.kind == "noise"]
    generator = AttackGeneratorFactory.get_generator(NGROK_ATTACK, {})
    lookalikes = ordinary = 0
    for event in noise:
        generator.use_identity(event.identity)
        fields = dns_fields(generator.generate_noise())
        assert not any(like(fields["query"], g) for g in NGROK_GLOBS), fields["query"]
        if "ngrok" in fields["query"].lower():
            lookalikes += 1
        else:
            ordinary += 1
    assert lookalikes and ordinary, (lookalikes, ordinary)


# ══ Windows Registry SIP Provider Modification ══════════════════════════════

SIP_ATTACK = "sysmon_sip_provider_registry"
SIP_GLOBS = ["*\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\*",
             "*\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType*",
             "*\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\*",
             "*\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType*"]


def sip_fields(event):
    from test_sysmon_cim import cim_fields
    return cim_fields(event)


def sip_matches(fields):
    return (any(like(fields.get("registry_path"), g) for g in SIP_GLOBS)
            and (fields.get("registry_value_name") or "") in ("Dll", "$DLL"))


@needs_ta
def test_the_value_name_is_still_the_last_segment_of_the_target_object():
    """The second clause rests on it — Sysmon writes no such field."""
    line = directive("EVAL-registry_value_name")
    assert 'EventCode="13"' in line and "TargetObject" in line, line


@needs_ta
def test_every_sip_write_satisfies_both_clauses():
    for _kind, line in rendered(SIP_ATTACK, attack_events_count=150):
        fields = sip_fields(line)
        assert sip_matches(fields), fields


@needs_ta
def test_the_sip_noise_misses_one_clause_at_a_time():
    noise = [e for e in plan(SIP_ATTACK, attack_events_count=1, attack_noise=True,
                             attack_noise_count=250) if e.kind == "noise"]
    generator = AttackGeneratorFactory.get_generator(SIP_ATTACK, {})
    right_key = wrong_key = ordinary = 0
    for event in noise:
        generator.use_identity(event.identity)
        fields = sip_fields(generator.generate_noise())
        assert not sip_matches(fields), fields
        path = fields.get("registry_path") or ""
        if any(like(path, g) for g in SIP_GLOBS):
            right_key += 1        # a SIP key, a value the search ignores
        elif "Cryptography" in path or "CurrentControlSet" in path or "CurrentVersion" in path:
            wrong_key += 1
        else:
            ordinary += 1
    assert right_key and wrong_key and ordinary, (right_key, wrong_key, ordinary)


@needs_ta
def test_both_value_names_the_search_reads_occur():
    names = {sip_fields(line)["registry_value_name"]
             for _kind, line in rendered(SIP_ATTACK, attack_events_count=200)}
    assert names == {"Dll", "$DLL"}, names


@needs_ta
def test_the_sip_keys_still_fill_registry_hive():
    """HKLM\\SOFTWARE\\ is one of the three prefixes the add-on maps."""
    for _kind, line in rendered(SIP_ATTACK, attack_events_count=60):
        assert sip_fields(line)["registry_hive"] == "HKEY_LOCAL_MACHINE\\Software"


# ══ Windows Network Connection From Program In Suspect Location ═════════════

NET_ATTACK = "sysmon_connection_from_suspect_path"
SUSPECT_GLOBS = ["*\\$Recycle.Bin\\*", "*\\Config\\SystemProfile\\*", "*\\PerfLogs\\*",
                 "*\\Users\\All Users\\*", "*\\Users\\Default\\*", "*\\Users\\Public\\*",
                 "*\\Windows\\addins\\*", "*\\Windows\\Fonts\\*", "*\\Windows\\IME\\*"]


def net_fields(event):
    raw = raw_fields(event)
    return {
        "app": raw.get("Image"),                       # EVAL-app, EventCode 3
        "dest_ip": raw.get("DestinationIp"),
        "dest_port": raw.get("DestinationPort"),
        "src_ip": raw.get("SourceIp"),
        "src_port": raw.get("SourcePort"),
        # EVAL-src falls through to SourceHostname before SourceIp.
        "src": raw.get("SourceHostname") or raw.get("SourceIp"),
        "transport": raw.get("Protocol"),
        "protocol": "ip",
        "protocol_version": "ipv6" if raw.get("DestinationIsIpv6") == "true" else "ipv4",
        "direction": "outbound" if raw.get("Initiated") == "true" else "inbound",
        "action": "allowed",
        "dvc": raw.get("Computer"),
        "dest": raw.get("Computer"),
        "user": (raw.get("User") or "").split("\\")[-1] or None,
        "vendor_product": "Microsoft Sysmon",
    }


@needs_ta
def test_app_on_a_connection_is_the_image():
    assert directive("EVAL-app").strip().startswith('case( EventCode="3", Image')


@needs_ta
def test_every_connection_comes_from_a_location_the_search_names():
    for _kind, line in rendered(NET_ATTACK, attack_events_count=150):
        fields = net_fields(line)
        assert any(like(fields["app"], g) for g in SUSPECT_GLOBS), fields["app"]


@needs_ta
def test_no_connection_noise_does():
    noise = [e for e in plan(NET_ATTACK, attack_events_count=1, attack_noise=True,
                             attack_noise_count=200) if e.kind == "noise"]
    generator = AttackGeneratorFactory.get_generator(NET_ATTACK, {})
    for event in noise:
        generator.use_identity(event.identity)
        fields = net_fields(generator.generate_noise())
        assert not any(like(fields["app"], g) for g in SUSPECT_GLOBS), fields["app"]


@needs_ta
def test_every_grouped_field_of_the_connection_search_is_present():
    for _kind, line in rendered(NET_ATTACK, attack_events_count=120):
        fields = net_fields(line)
        missing = [name for name in ATTACK_REGISTRY[NET_ATTACK]["detection"]["by"]
                   if not fields.get(name)]
        assert not missing, (missing, line[:200])


# ══ common to all four ══════════════════════════════════════════════════════

ALL_FOUR = [TEMP_ATTACK, NGROK_ATTACK, SIP_ATTACK, NET_ATTACK]


@pytest.mark.parametrize("attack", ALL_FOUR)
def test_each_declares_one_sysmon_source_and_needs_no_warning(attack):
    api = AttackGeneratorFactory.get_available_attack_types()[attack]
    assert api["warning"] is None
    assert [s["sourcetype"] for s in ATTACK_REGISTRY[attack]["data_sources"]] == \
        ["XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"]
    assert attack_destinations(ATTACK_REGISTRY[attack]) == ["file", "configuration"]


@pytest.mark.parametrize("attack", ALL_FOUR)
def test_each_holds_one_endpoint_and_one_account_for_the_run(attack):
    once = plan(attack, attack_events_count=8)
    assert len({e.identity["dest"] for e in once}) == 1
    assert len({e.identity["user"] for e in once}) == 1


@needs_ta
@pytest.mark.parametrize("attack", ALL_FOUR)
def test_each_renders_standalone(attack):
    """A preview asks for an event with no plan behind it."""
    generator = AttackGeneratorFactory.get_generator(attack, {})
    for _ in range(20):
        line = generator.generate()
        assert line.startswith("<Event xmlns=") and "\n" not in line


@needs_ta
@pytest.mark.parametrize("attack,event_id", [
    (TEMP_ATTACK, 11), (NGROK_ATTACK, 22), (SIP_ATTACK, 13), (NET_ATTACK, 3)])
def test_each_emits_the_event_id_its_detection_names(attack, event_id):
    for _kind, line in rendered(attack, attack_events_count=40):
        assert int(raw_fields(line)["EventCode"]) == event_id


@needs_ta
def test_one_tunnel_lookup_becomes_one_row_per_answer():
    """The search groups BY DNS.answer, which is multivalued, so Splunk emits a
    row per value. Two rows carrying the same query, the same answer_count and
    the same timestamps are one event with two answers — not two events."""
    multi = [line for _kind, line in rendered(NGROK_ATTACK, attack_events_count=200)
             if dns_fields(line)["answer_count"] > 1]
    assert multi, "no lookup resolved to more than one address"
    fields = dns_fields(multi[0])
    assert len(fields["answer"]) == fields["answer_count"] > 1
    assert len(set(fields["answer"])) == fields["answer_count"], \
        "duplicate answers would collapse into one row and undercount"
