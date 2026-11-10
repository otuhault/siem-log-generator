"""Sysmon registry events reach Endpoint.Registry, checked against the add-on.

The chain is unusual enough to be worth spelling out, because three different
files each own one link of it:

    XML event
       ↓  Splunk_TA_windows       [XmlWinEventLog] REPORT-* — generic XML kv
    raw fields (EventCode, TargetObject, Image, Details, …)
       ↓  Splunk_TA_..._sysmon    transforms.conf — RegistryValueData out of Details
       ↓  Splunk_TA_..._sysmon    props.conf [source::…] — 62 EVALs, 54 on EventCode
    CIM fields (action, registry_*, process_*, user, status, …)
       ↓  eventtypes.conf         ms-sysmon-regmod, matching on source=
       ↓  tags.conf               endpoint + registry
    Endpoint.Registry

Two links are easy to get wrong and silent when you do. The add-on's stanza is
keyed on **source**, not sourcetype — `XmlWinEventLog:Microsoft-Windows-Sysmon/
Operational` — and so are all seven eventtypes; send these under the wrong
source and they index, parse and produce nothing. And the RegistryValueData
transform reads `<Data Name='Details'>` with single quotes, so double-quoted
attributes would cost `registry_value_data` without any error.

These tests rebuild each link from the shipped .conf files rather than from a
restated expectation, so an add-on upgrade that moves one of them fails here.
"""

import re
from pathlib import Path

import pytest

from log_generators.sysmon import (FILE_CREATE_EVENT_ID, KEYWORDS_SUCCESS,
                                   PROCESS_EVENT_ID, SysmonLogGenerator)
from ta_registry import get_ta

ROOT = Path(__file__).resolve().parents[1]
SYSMON_TA = ROOT / "TAs" / "Splunk_TA_microsoft_sysmon" / "default"
WINDOWS_TA = ROOT / "TAs" / "Splunk_TA_windows" / "default"

needs_ta = pytest.mark.skipif(
    not SYSMON_TA.exists(), reason="Splunk_TA_microsoft_sysmon not present in TAs/")

SOURCE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"


# ── the add-on, read rather than remembered ─────────────────────────────────

def sysmon_props():
    text = (SYSMON_TA / "props.conf").read_text(errors="replace")
    return re.search(r"(?ms)^\[source::" + re.escape(SOURCE) + r"\]\s*$(.*?)(?=^\[|\Z)",
                     text).group(1)


def directive(name):
    """One EVAL/FIELDALIAS from the source stanza, continuation lines joined."""
    body = sysmon_props()
    match = re.search(r"(?m)^" + re.escape(name) + r"\s*=\s*((?:.*\\\n)*.*)$", body)
    return re.sub(r"\\\n\s*", " ", match.group(1)) if match else None


def event_codes(text):
    return {int(n) for n in re.findall(r"\b(\d{1,3})\b", text or "")}


# ── the fields, as the add-on would build them ──────────────────────────────

XML_DATA = re.compile(r"<Data Name='([^']+)'>(.*?)</Data>")

#: transforms.conf: RegistryValueData is lifted out of a `DWORD (0x…)` Details.
REGISTRY_VALUE_DATA = re.compile(r"<Data Name='Details'>\w+\s\((.+?)\)</Data>")


def raw_fields(event):
    """What Splunk_TA_windows' XML extraction leaves for the add-on to read."""
    fields = dict(XML_DATA.findall(event))
    fields["EventCode"] = re.search(r"<EventID>(\d+)</EventID>", event).group(1)
    fields["Computer"] = re.search(r"<Computer>([^<]+)</Computer>", event).group(1)
    fields["Keywords"] = re.search(r"<Keywords>([^<]+)</Keywords>", event).group(1)
    found = REGISTRY_VALUE_DATA.search(event)
    if found:
        fields["RegistryValueData"] = found.group(1)
    return fields


def cim_fields(event):
    """The CIM fields the detection's `stats … by` would need, per the EVALs."""
    raw = raw_fields(event)
    code = int(raw["EventCode"])
    target = raw.get("TargetObject", "")
    event_type = raw.get("EventType")
    out = {}

    # EVAL-action — note EventID 12 branches on EventType.
    if code == 12 and event_type == "CreateKey":
        out["action"] = "created"
    elif code == 12 and event_type in ("DeleteKey", "DeleteValue"):
        out["action"] = "deleted"
    elif code in (13, 14):
        out["action"] = "modified"

    # EVAL-status
    if code in (12, 13) or (code == 14 and raw.get("Keywords") == KEYWORDS_SUCCESS):
        out["status"] = "success"

    # EVAL-registry_hive — only these three prefixes are mapped.
    for prefix, hive in (("HKLM\\System\\", "HKEY_LOCAL_MACHINE\\System"),
                         ("HKU\\", "HKEY_CURRENT_USER"),
                         ("HKLM\\SOFTWARE\\", "HKEY_LOCAL_MACHINE\\Software")):
        if target.startswith(prefix):
            out["registry_hive"] = hive
            break

    out["registry_path"] = target or None                      # FIELDALIAS
    out["process_path"] = raw.get("Image")                     # EVAL-process_path
    out["process_guid"] = raw.get("ProcessGuid")
    out["process_id"] = raw.get("ProcessId")
    out["user"] = (raw.get("User") or "").split("\\")[-1] or None
    out["vendor_product"] = "Microsoft Sysmon"
    out["dest"] = raw.get("Computer")

    # EVAL-registry_key_name — the key itself on a 12 or 14, and on a 13 the
    # key that holds the value, so one segment further up.
    if target:
        parts = target.split("\\")
        out["registry_key_name"] = parts[-1] if code in (12, 14) else (
            parts[-2] if len(parts) > 1 else None)

    # EVAL-registry_value_data / _name — EventID 13, and a 14 RenameValue.
    if code == 13:
        out["registry_value_data"] = raw.get("RegistryValueData") or raw.get("Details")
        out["registry_value_name"] = target.rsplit("\\", 1)[-1] if target else None

    return {k: v for k, v in out.items() if v is not None}


#: The categories that produce registry events, for the tests below that are
#: about the registry group specifically.
REGISTRY_CATEGORIES = ["registry_set", "registry_key", "registry_rename"]


def events(categories=None, count=120):
    generator = SysmonLogGenerator(event_categories=categories)
    return [generator.generate() for _ in range(count)]


# ── the premise: the add-on still works the way these tests replay it ───────

@needs_ta
def test_the_add_on_keys_on_source_not_sourcetype():
    """Everything hangs off this. The sourcetype stanza only renames."""
    props = (SYSMON_TA / "props.conf").read_text(errors="replace")
    assert f"[source::{SOURCE}]" in props, "the source stanza moved"

    stanza = re.search(r"(?ms)^\[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\]"
                       r"\s*$(.*?)(?=^\[|\Z)", props).group(1)
    assert "rename = XmlWinEventLog" in stanza, \
        "the sourcetype no longer collapses to XmlWinEventLog"

    eventtypes = (SYSMON_TA / "eventtypes.conf").read_text(errors="replace")
    regmod = re.search(r"(?ms)^\[ms-sysmon-regmod\]\s*$(.*?)(?=^\[|\Z)", eventtypes).group(1)
    assert f'source="{SOURCE}"' in regmod, "ms-sysmon-regmod no longer matches on source"
    assert event_codes(regmod.split("EventCode")[1]) == {12, 13, 14}


@needs_ta
def test_the_success_keyword_is_the_one_the_add_on_reads():
    """EVAL-status names the value; the generator must not drift from it."""
    assert 'Keywords="0x8000000000000000"' in directive("EVAL-status").replace("'", '"'), \
        directive("EVAL-status")
    assert KEYWORDS_SUCCESS == "0x8000000000000000"


@needs_ta
def test_the_registry_group_is_what_grants_endpoint_and_registry():
    tags = (SYSMON_TA / "tags.conf").read_text(errors="replace")
    block = re.search(r"(?ms)^\[eventtype=ms-sysmon-regmod\]\s*$(.*?)(?=^\[|\Z)", tags).group(1)
    assert "endpoint = enabled" in block and "registry = enabled" in block


@needs_ta
def test_registry_value_data_is_still_lifted_out_of_details():
    """Single quotes on the attribute, and the payload inside the parentheses."""
    transforms = (SYSMON_TA / "transforms.conf").read_text(errors="replace")
    assert r"<Data Name='Details'>\w+\s\((.+)\)</Data>" in transforms, \
        "the RegistryValueData transform changed shape"


@needs_ta
@pytest.mark.parametrize("field,expected", [
    ("EVAL-action", {12, 13, 14}), ("EVAL-status", {12, 13}),
    ("EVAL-registry_hive", {12, 13, 14}), ("EVAL-process_path", {12, 13, 14}),
])
def test_the_evals_these_tests_replay_still_cover_the_registry_ids(field, expected):
    assert expected <= event_codes(directive(field)), field


# ── the events this repository emits ────────────────────────────────────────

@needs_ta
def test_every_event_is_one_line_of_parseable_sysmon_xml():
    for line in events():
        assert "\n" not in line
        assert line.startswith("<Event xmlns=") and line.endswith("</Event>")
        assert "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>" in line
        raw = raw_fields(line)
        assert int(raw["EventCode"]) in (1, 3, 7, 11, 12, 13, 14, 22)
        # The literal the add-on tests for, not the constant the generator uses:
        # comparing those two would pass whatever either of them said.
        assert raw["Keywords"] == "0x8000000000000000", \
            "EVAL-status checks this exact value; status is null on an EventID 14 without it"


@needs_ta
def test_data_attributes_use_single_quotes_or_the_transform_misses_them():
    """The add-on's own regex spells `<Data Name='Details'>`."""
    for line in events(["registry_set"], count=40):
        assert '<Data Name="' not in line, "double quotes would cost registry_value_data"
        assert "<Data Name='Details'>" in line


@needs_ta
def test_an_event_id_12_carries_no_details_and_an_event_type_that_decides_action():
    for line in events(["registry_key"], count=80):
        raw = raw_fields(line)
        assert "Details" not in raw, "Sysmon writes no Details on an EventID 12"
        assert raw["EventType"] in ("CreateKey", "DeleteKey", "DeleteValue")
        assert cim_fields(line)["action"] in ("created", "deleted")


@needs_ta
def test_an_event_id_13_always_yields_a_value_and_a_value_name():
    """registry_value_data falls back to Details verbatim when it is not a
    `DWORD (0x…)`, so a value is produced either way."""
    shapes = set()
    for line in events(["registry_set"], count=120):
        fields = cim_fields(line)
        assert fields["registry_value_data"], fields
        assert fields["registry_value_name"], fields
        shapes.add("typed" if REGISTRY_VALUE_DATA.search(line) else "verbatim")
    assert shapes == {"typed", "verbatim"}, f"only produced {shapes}"


@needs_ta
def test_every_event_carries_the_fields_a_registry_detection_groups_by():
    """The common ones — the per-EventID extras are checked above."""
    needed = ["action", "status", "registry_path", "process_path", "process_guid",
              "process_id", "user", "vendor_product", "dest"]
    for line in events(REGISTRY_CATEGORIES, count=150):
        fields = cim_fields(line)
        missing = [name for name in needed if not fields.get(name)]
        assert not missing, (missing, line[:160])


@needs_ta
def test_the_hives_the_add_on_maps_are_the_ones_generated():
    """registry_hive is only filled under three prefixes. Emitting nothing else
    would be tidy and wrong; emitting only the others would leave it always
    null."""
    hives = {cim_fields(line).get("registry_hive")
             for line in events(REGISTRY_CATEGORIES, count=200)}
    assert hives >= {"HKEY_LOCAL_MACHINE\\System", "HKEY_CURRENT_USER",
                     "HKEY_LOCAL_MACHINE\\Software"}, hives


@needs_ta
def test_a_category_emits_only_its_own_event_id():
    for category, event_id in SysmonLogGenerator.CATEGORY_EVENT_ID.items():
        seen = {int(raw_fields(line)["EventCode"]) for line in events([category], count=40)}
        assert seen == {event_id}, (category, seen)


# ── what the registry says about it ─────────────────────────────────────────

def test_the_registry_describes_the_wire_metadata_the_add_on_needs():
    ta = get_ta("sysmon")
    assert ta["hec_default_sourcetype"] == "XmlWinEventLog"
    assert ta["syslog_viable"] is False
    sourcetype = ta["sourcetypes"][0]
    assert sourcetype["hec_source"] == SOURCE
    assert sourcetype["datamodels"] == ["Endpoint", "Network_Traffic",
                                        "Network_Resolution"]
    assert sourcetype["eventtypes"] == ["ms-sysmon-process", "ms-sysmon-network",
                                        "ms-sysmon-dns", "ms-sysmon-filemod",
                                        "ms-sysmon-regmod"]
    assert set(sourcetype["tags"]) == {"process", "report", "network", "communicate",
                                       "resolution", "dns", "endpoint", "filesystem",
                                       "registry"}


def test_the_registry_claims_no_datamodel_the_generator_cannot_reach():
    """Five of the add-on's seven eventtypes are implemented, reaching three
    datamodels. The two left — WMI and service state — are not described, and
    Change and Endpoint.Services must not appear."""
    ta = get_ta("sysmon")
    declared = {dm for st in ta["sourcetypes"] for dm in st["datamodels"]}
    assert declared == {"Endpoint", "Network_Traffic", "Network_Resolution"}, declared

    conditions = ta["sourcetypes"][0]["datamodel_conditions"]
    assert {c["eventtype"] for c in conditions} == {
        "ms-sysmon-process", "ms-sysmon-network", "ms-sysmon-dns",
        "ms-sysmon-filemod", "ms-sysmon-regmod"}


# ── process creation, and Endpoint.Processes ────────────────────────────────

#: What a detection over Endpoint.Processes groups by. All must be non-null or
#: a tstats BY drops the row — the same trap as the registry ones.
PROCESS_BY_FIELDS = [
    "action", "dest", "original_file_name", "parent_process", "parent_process_exec",
    "parent_process_guid", "parent_process_id", "parent_process_name",
    "parent_process_path", "process", "process_exec", "process_guid", "process_hash",
    "process_id", "process_integrity_level", "process_name", "process_path",
    "user", "user_id", "vendor_product",
]

#: Splunk_TA_windows [XmlWinEventLog], which Sysmon reaches through the rename:
#: UserID_for_windows_security_from_xml, then FIELDALIAS … UserID AS user_id.
#: It accepts either quote style around the attribute.
USER_ID = re.compile(r"""<Security UserID=['"]([^<'"]+)['"]""")


def process_cim_fields(event):
    """Endpoint.Processes fields, as the add-on's EVALs build them from an ID 1."""
    raw = raw_fields(event)
    assert int(raw["EventCode"]) == PROCESS_EVENT_ID
    image, parent = raw["Image"], raw["ParentImage"]
    found = USER_ID.search(event)
    return {
        "action": "allowed",                                  # EVAL-action, EventCode 1
        "dest": raw["Computer"],
        "original_file_name": raw.get("OriginalFileName"),
        "parent_process": raw.get("ParentCommandLine"),       # FIELDALIAS
        "parent_process_path": parent,
        "parent_process_name": parent.rsplit("\\", 1)[-1],
        "parent_process_exec": parent.rsplit("\\", 1)[-1],
        "parent_process_guid": raw.get("ParentProcessGuid"),
        "parent_process_id": raw.get("ParentProcessId"),
        "process": raw.get("CommandLine"),                    # EVAL-process, EventCode 1
        "process_path": image,
        "process_name": image.rsplit("\\", 1)[-1],
        "process_exec": image.rsplit("\\", 1)[-1],
        "process_guid": raw.get("ProcessGuid"),
        "process_id": raw.get("ProcessId"),
        "process_hash": raw.get("Hashes"),
        "process_integrity_level": raw.get("IntegrityLevel"),  # FIELDALIAS
        "user": (raw.get("User") or "").split("\\")[-1] or None,
        "user_id": found.group(1) if found else None,
        "vendor_product": "Microsoft Sysmon",
    }


@needs_ta
def test_the_process_group_grants_process_and_report():
    tags = (SYSMON_TA / "tags.conf").read_text(errors="replace")
    block = re.search(r"(?ms)^\[eventtype=ms-sysmon-process\]\s*$(.*?)(?=^\[|\Z)", tags).group(1)
    assert "process = enabled" in block and "report = enabled" in block

    eventtypes = (SYSMON_TA / "eventtypes.conf").read_text(errors="replace")
    group = re.search(r"(?ms)^\[ms-sysmon-process\]\s*$(.*?)(?=^\[|\Z)", eventtypes).group(1)
    assert f'source="{SOURCE}"' in group
    assert PROCESS_EVENT_ID in event_codes(group.split("EventCode")[1])


@needs_ta
def test_user_id_comes_from_the_windows_add_on_not_this_one():
    """Sysmon's own add-on produces no user_id at all; the generic
    [XmlWinEventLog] stanza does, off the Security element, and Sysmon events
    reach it through `rename = XmlWinEventLog`. Without that the field would be
    null and every Endpoint.Processes detection grouping by it would drop."""
    assert "user_id" not in (SYSMON_TA / "props.conf").read_text(errors="replace")

    windows = WINDOWS_TA / "props.conf"
    if not windows.exists():
        pytest.skip("Splunk_TA_windows not present in TAs/")
    text = windows.read_text(errors="replace")
    stanza = re.search(r"(?ms)^\[XmlWinEventLog\]\s*$(.*?)(?=^\[|\Z)", text).group(1)
    assert "UserID  AS user_id" in stanza or "UserID AS user_id" in stanza

    transforms = (WINDOWS_TA / "transforms.conf").read_text(errors="replace")
    assert r"""<Security UserID=['"](?<UserID>[^<'"]+)['"]""" in transforms, \
        "the quote-tolerant UserID extraction changed"


@needs_ta
def test_every_process_event_carries_what_endpoint_processes_groups_by():
    for line in events(["process_creation"], count=150):
        fields = process_cim_fields(line)
        missing = [name for name in PROCESS_BY_FIELDS if not fields.get(name)]
        assert not missing, (missing, line[:200])


@needs_ta
def test_a_process_event_carries_no_event_type_and_says_version_five():
    """A registry event has EventType and Version 2; a process creation has
    neither of those values, and inventing one would be a shape Sysmon never
    writes."""
    for line in events(["process_creation"], count=40):
        assert "<Data Name='EventType'>" not in line
        assert "<Version>5</Version>" in line
    for line in events(["registry_set"], count=40):
        assert "<Data Name='EventType'>" in line
        assert "<Version>2</Version>" in line


@needs_ta
def test_the_original_file_name_is_never_the_placeholder_the_add_on_drops():
    """EVAL-original_file_name refuses "-", and the field is grouped by."""
    for line in events(["process_creation"], count=60):
        assert raw_fields(line)["OriginalFileName"] not in ("-", "")


@needs_ta
def test_the_hashes_are_the_three_the_add_on_passes_through():
    for line in events(["process_creation"], count=30):
        hashes = raw_fields(line)["Hashes"]
        assert re.fullmatch(r"MD5=[0-9A-F]{32},SHA256=[0-9A-F]{64},IMPHASH=[0-9A-F]{32}",
                            hashes), hashes


# ── file creation, and Endpoint.Filesystem ──────────────────────────────────

#: What the add-on builds for an EventID 11 — and, just as important, what it
#: does not. Sysmon reports no hash, size or ACL on a file creation, and the
#: add-on fills file_access_time and file_modify_time only for other event IDs.
FILESYSTEM_AVAILABLE = ["action", "dest", "file_name", "file_path", "file_create_time",
                        "process_guid", "process_id", "process_name", "process_path",
                        "user", "vendor_product"]
FILESYSTEM_ABSENT = ["file_hash", "file_size", "file_acl", "file_access_time",
                     "file_modify_time"]


def file_cim_fields(event):
    """Endpoint.Filesystem fields, as the add-on's EVALs build them from an ID 11."""
    raw = raw_fields(event)
    assert int(raw["EventCode"]) == FILE_CREATE_EVENT_ID
    target, image = raw["TargetFilename"], raw["Image"]
    return {
        # EVAL-action: the two timestamps decide it.
        "action": "created" if raw["UtcTime"] == raw["CreationUtcTime"] else "modified",
        "dest": raw["Computer"],
        "file_path": target,
        "file_name": target.rsplit("\\", 1)[-1],
        "file_create_time": raw["CreationUtcTime"],       # FIELDALIAS
        "process_path": image,
        "process_name": image.rsplit("\\", 1)[-1],
        "process_guid": raw["ProcessGuid"],
        "process_id": raw["ProcessId"],
        "user": (raw.get("User") or "").split("\\")[-1] or None,
        "vendor_product": "Microsoft Sysmon",
    }


@needs_ta
def test_the_file_group_grants_endpoint_and_filesystem():
    tags = (SYSMON_TA / "tags.conf").read_text(errors="replace")
    block = re.search(r"(?ms)^\[eventtype=ms-sysmon-filemod\]\s*$(.*?)(?=^\[|\Z)", tags).group(1)
    assert "endpoint = enabled" in block and "filesystem = enabled" in block

    eventtypes = (SYSMON_TA / "eventtypes.conf").read_text(errors="replace")
    group = re.search(r"(?ms)^\[ms-sysmon-filemod\]\s*$(.*?)(?=^\[|\Z)", eventtypes).group(1)
    assert FILE_CREATE_EVENT_ID in event_codes(group.split("EventCode")[1])


@needs_ta
def test_every_file_event_carries_what_the_add_on_can_build():
    for line in events(["file_create"], count=150):
        fields = file_cim_fields(line)
        missing = [name for name in FILESYSTEM_AVAILABLE if not fields.get(name)]
        assert not missing, (missing, line[:200])


@needs_ta
def test_both_actions_occur_because_the_add_on_compares_two_timestamps():
    """UtcTime == CreationUtcTime is a new file; different is an overwrite.
    Emitting only one of the two would leave half the detections unreachable."""
    actions = {file_cim_fields(line)["action"] for line in events(["file_create"], count=200)}
    assert actions == {"created", "modified"}, actions


@needs_ta
@pytest.mark.parametrize("field", FILESYSTEM_ABSENT)
def test_the_add_on_builds_no_hash_size_or_acl_for_a_file_creation(field):
    """Sysmon does not report these on an EventID 11, and the add-on fills the
    two timestamps only for other IDs. Of the 53 Filesystem detections naming
    Sysmon EventID 11, 40 group by one of them — but that does not block them:
    Splunk_SA_CIM defaults the field, so it reaches the datamodel as "unknown"
    and the tstats BY keeps the row. Measured on a real install: file_hash came
    back as 109 rows of "unknown". Pinned here so that the day the add-on does
    start filling one of these, the events can carry a real value instead."""
    props = (SYSMON_TA / "props.conf").read_text(errors="replace")
    directive_line = re.search(r"(?m)^(?:EVAL|FIELDALIAS)-[\w]*" + field + r"\s*=\s*(.+)$", props)
    if directive_line is None:
        return                                   # the add-on never mentions it
    covered = event_codes(directive_line.group(1))
    assert FILE_CREATE_EVENT_ID not in covered, \
        f"{field} now covers EventID 11 — the events can carry it, and should"


# ── image load, network connection, DNS ─────────────────────────────────────

#: transforms.conf [sysmon-dns-answer-data], SOURCE_KEY = QueryResults.
DNS_ANSWER = re.compile(r"(type:\s+(?P<record_type_id>\d+)\s+|)(?P<answer>[^;]+);")


@needs_ta
@pytest.mark.parametrize("eventtype,event_id,wanted", [
    ("ms-sysmon-process", 7, {"process", "report"}),
    ("ms-sysmon-network", 3, {"network", "communicate"}),
    ("ms-sysmon-dns", 22, {"network", "resolution", "dns"}),
])
def test_each_group_matches_its_event_id_and_grants_its_tags(eventtype, event_id, wanted):
    eventtypes = (SYSMON_TA / "eventtypes.conf").read_text(errors="replace")
    group = re.search(r"(?ms)^\[" + eventtype + r"\]\s*$(.*?)(?=^\[|\Z)", eventtypes).group(1)
    assert f'source="{SOURCE}"' in group
    assert event_id in event_codes(group.split("EventCode")[1])

    tags = (SYSMON_TA / "tags.conf").read_text(errors="replace")
    block = re.search(r"(?ms)^\[eventtype=" + eventtype + r"\]\s*$(.*?)(?=^\[|\Z)", tags).group(1)
    assert {line.split("=")[0].strip() for line in block.splitlines() if "=" in line} == wanted


@needs_ta
def test_an_image_load_carries_its_hashes_and_both_signature_states():
    """Signed and SignatureStatus are the pair the add-on reads for
    service_dll_signature_exists and _verified. An unsigned module is the half
    worth having, so both occur."""
    signed = set()
    for line in events(["image_load"], count=120):
        raw = raw_fields(line)
        assert raw["ImageLoaded"] and raw["Image"] != raw["ImageLoaded"]
        assert re.fullmatch(r"MD5=[0-9A-F]{32},SHA256=[0-9A-F]{64},IMPHASH=[0-9A-F]{32}",
                            raw["Hashes"])
        assert raw["OriginalFileName"] not in ("-", "")
        signed.add(raw["Signed"])
        assert (raw["SignatureStatus"] == "Valid") == (raw["Signed"] == "true")
    assert signed == {"true", "false"}, signed


@needs_ta
def test_a_network_connection_gives_both_directions():
    """EVAL-direction reads Initiated: true is outbound, anything else inbound.
    A workstation does both."""
    directions = set()
    for line in events(["network_connect"], count=200):
        raw = raw_fields(line)
        directions.add("outbound" if raw["Initiated"] == "true" else "inbound")
        # FIELDALIASes the Network_Traffic datamodel needs.
        for field in ("SourceIp", "SourcePort", "DestinationIp", "DestinationPort",
                      "Protocol", "Image"):
            assert raw.get(field), (field, line[:180])
        assert raw["Protocol"] in ("tcp", "udp")
    assert directions == {"outbound", "inbound"}, directions


@needs_ta
def test_a_dns_answer_survives_the_add_on_s_repeating_match():
    """The answer is pulled out of QueryResults with a repeating match on
    `type:  <n>  <value>;`. Drop the semicolon and answer_count is zero."""
    with_answers = without = 0
    for line in events(["dns_query"], count=150):
        raw = raw_fields(line)
        assert raw["QueryName"]
        answers = [m.group("answer") for m in DNS_ANSWER.finditer(raw["QueryResults"])]
        if answers:
            with_answers += 1
            # record_type_id feeds the add-on's record_type lookup.
            assert all(m.group("record_type_id")
                       for m in DNS_ANSWER.finditer(raw["QueryResults"]))
        else:
            without += 1
            assert raw["QueryResults"] == "-", raw["QueryResults"]
    assert with_answers and without, (with_answers, without)


@needs_ta
def test_a_cname_followed_by_an_address_yields_two_answers():
    """The repeating match has to keep both, or answer_count is wrong."""
    from log_generators.sysmon import DNS_QUERIES

    chained = [r for _n, r in DNS_QUERIES if r.count("type:") > 1]
    assert chained, "no multi-answer fixture left to check the repeat against"
    for results in chained:
        answers = [m.group("answer") for m in DNS_ANSWER.finditer(results)]
        assert len(answers) == results.count("type:"), (answers, results)


@needs_ta
def test_every_category_emits_only_its_own_event_id():
    for category, event_id in SysmonLogGenerator.CATEGORY_EVENT_ID.items():
        seen = {int(raw_fields(line)["EventCode"]) for line in events([category], count=40)}
        assert seen == {event_id}, (category, seen)
