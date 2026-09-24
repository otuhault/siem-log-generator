r"""PowerShell 4104 against Splunk_TA_windows and the 121 detections that read it.

This source is the one Windows channel here that reaches **no** CIM datamodel, so
there is no `| datamodel` to simulate. What there is instead is a chain of
generic XML transforms and 121 raw searches, and both are checked below against
the files that define them rather than against a restated expectation:

    XML event
       ↓  [XmlWinEventLog] REPORT-0xml_block_extract   System_Props_Xml, EventData_Xml
       ↓  [XmlWinEventLog] REPORT-0xml_kv_extract      EventID, Computer, Opcode,
       ↓                                               Name, Guid, ProcessID, UserID,
       ↓                                               ScriptBlockText, ScriptBlockId, Path
       ↓  [XmlWinEventLog] FIELDALIAS/EVAL             user_id, signature_id, vendor_product
       ↓  [source::…PowerShell/Operational]            dest, signature
    the 13 fields 107 of the detections group by

The transforms are read out of transforms.conf and applied here as Splunk would
apply them, so an add-on upgrade that renames a capture group or moves a
SOURCE_KEY fails in this file instead of silently costing a field.

Two facts are load-bearing and each gets its own test:

  - `eventdata_xml_data` matches `Name='...'` in **single** quotes only, so the
    whole EventData would extract to nothing under double quotes.
  - it captures `([^<]*)`, so a raw `<` in a script block would truncate
    ScriptBlockText at that character — hence the XML escaping.

And the noise is checked against the detections themselves: a benign event must
fire none of them. Each detection's leading filter is vendored as a boolean AST
over ScriptBlockText and evaluated here — not as a flat list of ANDed globs,
which is what the first version did and which silently under-reported every
`(A OR B) AND C` search, the shape two detections in three use.
"""

import json
import re
from pathlib import Path

import pytest

from log_generators.powershell import (CHANNEL, KEYWORDS, LEVEL, OPCODE,
                                       PROVIDER_GUID, PROVIDER_NAME,
                                       SCRIPT_BLOCK_EVENT_ID, SYSTEM_SID, TASK,
                                       PowerShellLogGenerator, user_sid)
from ta_registry import get_ta

ROOT = Path(__file__).resolve().parents[1]
WINDOWS_TA = ROOT / "TAs" / "Splunk_TA_windows" / "default"

needs_ta = pytest.mark.skipif(
    not WINDOWS_TA.exists(), reason="Splunk_TA_windows not present in TAs/")

SOURCE = "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
SOURCETYPE = "XmlWinEventLog"

#: The fields 107 of the 121 detections group by, verbatim from their stats.
CANONICAL_BY = ["dest", "signature", "signature_id", "user_id", "vendor_product",
                "EventID", "Guid", "Opcode", "Name", "Path", "ProcessID",
                "ScriptBlockId", "ScriptBlockText"]

#: `ScriptBlockText=*` selects every 4104; this detection does its real filtering
#: with `| lookup malicious_powershell_strings`, which ships in ESCU and is not
#: available here. Nothing about a benign event can keep it from matching, so it
#: is excluded from the noise test rather than silently passed.
CATCH_ALL = "windows_powershell_script_block_with_malicious_string.yml"


# ── the add-on, read rather than remembered ─────────────────────────────────

def _conf(name):
    return (WINDOWS_TA / name).read_text(errors="replace")


def stanza(text, header):
    """The body of one .conf stanza, up to the next one."""
    found = re.search(r"(?ms)^\[" + re.escape(header) + r"\]\s*$(.*?)(?=^\[|\Z)", text)
    return found.group(1) if found else None


def setting(body, name):
    """One key from a stanza body, continuation lines joined."""
    found = re.search(r"(?m)^" + re.escape(name) + r"\s*=\s*((?:.*\\\n)*.*)$", body)
    return re.sub(r"\\\n\s*", " ", found.group(1)).strip() if found else None


def _selectors(search, key):
    """Every value an eventtype search constrains `key` to.

    Both spellings occur in the shipped files and both have to be understood:
    `source=WinEventLog:Security` and `sourcetype IN ("WinEventLog", "XmlWin*")`.
    Reading only the first would quietly miss `windows_ta_data`, which is one of
    the two eventtypes this channel does match.
    """
    values = []
    for found in re.finditer(rf'\b{key}\s*(=|IN)\s*', search, re.I):
        rest = search[found.end():]
        if found.group(1).upper() == "IN":
            inner = re.match(r"\(([^)]*)\)", rest)
            if inner:
                values += [v.strip().strip('"\'') for v in inner.group(1).split(",")]
        else:
            one = re.match(r'"([^"]*)"|([^\s)]+)', rest)
            if one:
                values.append((one.group(1) or one.group(2)).strip('"\''))
    return [v for v in values if v]


def transform(name):
    """A transforms.conf stanza as (SOURCE_KEY, compiled REGEX, FORMAT)."""
    body = stanza(_conf("transforms.conf"), name)
    assert body is not None, f"transforms.conf no longer defines [{name}]"
    return (setting(body, "SOURCE_KEY"),
            re.compile(setting(body, "REGEX")),
            setting(body, "FORMAT"))


# ── the extraction chain, replayed with the add-on's own regexes ────────────

def extract(event):
    """Every field the generic [XmlWinEventLog] stanza leaves for a search.

    The transforms are applied in the order props.conf lists them: the two block
    transforms carve System_Props_Xml and EventData_Xml out of the raw event,
    then the three kv transforms read fields out of those.
    """
    keys = {}
    for block in ("system_xml_block", "eventdata_xml_block"):
        _src, regex, fmt = transform(block)
        found = regex.search(event)
        if found:
            keys[fmt.split("::")[0]] = found.group(1)

    fields = {}
    for kv in ("system_props_xml_kv", "system_props_xml_attributes",
               "eventdata_xml_data"):
        source_key, regex, _fmt = transform(kv)
        for name, *rest in regex.findall(keys.get(source_key, "")):
            fields[name] = rest[-1]

    # REPORT-EventCode_from_xml, then the stanza's own EVALs and aliases.
    if "EventID" in fields:
        fields["EventCode"] = fields["EventID"]
    if "UserID" in fields:
        fields["user_id"] = fields["UserID"]
    fields["vendor_product"] = "Microsoft Windows"
    fields["signature_id"] = fields.get("EventCode")

    # [source::…PowerShell/Operational]: the only two things it grants.
    _src, dest_regex, dest_fmt = transform("Computer_as_dest")
    found = dest_regex.search(event)
    if found:
        fields[dest_fmt.split("::")[0]] = found.group(1)
    fields["signature"] = signature_for(fields.get("EventCode"))
    return fields


def signature_for(event_code):
    """EVAL-signature from the source stanza, read off props.conf."""
    body = stanza(_conf("props.conf"), "source::" + SOURCE)
    case = setting(body, "EVAL-signature")
    found = re.search(r"EventCode==" + str(event_code) + r'\s*,\s*"([^"]+)"', case)
    return found.group(1) if found else None


def events(count=60, **kwargs):
    generator = PowerShellLogGenerator()
    return [generator.render(generator.script_block_event(**kwargs))
            for _ in range(count)]


# ── the premise: what the add-on grants this channel ────────────────────────

@needs_ta
def test_the_source_stanza_still_grants_only_dest_and_signature():
    body = stanza(_conf("props.conf"), "source::" + SOURCE)
    assert body is not None, "the add-on no longer has a stanza for this channel"
    keys = set(re.findall(r"(?m)^([A-Z][A-Za-z_0-9-]*)\s*=", body))
    assert keys == {"REPORT-dest_for_microsoft_windows_powershell", "EVAL-signature"}, \
        f"the add-on now grants more than dest and signature: {sorted(keys)}"


@needs_ta
def test_the_channel_reaches_no_cim_datamodel():
    """The claim the registry makes, checked against every eventtype in TAs/.

    Only two eventtypes can select this event, and between them they carry one
    tag — track_event_signatures — which is not a CIM tag. If an add-on upgrade
    ever tags this channel, this fails and the registry has to be updated.
    """
    selecting = []
    for conf in (ROOT / "TAs").rglob("eventtypes.conf"):
        name = None
        for line in conf.read_text(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                name = line[1:-1]
                continue
            if not line.lower().startswith("search"):
                continue
            search = line.split("=", 1)[1].strip()
            sources = _selectors(search, "source")
            types = _selectors(search, "sourcetype")
            if not sources and not types:
                continue          # defined by other eventtypes or bare terms
            def hit(patterns, value):
                return any(re.fullmatch(p.replace("*", ".*"), value, re.I)
                           for p in patterns)
            if ((not sources or hit(sources, SOURCE))
                    and (not types or hit(types, SOURCETYPE))):
                selecting.append(name)

    assert set(selecting) == {"windows_event_signature", "windows_ta_data"}, selecting

    tags = _conf("tags.conf")
    granted = set()
    for name in selecting:
        body = stanza(tags, "eventtype=" + name)
        if body:
            granted |= set(re.findall(r"(?m)^(\w+)\s*=\s*enabled", body))
    assert granted == {"track_event_signatures"}, granted

    declared = get_ta("powershell")["sourcetypes"][0]
    assert declared["datamodels"] == [], "the registry claims a datamodel"
    assert declared["datamodel_conditions"] == []
    assert set(declared["eventtypes"]) == set(selecting)
    assert set(declared["tags"]) == granted


# ── the two shapes that are silent when wrong ───────────────────────────────

@needs_ta
def test_the_eventdata_transform_needs_single_quotes():
    """Double-quoted Name attributes would cost the whole EventData, silently.

    Applied to EventData_Xml alone, as its SOURCE_KEY says. Running it over the
    whole event would match the System block's `<Provider Name=...>` instead and
    prove nothing about the five fields that matter.
    """
    _src, block_regex, _fmt = transform("eventdata_xml_block")
    _src, regex, _fmt = transform("eventdata_xml_data")

    event_data = block_regex.search(events(1)[0]).group(1)
    assert len(regex.findall(event_data)) == 5, "not all five Data fields extract"

    double = re.sub(r"<Data Name='([^']*)'>", r'<Data Name="\1">', event_data)
    assert '<Data Name="' in double and "<Data Name='" not in double
    assert regex.findall(double) == [], \
        "the transform would now accept double quotes — the generator's comment is stale"


@needs_ta
def test_script_text_is_escaped_so_the_transform_keeps_all_of_it():
    """`([^<]*)` stops at a raw `<`, so the text has to arrive escaped."""
    script = 'if ($n <5> $x) { Write-Output "a&b" } # <#comment#>'
    assert "<" in script and ">" in script and "&" in script   # the fixture's point
    event = events(1, script_block_text=script)[0]
    assert "&amp;" in event and "&lt;" in event and "&gt;" in event
    extracted = extract(event)["ScriptBlockText"]
    assert extracted == (script.replace("&", "&amp;")
                               .replace("<", "&lt;").replace(">", "&gt;")), extracted
    # The point is that nothing was lost. Splunk does not decode entities in a
    # transform, so a real event carrying `<` yields this same escaped form —
    # and unescaping it here returns the whole script, truncated at nothing.
    assert (extracted.replace("&lt;", "<").replace("&gt;", ">")
                     .replace("&amp;", "&")) == script


# ── the fields the detections read ──────────────────────────────────────────

@needs_ta
def test_every_canonical_grouped_field_is_present_on_a_script_backed_event():
    for event in events(80, path="C:\\Scripts\\Task.ps1"):
        fields = extract(event)
        missing = [name for name in CANONICAL_BY if not fields.get(name)]
        assert not missing, (missing, event[:160])


@needs_ta
def test_path_is_empty_for_an_interactive_block_and_set_for_a_file_backed_one():
    """Both are real states; only the file-backed one reaches the Path detection.

    `windows_powershell_invoke_restmethod_ip_information_collection` groups by
    Path with no fillnull in front of it, so an interactive block cannot show up
    there — on a real host either.
    """
    assert extract(events(1, path="")[0])["Path"] == ""
    assert extract(events(1, path="C:\\Scripts\\Task.ps1")[0])["Path"] \
        == "C:\\Scripts\\Task.ps1"

    generator = PowerShellLogGenerator()
    paths = [generator.script_block_event()["path"] for _ in range(400)]
    assert any(p == "" for p in paths), "no interactive block is ever generated"
    assert any(p for p in paths), "no file-backed block is ever generated"


@needs_ta
def test_signature_and_signature_id_come_from_the_add_on():
    expected = signature_for(SCRIPT_BLOCK_EVENT_ID)
    assert expected == "Microsoft-Windows-PowerShell Execute a Remote Command"
    for event in events(20):
        fields = extract(event)
        assert fields["signature"] == expected
        assert fields["signature_id"] == str(SCRIPT_BLOCK_EVENT_ID)
        assert fields["EventCode"] == str(SCRIPT_BLOCK_EVENT_ID)


@needs_ta
def test_dest_is_built_by_the_add_ons_own_regex():
    for event in events(20, dest="WKS-LAB-07"):
        assert extract(event)["dest"] == "WKS-LAB-07"


@needs_ta
def test_the_system_block_carries_the_real_provider_and_opcode():
    for event in events(20):
        fields = extract(event)
        assert fields["Name"] == PROVIDER_NAME
        assert fields["Guid"] == PROVIDER_GUID
        assert fields["Opcode"] == OPCODE
        assert fields["Channel"] == CHANNEL
        assert int(fields["ProcessID"]) > 0
    # Straight off the real event this source was modelled on. Spelled out as
    # literals: comparing the extracted value to the constant that produced it
    # would pass whatever the constant said.
    assert PROVIDER_NAME == "Microsoft-Windows-PowerShell"
    assert PROVIDER_GUID == "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"
    assert (OPCODE, KEYWORDS, LEVEL, TASK) == ("15", "0x0", "5", "2")


# ── the user, which this channel carries only as a SID ──────────────────────

@needs_ta
def test_the_account_becomes_a_stable_sid_and_user_id():
    first = extract(events(1, user="a.moreau")[0])
    assert first["UserID"] == user_sid("a.moreau")
    assert first["user_id"] == first["UserID"]
    assert first["UserID"].startswith("S-1-5-21-")
    # Stable across events, which is what the detections group by.
    for event in events(10, user="a.moreau"):
        assert extract(event)["user_id"] == first["user_id"]
    assert user_sid("a.moreau") != user_sid("jsmith")


@needs_ta
def test_no_user_name_travels_on_this_channel():
    """There is no `user` to build, which is why two detections rename UserID."""
    body = stanza(_conf("props.conf"), "source::" + SOURCE)
    assert "user" not in body.lower().replace("microsoft-windows-powershell", "")
    for event in events(40, user="a.moreau"):
        assert "a.moreau" not in event


@needs_ta
def test_a_machine_script_runs_as_system():
    for event in events(20, as_system=True):
        assert extract(event)["UserID"] == SYSTEM_SID
    generator = PowerShellLogGenerator()
    seen = {generator.script_block_event()["user_id"] == SYSTEM_SID
            for _ in range(400)}
    assert seen == {True, False}, "every event is SYSTEM, or none is"


# ── the noise, against the detections themselves ────────────────────────────

CONDITIONS = json.loads((Path(__file__).parent / "powershell_4104_conditions.json")
                        .read_text())


def splunk_glob(pattern):
    """Splunk's `field="*x*"`: only `*` is a wildcard, and the match is whole-value.

    Eleven of these globs spell a path as `System32\\\\config\\\\SAM`, because inside
    a quoted SPL string a backslash is escaped. Splunk's own handling of that in
    a wildcard is inconsistent, so both forms are accepted here — one backslash
    or two. Being permissive is the safe direction for a test whose job is to
    prove benign events fire *nothing*.
    """
    double = re.escape("\\") * 2
    segments = [re.escape(part).replace(double, r"\\{1,2}")
                for part in pattern.split("*")]
    return re.compile("^" + ".*".join(segments) + "$", re.IGNORECASE | re.DOTALL)


def evaluate(node, text):
    """One detection's parsed filter against a script block.

    The fixture holds a boolean AST, not a flat list, because two detections in
    three are of the form `(A OR B) AND C`. Flattening that to `A AND B AND C`
    was the first attempt, and it erred towards *not* firing — which would have
    made a noisy corpus look clean. `["true"]` stands for every clause that is
    not about ScriptBlockText, so the oracle stays conservative in the other
    direction: it may over-report, never under-report.
    """
    kind = node[0]
    if kind == "true":
        return True
    if kind == "match":
        return bool(splunk_glob(node[1]).match(text))
    if kind == "not":
        return not evaluate(node[1], text)
    if kind == "and":
        return all(evaluate(child, text) for child in node[1])
    if kind == "or":
        return any(evaluate(child, text) for child in node[1])
    raise AssertionError(f"unknown node {kind!r}")


def fired_by(text):
    """Which detections this script text would select, catch-all aside."""
    return [name for name, ast in CONDITIONS["detections"].items()
            if name != CATCH_ALL and evaluate(ast, text)]


def test_the_vendored_conditions_cover_every_published_detection():
    assert len(CONDITIONS["detections"]) == 121
    assert all(ast and isinstance(ast, list) for ast in CONDITIONS["detections"].values())
    assert CONDITIONS["_provenance"]["data_source"] == \
        "Powershell Script Block Logging 4104"
    assert CATCH_ALL in CONDITIONS["detections"]


def test_the_oracle_can_tell_a_hit_from_a_miss():
    """Guard the guard: a check that never fires proves nothing.

    The `(A OR B) AND C` shape gets its own case because getting it wrong is
    what a flat list of ANDed globs did, and it failed silently in the direction
    that matters — towards not firing.
    """
    assert fired_by("Get-Date -Format o") == []

    # (Add-MpPreference OR Set-MpPreference) AND -exclusion
    exclusion = "powershell_windows_defender_exclusion_commands.yml"
    assert exclusion in fired_by('Add-MpPreference -ExclusionPath "C:\\Temp"')
    assert exclusion in fired_by('Set-MpPreference -ExclusionExtension ".ps1"'), \
        "the OR branch is not reachable — the filter was flattened into an AND"
    assert exclusion not in fired_by("Add-MpPreference -DisableIOAVProtection $true"), \
        "the AND arm is not enforced"

    # A glob with no leading wildcard anchors at the start of the value.
    share = "windows_file_share_discovery_with_powerview.yml"
    assert share in fired_by("Invoke-ShareFinder -CheckShareAccess")
    assert share not in fired_by("# then Invoke-ShareFinder -CheckShareAccess")

    # A path spelled with SPL-escaped backslashes still matches a real path.
    com = "powershell_com_hijacking_inprocserver32_modification.yml"
    assert com in fired_by(
        r"New-Item -Path 'HKCU:\Software\Classes\CLSID\{0358b920}\InProcServer32'"), \
        "an escaped backslash in the glob no longer matches one on the wire"


def test_no_benign_script_block_fires_a_published_detection():
    generator = PowerShellLogGenerator()
    seen, offenders = set(), {}
    for _ in range(3000):
        text = generator.script_block_event()["script_block_text"]
        if text in seen:
            continue
        seen.add(text)
        hits = fired_by(text)
        if hits:
            offenders[text[:70]] = hits
    assert not offenders, offenders
    assert len(seen) >= 25, f"the corpus shrank to {len(seen)} blocks"


# ── the wire ────────────────────────────────────────────────────────────────

def test_every_event_is_one_line():
    """The app's contract, and the reason the corpus holds no multi-line block."""
    for event in events(200):
        assert "\n" not in event and "\r" not in event


def test_the_registry_and_the_generator_agree_on_the_wire_metadata():
    entry = get_ta("powershell")
    assert entry["hec_default_sourcetype"] == SOURCETYPE
    assert entry["syslog_viable"] is False
    sourcetype = entry["sourcetypes"][0]
    assert sourcetype["name"] == SOURCE
    assert sourcetype["hec_source"] == SOURCE
    assert PowerShellLogGenerator.LOG_TYPE == "powershell"


@needs_ta
def test_the_channel_is_what_makes_the_add_on_stanza_apply():
    """The whole chain, end to end, with nothing taken on trust.

    A forwarder does not send `source`: the add-on derives it at index time from
    the Channel element, with `ta-windows-fix-xml-source`. So the Channel we
    write decides which props.conf stanza applies, and therefore whether `dest`
    and `signature` exist at all. Asserting `CHANNEL in event` would only
    compare the generator to itself; this replays the transform instead and
    checks the source it produces is the one the add-on has a stanza for.
    """
    _src, regex, fmt = transform("ta-windows-fix-xml-source")
    assert fmt == "source::XmlWinEventLog:$1", fmt

    for event in events(20):
        channel = regex.search(event).group(1)
        derived = fmt.split("::", 1)[1].replace("$1", channel)
        assert derived == SOURCE, derived
        assert stanza(_conf("props.conf"), "source::" + derived) is not None, \
            f"the add-on has no stanza for the source this event lands under: {derived}"

    # And the literal the add-on names, so a rename of either side is caught.
    assert SOURCE == "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
    assert CHANNEL == "Microsoft-Windows-PowerShell/Operational"


@needs_ta
def test_every_block_is_part_one_of_one():
    for event in events(40):
        fields = extract(event)
        assert fields["MessageNumber"] == "1"
        assert fields["MessageTotal"] == "1"
        assert len(fields["ScriptBlockText"]) < 20000, \
            "a block this size would be split on a real host"


def test_the_ai_values_reach_the_event(tmp_path, monkeypatch):
    from environment_manager import EnvironmentManager

    env = EnvironmentManager(config_file=str(tmp_path / "environment.json"))
    env.create_entity("laptop", "endpoint", nt_host="WKS-ENV-01")
    env.create_account("env.user", account_type="standard")

    generator = PowerShellLogGenerator()
    env.inject_into(generator, "powershell", 100)
    assert "WKS-ENV-01" in generator.hostnames, \
        "powershell is not wired into ENTITY_TYPE_ROLES"
    assert "env.user" in generator.usernames, \
        "powershell is not wired into ACCOUNT_TYPE_ROLES"

    lines = [generator.generate() for _ in range(200)]
    assert any("WKS-ENV-01" in line for line in lines)
    assert any(user_sid("env.user") in line for line in lines)


def test_the_timestamp_has_the_precision_a_real_event_carries():
    """Nine fractional digits — measured across 127 real 4104 events.

    Nothing in Splunk_TA_windows declares a TIME_FORMAT for this channel, so
    Splunk auto-detects it and other precisions would still index. This is
    fidelity to the wire rather than a parsing requirement.
    """
    for event in events(20):
        stamp = re.search(r"SystemTime='([^']+)'", event).group(1)
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z", stamp), stamp
