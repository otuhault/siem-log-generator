"""XmlWinEventLog events against Splunk_TA_windows, read from disk.

Reported from a live Splunk: on XmlWinEventLog with source XmlWinEventLog:Security
— the right sourcetype and the right source — `EventCode` and `Computer`
extracted, and every `<Data Name=…>` field did not, so nothing reached Endpoint.

The metadata was never the problem. Splunk_TA_windows 11 extracts EventData at
search time with regexes written against the XML Windows actually renders —
single-quoted attributes — and our templates wrote double quotes. The System
regexes accept either quote, which is why half the event worked.

These tests run the add-on's own transforms over our events, the way Splunk
does: the block regex on the raw event, then the field regex on the block. They
fail the moment an add-on upgrade or a new template stops lining up.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import pytest

from helpers import compile_pcre

from attack_generators import AttackGeneratorFactory
from log_generators import REGISTRY
from log_generators.windows_xml import render, system_time

TA = Path(__file__).resolve().parents[1] / "TAs" / "Splunk_TA_windows" / "default"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _events(n=300):
    """Every producer of XmlWinEventLog: each Windows channel, AD, the TOR attack."""
    out = []
    windows = REGISTRY["windows"]
    for channel in ("Security", "System", "Application"):
        generator = windows(source=channel, render_format="xml")
        out += [(f"windows/{channel}", generator.generate()) for _ in range(n)]
    ad = REGISTRY["active_directory"]
    config = ad.SOURCETYPE_CONFIG
    generator = ad(**{config["param_key"]: config["defaults"]})
    out += [("active_directory", generator.generate()) for _ in range(n)]
    tor = AttackGeneratorFactory.get_generator("windows_tor_client_execution")
    out += [("attack/tor", tor.generate()) for _ in range(50)]
    return out


@pytest.fixture(scope="module")
def events():
    return _events()


def _data_fields(event):
    """name -> value for every <Data Name=…> element, read with a real parser."""
    root = ET.fromstring(event)
    return {d.get("Name"): (d.text or "")
            for d in root.iter(f"{NS}Data") if d.get("Name") is not None}


# ── the shape Windows renders ───────────────────────────────────────────────

def test_every_event_is_one_line_with_single_quoted_attributes(events):
    """One line between elements. A value may still hold a line break —
    Windows separates the entries of PrivilegeList (4672) that way."""
    for label, event in events:
        assert not re.search(r">\s*\n\s*<", event), f"{label}: indented over several lines"
        assert not re.search(r'\s\w+="', event), f"{label}: double-quoted attribute"
        ET.fromstring(event)            # and still well-formed


def test_system_time_is_utc_with_seven_digits(events):
    now = datetime.now(timezone.utc)
    shape = re.compile(r"<TimeCreated SystemTime='(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z)'/>")
    for label, event in events:
        match = shape.search(event)
        assert match, f"{label}: {re.search(r'<TimeCreated[^>]*>', event)}"
        stamped = datetime.strptime(match.group(1)[:26], "%Y-%m-%dT%H:%M:%S.%f")
        drift = abs((stamped.replace(tzinfo=timezone.utc) - now).total_seconds())
        # Local time labelled as UTC would be off by the machine's offset.
        assert drift < 120, f"{label}: SystemTime is {drift:.0f}s from now in UTC"


def test_rendering_changes_the_form_and_never_the_content():
    """Quotes, ampersands and angle brackets survive, in text and in attributes;
    a child in another namespace keeps its own."""
    source = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="O'Brien &amp; Co" Guid="{1}" /></System>
      <EventData>
        <Data Name="CommandLine">"C:\\a b\\x.exe" --flag &lt;in&gt; &amp; 'quoted'</Data>
        <Data Name="Empty" />
      </EventData>
      <UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>bob</SubjectUserName></LogFileCleared></UserData>
    </Event>"""
    rendered = render(source)

    assert "Name='O&apos;Brien &amp; Co'" in rendered
    assert _data_fields(rendered) == _data_fields(source)
    assert "<LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>" in rendered
    assert render(rendered) == rendered, "rendering is not idempotent"


@pytest.mark.parametrize("given, expected", [
    ("2026-09-14T15:51:56.4359330Z", "2026-09-14T15:51:56.4359330Z"),
    ("2026-09-14T17:51:56.435933+02:00", "2026-09-14T15:51:56.4359330Z"),
    ("2026-02-18T10:30:01.000Z", "2026-02-18T10:30:01.0000000Z"),
])
def test_system_time_normalises_to_utc(given, expected):
    assert system_time(given) == expected


# ── the add-on's own extractions ────────────────────────────────────────────

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


needs_ta = pytest.mark.skipif(not TA.exists(), reason="Splunk_TA_windows not present in TAs/")


@needs_ta
def test_the_add_on_extracts_every_data_field(events):
    """The reported bug: REPORT-0xml_block_extract then REPORT-0xml_kv_extract,
    exactly as [XmlWinEventLog] chains them, must yield every <Data> field."""
    transforms = _transforms()
    block = compile_pcre(transforms["eventdata_xml_block"]["REGEX"])
    field = compile_pcre(transforms["eventdata_xml_data"]["REGEX"])

    for label, event in events:
        expected = _data_fields(event)
        if not expected:
            continue
        extracted = {}
        for block_match in block.finditer(event):
            for match in field.finditer(block_match.group(1)):
                extracted[match.group(1)] = match.group(2)
        missing = sorted(set(expected) - set(extracted))
        assert not missing, f"{label}: the add-on extracts none of {missing}"
        assert extracted == expected, label


@needs_ta
def test_every_single_quoted_transform_matches_the_fields_we_emit(events):
    """Sixteen more transforms name one Data field in single quotes — process,
    new_process, parent_process, the command line. Each must match wherever
    that field is present."""
    transforms = _transforms()
    by_field = {}
    for name, stanza in transforms.items():
        pcre = stanza.get("REGEX", "")
        wanted = re.search(r"<Data Name='(\(?[\w|()]+\)?)'>", pcre)
        if wanted:
            # Some are scoped to an event id (4798, 5156|5157) and rightly match
            # nothing else.
            scope = re.search(r"<EventID>\(?([\d|]+)\)?<\\/EventID>", pcre)
            by_field[name] = (compile_pcre(pcre), wanted.group(1),
                              scope.group(1) if scope else None)

    checked = set()
    for label, event in events:
        present = _data_fields(event)
        event_id = re.search(r"<EventID>(\d+)</EventID>", event).group(1)
        for name, (regex, field_pattern, scope) in by_field.items():
            if scope and not re.fullmatch(scope, event_id):
                continue
            if any(re.fullmatch(field_pattern, field) for field in present):
                assert regex.search(event), f"{label}: [{name}] does not match"
                checked.add(name)
    # The Endpoint fields must actually have been exercised, or a passing run
    # would prove nothing.
    endpoint = {"new_process_for_windows_security_from_xml",
                "parent_process_for_windows_security_from_xml",
                "process_command_line_for_xml",
                "process_id_for_windows_security_from_xml__var1"}
    assert endpoint <= checked, f"not exercised: {sorted(endpoint - checked)}"


@needs_ta
def test_the_system_time_extraction_matches(events):
    regex = compile_pcre(_transforms()["extract_systemtime"]["REGEX"])
    for label, event in events:
        match = regex.search(event)
        assert match and match.group(1).endswith("Z"), label
