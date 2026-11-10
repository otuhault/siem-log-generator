"""Characterization tests for the 10 log generators in REGISTRY.

These lock in the observable output of every generator: shape, single-line
contract, default-category coverage and per-vendor format conformance.
"""

import re
import xml.etree.ElementTree as ET

import pytest

from log_generators.registry import GENERATORS, REGISTRY
from helpers import build_default_instances, default_categories, install_category_spy

ALL_LOG_TYPES = sorted(REGISTRY)

# Generators where one instance is built per source, so category coverage is
# structural rather than observed through a dispatch spy.
MULTI_INSTANCE = {"apache", "windows", "zscaler"}


# ---------------------------------------------------------------------------
# Registry-wide smoke properties
# ---------------------------------------------------------------------------

def test_registry_exposes_every_generator_once():
    assert len(REGISTRY) == len(GENERATORS), "a generator is registered twice or not at all"
    assert len(REGISTRY) == 12


@pytest.mark.parametrize("log_type", ALL_LOG_TYPES)
def test_instantiates_with_sourcetype_config_defaults(log_type):
    """Every generator builds from its own declared defaults, unaided."""
    instances = build_default_instances(log_type)
    assert instances, f"{log_type} produced no instance"

    cls = REGISTRY[log_type]
    for instance, _category in instances:
        assert isinstance(instance, cls)
        assert callable(instance.generate)

    # Class-level contract relied upon by log_senders.start_sender
    assert isinstance(cls.LOG_TYPE, str) and cls.LOG_TYPE == log_type
    assert isinstance(cls.AVG_LOG_SIZE, int) and cls.AVG_LOG_SIZE > 0
    assert "param_key" in cls.SOURCETYPE_CONFIG
    assert cls.SOURCETYPE_CONFIG["defaults"]


@pytest.mark.parametrize("log_type", ALL_LOG_TYPES)
def test_generate_returns_single_line_non_empty_string(log_type):
    """generate() returns one ready-to-emit line with no embedded newline.

    log_senders writes `generator.generate() + '\\n'`, so an interior newline
    would silently split one event into several.
    """
    for instance, _category in build_default_instances(log_type):
        for _ in range(20):
            line = instance.generate()
            assert isinstance(line, str), f"{log_type} did not return str"
            assert line, f"{log_type} returned an empty string"
            assert line.strip(), f"{log_type} returned blank output"
            if log_type in ("windows", "active_directory"):
                # Windows Event XML is pretty-printed and legitimately multi-line.
                continue
            assert "\n" not in line, f"{log_type} emitted an interior newline"


@pytest.mark.parametrize("log_type", ALL_LOG_TYPES)
def test_two_hundred_calls_cover_every_default_category(log_type):
    """200 calls: no exception, and every default category is exercised."""
    expected = set(default_categories(log_type))
    observed = set()
    produced = 0

    if log_type in MULTI_INSTANCE:
        instances = build_default_instances(log_type)
        per_instance = max(1, 200 // len(instances))
        for instance, category in instances:
            for _ in range(per_instance):
                assert instance.generate()
                produced += 1
            observed.add(category)
    else:
        (instance, _), = build_default_instances(log_type)
        observed = install_category_spy(instance, log_type)
        for _ in range(200):
            assert instance.generate()
            produced += 1

    assert produced >= 200 or log_type in MULTI_INSTANCE
    missing = expected - observed
    assert not missing, f"{log_type}: categories never produced in 200 calls: {sorted(missing)}"
    assert not (observed - expected), f"{log_type}: unexpected categories {sorted(observed - expected)}"


# ---------------------------------------------------------------------------
# Format conformance — one assertion per generator
# ---------------------------------------------------------------------------

def _sample(log_type, n=60, category=None):
    """Collect n lines. `category` restricts a multi-instance generator."""
    lines = []
    for instance, inst_category in build_default_instances(log_type):
        if category is not None and inst_category != category:
            continue
        lines.extend(instance.generate() for _ in range(n))
    assert lines, f"no sample produced for {log_type}/{category}"
    return lines


# PAN-OS CSV width is fixed per log type (measured, no variance).
PALOALTO_COMMA_COUNTS = {"traffic": 104, "threat": 121, "system": 25}


def test_format_paloalto_is_pri_framed_csv():
    """<PRI> syslog header followed by a PAN-OS CSV record."""
    pattern = re.compile(r"^<\d{1,3}>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ ")
    for line in _sample("paloalto"):
        assert pattern.match(line), f"missing PRI/syslog header: {line[:90]}"
        payload = line.split(" ", 4)[-1]
        assert payload.count(",") >= 25, f"payload is not CSV: {line[:90]}"


@pytest.mark.parametrize("pa_log_type,expected_commas", sorted(PALOALTO_COMMA_COUNTS.items()))
def test_format_paloalto_csv_width_per_log_type(pa_log_type, expected_commas):
    """Record the exact CSV width of each PAN-OS log type.

    traffic/threat are the wide records (>=90 commas); system is the narrow
    26-field record, so a single global width assertion would not hold.
    """
    generator = REGISTRY["paloalto"](log_types=[pa_log_type])
    for _ in range(40):
        line = generator.generate()
        assert line.count(",") == expected_commas, (
            f"pan:{pa_log_type} width changed: {line.count(',')} != {expected_commas}"
        )
    if pa_log_type in ("traffic", "threat"):
        assert expected_commas >= 90


def test_format_cisco_ios_carries_facility_severity_mnemonic():
    pattern = re.compile(r"%[A-Z][A-Z0-9_]*-\d-[A-Z][A-Z0-9_]*:")
    for line in _sample("cisco_ios"):
        assert pattern.search(line), f"no %FAC-SEV-MNEMONIC in: {line[:90]}"


def test_format_cisco_asa_carries_asa_message_id():
    pattern = re.compile(r"%ASA-\d-\d{6}:")
    for line in _sample("cisco_asa"):
        assert "%ASA-" in line, f"missing %ASA- marker: {line[:90]}"
        assert pattern.search(line), f"malformed ASA message id: {line[:90]}"



def test_format_zscaler_web_is_wide_tab_separated_key_values():
    for line in _sample("zscaler", n=40, category="web"):
        assert line.count("\t") >= 40, f"expected >=40 tabs, got {line.count(chr(9))}"
        fields = line.split("\t")
        kv = [f for f in fields if "=" in f]
        assert len(kv) >= 40, f"expected >=40 key=value fields, got {len(kv)}"
        for field in kv[:10]:
            assert re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", field), f"not key=value: {field!r}"


def test_format_windows_is_well_formed_xml():
    for line in _sample("windows", n=30):
        root = ET.fromstring(line)          # raises on malformed XML
        assert root.tag.endswith("Event")
        assert root.find("{*}System") is not None or root.find("System") is not None


def test_format_active_directory_is_well_formed_xml():
    for line in _sample("active_directory", n=30):
        root = ET.fromstring(line)          # raises on malformed XML
        assert root.tag.endswith("Event")


def test_format_apache_access_matches_common_log_format():
    """Default apache source is 'combined': CLF plus referer and user-agent."""
    clf = re.compile(
        r'^(\S+) (\S+) (\S+) '
        r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] '
        r'"([A-Z]+) (\S+) (HTTP/\d\.\d)" '
        r'(\d{3}) (\d+|-)'
    )
    for line in _sample("apache", n=40):
        assert clf.match(line), f"not Common Log Format: {line[:110]}"


def test_format_ssh_is_bsd_syslog_with_daemon_and_pid():
    pattern = re.compile(
        r"^[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} "   # BSD timestamp
        r"(\S+) "                                        # hostname
        r"([A-Za-z_-]+)\[(\d+)\]: "                      # daemon[pid]:
    )
    for line in _sample("ssh", n=60):
        match = pattern.match(line)
        assert match, f"not BSD syslog with daemon[pid]: {line[:110]}"
        assert match.group(1), "empty hostname"
        assert match.group(3).isdigit(), "pid is not numeric"


# ---------------------------------------------------------------------------
# Format contracts previously recorded as known bugs (audit §8.1 and §8.2).
# Both are fixed, so they are plain assertions now.
# ---------------------------------------------------------------------------

def test_format_apache_error_log_matches_default_errorlogformat():
    """Apache 2.4 default ErrorLogFormat, field by field.

    Documented default (threaded MPMs):
        "[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\\ %a] %M"
    Reference line from the docs:
        [Thu May 12 08:28:57.652118 2011] [core:error] [pid 8777:tid 4326490112] \
[client ::1:58619] AH00124: ...
    https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat

    %{u}t is microsecond precision: 6 sub-second digits and a 4-digit year.
    """
    generator = REGISTRY["apache"](log_type="error")
    line_pattern = re.compile(
        r"^\[(?P<ts>"
        r"(?P<dow>Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
        r"(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
        r"(?P<day>[ 0-3]?\d) "
        r"(?P<time>\d{2}:\d{2}:\d{2})\.(?P<usec>\d{6}) "
        r"(?P<year>\d{4})"
        r")\] "
        r"\[(?P<level>[a-z]+)\] "
        r"\[pid (?P<pid>\d+):tid (?P<tid>\d+)\] "
        r"\[client (?P<client>[^\]]+)\] "
        r"(?P<message>.+)$"
    )

    for _ in range(60):
        line = generator.generate()
        match = line_pattern.match(line)
        assert match, f"does not match the default ErrorLogFormat: {line[:120]}"

        assert len(match.group("year")) == 4, f"year must be 4 digits: {match.group('year')!r}"
        assert len(match.group("usec")) == 6, (
            f"%{{u}}t is microsecond precision, expected 6 digits, "
            f"got {len(match.group('usec'))}: {match.group('usec')!r}"
        )
        assert match.group("message").strip(), "empty message"

        # The timestamp must round-trip through the documented strftime shape.
        from datetime import datetime as _dt
        _dt.strptime(match.group("ts"), "%a %b %d %H:%M:%S.%f %Y")


def test_ssh_daemon_tag_casing_follows_debian_convention():
    """auth.log emits lowercase 'sshd' and uppercase 'CRON' as syslog tags.

    The pam_unix(...) argument stays lowercase for both services.
    """
    cfg = REGISTRY["ssh"].SOURCETYPE_CONFIG
    generator = REGISTRY["ssh"](**{cfg["param_key"]: list(cfg["defaults"])})

    lines = [generator.generate() for _ in range(500)]

    uppercase_sshd = [line for line in lines if "SSHD[" in line]
    assert not uppercase_sshd, (
        f"{len(uppercase_sshd)}/500 events used uppercase SSHD[, "
        f"e.g. {uppercase_sshd[0][:100]}"
    )

    lowercase_cron = [line for line in lines if "cron[" in line]
    assert not lowercase_cron, (
        f"{len(lowercase_cron)}/500 events used lowercase cron[, "
        f"e.g. {lowercase_cron[0][:100]}"
    )

    assert any("sshd[" in line for line in lines), "no sshd[ tag produced at all"

    # pam_unix keeps the service name lowercase whatever the syslog tag is.
    for line in lines:
        if "pam_unix(" in line:
            service = re.search(r"pam_unix\((\w+):session\)", line)
            assert service, f"malformed pam_unix stanza: {line[:100]}"
            assert service.group(1).islower(), (
                f"pam_unix argument must stay lowercase: {line[:100]}"
            )
            tag = re.search(r"\s([A-Za-z_-]+)\[\d+\]:", line).group(1)
            expected = {"sshd": "sshd", "cron": "CRON"}[service.group(1)]
            assert tag == expected, (
                f"service {service.group(1)!r} should be tagged {expected!r}, "
                f"got {tag!r}: {line[:100]}"
            )
