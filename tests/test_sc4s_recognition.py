"""What the three network sources put on the syslog wire, pinned literally.

Two of these three were working against a live SC4S and got changed anyway, on
the strength of a reading of SC4S's own filter files. The reading was wrong and
the observation was right. So this file does not reason about SC4S: it pins the
exact wire shape of each source, and the two that work are pinned so they cannot
be altered as collateral again.

Confirmed against a running SC4S 3.40.0:

    cisco_asa   <166>Sep 14 11:24:54 asa-edge-gw : %ASA-6-725002: …      identified
    fortigate   <189>date=2026-09-14 time=… devname="fgt-…" devid=…      identified
    cisco_ios   009046: Sep 14 00:05:58.677: %STANDBY-6-STATECHANGE: …   NOT identified

The third is the one this file also explains. The events landed in
`sc4s:fallback` carrying `PRI=13` — user.notice, the value syslog-ng assigns when
a message arrives with no priority at all — because SC4S's source only offers a
message to the Cisco parsers when it matches `^\\<\\d+\\>`.
"""

import re

import pytest

from log_generators import REGISTRY
from syslog_framing import SyslogFramedGenerator, SyslogFramer, host_pool_for
from ta_registry import get_ta

HAS_PRI = re.compile(r"^<(\d+)>")


def _wire(log_type, n=40):
    """Exactly what the syslog sink sends, framing included."""
    config = REGISTRY[log_type].SOURCETYPE_CONFIG
    generator = REGISTRY[log_type](**{config["param_key"]: config["defaults"]})
    framing = get_ta(log_type).get("syslog_framing")
    if not framing:
        return [generator.generate() for _ in range(n)]     # self-framing
    wrapped = SyslogFramedGenerator(generator, SyslogFramer(framing, host_pool_for(log_type)))
    return [wrapped.generate() for _ in range(n)]


# ── the two that work: pinned so they cannot change by accident ─────────────

def test_cisco_asa_keeps_its_own_rfc3164_frame():
    """ASA writes the priority itself, in the generator. It declares no
    `syslog_framing` and must never acquire one."""
    assert "syslog_framing" not in get_ta("cisco_asa")
    shape = re.compile(r"^<\d+>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}\s\S+\s:\s%ASA-\d-\d{6}:\s")
    for line in _wire("cisco_asa"):
        assert shape.match(line), line


def test_fortigate_sends_the_priority_and_then_its_payload():
    """Identified by SC4S in this exact shape. A pass over this file once added
    a BSD header on the theory that [sc4s-syslog] required one; it does not, and
    the change broke a working source. The shape is pinned rather than argued."""
    assert get_ta("fortigate")["syslog_framing"]["header"] == "none"
    shape = re.compile(r'^<\d+>date=\d{4}-\d{2}-\d{2} time=\d{2}:\d{2}:\d{2} devname="[^"]+" devid="F')
    for line in _wire("fortigate"):
        assert shape.match(line), line


# ── the one that does not: SC4S's Cisco rules, transcribed ──────────────────
#
#   package/shared/conf.d/sources/source_syslog/plugin.jinja
#   package/shared/addons/cisco/app-almost-syslog-cisco_syslog.conf

IOS_CLAIMS = ": %"
IOS_HEADER_LOOKS_CISCO = [re.compile(p) for p in (r": ?|\*", r"[A-Z]{3,4}:?$", r"\d+:?$")]
IOS_HEADER_REJECTS = [re.compile(p) for p in (r"[a-z]\S+$", r" \w+\[\d+\]$")]

#: Four characters minimum, and never a run of four or more digits — which is
#: what rules out the sequence number an IOS device puts in its own header.
IOS_HOST = re.compile(
    r"(?:[ ]|^(?P<pri>\<\d+\>)|^)"
    r"(?P<host>(?<!\*)(?!\d{4,})(?!\w+\[)"
    r"(?:[0-9A-Za-z\-_]{4,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"
)

#: tests/test_cisco_ios.py in SC4S, rendered. The control group: these are
#: messages SC4S ships a passing test for, so a gate that rejects one of them is
#: a gate transcribed wrongly rather than a wire built wrongly.
SC4S_OWN_IOS = [
    "<166>30: abcde-fghij: 6340004: Mar  4 11:45:20: %SEC-6-IPACCESSLOGP: list "
    "INET-BLOCK permitted tcp 192.168.20.252(55244) -> 10.54.3.178(44818), 1 packet",
    "<166>30: abcde-fghij: Apr 29 13:58:46.411: %SYS-6-LOGGINGHOST_STARTSTOP: "
    "Logging to host 192.168.1.239 stopped - CLI initiated",
    "<166>abcde-fghij: Apr 29 13:58:46.411: %SYSMGR-STANDBY-3-SHUTDOWN_START: "
    "The System Manager has started the shutdown procedure.",
]


def _ios_host_sc4s_would_set(datagram):
    """Walk SC4S's Cisco gates over one datagram; return the host it would set."""
    assert HAS_PRI.match(datagram), "no priority: the Cisco parsers are never tried"
    body = HAS_PRI.sub("", datagram, count=1)
    assert IOS_CLAIMS in body, "app-almost-syslog-cisco_syslog would not claim it"

    header, _, _rest = body.partition(": %")
    assert any(p.search(header) for p in IOS_HEADER_LOOKS_CISCO), (
        f"header {header!r} matches none of SC4S's Cisco shapes")
    for pattern in IOS_HEADER_REJECTS:
        assert not pattern.search(header), (
            f"header {header!r} trips SC4S's {pattern.pattern!r} guard")

    match = IOS_HOST.search(header)
    return match.group("host") if match else None


@pytest.mark.parametrize("datagram", SC4S_OWN_IOS)
def test_sc4s_own_ios_messages_pass_these_gates(datagram):
    """The control. If this fails, the transcription is wrong, not our wire."""
    assert _ios_host_sc4s_would_set(datagram) == "abcde-fghij"


def test_our_ios_wire_travels_the_same_path_and_names_its_device():
    devices = set()
    for datagram in _wire("cisco_ios", n=60):
        host = _ios_host_sc4s_would_set(datagram)
        assert host, f"SC4S would find no device name in {datagram!r}"
        devices.add(host)

    known = set(REGISTRY["cisco_ios"](event_categories=["system"]).hostnames)
    assert devices <= known, f"unexpected device names: {sorted(devices - known)}"
    assert len(devices) > 1, "every event names the same device"


def test_the_sequence_number_never_stands_in_for_the_device():
    """SC4S's host regex refuses four or more digits, so the origin id has to
    come before the sequence number — the order IOS itself uses."""
    for datagram in _wire("cisco_ios", n=30):
        body = HAS_PRI.sub("", datagram, count=1)
        origin, _, rest = body.partition(": ")
        assert not origin.isdigit(), f"the sequence number leads: {datagram!r}"
        assert re.match(r"^\d+: ", rest), f"no sequence number after it: {datagram!r}"


def test_the_ios_priority_severity_is_the_one_in_the_message_tag():
    """IOS derives its PRI severity from %FACILITY-SEVERITY-MNEMONIC, so the two
    can never disagree. local7 is the device default."""
    for datagram in _wire("cisco_ios"):
        pri = int(HAS_PRI.match(datagram).group(1))
        tag = re.search(r"%[A-Z0-9_]+-(\d)-", datagram)
        assert tag, datagram
        assert pri == 23 * 8 + int(tag.group(1)), datagram


def test_ios_must_not_be_given_an_rfc3164_header():
    """The contrast with ASA, pinned so a fix to one is never copied onto the
    other. SC4S's own IOS corpus has no header either."""
    header = re.compile(r"^<\d+>\s?\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s")
    for datagram in _wire("cisco_ios", n=20) + SC4S_OWN_IOS:
        assert not header.match(datagram), datagram


# ── and the gate all three depend on ────────────────────────────────────────

@pytest.mark.parametrize("log_type", ["cisco_asa", "cisco_ios", "fortigate"])
def test_nothing_leaves_the_syslog_sink_without_a_priority(log_type):
    """`^\\<\\d+\\>` is the source's first gate; without it a message falls to
    app-group-sc4s-raw and is never identified. Observed as `PRI=13` events in
    `sc4s:fallback` for every unframed Cisco IOS line."""
    for line in _wire(log_type, n=20):
        assert HAS_PRI.match(line), f"{log_type} would go out unframed: {line!r}"


# ── who the syslog sink frames, and who still asks ──────────────────────────

#: Which sources the sink frames on its own, and which still wait for the
#: `delivery_format` option. Pinned as a whole table rather than per source: the
#: two regressions in this area were both a change to one source that silently
#: moved another, and only the table makes that visible.
FRAMES_WITHOUT_ASKING = {"cisco_ios"}
FRAMES_WHEN_ASKED = {"apache", "auditd", "fortigate", "ssh", "zscaler"}
NEVER_FRAMED = {"active_directory", "cisco_asa", "paloalto", "sysmon", "windows",
                "powershell"}


def _framed_by_the_sink(log_type, options):
    from log_senders import SenderManager
    config = REGISTRY[log_type].SOURCETYPE_CONFIG
    if config.get("multi_instance"):
        generator = REGISTRY[log_type](**{config["single_param_name"]: config["defaults"][0]})
    else:
        generator = REGISTRY[log_type](**{config["param_key"]: config["defaults"]})
    manager = SenderManager.__new__(SenderManager)
    wrapped = manager._apply_delivery_format([generator], log_type, options, "syslog")[0]
    return isinstance(wrapped, SyslogFramedGenerator)


def test_the_sink_frames_exactly_these_sources():
    assert (FRAMES_WITHOUT_ASKING | FRAMES_WHEN_ASKED | NEVER_FRAMED) == set(REGISTRY), (
        "a source was added without deciding how it leaves on the syslog sink")

    for log_type in FRAMES_WITHOUT_ASKING:
        # A router writes no file a forwarder could tail, so the sink decides.
        assert _framed_by_the_sink(log_type, {}), log_type
        assert _framed_by_the_sink(log_type, {"delivery_format": "syslog"}), log_type

    for log_type in FRAMES_WHEN_ASKED:
        assert not _framed_by_the_sink(log_type, {}), (
            f"{log_type} started framing without being asked")
        assert _framed_by_the_sink(log_type, {"delivery_format": "syslog"}), log_type

    for log_type in NEVER_FRAMED:
        # Either it writes its own priority, or it is never collected over syslog.
        assert not _framed_by_the_sink(log_type, {}), log_type
        assert not _framed_by_the_sink(log_type, {"delivery_format": "syslog"}), log_type
