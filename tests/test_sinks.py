"""Characterization tests for the three output sinks.

No real socket is opened: the syslog tests swap the `socket` module reference
inside syslog_sender, and the HEC tests replace the requests Session. The file
sink writes only under pytest's tmp_path.
"""

import json

import pytest

import hec_sender
import syslog_sender
from configuration_manager import ConfigurationManager
from hec_sender import HECSender
from log_senders import SenderManager
from syslog_destinations import SyslogDestinationsManager
from syslog_sender import SyslogSender


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class CountdownEvent:
    """threading.Event stand-in: reports 'not set' exactly `n` times.

    `_generate_logs` calls is_set() once per loop iteration, so this yields a
    deterministic number of emitted events with no reliance on wall-clock time.
    """

    def __init__(self, n):
        self._remaining = n

    def is_set(self):
        if self._remaining <= 0:
            return True
        self._remaining -= 1
        return False


class FixedGenerator:
    """Emits a predictable, numbered payload."""

    def __init__(self, template="event-{i}"):
        self.template = template
        self.i = 0

    def generate(self):
        self.i += 1
        return self.template.format(i=self.i)


class FakeResponse:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text


class RecordingSession:
    """Stands in for requests.Session; records every post()."""

    def __init__(self, status_code=200):
        self.calls = []
        self.headers = {}
        self._status_code = status_code

    def post(self, url, data=None, **kwargs):
        self.calls.append({"url": url, "data": data, "kwargs": kwargs})
        return FakeResponse(self._status_code)

    def close(self):
        pass


class FakeSocket:
    def __init__(self, family, kind):
        self.family = family
        self.kind = kind
        self.sent = []
        self.sent_to = []
        self.connected_to = None
        self.timeout = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def connect(self, address):
        self.connected_to = address

    def sendall(self, payload):
        self.sent.append(payload)

    def sendto(self, payload, address):
        self.sent_to.append((payload, address))

    def close(self):
        self.closed = True


class FakeSocketModule:
    """Minimal stand-in for the stdlib socket module."""

    AF_INET = "AF_INET"
    SOCK_STREAM = "SOCK_STREAM"
    SOCK_DGRAM = "SOCK_DGRAM"

    def __init__(self):
        self.created = []

    def socket(self, family, kind):
        sock = FakeSocket(family, kind)
        self.created.append(sock)
        return sock


@pytest.fixture
def sender_manager(tmp_path):
    """SenderManager wired entirely to tmp_path — never the real state files."""
    return SenderManager(
        config_file=str(tmp_path / "senders_config.json"),
        config_mgr=ConfigurationManager(config_file=str(tmp_path / "configurations.json")),
        syslog_dests_mgr=SyslogDestinationsManager(
            config_file=str(tmp_path / "syslog_destinations.json")
        ),
    )


# ---------------------------------------------------------------------------
# File sink
# ---------------------------------------------------------------------------

def test_file_sink_writes_one_line_per_event(sender_manager, tmp_path):
    """The file sink appends exactly one newline-terminated line per event."""
    destination = tmp_path / "logs" / "out.log"
    sender_id = sender_manager.create_sender(
        name="file-sink",
        log_type="apache",
        frequency=10_000,          # interval ~0.1 ms, keeps the test fast
        enabled=False,
        options={"log_types": ["combined"]},
        destination=str(destination),
        destination_type="file",
    )

    sender_manager._generate_logs(
        sender_id,
        FixedGenerator(),
        sender_manager.get_sender(sender_id),
        CountdownEvent(25),
    )

    assert destination.exists(), "sink did not create the destination file"
    lines = destination.read_text().splitlines()
    assert len(lines) == 25, f"expected 25 lines, got {len(lines)}"
    assert lines[0] == "event-1"
    assert lines[-1] == "event-25"
    assert sender_manager.get_sender(sender_id)["logs_generated"] == 25


def test_file_sink_creates_missing_parent_directories(sender_manager, tmp_path):
    destination = tmp_path / "deep" / "nested" / "tree" / "out.log"
    sender_id = sender_manager.create_sender(
        name="mkdir-sink",
        log_type="ssh",
        frequency=10_000,
        enabled=False,
        options={},
        destination=str(destination),
        destination_type="file",
    )

    sender_manager._generate_logs(
        sender_id, FixedGenerator(), sender_manager.get_sender(sender_id), CountdownEvent(3)
    )

    assert destination.parent.is_dir()
    assert len(destination.read_text().splitlines()) == 3


def test_file_sink_appends_across_runs(sender_manager, tmp_path):
    """Re-running a sender appends rather than truncating."""
    destination = tmp_path / "append.log"
    sender_id = sender_manager.create_sender(
        name="append-sink",
        log_type="ssh",
        frequency=10_000,
        enabled=False,
        options={},
        destination=str(destination),
        destination_type="file",
    )
    config = sender_manager.get_sender(sender_id)

    sender_manager._generate_logs(sender_id, FixedGenerator(), config, CountdownEvent(4))
    sender_manager._generate_logs(sender_id, FixedGenerator(), config, CountdownEvent(6))

    assert len(destination.read_text().splitlines()) == 10


# ---------------------------------------------------------------------------
# HEC sink
# ---------------------------------------------------------------------------

def test_hec_build_payload_drops_the_priority_and_keeps_the_header():
    """Only the priority is transport; the header belongs to the message.

    Removing it too left ASA events beginning `: %ASA-6-302013:` with no
    timestamp where [cisco:asa] looks for one (TIME_PREFIX = ^), and cost
    Splunk_TA_nix the hostname it reads `dest` from.
    """
    hec = HECSender(url="https://splunk.invalid", port=8088, token="tok")
    raw = "<14>Sep 10 18:54:33 pa-fw-01 1,2026/09/10 18:54:33,SERIAL,TRAFFIC,end"

    payload = hec._build_payload(raw, 1_700_000_000.0)

    assert payload["event"] == "Sep 10 18:54:33 pa-fw-01 1,2026/09/10 18:54:33,SERIAL,TRAFFIC,end"
    assert "<14>" not in payload["event"], "the priority is transport and must go"
    assert payload["host"] == "pa-fw-01"
    assert payload["time"] == 1_700_000_000.0


def test_hec_build_payload_leaves_non_syslog_events_intact():
    hec = HECSender(url="https://splunk.invalid", port=8088, token="tok")
    raw = '192.168.1.10 - - [10/Sep/2026:18:00:00 +0200] "GET / HTTP/1.1" 200 12'

    payload = hec._build_payload(raw, 1.0)

    assert payload["event"] == raw
    assert "host" not in payload, "no hostname should be invented for non-syslog input"


def test_hec_explicit_host_override_wins_over_syslog_hostname():
    hec = HECSender(
        url="https://splunk.invalid", port=8088, token="tok",
        index="main", sourcetype="pan:traffic", host="forced-host", source="src",
    )
    payload = hec._build_payload("<14>Sep 10 18:54:33 pa-fw-01 message body", 1.0)

    assert payload["host"] == "forced-host"
    assert payload["index"] == "main"
    assert payload["sourcetype"] == "pan:traffic"
    assert payload["source"] == "src"


def test_hec_send_event_posts_json_without_touching_the_network(monkeypatch):
    hec = HECSender(url="https://splunk.invalid", port=8088, token="tok")
    session = RecordingSession(status_code=200)
    monkeypatch.setattr(hec, "session", session)

    assert hec.send_event("<14>Sep 10 18:54:33 host-a hello") is True
    assert len(session.calls) == 1

    call = session.calls[0]
    assert call["url"] == "https://splunk.invalid:8088/services/collector/event"
    assert call["kwargs"]["verify"] is False        # current behaviour, audit §5
    body = json.loads(call["data"])
    assert body["event"] == "Sep 10 18:54:33 host-a hello"
    assert body["host"] == "host-a"


def test_hec_send_event_returns_false_on_error_status(monkeypatch):
    """A failing HEC never raises: it logs and returns False (audit §5)."""
    hec = HECSender(url="https://splunk.invalid", port=8088, token="tok")
    monkeypatch.setattr(hec, "session", RecordingSession(status_code=503))

    assert hec.send_event("payload") is False


# ---------------------------------------------------------------------------
# Syslog sink
# ---------------------------------------------------------------------------

def test_syslog_udp_sends_datagram_with_trailing_newline(monkeypatch):
    fake_module = FakeSocketModule()
    monkeypatch.setattr(syslog_sender, "socket", fake_module)

    sender = SyslogSender(host="10.0.0.5", port=514, protocol="udp")

    assert len(fake_module.created) == 1
    sock = fake_module.created[0]
    assert sock.kind == FakeSocketModule.SOCK_DGRAM
    assert sock.connected_to is None, "UDP must not connect()"

    assert sender.send_event("hello udp") is True
    assert sock.sent_to == [(b"hello udp\n", ("10.0.0.5", 514))]

    sender.close()
    assert sock.closed is True


def test_syslog_tcp_connects_and_uses_sendall(monkeypatch):
    fake_module = FakeSocketModule()
    monkeypatch.setattr(syslog_sender, "socket", fake_module)

    sender = SyslogSender(host="sc4s.invalid", port=601, protocol="tcp")

    sock = fake_module.created[0]
    assert sock.kind == FakeSocketModule.SOCK_STREAM
    assert sock.connected_to == ("sc4s.invalid", 601)

    assert sender.send_event("hello tcp") is True
    assert sock.sent == [b"hello tcp\n"]

    sender.close()
    assert sock.closed is True


def test_syslog_tcp_resets_socket_on_send_failure(monkeypatch):
    """A TCP send error returns False and drops the socket for reconnection."""
    fake_module = FakeSocketModule()
    monkeypatch.setattr(syslog_sender, "socket", fake_module)

    sender = SyslogSender(host="sc4s.invalid", port=601, protocol="tcp")

    def exploding_sendall(_payload):
        raise OSError("connection reset by peer")

    fake_module.created[0].sendall = exploding_sendall

    assert sender.send_event("doomed") is False
    assert sender._sock is None, "failed TCP socket should be reset"

    # Next send re-creates a socket rather than staying broken.
    assert sender.send_event("recovered") is True
    assert len(fake_module.created) == 2
    assert fake_module.created[1].sent == [b"recovered\n"]


def test_syslog_destination_id_is_resolved_from_the_registry(sender_manager, tmp_path, monkeypatch):
    """_build_syslog_sender prefers syslog_destination_id over inline fields."""
    fake_module = FakeSocketModule()
    monkeypatch.setattr(syslog_sender, "socket", fake_module)

    dest_id = sender_manager._syslog_dests_mgr.create_destination(
        name="lab", host="192.0.2.10", port=5514, protocol="tcp"
    )
    built = sender_manager._build_syslog_sender({"syslog_destination_id": dest_id})

    assert built.host == "192.0.2.10"
    assert built.port == 5514
    assert built.protocol == "tcp"
    assert fake_module.created[0].connected_to == ("192.0.2.10", 5514)


def test_syslog_inline_fields_used_when_no_destination_id(sender_manager, monkeypatch):
    """Legacy inline host/port/protocol remain supported (audit §3.D)."""
    fake_module = FakeSocketModule()
    monkeypatch.setattr(syslog_sender, "socket", fake_module)

    built = sender_manager._build_syslog_sender(
        {"syslog_host": "198.51.100.7", "syslog_port": 1514, "syslog_protocol": "udp"}
    )

    assert built.host == "198.51.100.7"
    assert built.port == 1514
    assert built.protocol == "udp"


# ---------------------------------------------------------------------------
# Per-sourcetype HEC attribution
# ---------------------------------------------------------------------------

def test_multisource_generator_reports_the_emitting_sourcetype():
    """generate_with_sourcetype() pairs each line with the instance that made it."""
    from log_senders import MultiSourceLogGenerator

    a, b = FixedGenerator("from-a"), FixedGenerator("from-b")
    gen = MultiSourceLogGenerator([a, b], ["pan:traffic", "pan:threat"])

    pairs = [gen.generate_with_sourcetype() for _ in range(200)]
    for line, sourcetype in pairs:
        expected = {"from-a": "pan:traffic", "from-b": "pan:threat"}[line.split("-")[0] + "-" + line.split("-")[1]]
        assert sourcetype == expected, f"{line} attributed to {sourcetype}"

    seen = {st for _, st in pairs}
    assert seen == {"pan:traffic", "pan:threat"}, f"both instances should fire, saw {seen}"


def test_multisource_generator_without_sourcetypes_reports_none():
    """Unattributed generators (attacks, umbrella TAs with no bridge) yield None."""
    from log_senders import MultiSourceLogGenerator

    gen = MultiSourceLogGenerator(FixedGenerator())
    line, sourcetype = gen.generate_with_sourcetype()
    assert line == "event-1"
    assert sourcetype is None
    # The legacy string-only contract still holds.
    assert gen.generate() == "event-2"


def test_hec_payload_uses_the_per_event_sourcetype():
    """A per-event sourcetype overrides the sender-wide default."""
    hec = HECSender(url="https://splunk.invalid", port=8088, token="tok",
                    sourcetype="pan:log")

    default = hec._build_payload("plain event", 1.0)
    assert default["sourcetype"] == "pan:log"

    overridden = hec._build_payload("plain event", 1.0, sourcetype="pan:threat")
    assert overridden["sourcetype"] == "pan:threat"


def test_hec_send_event_forwards_the_per_event_sourcetype(monkeypatch):
    hec = HECSender(url="https://splunk.invalid", port=8088, token="tok")
    session = RecordingSession()
    monkeypatch.setattr(hec, "session", session)

    hec.send_event("line one", sourcetype="pan:traffic")
    hec.send_event("line two", sourcetype="pan:system")

    sent = [json.loads(call["data"])["sourcetype"] for call in session.calls]
    assert sent == ["pan:traffic", "pan:system"]


def test_bridged_ta_splits_into_one_instance_per_sourcetype(sender_manager):
    """Palo Alto declares a sourcetype per source, so each gets its own instance."""
    meta = [
        {"id": "traffic", "sourcetype": "pan:traffic"},
        {"id": "threat", "sourcetype": "pan:threat"},
    ]
    assert sender_manager._bridge_sourcetype(meta, "traffic") == "pan:traffic"
    assert sender_manager._bridge_sourcetype(meta, "threat") == "pan:threat"
    assert sender_manager._bridge_sourcetype(meta, "nope") is None


def test_umbrella_ta_resolves_to_its_single_registry_sourcetype(sender_manager):
    """TAs with one declared sourcetype attribute every event to it."""
    assert sender_manager._single_registry_sourcetype("ssh") == "linux_secure"
    assert sender_manager._single_registry_sourcetype("cisco_asa") == "cisco:asa"
    # Palo Alto declares three, so there is no single answer.
    assert sender_manager._single_registry_sourcetype("paloalto") is None
