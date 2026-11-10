"""Senders persisted before the per-sourcetype HEC work must still run.

Those configs predate `options.hec_sourcetype_map`, so the emission path has to
fall back to the sourcetype the registry declares for each source, with no
migration of the on-disk file.
"""

import json
import time

import pytest

import hec_sender
from configuration_manager import ConfigurationManager
from log_senders import SenderManager
from network_pools import NetworkPoolManager
from syslog_destinations import SyslogDestinationsManager


class FakeResponse:
    status_code = 200
    text = "ok"


class CapturingSession:
    """Collects HEC payloads instead of reaching the network."""

    def __init__(self):
        self.payloads = []
        self.headers = {}

    def post(self, url, data=None, **kwargs):
        self.payloads.append(json.loads(data))
        return FakeResponse()

    def close(self):
        pass


@pytest.fixture
def captured_hec(monkeypatch):
    """Every HECSender built during the test writes into one shared list."""
    sessions = []
    original_init = hec_sender.HECSender.__init__

    def patched_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        session = CapturingSession()
        sessions.append(session)
        self.session = session

    monkeypatch.setattr(hec_sender.HECSender, "__init__", patched_init)
    return sessions


def _legacy_sender_config(sender_id, config_id, *, use_ai):
    """A sender dict exactly as it was persisted before hec_sourcetype_map existed."""
    options = {
        "log_types": ["traffic", "threat", "system"],
        "use_assets_identities": use_ai,
        "assets_identities_ratio": 50,
        "hec_index": "test",
    }
    return {
        "id": sender_id,
        "name": "legacy palo",
        "log_type": "paloalto",
        "destination": None,
        "destination_type": "configuration",
        "configuration_id": config_id,
        "syslog_destination_id": None,
        "syslog_host": None,
        "syslog_port": 514,
        "syslog_protocol": "udp",
        "frequency": 20000,
        "enabled": False,
        "created_at": "2026-05-10T23:46:38.943082",
        "logs_generated": 700,
        "options": options,
        "attack_status": None,
    }


def _manager_over_legacy_state(tmp_path, use_ai):
    """SenderManager loaded from a hand-written legacy senders_config.json."""
    config_mgr = ConfigurationManager(config_file=str(tmp_path / "configurations.json"))
    config_id = config_mgr.create_configuration(
        name="lab", url="https://splunk.invalid", port=8088, token="tok"
    )

    sender_id = "11111111-2222-3333-4444-555555555555"
    legacy = {sender_id: _legacy_sender_config(sender_id, config_id, use_ai=use_ai)}
    state_file = tmp_path / "senders_config.json"
    state_file.write_text(json.dumps(legacy, indent=2))

    manager = SenderManager(
        config_file=str(state_file),
        config_mgr=config_mgr,
        syslog_dests_mgr=SyslogDestinationsManager(
            config_file=str(tmp_path / "syslog_destinations.json")
        ),
    )
    # Keep the lazily-created pool manager inside tmp_path.
    manager._network_pool_mgr = NetworkPoolManager(
        config_file=str(tmp_path / "network_pools.json")
    )
    return manager, sender_id


def _run_briefly(manager, sender_id, seconds=0.4):
    manager.start_sender(sender_id)
    time.sleep(seconds)
    manager.stop_sender(sender_id)


def test_legacy_sender_config_has_no_sourcetype_map(tmp_path):
    """Guard the premise: the fixture really is a pre-migration shape."""
    manager, sender_id = _manager_over_legacy_state(tmp_path, use_ai=False)
    options = manager.get_sender(sender_id)["options"]
    assert "hec_sourcetype_map" not in options


@pytest.mark.parametrize("use_ai", [False, True], ids=["without-a&i", "with-a&i"])
def test_legacy_sender_emits_with_the_ta_default_sourcetype(tmp_path, captured_hec, use_ai):
    """No hec_sourcetype_map: fall back to the TA's ingestion sourcetype.

    Palo Alto declares pan:log, which the TA splits back into pan:traffic /
    pan:threat / pan:system at index time. Senders persisted before the
    override map existed follow that same documented path.
    """
    manager, sender_id = _manager_over_legacy_state(tmp_path, use_ai=use_ai)

    _run_briefly(manager, sender_id)

    payloads = [p for session in captured_hec for p in session.payloads]
    assert payloads, "legacy sender produced no event at all"

    sourcetypes = {p.get("sourcetype") for p in payloads}
    assert sourcetypes == {"pan:log"}, (
        f"expected the TA default pan:log, got {sourcetypes}"
    )

    # The rest of the legacy options must still be honoured.
    assert all(p.get("index") == "test" for p in payloads)
    assert manager.get_sender(sender_id)["logs_generated"] > 700


def test_ta_without_a_declared_default_keeps_its_own_sourcetype(tmp_path):
    """Only TAs that declare hec_default_sourcetype are redirected."""
    manager, _ = _manager_over_legacy_state(tmp_path, use_ai=False)
    assert manager._ta_default_sourcetype("paloalto") == "pan:log"
    assert manager._ta_default_sourcetype("ssh") is None
    # windows declares one per render_format instead of a single flat value.
    assert manager._ta_default_sourcetype("windows", "xml") == "XmlWinEventLog"
    assert manager._ta_default_sourcetype("windows", "classic") == "WinEventLog"


def test_legacy_sender_file_destination_still_writes(tmp_path):
    """The file sink path is unaffected by the sourcetype work."""
    manager, sender_id = _manager_over_legacy_state(tmp_path, use_ai=False)
    destination = tmp_path / "out" / "legacy.log"

    manager.update_sender(sender_id, {
        "destination_type": "file",
        "destination": str(destination),
    })
    _run_briefly(manager, sender_id)

    assert destination.exists()
    lines = destination.read_text().splitlines()
    assert lines, "no line written"
    assert all(line.strip() for line in lines)


def test_legacy_sender_untouched_on_disk(tmp_path, captured_hec):
    """Running a legacy sender must not rewrite its options with new keys."""
    manager, sender_id = _manager_over_legacy_state(tmp_path, use_ai=False)
    state_file = tmp_path / "senders_config.json"

    _run_briefly(manager, sender_id)

    on_disk = json.loads(state_file.read_text())[sender_id]
    assert "hec_sourcetype_map" not in on_disk["options"], (
        "the emission path must not migrate the persisted config"
    )


# ── `source` metadata (added after the per-sourcetype source work) ───────────

def _legacy_windows_sender_config(sender_id, config_id):
    """A Windows sender exactly as it was persisted before hec_source_map existed."""
    return {
        "id": sender_id,
        "name": "legacy windows",
        "log_type": "windows",
        "destination": None,
        "destination_type": "configuration",
        "configuration_id": config_id,
        "syslog_destination_id": None,
        "syslog_host": None,
        "syslog_port": 514,
        "syslog_protocol": "udp",
        "frequency": 20000,
        "enabled": False,
        "created_at": "2026-05-10T23:46:38.943082",
        "logs_generated": 41,
        "options": {
            "sources": ["Security", "System", "Application"],
            "use_assets_identities": False,
            "assets_identities_ratio": 100,
        },
        "attack_status": None,
    }


def _manager_over_legacy_windows(tmp_path):
    config_mgr = ConfigurationManager(config_file=str(tmp_path / "configurations.json"))
    config_id = config_mgr.create_configuration(
        name="lab", url="https://splunk.invalid", port=8088, token="tok"
    )

    sender_id = "99999999-8888-7777-6666-555555555555"
    state_file = tmp_path / "senders_config.json"
    state_file.write_text(json.dumps(
        {sender_id: _legacy_windows_sender_config(sender_id, config_id)}, indent=2))

    manager = SenderManager(
        config_file=str(state_file),
        config_mgr=config_mgr,
        syslog_dests_mgr=SyslogDestinationsManager(
            config_file=str(tmp_path / "syslog_destinations.json")
        ),
    )
    manager._network_pool_mgr = NetworkPoolManager(
        config_file=str(tmp_path / "network_pools.json")
    )
    return manager, sender_id


def test_legacy_windows_sender_has_neither_map(tmp_path):
    """Guard the premise: the fixture really is a pre-migration shape."""
    manager, sender_id = _manager_over_legacy_windows(tmp_path)
    options = manager.get_sender(sender_id)["options"]
    assert "hec_sourcetype_map" not in options
    assert "hec_source_map" not in options


def test_legacy_windows_sender_emits_the_registry_source(tmp_path, captured_hec):
    """No hec_source_map: resolve each channel's source from the registry."""
    manager, sender_id = _manager_over_legacy_windows(tmp_path)

    _run_briefly(manager, sender_id)

    payloads = [p for session in captured_hec for p in session.payloads]
    assert payloads, "legacy windows sender produced no event at all"

    # No render_format persisted either: the emitter defaults to xml, as before.
    assert {p.get("sourcetype") for p in payloads} == {"XmlWinEventLog"}
    assert {p.get("source") for p in payloads} == {
        "XmlWinEventLog:Security",
        "XmlWinEventLog:System",
        "XmlWinEventLog:Application",
    }


def test_legacy_windows_sender_untouched_on_disk(tmp_path, captured_hec):
    """Resolving from the registry must not write the resolved values back."""
    manager, sender_id = _manager_over_legacy_windows(tmp_path)
    state_file = tmp_path / "senders_config.json"

    _run_briefly(manager, sender_id)

    on_disk = json.loads(state_file.read_text())[sender_id]
    assert "hec_source_map" not in on_disk["options"]
    assert "hec_sourcetype_map" not in on_disk["options"]
