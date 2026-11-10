"""After a restart, nothing is listed as running unless it is.

`enabled` and a simulation's `status` are persisted; the threads and timers that
honour them are not. Every restart — a manual one, or Flask's reloader reacting
to a changed .py — used to bring senders back under *Active* with a pause button
while they generated nothing, and simulations back with a countdown while they
sent nothing. The first click on such a sender stopped it instead of starting it.
"""

import importlib
import json
import sys
import threading

import pytest

from log_senders import SenderManager
from simulation_manager import SimulationManager

MB = 1024 ** 2


def _sender(**overrides):
    base = {
        "id": "s1", "name": "a sender", "log_type": "ssh", "enabled": True,
        "destination_type": "file", "destination": "/dev/null", "frequency": 1,
        "logs_generated": 0, "created_at": "2026-09-14T10:00:00", "options": {},
        "attack_status": None,
    }
    base.update(overrides)
    return base


def _write_senders(path, *senders):
    path.write_text(json.dumps({s["id"]: s for s in senders}))


@pytest.fixture
def senders_file(tmp_path):
    return tmp_path / "senders_config.json"


def _manager(tmp_path, senders_file):
    from configuration_manager import ConfigurationManager
    from syslog_destinations import SyslogDestinationsManager
    return SenderManager(
        config_file=str(senders_file),
        config_mgr=ConfigurationManager(config_file=str(tmp_path / "configurations.json")),
        syslog_dests_mgr=SyslogDestinationsManager(
            config_file=str(tmp_path / "syslog_destinations.json")),
    )


# ── senders ─────────────────────────────────────────────────────────────────

def test_a_sender_left_enabled_comes_back_stopped(tmp_path, senders_file):
    _write_senders(senders_file, _sender(id="on"), _sender(id="off", enabled=False))
    manager = _manager(tmp_path, senders_file)

    assert manager.reconcile_after_restart() == ["on"]

    assert manager.get_sender("on")["enabled"] is False
    assert manager.get_sender("off")["enabled"] is False
    # Persisted, so the list the page polls agrees with what is running.
    on_disk = json.loads(senders_file.read_text())
    assert on_disk["on"]["enabled"] is False


def test_an_interrupted_attack_says_so(tmp_path, senders_file):
    """Not `Disabled`: that reads as an attack nobody ran, and this one did."""
    _write_senders(senders_file,
                   _sender(id="atk", log_type="ssh_bruteforce", attack_status="Running"),
                   _sender(id="done", log_type="ssh_bruteforce", enabled=False,
                           attack_status="Done (09/14 11:45:00)"))
    manager = _manager(tmp_path, senders_file)

    manager.reconcile_after_restart()

    assert manager.get_sender("atk")["attack_status"] == SenderManager.INTERRUPTED
    assert manager.get_sender("done")["attack_status"] == "Done (09/14 11:45:00)"


def test_a_sender_that_really_runs_is_left_alone(tmp_path, senders_file):
    """Callable at any moment, not only at boot."""
    _write_senders(senders_file, _sender(id="live"))
    manager = _manager(tmp_path, senders_file)
    manager.threads["live"] = {"thread": threading.Thread(target=lambda: None),
                               "stop_event": threading.Event()}

    assert manager.reconcile_after_restart() == []
    assert manager.get_sender("live")["enabled"] is True


def test_the_first_click_after_a_restart_starts_the_sender(tmp_path, senders_file):
    """The user-visible bug: the toggle used to stop a sender that was not running."""
    _write_senders(senders_file, _sender(id="on"))
    manager = _manager(tmp_path, senders_file)
    manager.reconcile_after_restart()

    started = []
    manager.start_sender = lambda sender_id: started.append(sender_id)
    manager.toggle_sender("on")

    assert started == ["on"]
    assert manager.get_sender("on")["enabled"] is True


# ── simulations ─────────────────────────────────────────────────────────────

def test_a_simulation_left_running_comes_back_stopped_with_its_senders_gone(
        tmp_path, senders_file):
    senders = _manager(tmp_path, senders_file)
    sims = SimulationManager(config_file=str(tmp_path / "simulations.json"))
    sim_id = sims.create_simulation(
        name="t", duration_seconds=3600, destination_type="file",
        destination="/dev/null", sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])

    # What a restart leaves on disk: running, deadline ahead, senders enabled,
    # and neither thread nor timer behind any of it.
    senders.start_sender = lambda sender_id: None
    sims.start_simulation(sim_id, senders)
    sims._cancel_timer(sim_id)
    sim_sender = sims._data[sim_id]["sourcetypes"][0]["sender_id"]
    assert senders.get_sender(sim_sender)["enabled"] is True

    assert sims.reconcile_after_restart(senders) == [sim_id]

    sim = sims._data[sim_id]
    assert sim["status"] == "stopped"
    assert "ends_at" not in sim
    assert senders.get_sender(sim_sender) is None, "its sender outlived it"


def test_a_simulation_with_a_live_deadline_is_left_alone(tmp_path, senders_file):
    senders = _manager(tmp_path, senders_file)
    sims = SimulationManager(config_file=str(tmp_path / "simulations.json"))
    sim_id = sims.create_simulation(
        name="t", duration_seconds=3600, destination_type="file",
        destination="/dev/null", sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])
    senders.start_sender = lambda sender_id: None
    sims.start_simulation(sim_id, senders)
    try:
        assert sims.reconcile_after_restart(senders) == []
        assert sims._data[sim_id]["status"] == "running"
    finally:
        sims.stop_simulation(sim_id, senders)


# ── wired at boot ───────────────────────────────────────────────────────────

def test_starting_the_application_reconciles(tmp_path, monkeypatch):
    """Imports the real app against a state directory seeded the way a restart
    leaves it, so the test fails if the call is ever dropped from startup."""
    state = tmp_path / "state"
    state.mkdir()
    _write_senders(state / "senders_config.json",
                   _sender(id="on"),
                   _sender(id="atk", log_type="ssh_bruteforce", attack_status="Running"))
    monkeypatch.setenv("LOG_GENERATOR_STATE_DIR", str(state))
    monkeypatch.delitem(sys.modules, "app", raising=False)

    app = importlib.import_module("app")
    try:
        listed = {s["id"]: s for s in app.sender_manager.get_all_senders()}
        assert listed["on"]["enabled"] is False
        assert listed["atk"]["attack_status"] == SenderManager.INTERRUPTED
    finally:
        sys.modules.pop("app", None)
