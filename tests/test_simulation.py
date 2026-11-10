"""Simulation sizing, and the index it stamps.

Volume is turned into a rate exactly once, when the simulation is created, by
dividing the target bytes by the average size of one event. That average used to
be a constant declared on each generator, and every one of them was wrong — so a
simulation asked for 10 GB of Windows and produced 20. It is measured now.
"""

import pytest

from log_generators import REGISTRY
from simulation_manager import SimulationManager

GB = 1024 ** 3
MB = 1024 ** 2


@pytest.fixture
def manager(tmp_path):
    return SimulationManager(config_file=str(tmp_path / "simulations.json"))


# ── the size is measured, not declared ──────────────────────────────────────

def test_the_measured_size_matches_what_the_generator_emits():
    """Within 10% of a fresh sample — the constants were out by up to 100%."""
    import random

    for log_type, generator_cls in REGISTRY.items():
        config = generator_cls.SOURCETYPE_CONFIG
        # A multi_instance source runs one generator per category, and a sender
        # draws across all of them — so the average has to span them too. Sizing
        # zscaler on its web feed alone overstates it by half.
        if config.get("multi_instance"):
            instances = [generator_cls(**{config["single_param_name"]: value})
                         for value in config["defaults"]]
        else:
            instances = [generator_cls(**{config["param_key"]: config["defaults"]})]

        observed = sum(len(random.choice(instances).generate().encode()) + 1
                       for _ in range(600)) / 600
        measured = SimulationManager.average_log_size(log_type)

        assert abs(measured - observed) / observed < 0.10, (
            f"{log_type}: measured {measured}, sample says {observed:.0f}"
        )


def test_options_change_the_size_and_the_measurement_follows():
    """A classic Windows event and an XML one differ by hundreds of bytes."""
    xml = SimulationManager.average_log_size("windows", {"render_format": "xml"})
    classic = SimulationManager.average_log_size("windows", {"render_format": "classic"})

    assert xml != classic, "render_format is not reaching the measurement"
    assert xml > classic


def test_an_unknown_log_type_falls_back_rather_than_raising():
    assert SimulationManager.average_log_size("nope") == 300


# ── volume becomes a rate ───────────────────────────────────────────────────

def test_the_rate_would_produce_the_volume_asked_for(manager):
    """rate x duration x size should land back on the target."""
    for log_type in ("ssh", "windows", "apache"):
        size = SimulationManager.average_log_size(log_type)
        rate = manager.calculate_frequency(2 * GB, 3600, log_type)
        produced = rate * 3600 * size

        assert abs(produced - 2 * GB) / (2 * GB) < 0.02, (
            f"{log_type}: {produced / GB:.2f} GB instead of 2"
        )


def test_a_rate_is_clamped_to_something_a_sender_can_hold(manager):
    assert manager.calculate_frequency(1000 * GB, 1, "ssh") == 10000
    assert manager.calculate_frequency(1, 3600, "ssh") == 1
    assert manager.calculate_frequency(0, 3600, "ssh") == 0
    assert manager.calculate_frequency(GB, 0, "ssh") == 0


# ── duration and volume, at any granularity ─────────────────────────────────

@pytest.mark.parametrize("seconds", [30, 90, 3600, 86400])
def test_a_duration_in_seconds_is_kept_as_given(manager, seconds):
    sim_id = manager.create_simulation(
        name="t", duration_seconds=seconds,
        sourcetypes=[{"log_type": "ssh", "volume_bytes": 10 * MB}])

    assert manager._data[sim_id]["duration_seconds"] == float(seconds)


def test_hours_are_still_accepted_for_records_written_before_seconds(manager):
    sim_id = manager.create_simulation(
        name="t", duration_hours=2,
        sourcetypes=[{"log_type": "ssh", "volume_bytes": 10 * MB}])

    assert manager._data[sim_id]["duration_seconds"] == 7200.0


def test_a_volume_in_gigabytes_is_still_accepted(manager):
    """Entries written before bytes carry volume_gb."""
    sim_id = manager.create_simulation(
        name="t", duration_seconds=3600,
        sourcetypes=[{"log_type": "ssh", "volume_gb": 1}])

    assert manager._data[sim_id]["sourcetypes"][0]["volume_bytes"] == float(GB)


def test_a_small_volume_over_a_short_window_is_not_rounded_away(manager):
    """The point of the finer units: 5 MB over 30 seconds must still work."""
    sim_id = manager.create_simulation(
        name="t", duration_seconds=30,
        sourcetypes=[{"log_type": "ssh", "volume_bytes": 5 * MB}])

    entry = manager._data[sim_id]["sourcetypes"][0]
    assert entry["frequency"] > 1
    produced = entry["frequency"] * 30 * entry["avg_log_size"]
    assert abs(produced - 5 * MB) / (5 * MB) < 0.05


# ── the index, and where it must not go ─────────────────────────────────────

def test_the_index_is_stamped_on_every_entry_over_hec(manager):
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60, destination_type="configuration",
        configuration_id="c1", hec_index="sim_index",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB},
                     {"log_type": "apache", "volume_bytes": MB}])

    sim = manager._data[sim_id]
    assert sim["hec_index"] == "sim_index"
    for entry in sim["sourcetypes"]:
        assert entry["options"]["hec_index"] == "sim_index"


@pytest.mark.parametrize("destination_type", ["syslog", "file"])
def test_no_index_is_sent_where_the_sender_does_not_use_one(manager, destination_type):
    """A collector such as SC4S decides the index itself; stamping one would
    describe a routing decision it has not made."""
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60, destination_type=destination_type,
        hec_index="should-not-appear",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])

    sim = manager._data[sim_id]
    assert sim["hec_index"] is None
    assert "hec_index" not in sim["sourcetypes"][0]["options"]


def test_a_row_may_name_its_own_index(manager):
    """One simulation, two indexes: a row that names one overrides the
    simulation-wide value for that source alone."""
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60, destination_type="configuration",
        configuration_id="c1", hec_index="sim_index",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB,
                      "hec_index": "linux_idx"},
                     {"log_type": "apache", "volume_bytes": MB}])

    ssh, apache = manager._data[sim_id]["sourcetypes"]
    assert ssh["options"]["hec_index"] == "linux_idx"
    assert ssh["hec_index"] == "linux_idx"
    # The row that named nothing still follows the simulation.
    assert apache["options"]["hec_index"] == "sim_index"
    assert apache["hec_index"] == "sim_index"
    # And the simulation itself keeps its own value, so the form can tell an
    # inherited index from an overridden one when it reopens.
    assert manager._data[sim_id]["hec_index"] == "sim_index"


def test_a_row_index_stands_without_a_simulation_wide_one(manager):
    """The HEC index field may be left blank and the rows fill it in."""
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60, destination_type="configuration",
        configuration_id="c1", hec_index="",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB,
                      "hec_index": "linux_idx"},
                     {"log_type": "apache", "volume_bytes": MB}])

    ssh, apache = manager._data[sim_id]["sourcetypes"]
    assert ssh["options"]["hec_index"] == "linux_idx"
    assert "hec_index" not in apache["options"]
    assert apache["hec_index"] is None


@pytest.mark.parametrize("destination_type", ["syslog", "file"])
def test_a_row_cannot_conjure_an_index_the_destination_has_not(
        manager, destination_type):
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60, destination_type=destination_type,
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB,
                      "hec_index": "should-not-appear"}])

    entry = manager._data[sim_id]["sourcetypes"][0]
    assert "hec_index" not in entry["options"]
    assert entry["hec_index"] is None


def test_a_row_index_survives_an_edit(manager):
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60, destination_type="configuration",
        configuration_id="c1", hec_index="sim_index",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB,
                      "hec_index": "linux_idx"}])
    manager.update_simulation(
        sim_id, name="t2", duration_seconds=120,
        destination_type="configuration", configuration_id="c1",
        hec_index="sim_index",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": 2 * MB,
                      "hec_index": "linux_idx"}])

    assert manager._data[sim_id]["sourcetypes"][0]["hec_index"] == "linux_idx"


def test_the_sourcetype_is_left_to_the_source(manager):
    """Simulation sets the index only — each source keeps the sourcetype its
    registry entry declares."""
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60, destination_type="configuration",
        configuration_id="c1", hec_index="sim_index",
        sourcetypes=[{"log_type": "paloalto", "volume_bytes": MB}])

    options = manager._data[sim_id]["sourcetypes"][0]["options"]
    assert "hec_sourcetype" not in options
    assert "hec_sourcetype_map" not in options


# ── editing ─────────────────────────────────────────────────────────────────

def test_editing_keeps_the_id_and_rewrites_the_rest(manager):
    sim_id = manager.create_simulation(
        name="before", duration_seconds=60, destination_type="file",
        destination="/tmp/a.log",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])

    manager.update_simulation(
        sim_id, name="after", duration_seconds=120,
        destination_type="configuration", configuration_id="c1",
        hec_index="idx",
        sourcetypes=[{"log_type": "apache", "volume_bytes": 2 * MB}])

    sim = manager._data[sim_id]
    assert sim["id"] == sim_id
    assert sim["name"] == "after"
    assert sim["duration_seconds"] == 120.0
    assert sim["destination_type"] == "configuration"
    assert sim["hec_index"] == "idx"
    assert [e["log_type"] for e in sim["sourcetypes"]] == ["apache"]


def test_editing_recomputes_the_rate(manager):
    """Halving the window must double the rate, not leave a stale one."""
    sim_id = manager.create_simulation(
        name="t", duration_seconds=120,
        sourcetypes=[{"log_type": "ssh", "volume_bytes": 10 * MB}])
    before = manager._data[sim_id]["sourcetypes"][0]["frequency"]

    manager.update_simulation(
        sim_id, name="t", duration_seconds=60,
        sourcetypes=[{"log_type": "ssh", "volume_bytes": 10 * MB}])
    after = manager._data[sim_id]["sourcetypes"][0]["frequency"]

    assert after == pytest.approx(before * 2, rel=0.02)


def test_editing_a_running_simulation_is_refused(manager):
    """Its senders were built from the current rates; changing them underneath
    would leave the simulation describing one thing and emitting another."""
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60,
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])
    manager._data[sim_id]["status"] = "running"

    with pytest.raises(ValueError, match="Stop the simulation"):
        manager.update_simulation(
            sim_id, name="t", duration_seconds=60,
            sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])


def test_editing_an_unknown_simulation_is_refused(manager):
    with pytest.raises(ValueError, match="not found"):
        manager.update_simulation(
            "nope", name="t", duration_seconds=60,
            sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])


def test_editing_to_syslog_drops_the_index(manager):
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60, destination_type="configuration",
        configuration_id="c1", hec_index="idx",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])
    assert manager._data[sim_id]["sourcetypes"][0]["options"]["hec_index"] == "idx"

    manager.update_simulation(
        sim_id, name="t", duration_seconds=60, destination_type="syslog",
        syslog_host="sc4s", hec_index="idx",
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])

    sim = manager._data[sim_id]
    assert sim["hec_index"] is None
    assert "hec_index" not in sim["sourcetypes"][0]["options"]


def test_editing_to_nothing_is_refused(manager):
    sim_id = manager.create_simulation(
        name="t", duration_seconds=60,
        sourcetypes=[{"log_type": "ssh", "volume_bytes": MB}])

    with pytest.raises(ValueError, match="at least one|At least one"):
        manager.update_simulation(sim_id, name="t", duration_seconds=60,
                                  sourcetypes=[{"log_type": "ssh", "volume_bytes": 0}])


# ── the window closes on its own ────────────────────────────────────────────

@pytest.fixture
def senders(tmp_path):
    from configuration_manager import ConfigurationManager
    from log_senders import SenderManager
    from network_pools import NetworkPoolManager
    from syslog_destinations import SyslogDestinationsManager

    manager = SenderManager(
        config_file=str(tmp_path / "senders.json"),
        config_mgr=ConfigurationManager(config_file=str(tmp_path / "configs.json")),
        syslog_dests_mgr=SyslogDestinationsManager(
            config_file=str(tmp_path / "syslog.json")))
    manager._network_pool_mgr = NetworkPoolManager(
        config_file=str(tmp_path / "pools.json"))
    return manager


def _short_sim(manager, tmp_path, seconds=2):
    return manager.create_simulation(
        name="short", duration_seconds=seconds, destination_type="file",
        destination=str(tmp_path / "out.log"),
        sourcetypes=[{"log_type": "ssh", "volume_bytes": 4096}])


def test_starting_sets_an_absolute_deadline(manager, senders, tmp_path):
    """A timer dies with its process; a deadline written down does not."""
    from datetime import datetime, timezone

    sim_id = _short_sim(manager, tmp_path, seconds=60)
    manager.start_simulation(sim_id, senders)

    sim = manager._data[sim_id]
    assert sim["ends_at"], "no deadline recorded"
    ends = datetime.fromisoformat(sim["ends_at"])
    remaining = (ends - datetime.now(timezone.utc)).total_seconds()
    assert 55 < remaining <= 60

    manager.stop_simulation(sim_id, senders)


def test_the_listing_reports_the_seconds_left(manager, senders, tmp_path):
    sim_id = _short_sim(manager, tmp_path, seconds=60)
    manager.start_simulation(sim_id, senders)

    entry = next(s for s in manager.get_all_simulations() if s["id"] == sim_id)
    assert 55 <= entry["seconds_remaining"] <= 60

    manager.stop_simulation(sim_id, senders)
    entry = next(s for s in manager.get_all_simulations() if s["id"] == sim_id)
    assert entry["seconds_remaining"] is None


def test_it_stops_itself_when_the_window_closes(manager, senders, tmp_path):
    import time

    sim_id = _short_sim(manager, tmp_path, seconds=2)
    manager.start_simulation(sim_id, senders)
    assert senders.threads, "no sender was started"

    deadline = time.time() + 8
    while time.time() < deadline and manager._data[sim_id]["status"] == "running":
        time.sleep(0.2)

    assert manager._data[sim_id]["status"] == "stopped", "the window never closed"
    assert not senders.threads, "senders outlived the simulation"
    assert manager._data[sim_id]["sourcetypes"][0]["sender_id"] is None


def test_a_deadline_already_past_is_expired_on_read(manager, senders, tmp_path):
    """What catches a simulation that outlived the process that started it."""
    from datetime import datetime, timedelta, timezone

    sim_id = _short_sim(manager, tmp_path, seconds=3600)
    manager.start_simulation(sim_id, senders)
    manager._cancel_timer(sim_id)                     # as a restart would leave it
    manager._data[sim_id]["ends_at"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()

    manager.get_all_simulations(senders)

    assert manager._data[sim_id]["status"] == "stopped"
    assert not senders.threads


def test_stopping_twice_is_harmless(manager, senders, tmp_path):
    """The deadline and a click can land together; the loser must not raise."""
    sim_id = _short_sim(manager, tmp_path, seconds=60)
    manager.start_simulation(sim_id, senders)

    manager.stop_simulation(sim_id, senders)
    manager.stop_simulation(sim_id, senders)          # no exception

    assert manager._data[sim_id]["status"] == "stopped"


def test_a_stopped_simulation_keeps_no_deadline(manager, senders, tmp_path):
    sim_id = _short_sim(manager, tmp_path, seconds=60)
    manager.start_simulation(sim_id, senders)
    manager.stop_simulation(sim_id, senders)

    assert "ends_at" not in manager._data[sim_id]
    assert "started_at" not in manager._data[sim_id]
