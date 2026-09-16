"""A sender that stops on its own after the time it was given.

Zero keeps what senders always did — run until someone stops them — so a sender
saved before this existed carries no duration and behaves as it did.
"""

import tempfile
import threading
import time
from pathlib import Path

import pytest

from log_senders import SenderManager


@pytest.fixture
def manager(tmp_path):
    return SenderManager(config_file=str(tmp_path / "senders.json"))


def _file_sender(manager, tmp_path, **extra):
    return manager.create_sender("s", "cisco_asa", 50, destination=str(tmp_path / "out.log"),
                                 destination_type="file", **extra)


def test_zero_is_the_manual_mode_and_the_default_for_an_older_sender(manager, tmp_path):
    assert manager.get_sender(_file_sender(manager, tmp_path))["duration_seconds"] == 0
    assert manager.get_sender(
        _file_sender(manager, tmp_path, duration_seconds=90))["duration_seconds"] == 90


def test_a_sender_with_a_duration_stops_itself_and_is_marked_stopped(manager, tmp_path):
    sender_id = _file_sender(manager, tmp_path, duration_seconds=1)
    manager._data[sender_id]["enabled"] = True
    manager.start_sender(sender_id)

    deadline = time.monotonic() + 5
    while sender_id in manager.threads and time.monotonic() < deadline:
        time.sleep(0.05)

    assert sender_id not in manager.threads, "the thread outlived its duration"
    assert manager.get_sender(sender_id)["enabled"] is False, "the page would still call it running"
    assert manager.get_sender(sender_id)["logs_generated"] > 0
    assert Path(tmp_path / "out.log").read_text().strip(), "it should have written something"


def test_without_a_duration_it_keeps_going(manager, tmp_path):
    sender_id = _file_sender(manager, tmp_path)
    manager.start_sender(sender_id)
    try:
        time.sleep(0.6)
        assert sender_id in manager.threads, "a manual sender stopped on its own"
    finally:
        manager.stop_sender(sender_id)


def test_a_duration_can_still_be_cut_short_by_hand(manager, tmp_path):
    sender_id = _file_sender(manager, tmp_path, duration_seconds=3600)
    manager._data[sender_id]["enabled"] = True
    manager.start_sender(sender_id)
    time.sleep(0.2)
    manager.stop_sender(sender_id)
    assert sender_id not in manager.threads

    # Stopped by hand, not by running out: the caller owns `enabled` there, and
    # the worker must not have raced it back to False for its own reason.
    assert manager.get_sender(sender_id)["enabled"] is True


@pytest.mark.parametrize("seconds, lower, upper", [(1, 0.8, 3.0)])
def test_it_runs_for_about_the_time_asked(manager, tmp_path, seconds, lower, upper):
    sender_id = _file_sender(manager, tmp_path, duration_seconds=seconds)
    started = time.monotonic()
    manager.start_sender(sender_id)
    while sender_id in manager.threads and time.monotonic() - started < 10:
        time.sleep(0.05)
    assert lower <= time.monotonic() - started <= upper


def test_the_still_running_test_reads_the_stop_event_first():
    """Both halves of the condition, so neither can be dropped unnoticed."""
    stop = threading.Event()
    assert SenderManager._still_running(stop, None) is True
    assert SenderManager._still_running(stop, time.monotonic() + 10) is True
    assert SenderManager._still_running(stop, time.monotonic() - 1) is False
    stop.set()
    assert SenderManager._still_running(stop, None) is False
    assert SenderManager._still_running(stop, time.monotonic() + 10) is False


# ── when an attack last ran ─────────────────────────────────────────────────

def test_an_attack_records_when_it_last_ran(manager, tmp_path):
    """Stamped as it starts, so a run under way says when it began.

    The table shows this instead of a creation date and a counter: what a reader
    wants of an attack is whether it has run, and when.
    """
    from datetime import datetime

    sender_id = manager.create_sender(
        "tor", "windows_tor_client_execution", 0, destination=str(tmp_path / "a.log"),
        destination_type="file",
        options={"attack_events_count": 1, "attack_duration": 0})
    assert manager.get_sender(sender_id).get("last_run_at") is None, "never run yet"

    manager.start_sender(sender_id)
    first = manager.get_sender(sender_id)["last_run_at"]
    assert datetime.fromisoformat(first), "not a readable timestamp"

    deadline = time.monotonic() + 10
    while sender_id in manager.threads and time.monotonic() < deadline:
        time.sleep(0.05)
    assert manager.get_sender(sender_id)["last_run_at"] == first, \
        "finishing must not move the time it started at"

    time.sleep(1.1)
    manager.start_sender(sender_id)
    assert manager.get_sender(sender_id)["last_run_at"] > first, "a second run must update it"


def test_a_plain_sender_does_not_get_one(manager, tmp_path):
    """Only attacks are read that way; a sender has a rate and a duration."""
    sender_id = _file_sender(manager, tmp_path)
    manager.start_sender(sender_id)
    try:
        assert "last_run_at" not in manager.get_sender(sender_id)
    finally:
        manager.stop_sender(sender_id)
