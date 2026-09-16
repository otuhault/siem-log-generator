"""Shared pytest fixtures and import wiring for the characterization suite.

Executed before any test module is imported, so the sys.path / cwd wiring below
is in place by the time `import log_senders` runs at collection time.

Isolation guarantees enforced here:
  * `log-generator/` is importable without installing the project.
  * LOG_GENERATOR_STATE_DIR points at a throwaway directory, so a manager built
    with its default store name (`environment.json`) reads and writes there and
    never the 7 real runtime-state files next to the app.
  * A session guard snapshots those 7 files and fails the run if any is
    created, modified or deleted.
  * Real outbound sockets are blocked for the whole session.
  * `random.seed(42)` runs before every test.
"""

import atexit
import hashlib
import os
import random
import shutil
import socket
import sys
import tempfile
from pathlib import Path

import pytest

# --------------------------------------------------------------------------
# Import wiring (module level: runs before test modules are imported)
# --------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "log-generator"

if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

# Stores resolve bare names against the app directory, whatever the cwd, so
# isolation comes from redirecting that directory rather than from where the
# suite happens to run. Set before any manager can be imported.
os.environ["LOG_GENERATOR_STATE_DIR"] = tempfile.mkdtemp(prefix="log-generator-state-")
atexit.register(shutil.rmtree, os.environ["LOG_GENERATOR_STATE_DIR"], ignore_errors=True)
os.chdir(REPO_ROOT)


# --------------------------------------------------------------------------
# Runtime-state guard
# --------------------------------------------------------------------------

STATE_FILES = (
    "senders_config.json",
    "configurations.json",
    "syslog_destinations.json",
    "environment.json",
    "network_pools.json",
    "simulations_config.json",
    "assets_identities.json",
)


def _state_fingerprint():
    """Map each runtime-state file to (exists, size, sha256) or None."""
    out = {}
    for name in STATE_FILES:
        path = APP_DIR / name
        if not path.exists():
            out[name] = None
            continue
        data = path.read_bytes()
        out[name] = (len(data), hashlib.sha256(data).hexdigest())
    return out


@pytest.fixture(scope="session", autouse=True)
def guard_runtime_state():
    """Fail the session if any of the 7 runtime-state files is touched."""
    before = _state_fingerprint()
    yield
    after = _state_fingerprint()
    changed = [name for name in STATE_FILES if before[name] != after[name]]
    assert not changed, f"Tests mutated runtime-state file(s): {changed}"


# --------------------------------------------------------------------------
# Network guard
# --------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def block_real_network():
    """Prevent any test from opening a real outbound socket.

    Tests that exercise the syslog sink swap `syslog_sender.socket` for a fake,
    so they never reach these methods.
    """
    def _blocked(*args, **kwargs):
        raise RuntimeError("Real network access is disabled in the test suite")

    original_connect = socket.socket.connect
    original_sendto = socket.socket.sendto
    socket.socket.connect = _blocked
    socket.socket.sendto = _blocked
    try:
        yield
    finally:
        socket.socket.connect = original_connect
        socket.socket.sendto = original_sendto


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def deterministic_random():
    """Seed the global RNG before every test."""
    random.seed(42)
    yield


# --------------------------------------------------------------------------
# Convenience fixtures
# --------------------------------------------------------------------------

@pytest.fixture(scope="session")
def repo_root():
    return REPO_ROOT


@pytest.fixture(scope="session")
def app_dir():
    return APP_DIR
