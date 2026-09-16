"""Every store the app writes is gitignored, wherever it lands.

Two HEC tokens reached a public repository through this gap. `configurations.json`
was committed on 2026-02-04 and removed from the tip on 2026-03-02, but stayed in
the history for another six months — long enough for anyone to read it.

The .gitignore did cover `log-generator/*.json`, which is where the stores
normally live. It did not cover them anywhere else, and they do land elsewhere:
`store_path()` honours LOG_GENERATOR_STATE_DIR, and an earlier version resolved
bare names against the working directory, so launching the app from the
repository root wrote every store to the root — where nothing ignored them.

So the check is not "is the .gitignore as we last wrote it" but "would git
actually refuse each of these files, at each place it can appear". The store
names come from the source, so adding a manager without a .gitignore entry
fails here rather than on someone's next commit.
"""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "log-generator"

#: Where a store can end up: beside the code, at the repository root (the way
#: the tokens escaped), and under any state directory inside the checkout.
PLACES = ["log-generator/{}", "{}", "state/{}", "var/run/{}", "log-generator/{}.bak-20260101"]


def declared_stores():
    """Every JSON store named in the application source.

    Read from the `config_file='…'` defaults rather than listed here: a manager
    added with a new store is caught the day it appears.
    """
    names = set()
    for path in APP.glob("*.py"):
        # store.py is the base class. It declares no store of its own; its
        # docstring shows the pattern with a made-up `my_data.json`.
        if path.name == "store.py":
            continue
        text = path.read_text(errors="replace")
        names |= set(re.findall(r"config_file\s*=\s*['\"]([\w.-]+\.json)['\"]", text))
        names |= set(re.findall(r"super\(\)\.__init__\(\s*['\"]([\w.-]+\.json)['\"]", text))
        # A store reached directly rather than through a manager — the v1
        # assets_identities.json, still read once to migrate it — holds the
        # same kind of data and needs the same treatment.
        names |= set(re.findall(r"store_path\(\s*['\"]([\w.-]+\.json)['\"]", text))
    return sorted(names)


def is_ignored(relative_path):
    """What git itself says, not what the .gitignore appears to say."""
    result = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", relative_path],
        cwd=ROOT, capture_output=True)
    return result.returncode == 0


def test_the_source_still_declares_its_stores():
    """If this finds nothing, every other test here would pass vacuously."""
    stores = declared_stores()
    assert len(stores) >= 5, f"only found {stores} — the declaration style changed"
    assert "configurations.json" in stores, "the store that leaked is no longer declared"


@pytest.mark.parametrize("store", declared_stores())
@pytest.mark.parametrize("place", PLACES)
def test_every_store_is_ignored_wherever_it_lands(store, place):
    path = place.format(store)
    assert is_ignored(path), (
        f"{path} would be committed. It holds whatever HEC token, lab address or "
        f"account name the app was given.")


def test_the_repository_carries_no_store_right_now():
    """Not just ignorable — actually absent from what git tracks."""
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT,
                             capture_output=True, text=True).stdout.split()
    stores = set(declared_stores())
    committed = [p for p in tracked if Path(p).name in stores]
    assert not committed, f"a state file is tracked: {committed}"


def test_the_rules_do_not_swallow_files_that_must_ship():
    """A pattern broad enough to catch every store could catch these too."""
    for needed in ("package.json", "pyproject.toml", "log-generator/templates/index.html",
                   "tests/conftest.py", "references/adding-a-source.md"):
        assert not is_ignored(needed), f"{needed} is ignored but has to be published"
