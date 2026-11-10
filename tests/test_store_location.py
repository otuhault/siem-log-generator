"""Runtime stores are written next to the app, whatever directory it is run from.

They hold HEC tokens, lab addresses and account names, and .gitignore protects
them only under log-generator/. Resolving against the working directory meant
that launching `python log-generator/app.py` from the repository root — the
natural thing to type after cloning — wrote them to the root instead, where
nothing ignores them.
"""

from pathlib import Path

import store
from configuration_manager import ConfigurationManager

APP_DIR = Path(store.__file__).resolve().parent


def test_a_bare_store_name_resolves_to_the_app_directory(tmp_path, monkeypatch):
    """Checked on the path alone: constructing the store would read the real
    configuration, which the suite must never touch."""
    monkeypatch.chdir(tmp_path)                  # anywhere but log-generator/
    monkeypatch.delenv(store.STATE_DIR_ENV, raising=False)

    assert store.store_path("configurations.json") == APP_DIR / "configurations.json"


def test_the_suite_itself_is_redirected_away_from_the_real_stores(tmp_path):
    manager = ConfigurationManager()             # default name, no path given
    assert APP_DIR not in manager._path.parents, (
        f"a test manager resolved to the real configuration: {manager._path}")


def test_an_absolute_path_is_kept_as_given(tmp_path):
    target = tmp_path / "elsewhere.json"
    assert store.store_path(str(target)) == target


def test_gitignore_covers_where_the_stores_actually_go():
    root = APP_DIR.parent
    rules = (root / ".gitignore").read_text().splitlines()
    assert f"{APP_DIR.name}/*.json" in rules, (
        "the stores moved, or the rule that keeps them out of git did")
