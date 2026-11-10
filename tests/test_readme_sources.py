r"""The README's data source and add-on tables, held to the registry.

They are rendered by tools/readme_sources.py from ta_registry.py. Nothing
forces anyone to run it, so this does: add a source, forget the README, and the
suite says so — with the command that fixes it. The tables iterate the registry,
so a new source is covered the moment it is registered, with no list to keep.
"""

import configparser
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TAS = ROOT / "TAs"

spec = importlib.util.spec_from_file_location(
    "readme_sources", ROOT / "tools" / "readme_sources.py")
readme_sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readme_sources)

from ta_registry import TA_REGISTRY  # noqa: E402


def generated_block():
    text = (ROOT / "README.md").read_text()
    assert readme_sources.BEGIN in text and readme_sources.END in text, \
        "the README lost its generated-block markers"
    return text.split(readme_sources.BEGIN, 1)[1].split(readme_sources.END, 1)[0].strip()


def test_the_readme_tables_match_the_registry():
    assert generated_block() == readme_sources.render().strip(), (
        "README.md no longer lists what the registry declares. "
        "Run: python tools/readme_sources.py")


@pytest.mark.parametrize("key", sorted(TA_REGISTRY))
def test_every_source_and_its_add_on_appear(key):
    """Stated per source, so a failure names the one that is missing."""
    entry = TA_REGISTRY[key]
    block = generated_block()
    assert f"| {entry['display_name']} |" in block, entry["display_name"]
    assert f"[{entry['name']}]({entry['splunkbase_url']})" in block, entry["name"]


def test_an_add_on_shared_by_several_sources_is_listed_once():
    """Windows, Active Directory and PowerShell all need Splunk_TA_windows."""
    block = generated_block()
    for package in {entry["add_on_package"] for entry in TA_REGISTRY.values()}:
        assert block.count(f"| `{package}` |") == 1, package


def _app_conf_version(package):
    conf = configparser.ConfigParser(strict=False, interpolation=None)
    conf.read(TAS / package / "default" / "app.conf")
    for section in ("launcher", "id"):
        if conf.has_option(section, "version"):
            return conf.get(section, "version")
    return None


@pytest.mark.parametrize("package", sorted(
    {entry["add_on_package"] for entry in TA_REGISTRY.values()}))
def test_the_version_announced_is_the_one_in_tas(package):
    """"Checked against" must be the add-on the tests actually read.

    The README tells a reader which version the events were verified against.
    That is only true if it is the version sitting in TAs/, where the add-on's
    own configuration is replayed against the generators.
    """
    if not (TAS / package).exists():
        pytest.skip(f"{package} not present in TAs/")
    announced = {entry["add_on_version"] for entry in TA_REGISTRY.values()
                 if entry["add_on_package"] == package}
    assert announced == {_app_conf_version(package)}, (
        f"{package}: the registry says {sorted(announced)}, "
        f"TAs/ holds {_app_conf_version(package)}")
