"""No source file compiles with a warning.

`ta_registry.py` quoted a Splunk regex in its module docstring — `\\S+`, `\\w`,
`\\s`, `\\/` — in an ordinary string rather than a raw one. Python keeps an
unrecognised escape as the two characters it was written as, so the text read
correctly and nothing failed; it only emitted a SyntaxWarning, which is easy to
scroll past.

The docstring was harmless. The same mistake one line lower is not: a regex
written as "\\d+" in a non-raw string works today by that same accident, and
Python has said these sequences will stop working. A pattern that silently
stops matching is exactly the kind of failure this repository tries not to
have — the add-on regexes it replays are its whole basis for claiming the
events parse.

So every file is compiled with warnings raised as errors, rather than this one
being fixed on its own.
"""

import re
import subprocess
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

SOURCES = sorted(
    p for p in ROOT.rglob("*.py")
    if not any(part in {"venv", ".venv", "TAs", "node_modules", "__pycache__", "build", "dist"}
               for part in p.parts)
)


def test_there_are_sources_to_check():
    """Otherwise the sweep below would pass by finding nothing."""
    assert len(SOURCES) > 40, f"only found {len(SOURCES)} source files"
    assert any(p.name == "ta_registry.py" for p in SOURCES)


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(ROOT)))
def test_compiles_without_a_warning(path):
    source = path.read_text(encoding="utf-8")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        try:
            compile(source, str(path), "exec")
        except SyntaxWarning as warning:
            pytest.fail(f"{path.relative_to(ROOT)}: {warning}\n"
                        f"An unrecognised escape survives today and stops working later. "
                        f"Use a raw string for a regex, or double the backslash.")


# ── and nothing carries the author's machine into the repository ────────────

#: A dated read-only audit, kept as the record of one day. It quotes the path it
#: was run against, and is not part of what gets published.
PERSONAL_PATH_EXEMPT = {"AUDIT.md"}

HOME_PATH = re.compile(r"/(?:Users|home)/(?!runner\b|user\b)[A-Za-z0-9_.-]+/")


def test_no_tracked_file_carries_a_path_from_someone_s_machine():
    """An absolute home path names the account it came from.

    It has nearly shipped twice: once as a .gitignore comment, once as a test
    fixture using the author's own login as example lsof output. Neither broke
    anything — both would have published a name that has no business being in
    the repository.
    """
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT,
                             capture_output=True, text=True).stdout.split()
    offenders = []
    for name in tracked:
        if name in PERSONAL_PATH_EXEMPT:
            continue
        path = ROOT / name
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if HOME_PATH.search(line):
                offenders.append(f"{name}:{number}: {line.strip()[:90]}")
    assert not offenders, "a personal path is about to be committed:\n  " + "\n  ".join(offenders)
