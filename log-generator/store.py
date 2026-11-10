"""
Base class for JSON-backed persistent storage.
Provides load/save boilerplate shared by all manager classes.
"""

import json
import os
from pathlib import Path

#: Where relative store names resolve: this directory, which is where
#: .gitignore expects them. Resolving against the working directory instead meant
#: `python log-generator/app.py` from the repository root wrote every store —
#: HEC tokens included — to the root, where nothing ignores them.
APP_DIR = Path(__file__).resolve().parent

#: Overrides APP_DIR. The test suite points it at a temporary directory, so no
#: test can reach the real configuration however a manager is constructed.
STATE_DIR_ENV = 'LOG_GENERATOR_STATE_DIR'


def store_path(filepath) -> Path:
    """An absolute path stays as given; a bare name lives in the state directory."""
    path = Path(filepath)
    if path.is_absolute():
        return path
    return Path(os.environ.get(STATE_DIR_ENV) or APP_DIR) / path


class JsonStore:
    """Key/value store backed by a JSON file.

    Subclasses get self._data (dict) pre-loaded from disk.
    Call self._save() after any mutation.

    Usage::

        class MyManager(JsonStore):
            def __init__(self):
                super().__init__('my_data.json')
                self.items = self._data  # optional alias
    """

    def __init__(self, filepath: str):
        self._path = store_path(filepath)
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            with self._path.open() as f:
                self._data = json.load(f)

    def _save(self) -> None:
        with self._path.open('w') as f:
            json.dump(self._data, f, indent=2)
