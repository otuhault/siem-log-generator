"""
Base class for JSON-backed persistent storage.
Provides load/save boilerplate shared by all manager classes.
"""

import json
from pathlib import Path


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
        self._path = Path(filepath)
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            with self._path.open() as f:
                self._data = json.load(f)

    def _save(self) -> None:
        with self._path.open('w') as f:
            json.dump(self._data, f, indent=2)
