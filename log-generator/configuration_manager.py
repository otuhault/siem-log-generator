"""
Configuration Management for HEC Destinations
"""

import uuid
from datetime import datetime
from store import JsonStore


class ConfigurationManager(JsonStore):
    """Manages HEC destination configurations"""

    def __init__(self, config_file='configurations.json'):
        super().__init__(config_file)
        self.configurations = self._data  # alias kept for backward compatibility

    def create_configuration(self, name, url, port, token, index=None, sourcetype=None, host=None, source=None):
        config_id = str(uuid.uuid4())
        self._data[config_id] = {
            'id': config_id,
            'name': name,
            'url': url,
            'port': port,
            'token': token,
            'index': index,
            'sourcetype': sourcetype,
            'host': host,
            'source': source,
            'created_at': datetime.now().isoformat(),
        }
        self._save()
        return config_id

    def get_configuration(self, config_id):
        return self._data.get(config_id)

    def get_all_configurations(self):
        return list(self._data.values())

    def update_configuration(self, config_id, data):
        if config_id not in self._data:
            raise ValueError(f"Configuration {config_id} not found")
        self._data[config_id].update(data)
        self._save()

    def delete_configuration(self, config_id):
        if config_id not in self._data:
            raise ValueError(f"Configuration {config_id} not found")
        del self._data[config_id]
        self._save()

    def clone_configuration(self, config_id):
        if config_id not in self._data:
            raise ValueError(f"Configuration {config_id} not found")
        original = self._data[config_id].copy()
        new_id = str(uuid.uuid4())
        original['id'] = new_id
        original['name'] = f"{original['name']} (copy)"
        original['created_at'] = datetime.now().isoformat()
        self._data[new_id] = original
        self._save()
        return new_id
