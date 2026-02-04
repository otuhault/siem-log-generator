"""
Configuration Management for HEC Destinations
"""

import json
import uuid
from datetime import datetime
from pathlib import Path


class ConfigurationManager:
    """Manages HEC destination configurations"""

    def __init__(self, config_file='configurations.json'):
        self.config_file = config_file
        self.configurations = {}
        self.load_config()

    def load_config(self):
        """Load configuration from file"""
        if Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                self.configurations = json.load(f)

    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.configurations, f, indent=2)

    def create_configuration(self, name, url, port, token, index=None, sourcetype=None, host=None, source=None):
        """Create a new configuration"""
        config_id = str(uuid.uuid4())
        self.configurations[config_id] = {
            'id': config_id,
            'name': name,
            'url': url,
            'port': port,
            'token': token,
            'index': index,
            'sourcetype': sourcetype,
            'host': host,
            'source': source,
            'created_at': datetime.now().isoformat()
        }
        self.save_config()
        return config_id

    def get_configuration(self, config_id):
        """Get a specific configuration"""
        return self.configurations.get(config_id)

    def get_all_configurations(self):
        """Get all configurations"""
        return list(self.configurations.values())

    def update_configuration(self, config_id, data):
        """Update configuration"""
        if config_id not in self.configurations:
            raise ValueError(f"Configuration {config_id} not found")

        self.configurations[config_id].update(data)
        self.save_config()

    def delete_configuration(self, config_id):
        """Delete a configuration"""
        if config_id not in self.configurations:
            raise ValueError(f"Configuration {config_id} not found")

        del self.configurations[config_id]
        self.save_config()

    def clone_configuration(self, config_id):
        """Clone a configuration"""
        if config_id not in self.configurations:
            raise ValueError(f"Configuration {config_id} not found")

        original = self.configurations[config_id].copy()
        new_id = str(uuid.uuid4())
        original['id'] = new_id
        original['name'] = f"{original['name']} (copy)"
        original['created_at'] = datetime.now().isoformat()

        self.configurations[new_id] = original
        self.save_config()
        return new_id
