"""
Lists Management for Custom Value Lists
"""

import json
import re
import uuid
from datetime import datetime
from pathlib import Path


# Supported list types and their validators
LIST_TYPES = {
    'user': 'Usernames',
    'ip': 'IP Addresses',
    'port': 'Ports',
    'hostname': 'Hostnames',
    'url': 'URLs'
}

# Validation patterns
IP_PATTERN = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)
HOSTNAME_PATTERN = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)
URL_PATTERN = re.compile(
    r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE
)


class ListsManager:
    """Manages custom value lists for attack field overrides"""

    def __init__(self, config_file='lists.json'):
        self.config_file = config_file
        self.lists = {}
        self.load_config()

    def load_config(self):
        """Load lists from file"""
        if Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                self.lists = json.load(f)

    def save_config(self):
        """Save lists to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.lists, f, indent=2)

    def validate_value(self, list_type, value):
        """Validate a single value against its list type"""
        if not value or not value.strip():
            return False, "Value cannot be empty"

        value = value.strip()

        if list_type == 'user':
            if ' ' in value:
                return False, f"Username '{value}' must not contain spaces"
            return True, None

        elif list_type == 'ip':
            if not IP_PATTERN.match(value):
                return False, f"'{value}' is not a valid IPv4 address"
            return True, None

        elif list_type == 'port':
            try:
                port = int(value)
                if port < 1 or port > 65535:
                    return False, f"Port {value} must be between 1 and 65535"
                return True, None
            except ValueError:
                return False, f"'{value}' is not a valid port number"

        elif list_type == 'hostname':
            if not HOSTNAME_PATTERN.match(value):
                return False, f"'{value}' is not a valid hostname"
            return True, None

        elif list_type == 'url':
            if not URL_PATTERN.match(value):
                return False, f"'{value}' is not a valid URL"
            return True, None

        return False, f"Unknown list type: {list_type}"

    def validate_values(self, list_type, values):
        """Validate all values in a list"""
        errors = []
        for value in values:
            valid, error = self.validate_value(list_type, value)
            if not valid:
                errors.append(error)
        return errors

    def create_list(self, name, list_type, values):
        """Create a new list"""
        if list_type not in LIST_TYPES:
            raise ValueError(f"Unknown list type: {list_type}. Supported: {', '.join(LIST_TYPES.keys())}")

        if not values:
            raise ValueError("List must contain at least one value")

        # Validate all values
        errors = self.validate_values(list_type, values)
        if errors:
            raise ValueError(f"Validation errors: {'; '.join(errors)}")

        list_id = str(uuid.uuid4())
        self.lists[list_id] = {
            'id': list_id,
            'name': name,
            'type': list_type,
            'values': [v.strip() for v in values],
            'created_at': datetime.now().isoformat()
        }
        self.save_config()
        return list_id

    def get_list(self, list_id):
        """Get a specific list"""
        return self.lists.get(list_id)

    def get_all_lists(self):
        """Get all lists"""
        return list(self.lists.values())

    def get_lists_by_type(self, list_type):
        """Get lists filtered by type"""
        return [l for l in self.lists.values() if l['type'] == list_type]

    def update_list(self, list_id, data):
        """Update a list"""
        if list_id not in self.lists:
            raise ValueError(f"List {list_id} not found")

        # If values or type are being updated, validate
        new_type = data.get('type', self.lists[list_id]['type'])
        new_values = data.get('values', self.lists[list_id]['values'])

        if new_type not in LIST_TYPES:
            raise ValueError(f"Unknown list type: {new_type}")

        if new_values:
            errors = self.validate_values(new_type, new_values)
            if errors:
                raise ValueError(f"Validation errors: {'; '.join(errors)}")

        self.lists[list_id].update(data)
        self.save_config()

    def delete_list(self, list_id):
        """Delete a list"""
        if list_id not in self.lists:
            raise ValueError(f"List {list_id} not found")

        del self.lists[list_id]
        self.save_config()

    def clone_list(self, list_id):
        """Clone a list"""
        if list_id not in self.lists:
            raise ValueError(f"List {list_id} not found")

        original = self.lists[list_id].copy()
        new_id = str(uuid.uuid4())
        original['id'] = new_id
        original['name'] = f"{original['name']} (copy)"
        original['values'] = original['values'].copy()
        original['created_at'] = datetime.now().isoformat()

        self.lists[new_id] = original
        self.save_config()
        return new_id
