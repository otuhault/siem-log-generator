"""
Syslog Destinations Manager — persistence for named syslog endpoints.

Mirrors ConfigurationManager (HEC) so a sender can pick a destination by id.
Model: name + host + port + protocol (udp|tcp).
"""

import uuid
from datetime import datetime
from store import JsonStore


class SyslogDestinationsManager(JsonStore):
    """Manages persisted Syslog destinations (UDP/TCP)."""

    def __init__(self, config_file='syslog_destinations.json'):
        super().__init__(config_file)

    def create_destination(self, name, host, port, protocol='udp'):
        protocol = (protocol or 'udp').lower()
        if protocol not in ('udp', 'tcp'):
            raise ValueError("protocol must be 'udp' or 'tcp'")
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError("port must be between 1 and 65535")

        dest_id = str(uuid.uuid4())
        self._data[dest_id] = {
            'id':         dest_id,
            'name':       name,
            'host':       host,
            'port':       port,
            'protocol':   protocol,
            'created_at': datetime.now().isoformat(),
        }
        self._save()
        return dest_id

    def get_destination(self, dest_id):
        return self._data.get(dest_id)

    def get_all_destinations(self):
        return list(self._data.values())

    def update_destination(self, dest_id, data):
        if dest_id not in self._data:
            raise ValueError(f"Syslog destination {dest_id} not found")
        if 'protocol' in data:
            data['protocol'] = (data['protocol'] or 'udp').lower()
            if data['protocol'] not in ('udp', 'tcp'):
                raise ValueError("protocol must be 'udp' or 'tcp'")
        if 'port' in data:
            data['port'] = int(data['port'])
        self._data[dest_id].update(data)
        self._save()

    def delete_destination(self, dest_id):
        if dest_id not in self._data:
            raise ValueError(f"Syslog destination {dest_id} not found")
        del self._data[dest_id]
        self._save()

    def clone_destination(self, dest_id):
        if dest_id not in self._data:
            raise ValueError(f"Syslog destination {dest_id} not found")
        original = self._data[dest_id].copy()
        new_id = str(uuid.uuid4())
        original['id']         = new_id
        original['name']       = f"{original['name']} (copy)"
        original['created_at'] = datetime.now().isoformat()
        self._data[new_id] = original
        self._save()
        return new_id
