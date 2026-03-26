"""
Simulation Manager
Orchestrates multiple senders to simulate a real infrastructure's log volume.
"""

import uuid
from datetime import datetime
from store import JsonStore
from log_generators.registry import REGISTRY


class SimulationManager(JsonStore):
    """Manages infrastructure simulations"""

    def __init__(self, config_file='simulations_config.json'):
        super().__init__(config_file)
        self.simulations = self._data  # alias kept for backward compatibility

    def calculate_frequency(self, volume_gb, duration_seconds, log_type):
        """Return logs/sec needed to reach volume_gb over duration_seconds."""
        if volume_gb <= 0 or duration_seconds <= 0:
            return 0
        cls = REGISTRY.get(log_type)
        avg_size = cls.AVG_LOG_SIZE if cls else 300
        volume_bytes = volume_gb * 1024 ** 3
        freq = volume_bytes / (duration_seconds * avg_size)
        return max(1, min(10000, round(freq, 2)))

    def create_simulation(self, name, duration_hours, sourcetypes, destination=None,
                          destination_type='file', configuration_id=None):
        """
        Create a simulation.

        sourcetypes: list of dicts:
            { 'log_type': str, 'volume_gb': float, 'options': dict }
        """
        sim_id = str(uuid.uuid4())
        duration_seconds = duration_hours * 3600

        entries = []
        for st in sourcetypes:
            log_type = st['log_type']
            volume_gb = float(st.get('volume_gb', 0))
            if volume_gb <= 0:
                continue
            freq = self.calculate_frequency(volume_gb, duration_seconds, log_type)
            entries.append({
                'log_type': log_type,
                'volume_gb': volume_gb,
                'frequency': freq,
                'options': st.get('options', {}),
                'sender_id': None,
            })

        if not entries:
            raise ValueError("At least one sourcetype with volume > 0 is required.")

        self._data[sim_id] = {
            'id': sim_id,
            'name': name,
            'duration_hours': duration_hours,
            'destination': destination,
            'destination_type': destination_type,
            'configuration_id': configuration_id,
            'sourcetypes': entries,
            'status': 'stopped',
            'created_at': datetime.now().isoformat(),
        }
        self._save()
        return sim_id

    def start_simulation(self, sim_id, sender_manager):
        """Start all senders for a simulation."""
        if sim_id not in self._data:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self._data[sim_id]
        if sim['status'] == 'running':
            raise ValueError("Simulation is already running")

        for entry in sim['sourcetypes']:
            sender_id = sender_manager.create_sender(
                name=f"[SIM] {sim['name']} — {entry['log_type']}",
                log_type=entry['log_type'],
                frequency=entry['frequency'],
                enabled=True,
                options=entry.get('options', {}),
                destination=sim.get('destination'),
                destination_type=sim['destination_type'],
                configuration_id=sim.get('configuration_id'),
            )
            entry['sender_id'] = sender_id

        sim['status'] = 'running'
        sim['started_at'] = datetime.now().isoformat()
        self._save()

    def stop_simulation(self, sim_id, sender_manager):
        """Stop and delete all senders for a simulation."""
        if sim_id not in self._data:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self._data[sim_id]
        for entry in sim['sourcetypes']:
            sender_id = entry.get('sender_id')
            if sender_id and sender_id in sender_manager.senders:
                sender_manager.delete_sender(sender_id)
            entry['sender_id'] = None

        sim['status'] = 'stopped'
        sim.pop('started_at', None)
        self._save()

    def delete_simulation(self, sim_id, sender_manager):
        """Stop and remove a simulation."""
        if sim_id not in self._data:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self._data[sim_id]
        if sim['status'] == 'running':
            self.stop_simulation(sim_id, sender_manager)

        del self._data[sim_id]
        self._save()

    def get_all_simulations(self):
        return list(self._data.values())

    def get_simulation(self, sim_id):
        return self._data.get(sim_id)
