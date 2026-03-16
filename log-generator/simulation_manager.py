"""
Simulation Manager
Orchestrates multiple senders to simulate a real infrastructure's log volume.
"""

import json
import uuid
from datetime import datetime
from pathlib import Path


# Estimated average log size in bytes per sourcetype
AVG_LOG_SIZES = {
    'apache':           200,
    'windows':          600,
    'ssh':              150,
    'paloalto':         400,
    'active_directory': 900,
    'cisco_ios':        150,
    'cisco_ftd':        250,
}


class SimulationManager:
    """Manages infrastructure simulations"""

    def __init__(self, config_file='simulations_config.json'):
        self.config_file = config_file
        self.simulations = {}
        self.load_config()

    def load_config(self):
        if Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                self.simulations = json.load(f)

    def save_config(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.simulations, f, indent=2)

    def calculate_frequency(self, volume_gb, duration_seconds, log_type):
        """Return logs/sec needed to reach volume_gb over duration_seconds."""
        if volume_gb <= 0 or duration_seconds <= 0:
            return 0
        avg_size = AVG_LOG_SIZES.get(log_type, 300)
        volume_bytes = volume_gb * 1024 ** 3
        freq = volume_bytes / (duration_seconds * avg_size)
        # Clamp to [1, 10000]
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

        self.simulations[sim_id] = {
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
        self.save_config()
        return sim_id

    def start_simulation(self, sim_id, sender_manager):
        """Start all senders for a simulation."""
        if sim_id not in self.simulations:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self.simulations[sim_id]
        if sim['status'] == 'running':
            raise ValueError("Simulation is already running")

        for entry in sim['sourcetypes']:
            log_type = entry['log_type']
            freq = entry['frequency']

            sender_id = sender_manager.create_sender(
                name=f"[SIM] {sim['name']} — {log_type}",
                log_type=log_type,
                frequency=freq,
                enabled=True,
                options=entry.get('options', {}),
                destination=sim.get('destination'),
                destination_type=sim['destination_type'],
                configuration_id=sim.get('configuration_id'),
            )
            entry['sender_id'] = sender_id

        sim['status'] = 'running'
        sim['started_at'] = datetime.now().isoformat()
        self.save_config()

    def stop_simulation(self, sim_id, sender_manager):
        """Stop and delete all senders for a simulation."""
        if sim_id not in self.simulations:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self.simulations[sim_id]

        for entry in sim['sourcetypes']:
            sender_id = entry.get('sender_id')
            if sender_id and sender_id in sender_manager.senders:
                sender_manager.delete_sender(sender_id)
            entry['sender_id'] = None

        sim['status'] = 'stopped'
        sim.pop('started_at', None)
        self.save_config()

    def delete_simulation(self, sim_id, sender_manager):
        """Stop and remove a simulation."""
        if sim_id not in self.simulations:
            raise ValueError(f"Simulation {sim_id} not found")

        sim = self.simulations[sim_id]
        if sim['status'] == 'running':
            self.stop_simulation(sim_id, sender_manager)

        del self.simulations[sim_id]
        self.save_config()

    def get_all_simulations(self):
        return list(self.simulations.values())

    def get_simulation(self, sim_id):
        return self.simulations.get(sim_id)
