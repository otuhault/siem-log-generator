"""
Attack Pattern Management for Log Generator
"""

import json
import uuid
from datetime import datetime
from pathlib import Path


class AttacksManager:
    """Manages attack pattern definitions"""

    def __init__(self, config_file='attacks.json'):
        self.config_file = config_file
        self.attacks = {}
        self.load_config()

    def load_config(self):
        """Load attacks from file"""
        if Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                self.attacks = json.load(f)

    def save_config(self):
        """Save attacks to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.attacks, f, indent=2)

    def create_attack(self, name, description, log_type, example,
                      attack_type=None, attack_options=None):
        """Create a new attack pattern"""
        attack_id = str(uuid.uuid4())
        self.attacks[attack_id] = {
            'id': attack_id,
            'name': name,
            'description': description,
            'log_type': log_type,
            'example': example,
            'attack_type': attack_type,  # e.g., 'ssh_bruteforce'
            'attack_options': attack_options or {},  # e.g., {'mode': 'diff_user_same_ip'}
            'created_at': datetime.now().isoformat()
        }
        self.save_config()
        return attack_id

    def get_attack(self, attack_id):
        """Get a specific attack"""
        return self.attacks.get(attack_id)

    def get_all_attacks(self):
        """Get all attacks"""
        return list(self.attacks.values())

    def update_attack(self, attack_id, data):
        """Update attack"""
        if attack_id not in self.attacks:
            raise ValueError(f"Attack {attack_id} not found")

        self.attacks[attack_id].update(data)
        self.save_config()

    def delete_attack(self, attack_id):
        """Delete an attack"""
        if attack_id not in self.attacks:
            raise ValueError(f"Attack {attack_id} not found")

        del self.attacks[attack_id]
        self.save_config()

    def clone_attack(self, attack_id):
        """Clone an attack"""
        if attack_id not in self.attacks:
            raise ValueError(f"Attack {attack_id} not found")

        original = self.attacks[attack_id].copy()
        new_id = str(uuid.uuid4())
        original['id'] = new_id
        original['name'] = f"{original['name']} (copy)"
        original['created_at'] = datetime.now().isoformat()

        self.attacks[new_id] = original
        self.save_config()
        return new_id
