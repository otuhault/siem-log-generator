"""
Sender Management and Log Generation Engine
"""

import json
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from log_generators.apache import ApacheAccessLogGenerator
from log_generators.windows import WindowsEventLogGenerator

class SenderManager:
    """Manages log senders and their lifecycle"""
    
    def __init__(self, config_file='senders_config.json'):
        self.config_file = config_file
        self.senders = {}
        self.threads = {}
        self.load_config()
        
        # Register available log generators
        self.log_generators = {
            'apache_access': ApacheAccessLogGenerator,
            'windows_security': WindowsEventLogGenerator,
        }
    
    def load_config(self):
        """Load sender configuration from file"""
        if Path(self.config_file).exists():
            with open(self.config_file, 'r') as f:
                self.senders = json.load(f)
    
    def save_config(self):
        """Save sender configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.senders, f, indent=2)
    
    def create_sender(self, name, log_type, destination, frequency, enabled=False):
        """Create a new sender"""
        if log_type not in self.log_generators:
            raise ValueError(f"Unknown log type: {log_type}")
        
        sender_id = str(uuid.uuid4())
        self.senders[sender_id] = {
            'id': sender_id,
            'name': name,
            'log_type': log_type,
            'destination': destination,
            'frequency': frequency,  # logs per second
            'enabled': enabled,
            'created_at': datetime.now().isoformat(),
            'logs_generated': 0
        }
        self.save_config()
        
        if enabled:
            self.start_sender(sender_id)
        
        return sender_id
    
    def update_sender(self, sender_id, data):
        """Update sender configuration"""
        if sender_id not in self.senders:
            raise ValueError(f"Sender {sender_id} not found")
        
        was_enabled = self.senders[sender_id]['enabled']
        self.senders[sender_id].update(data)
        self.save_config()
        
        # Restart if configuration changed while enabled
        if was_enabled:
            self.stop_sender(sender_id)
            if self.senders[sender_id]['enabled']:
                self.start_sender(sender_id)
    
    def delete_sender(self, sender_id):
        """Delete a sender"""
        if sender_id not in self.senders:
            raise ValueError(f"Sender {sender_id} not found")
        
        self.stop_sender(sender_id)
        del self.senders[sender_id]
        self.save_config()
    
    def toggle_sender(self, sender_id):
        """Enable or disable a sender"""
        if sender_id not in self.senders:
            raise ValueError(f"Sender {sender_id} not found")
        
        enabled = not self.senders[sender_id]['enabled']
        self.senders[sender_id]['enabled'] = enabled
        self.save_config()
        
        if enabled:
            self.start_sender(sender_id)
        else:
            self.stop_sender(sender_id)
    
    def clone_sender(self, sender_id):
        """Clone a sender"""
        if sender_id not in self.senders:
            raise ValueError(f"Sender {sender_id} not found")
        
        original = self.senders[sender_id].copy()
        new_id = str(uuid.uuid4())
        original['id'] = new_id
        original['name'] = f"{original['name']} (copy)"
        original['enabled'] = False
        original['created_at'] = datetime.now().isoformat()
        original['logs_generated'] = 0
        
        self.senders[new_id] = original
        self.save_config()
        return new_id
    
    def start_sender(self, sender_id):
        """Start a sender thread"""
        if sender_id in self.threads:
            return  # Already running
        
        sender = self.senders[sender_id]
        generator_class = self.log_generators[sender['log_type']]
        generator = generator_class()
        
        stop_event = threading.Event()
        thread = threading.Thread(
            target=self._generate_logs,
            args=(sender_id, generator, sender['destination'], 
                  sender['frequency'], stop_event),
            daemon=True
        )
        
        self.threads[sender_id] = {'thread': thread, 'stop_event': stop_event}
        thread.start()
    
    def stop_sender(self, sender_id):
        """Stop a sender thread"""
        if sender_id in self.threads:
            self.threads[sender_id]['stop_event'].set()
            self.threads[sender_id]['thread'].join(timeout=2)
            del self.threads[sender_id]
    
    def _generate_logs(self, sender_id, generator, destination, frequency, stop_event):
        """Generate logs at specified frequency"""
        interval = 1.0 / frequency if frequency > 0 else 1.0
        
        # Ensure destination directory exists
        dest_path = Path(destination)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(destination, 'a') as f:
            while not stop_event.is_set():
                log_line = generator.generate()
                f.write(log_line + '\n')
                f.flush()
                
                self.senders[sender_id]['logs_generated'] += 1
                
                time.sleep(interval)
    
    def get_all_senders(self):
        """Get all senders"""
        return list(self.senders.values())
    
    def get_available_log_types(self):
        """Get available log types with descriptions"""
        return {
            'apache_access': {
                'name': 'Apache Access Log',
                'description': 'Apache/Nginx web server access logs (Combined Log Format)',
                'example': '192.168.1.100 - - [02/Feb/2026:18:52:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
            },
            'windows_security': {
                'name': 'Windows Security Event Log',
                'description': 'Windows Security Event Logs (XML format, common Event IDs)',
                'example': 'Event ID 4624 - Successful Logon'
            }
        }
