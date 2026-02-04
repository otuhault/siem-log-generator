"""
Sender Management and Log Generation Engine
"""

import json
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from log_generators.apache import ApacheLogGenerator
from log_generators.windows import WindowsEventLogGenerator
from log_generators.ssh import SSHAuthLogGenerator
from log_generators.paloalto import PaloAltoLogGenerator
from hec_sender import HECSender

class SSHMultiCategoryGenerator:
    """Wrapper that generates logs from multiple SSH event categories"""

    def __init__(self, event_categories):
        """
        Initialize with multiple event categories
        event_categories: list of category names like ['auth_success', 'auth_failed', 'sessions', 'connections', 'errors']
        """
        self.generator = SSHAuthLogGenerator(event_categories=event_categories)
        self.event_categories = event_categories

    def generate(self):
        """Generate a log from the configured categories"""
        return self.generator.generate()

class ApacheMultiSourceGenerator:
    """Wrapper that generates logs from multiple Apache log types"""

    def __init__(self, log_types):
        """
        Initialize with multiple log types
        log_types: list of type names like ['access', 'error', 'combined']
        """
        self.generators = [
            ApacheLogGenerator(log_type=log_type)
            for log_type in log_types
        ]
        self.log_types = log_types

    def generate(self):
        """Generate a log from a randomly selected type"""
        import random
        generator = random.choice(self.generators)
        return generator.generate()

class WindowsMultiSourceGenerator:
    """Wrapper that generates logs from multiple Windows sources"""

    def __init__(self, sources, render_format='xml'):
        """
        Initialize with multiple sources
        sources: list of source names like ['Security', 'Application', 'System']
        """
        self.generators = [
            WindowsEventLogGenerator(source=source, render_format=render_format)
            for source in sources
        ]
        self.sources = sources

    def generate(self):
        """Generate a log from a randomly selected source"""
        import random
        generator = random.choice(self.generators)
        return generator.generate()


class PaloAltoMultiTypeGenerator:
    """Wrapper that generates logs from multiple Palo Alto log types"""

    def __init__(self, log_types):
        """
        Initialize with multiple log types
        log_types: list of type names like ['traffic', 'threat', 'system']
        """
        self.generator = PaloAltoLogGenerator(log_types=log_types)
        self.log_types = log_types

    def generate(self):
        """Generate a log from the configured types"""
        return self.generator.generate()

class SenderManager:
    """Manages log senders and their lifecycle"""
    
    def __init__(self, config_file='senders_config.json'):
        self.config_file = config_file
        self.senders = {}
        self.threads = {}
        self.load_config()
        
        # Register available log generators
        self.log_generators = {
            'apache': ApacheLogGenerator,
            'windows': WindowsEventLogGenerator,
            'ssh': SSHAuthLogGenerator,
            'paloalto': PaloAltoLogGenerator,
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
    
    def create_sender(self, name, log_type, frequency, enabled=False, options=None,
                      destination=None, destination_type='file', configuration_id=None):
        """Create a new sender"""
        if log_type not in self.log_generators:
            raise ValueError(f"Unknown log type: {log_type}")

        sender_id = str(uuid.uuid4())
        self.senders[sender_id] = {
            'id': sender_id,
            'name': name,
            'log_type': log_type,
            'destination': destination,
            'destination_type': destination_type,
            'configuration_id': configuration_id,
            'frequency': frequency,  # logs per second
            'enabled': enabled,
            'created_at': datetime.now().isoformat(),
            'logs_generated': 0,
            'options': options or {}  # Store log type specific options
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

        # Pass options to generator if available
        options = sender.get('options', {})

        # Handle Windows Event Log generators
        if sender['log_type'] == 'windows':
            # Get selected sources (default to Security if none specified)
            sources = options.get('sources', ['Security'])
            render_format = options.get('render_format', 'xml')

            # Create a multi-source generator wrapper
            generator = WindowsMultiSourceGenerator(sources, render_format)
        # Handle Apache Log generators
        elif sender['log_type'] == 'apache':
            # Get selected log types (default to combined if none specified)
            log_types = options.get('log_types', ['combined'])

            # Create a multi-source generator wrapper
            generator = ApacheMultiSourceGenerator(log_types)
        # Handle SSH Log generators
        elif sender['log_type'] == 'ssh':
            # Get selected event categories (default to all if none specified)
            event_categories = options.get('event_categories', ['auth_success', 'auth_failed', 'sessions', 'connections', 'errors'])

            # Create a multi-category generator wrapper
            generator = SSHMultiCategoryGenerator(event_categories)
        # Handle Palo Alto Log generators
        elif sender['log_type'] == 'paloalto':
            # Get selected log types (default to all if none specified)
            log_types = options.get('log_types', ['traffic', 'threat', 'system'])

            # Create a multi-type generator wrapper
            generator = PaloAltoMultiTypeGenerator(log_types)
        else:
            # Other log types
            generator = generator_class()
        
        stop_event = threading.Event()
        thread = threading.Thread(
            target=self._generate_logs,
            args=(sender_id, generator, sender, stop_event),
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
    
    def _generate_logs(self, sender_id, generator, sender_config, stop_event):
        """Generate logs at specified frequency"""
        frequency = sender_config['frequency']
        interval = 1.0 / frequency if frequency > 0 else 1.0

        destination_type = sender_config.get('destination_type', 'file')

        # Handle file destination
        if destination_type == 'file':
            destination = sender_config['destination']

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

        # Handle HEC destination
        elif destination_type == 'configuration':
            # Load configuration manager to get HEC config
            from configuration_manager import ConfigurationManager
            config_mgr = ConfigurationManager()

            config_id = sender_config.get('configuration_id')
            if not config_id:
                print(f"Error: No configuration_id specified for sender {sender_id}")
                return

            hec_config = config_mgr.get_configuration(config_id)
            if not hec_config:
                print(f"Error: Configuration {config_id} not found")
                return

            # Create HEC sender
            hec_sender = HECSender(
                url=hec_config['url'],
                port=hec_config['port'],
                token=hec_config['token'],
                index=hec_config.get('index'),
                sourcetype=hec_config.get('sourcetype'),
                host=hec_config.get('host'),
                source=hec_config.get('source')
            )

            try:
                while not stop_event.is_set():
                    log_line = generator.generate()

                    # Send to HEC
                    success = hec_sender.send_event(log_line)

                    if success:
                        self.senders[sender_id]['logs_generated'] += 1

                    time.sleep(interval)
            finally:
                hec_sender.close()
    
    def get_all_senders(self):
        """Get all senders"""
        return list(self.senders.values())

    def get_sender(self, sender_id):
        """Get a specific sender"""
        return self.senders.get(sender_id)

    def get_available_log_types(self):
        """Get available log types with descriptions"""
        return {
            'apache': {
                'name': 'Apache/Nginx Log',
                'description': 'Apache/Nginx web server logs in various formats',
                'example': 'Access, Error, and Combined log formats',
                'sources': [
                    {
                        'id': 'access',
                        'name': 'Access Log (Common)',
                        'description': 'Common Log Format without referer and user-agent'
                    },
                    {
                        'id': 'error',
                        'name': 'Error Log',
                        'description': 'Apache error logs with various severity levels'
                    },
                    {
                        'id': 'combined',
                        'name': 'Access Log (Combined)',
                        'description': 'Combined Log Format with referer and user-agent'
                    }
                ]
            },
            'ssh': {
                'name': 'SSH Auth Log',
                'description': 'SSH authentication logs (auth.log) - login attempts, sessions, disconnections',
                'example': 'Failed password, accepted publickey, connection closed, etc.',
                'sources': [
                    {
                        'id': 'auth_success',
                        'name': 'Successful Authentication',
                        'description': 'Accepted password and publickey authentications'
                    },
                    {
                        'id': 'auth_failed',
                        'name': 'Failed Authentication',
                        'description': 'Failed password, invalid users, max auth attempts'
                    },
                    {
                        'id': 'sessions',
                        'name': 'Session Management',
                        'description': 'Session opened and closed events (PAM)'
                    },
                    {
                        'id': 'connections',
                        'name': 'Connection Events',
                        'description': 'Connection closed, disconnected, reset events'
                    },
                    {
                        'id': 'errors',
                        'name': 'Errors & Other',
                        'description': 'Protocol errors, identification issues, server events'
                    }
                ]
            },
            'windows': {
                'name': 'Windows Event Log',
                'description': 'Windows Event Logs - Security, Application, and System sources',
                'example': 'Event ID 4624 - Successful Logon (Security)',
                'sources': [
                    {
                        'id': 'Security',
                        'name': 'Security',
                        'description': 'Authentication, privileges, processes (4624, 4625, 4688, etc.)'
                    },
                    {
                        'id': 'Application',
                        'name': 'Application',
                        'description': 'Application errors, installations, updates (1000, 1001, 11707, etc.)'
                    },
                    {
                        'id': 'System',
                        'name': 'System',
                        'description': 'Service management, system events (6005, 7036, 7034, etc.)'
                    }
                ]
            },
            'paloalto': {
                'name': 'Palo Alto Firewall',
                'description': 'Palo Alto Networks PAN-OS firewall logs in syslog CSV format',
                'example': 'Traffic, Threat, and System logs',
                'sources': [
                    {
                        'id': 'traffic',
                        'name': 'Traffic',
                        'description': 'Network traffic logs (sessions, bytes, packets, actions)'
                    },
                    {
                        'id': 'threat',
                        'name': 'Threat',
                        'description': 'Security threat logs (vulnerabilities, malware, spyware, URLs)'
                    },
                    {
                        'id': 'system',
                        'name': 'System',
                        'description': 'System events (authentication, configuration, HA, upgrades)'
                    }
                ]
            }
        }
