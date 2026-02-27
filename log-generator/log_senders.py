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
from log_generators.active_directory import ActiveDirectoryLogGenerator
from log_generators.cisco_ios import CiscoIOSLogGenerator
from hec_sender import HECSender
from attack_generators import ALL_ATTACK_TYPES

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

class ADMultiCategoryGenerator:
    """Wrapper that generates logs from multiple AD event categories"""

    def __init__(self, event_categories):
        self.generator = ActiveDirectoryLogGenerator(event_categories=event_categories)

    def generate(self):
        return self.generator.generate()

class CiscoIOSMultiCategoryGenerator:
    """Wrapper that generates logs from multiple Cisco IOS event categories"""

    def __init__(self, event_categories):
        self.generator = CiscoIOSLogGenerator(event_categories=event_categories)

    def generate(self):
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
            'active_directory': ActiveDirectoryLogGenerator,
            'cisco_ios': CiscoIOSLogGenerator,
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
                      destination=None, destination_type='file', configuration_id=None,
                      attack_status=None):
        """Create a new sender"""
        # Check if it's an attack type (direct key or legacy attack:UUID)
        is_attack = log_type in ALL_ATTACK_TYPES or (log_type and log_type.startswith('attack:'))

        if not is_attack and log_type not in self.log_generators:
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
            'options': options or {},  # Store log type specific options
            'attack_status': attack_status if is_attack else None  # Attack status (Disabled/Running/Done)
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

        sender = self.senders[sender_id]
        is_attack = sender['log_type'] in ALL_ATTACK_TYPES or (sender['log_type'] and sender['log_type'].startswith('attack:'))

        # For attacks, toggle means restart the attack
        if is_attack:
            current_status = sender.get('attack_status', 'Disabled')
            if current_status == 'Running':
                # Stop the running attack
                self.senders[sender_id]['enabled'] = False
                self.senders[sender_id]['attack_status'] = 'Disabled'
                self.save_config()
                self.stop_sender(sender_id)
            else:
                # Start/restart the attack
                self.senders[sender_id]['enabled'] = True
                self.save_config()
                self.start_sender(sender_id)
        else:
            # Normal sender toggle
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
        log_type = sender['log_type']

        # Pass options to generator if available
        options = sender.get('options', {})

        # Handle attack types (direct key or legacy attack:UUID)
        if log_type in ALL_ATTACK_TYPES or (log_type and log_type.startswith('attack:')):
            # Update attack status to Running
            self.senders[sender_id]['attack_status'] = 'Running'
            self.save_config()

            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._execute_attack,
                args=(sender_id, sender, stop_event),
                daemon=True
            )
            self.threads[sender_id] = {'thread': thread, 'stop_event': stop_event}
            thread.start()
            return

        generator_class = self.log_generators[log_type]

        # Handle Windows Event Log generators
        if log_type == 'windows':
            # Get selected sources (default to Security if none specified)
            sources = options.get('sources', ['Security'])
            render_format = options.get('render_format', 'xml')

            # Create a multi-source generator wrapper
            generator = WindowsMultiSourceGenerator(sources, render_format)
        # Handle Apache Log generators
        elif log_type == 'apache':
            # Get selected log types (default to combined if none specified)
            log_types = options.get('log_types', ['combined'])

            # Create a multi-source generator wrapper
            generator = ApacheMultiSourceGenerator(log_types)
        # Handle SSH Log generators
        elif log_type == 'ssh':
            # Get selected event categories (default to all if none specified)
            event_categories = options.get('event_categories', ['auth_success', 'auth_failed', 'sessions', 'connections', 'errors'])

            # Create a multi-category generator wrapper
            generator = SSHMultiCategoryGenerator(event_categories)
        # Handle Palo Alto Log generators
        elif log_type == 'paloalto':
            # Get selected log types (default to all if none specified)
            log_types = options.get('log_types', ['traffic', 'threat', 'system'])

            # Create a multi-type generator wrapper
            generator = PaloAltoMultiTypeGenerator(log_types)
        # Handle Active Directory Log generators
        elif log_type == 'active_directory':
            event_categories = options.get('event_categories', [
                'account_management', 'group_management', 'directory_service',
                'authentication', 'computer_management'
            ])
            generator = ADMultiCategoryGenerator(event_categories)
        # Handle Cisco IOS Log generators
        elif log_type == 'cisco_ios':
            event_categories = options.get('event_categories', [
                'interface', 'system', 'authentication', 'acl_security',
                'routing', 'redundancy', 'spanning_tree', 'hardware'
            ])
            generator = CiscoIOSMultiCategoryGenerator(event_categories)
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
    
    def _execute_attack(self, sender_id, sender_config, stop_event):
        """Execute an attack with finite events over a duration"""
        from attack_generators import AttackGeneratorFactory

        log_type = sender_config['log_type']
        options = sender_config.get('options', {})

        # Get attack configuration with safety limits
        events_count = min(max(int(options.get('attack_events_count', 100)), 1), 10000)
        duration = min(max(int(options.get('attack_duration', 60)), 1), 3600)

        # Calculate interval between events
        interval = duration / events_count if events_count > 0 else 1.0

        print(f"[Attack] Starting attack {sender_id}: {events_count} events over {duration}s (interval: {interval:.3f}s)")

        # Determine attack_type: direct key or legacy attack:UUID
        if log_type in ALL_ATTACK_TYPES:
            attack_type = log_type
        elif log_type.startswith('attack:'):
            # Legacy: lookup via AttacksManager
            attack_id = log_type.replace('attack:', '')
            from attacks_manager import AttacksManager
            attacks_mgr = AttacksManager()
            attack = attacks_mgr.get_attack(attack_id)
            if not attack:
                print(f"[Attack] Error: Attack {attack_id} not found")
                self.senders[sender_id]['attack_status'] = 'Error: Attack not found'
                self.senders[sender_id]['enabled'] = False
                self.save_config()
                if sender_id in self.threads:
                    del self.threads[sender_id]
                return
            attack_type = attack.get('attack_type')
        else:
            print(f"[Attack] Error: Unknown attack type {log_type}")
            self.senders[sender_id]['attack_status'] = 'Error: Unknown type'
            self.senders[sender_id]['enabled'] = False
            self.save_config()
            if sender_id in self.threads:
                del self.threads[sender_id]
            return

        # Create generator with sender options (includes target_src_ip, target_dest_ip, etc.)
        generator = AttackGeneratorFactory.get_generator(attack_type, options)
        if not generator:
            print(f"[Attack] Error: No generator for attack_type {attack_type}")
            self.senders[sender_id]['attack_status'] = 'Error: No generator'
            self.senders[sender_id]['enabled'] = False
            self.save_config()
            if sender_id in self.threads:
                del self.threads[sender_id]
            return

        print(f"[Attack] Using generator: {attack_type}")

        destination_type = sender_config.get('destination_type', 'file')

        try:
            events_sent = 0

            if destination_type == 'file':
                destination = sender_config['destination']
                dest_path = Path(destination)
                dest_path.parent.mkdir(parents=True, exist_ok=True)

                with open(destination, 'a') as f:
                    while not stop_event.is_set() and events_sent < events_count:
                        log_line = generator.generate()
                        f.write(log_line + '\n')
                        f.flush()
                        events_sent += 1
                        self.senders[sender_id]['logs_generated'] += 1
                        time.sleep(interval)

            elif destination_type == 'configuration':
                from configuration_manager import ConfigurationManager
                config_mgr = ConfigurationManager()

                config_id = sender_config.get('configuration_id')
                if not config_id:
                    print(f"[Attack] Error: No configuration_id specified for sender {sender_id}")
                    self.senders[sender_id]['attack_status'] = 'Error: No configuration'
                    self.senders[sender_id]['enabled'] = False
                    self.save_config()
                    if sender_id in self.threads:
                        del self.threads[sender_id]
                    return

                hec_config = config_mgr.get_configuration(config_id)
                if not hec_config:
                    print(f"[Attack] Error: Configuration {config_id} not found")
                    self.senders[sender_id]['attack_status'] = 'Error: Config not found'
                    self.senders[sender_id]['enabled'] = False
                    self.save_config()
                    if sender_id in self.threads:
                        del self.threads[sender_id]
                    return

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
                    while not stop_event.is_set() and events_sent < events_count:
                        log_line = generator.generate()
                        success = hec_sender.send_event(log_line)
                        if success:
                            events_sent += 1
                            self.senders[sender_id]['logs_generated'] += 1
                        time.sleep(interval)
                finally:
                    hec_sender.close()

            # Attack completed - update status
            print(f"[Attack] Completed: {events_sent}/{events_count} events sent")
            completion_time = datetime.now().strftime('%m/%d %H:%M:%S')
            self.senders[sender_id]['attack_status'] = f'Done ({completion_time})'
            self.senders[sender_id]['enabled'] = False
            self.save_config()
            print(f"[Attack] Status updated to Done ({completion_time})")

        except Exception as e:
            print(f"[Attack] Exception: {str(e)}")
            self.senders[sender_id]['attack_status'] = f'Error: {str(e)}'
            self.senders[sender_id]['enabled'] = False
            self.save_config()
        finally:
            # Clean up thread reference
            if sender_id in self.threads:
                del self.threads[sender_id]
            print(f"[Attack] Thread cleaned up for {sender_id}")

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
            },
            'active_directory': {
                'name': 'Active Directory',
                'description': 'Active Directory domain controller event logs (XmlWinEventLog)',
                'example': 'Account management, group changes, Kerberos, directory service',
                'sources': [
                    {
                        'id': 'account_management',
                        'name': 'Account Management',
                        'description': 'User account created, enabled, disabled, deleted, changed, locked out (4720, 4722, 4725, 4726, 4738, 4740, 4767)'
                    },
                    {
                        'id': 'group_management',
                        'name': 'Group Management',
                        'description': 'Members added/removed from security groups (4728, 4729, 4732, 4733, 4756, 4757)'
                    },
                    {
                        'id': 'directory_service',
                        'name': 'Directory Service',
                        'description': 'LDAP object modifications, creations, and access operations (5136, 5137, 4662)'
                    },
                    {
                        'id': 'authentication',
                        'name': 'Authentication',
                        'description': 'Kerberos TGT/TGS requests, pre-auth failures, NTLM validation (4768, 4769, 4771, 4776)'
                    },
                    {
                        'id': 'computer_management',
                        'name': 'Computer Management',
                        'description': 'Computer accounts created, changed, deleted (4741, 4742, 4743)'
                    }
                ]
            },
            'cisco_ios': {
                'name': 'Cisco IOS',
                'description': 'Cisco IOS syslog messages (cisco:ios sourcetype)',
                'example': 'Interface status, AAA authentication, ACL logs, routing protocols, HSRP, STP',
                'sources': [
                    {
                        'id': 'interface',
                        'name': 'Interface & Link Status',
                        'description': 'Interface and line protocol state changes (LINK, LINEPROTO)'
                    },
                    {
                        'id': 'system',
                        'name': 'System Events',
                        'description': 'Configuration changes, restarts, memory/CPU events (SYS, PARSER)'
                    },
                    {
                        'id': 'authentication',
                        'name': 'Authentication & AAA',
                        'description': 'Login success/failed, user sessions, 802.1X (SEC_LOGIN, AAA, AUTHMGR)'
                    },
                    {
                        'id': 'acl_security',
                        'name': 'ACL & Security',
                        'description': 'Access list permit/deny, zone-based firewall sessions (SEC, FW)'
                    },
                    {
                        'id': 'routing',
                        'name': 'Routing Protocols',
                        'description': 'OSPF, BGP, EIGRP adjacency and neighbor changes'
                    },
                    {
                        'id': 'redundancy',
                        'name': 'HSRP/VRRP',
                        'description': 'Hot Standby Router Protocol state transitions (STANDBY)'
                    },
                    {
                        'id': 'spanning_tree',
                        'name': 'Spanning Tree',
                        'description': 'Topology changes, root guard, PVID inconsistency (SPANTREE)'
                    },
                    {
                        'id': 'hardware',
                        'name': 'Hardware & Environment',
                        'description': 'SNMP events, NTP sync, fan failures, card insert/remove (SNMP, NTP, ENV, OIR)'
                    }
                ]
            }
        }
