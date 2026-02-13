"""
Attack Generators - Dynamic log generation for attack simulations
"""

import random
from datetime import datetime

# Common usernames for brute force attacks (~100)
COMMON_USERNAMES = [
    # System/default accounts
    'root', 'admin', 'administrator', 'user', 'guest', 'test', 'ubuntu', 'centos',
    'debian', 'ec2-user', 'oracle', 'postgres', 'mysql', 'mongodb', 'redis',
    'git', 'jenkins', 'deploy', 'ansible', 'vagrant', 'docker', 'kubernetes',
    'nagios', 'zabbix', 'prometheus', 'grafana', 'elastic', 'logstash', 'kibana',

    # Common names
    'john', 'jane', 'mike', 'david', 'chris', 'alex', 'sam', 'tom', 'bob', 'alice',
    'steve', 'paul', 'mark', 'james', 'peter', 'jack', 'joe', 'bill', 'dan', 'matt',
    'sarah', 'lisa', 'emma', 'anna', 'kate', 'mary', 'laura', 'susan', 'karen', 'nancy',

    # IT/Dev usernames
    'sysadmin', 'webmaster', 'webadmin', 'ftpuser', 'ftpadmin', 'backup', 'support',
    'helpdesk', 'service', 'daemon', 'www-data', 'apache', 'nginx', 'tomcat',
    'developer', 'dev', 'devops', 'ops', 'engineer', 'tech', 'it', 'infra',

    # Corporate patterns
    'jsmith', 'jdoe', 'asmith', 'bwilson', 'cjohnson', 'dlee', 'ewang', 'fgarcia',
    'gmartin', 'hbrown', 'ijones', 'jmiller', 'kdavis', 'lwilson', 'mmoore', 'ntaylor',

    # Service accounts
    'svc_backup', 'svc_deploy', 'svc_monitor', 'svc_web', 'svc_db', 'svc_app',
    'sa_admin', 'sa_service', 'batch', 'scheduler', 'cron', 'automation',

    # Vendor defaults
    'pi', 'raspberrypi', 'synology', 'qnap', 'netgear', 'linksys', 'cisco',
    'ubnt', 'mikrotik', 'pfsense', 'opnsense', 'vyos', 'arista',

    # Additional common
    'info', 'mail', 'email', 'postmaster', 'sales', 'marketing', 'hr', 'finance',
    'security', 'audit', 'compliance', 'legal', 'ceo', 'cto', 'cfo', 'ciso'
]

# Attacker source IPs (realistic malicious IPs from various countries)
ATTACKER_IPS = [
    # Russia
    '185.220.101.45', '185.220.101.46', '185.220.101.47', '185.220.101.48',
    '91.240.118.10', '91.240.118.11', '91.240.118.12', '91.240.118.13',
    '195.54.160.100', '195.54.160.101', '195.54.160.102',

    # China
    '218.92.0.100', '218.92.0.101', '218.92.0.102', '218.92.0.103',
    '61.177.172.50', '61.177.172.51', '61.177.172.52',
    '222.186.30.10', '222.186.30.11', '222.186.30.12',

    # North Korea / Asia
    '175.45.176.10', '175.45.176.11', '175.45.176.12',
    '210.52.109.20', '210.52.109.21', '210.52.109.22',

    # Eastern Europe
    '89.248.167.130', '89.248.167.131', '89.248.167.132',
    '141.98.10.50', '141.98.10.51', '141.98.10.52',
    '45.155.205.30', '45.155.205.31', '45.155.205.32',

    # Tor exit nodes (common for attacks)
    '185.220.100.240', '185.220.100.241', '185.220.100.242',
    '185.220.102.8', '185.220.102.9', '185.220.102.10',
    '23.129.64.100', '23.129.64.101', '23.129.64.102',

    # VPN/Proxy services often abused
    '104.244.76.50', '104.244.76.51', '104.244.76.52',
    '198.98.56.10', '198.98.56.11', '198.98.56.12',
    '209.141.55.20', '209.141.55.21', '209.141.55.22',

    # Random international
    '177.54.150.100', '177.54.150.101',  # Brazil
    '41.215.241.50', '41.215.241.51',    # Africa
    '103.75.118.20', '103.75.118.21',    # India
    '185.156.73.30', '185.156.73.31',    # Netherlands (bulletproof hosting)
]

# Target hostnames
TARGET_HOSTNAMES = [
    'vmi829310', 'prod-web-01', 'srv-app-01', 'db-master', 'jump-server',
    'bastion-01', 'gateway-01', 'mail-server', 'file-server', 'backup-srv'
]

# Field defaults for SSH attacks
SSH_FIELD_DEFAULTS = {
    'user': lambda: random.choice(COMMON_USERNAMES),
    'src_ip': lambda: random.choice(ATTACKER_IPS),
    'hostname': lambda: random.choice(TARGET_HOSTNAMES),
    'port': lambda: random.randint(30000, 65535),
}

# SSH attack types with metadata and field behaviors
SSH_ATTACK_TYPES = {
    'ssh_bruteforce': {
        'name': 'SSH Brute Force',
        'description': 'Single attacker targeting one account with repeated password attempts',
        'log_type': 'ssh',
        'field_behaviors': {
            'user': 'fixed', 'src_ip': 'fixed', 'hostname': 'fixed', 'port': 'rotating'
        },
        'sample_logs': [
            'Feb 10 14:23:01 vmi829310 sshd[12345]: Failed password for root from 185.220.101.45 port 43210 ssh2',
            'Feb 10 14:23:02 vmi829310 sshd[12346]: Failed password for root from 185.220.101.45 port 43211 ssh2',
            'Feb 10 14:23:03 vmi829310 sshd[12347]: Failed password for root from 185.220.101.45 port 43212 ssh2',
        ]
    },
    'ssh_password_spraying': {
        'name': 'SSH Password Spraying',
        'description': 'Single attacker trying multiple usernames from one IP',
        'log_type': 'ssh',
        'field_behaviors': {
            'user': 'rotating', 'src_ip': 'fixed', 'hostname': 'fixed', 'port': 'rotating'
        },
        'sample_logs': [
            'Feb 10 14:23:01 vmi829310 sshd[12345]: Failed password for admin from 91.240.118.10 port 52100 ssh2',
            'Feb 10 14:23:02 vmi829310 sshd[12346]: Failed password for invalid user oracle from 91.240.118.10 port 52101 ssh2',
            'Feb 10 14:23:03 vmi829310 sshd[12347]: Failed password for root from 91.240.118.10 port 52102 ssh2',
        ]
    },
    'ssh_credential_stuffing': {
        'name': 'SSH Credential Stuffing',
        'description': 'Distributed attack with rotating users and IPs (leaked credentials)',
        'log_type': 'ssh',
        'field_behaviors': {
            'user': 'rotating', 'src_ip': 'rotating', 'hostname': 'fixed', 'port': 'rotating'
        },
        'sample_logs': [
            'Feb 10 14:23:01 vmi829310 sshd[12345]: Failed password for admin from 218.92.0.100 port 39400 ssh2',
            'Feb 10 14:23:02 vmi829310 sshd[12346]: Failed password for invalid user jsmith from 89.248.167.131 port 41200 ssh2',
            'Feb 10 14:23:03 vmi829310 sshd[12347]: Failed password for root from 175.45.176.10 port 55300 ssh2',
        ]
    },
    'ssh_distributed_bruteforce': {
        'name': 'SSH Distributed Brute Force',
        'description': 'Botnet targeting one account from multiple source IPs',
        'log_type': 'ssh',
        'field_behaviors': {
            'user': 'fixed', 'src_ip': 'rotating', 'hostname': 'fixed', 'port': 'rotating'
        },
        'sample_logs': [
            'Feb 10 14:23:01 vmi829310 sshd[12345]: Failed password for admin from 185.220.101.45 port 43210 ssh2',
            'Feb 10 14:23:02 vmi829310 sshd[12346]: Failed password for admin from 61.177.172.51 port 38100 ssh2',
            'Feb 10 14:23:03 vmi829310 sshd[12347]: Failed password for admin from 141.98.10.50 port 44500 ssh2',
        ]
    },
}

# Backward compatibility: old mode names -> new attack types
MODE_TO_ATTACK_TYPE = {
    'same_user_same_ip': 'ssh_bruteforce',
    'diff_user_same_ip': 'ssh_password_spraying',
    'diff_user_diff_ip': 'ssh_credential_stuffing',
    'same_user_diff_ip': 'ssh_distributed_bruteforce',
}


class SSHBruteForceGenerator:
    """Generate SSH brute force attack logs (behavior-driven)"""

    def __init__(self, field_behaviors, options=None):
        """
        Initialize the SSH brute force generator

        Args:
            field_behaviors: Dict mapping field names to 'fixed' or 'rotating'
            options: Optional dict with overrides (target_user, target_ip, etc.)
        """
        options = options or {}
        self.field_behaviors = field_behaviors

        # Initialize fixed values (cached for the entire attack session)
        self._fixed_values = {}
        for field_name, behavior in field_behaviors.items():
            if behavior == 'fixed':
                # Use provided override or generate default
                override_key = f'target_{field_name}'
                if override_key in options and options[override_key]:
                    self._fixed_values[field_name] = options[override_key]
                else:
                    self._fixed_values[field_name] = SSH_FIELD_DEFAULTS[field_name]()

        self.pid_base = random.randint(10000, 99999)
        self.event_count = 0

    def _get_field_value(self, field_name):
        """Get field value based on behavior (fixed returns cached, rotating generates new)"""
        if self.field_behaviors.get(field_name) == 'fixed':
            return self._fixed_values[field_name]
        return SSH_FIELD_DEFAULTS[field_name]()

    def generate(self):
        """Generate a single SSH brute force log entry"""
        self.event_count += 1

        user = self._get_field_value('user')
        src_ip = self._get_field_value('src_ip')
        hostname = self._get_field_value('hostname')
        port = self._get_field_value('port')

        # Generate timestamp
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')

        # Vary the PID slightly
        pid = self.pid_base + (self.event_count % 100)

        # Vary the message type for realism
        message_types = [
            f"Failed password for invalid user {user} from {src_ip} port {port} ssh2",
            f"Failed password for {user} from {src_ip} port {port} ssh2",
            f"Invalid user {user} from {src_ip} port {port}",
            f"Connection closed by invalid user {user} {src_ip} port {port} [preauth]",
            f"Disconnected from invalid user {user} {src_ip} port {port} [preauth]",
        ]

        # Weight towards "Failed password" messages (most common in brute force)
        weights = [0.4, 0.3, 0.15, 0.1, 0.05]
        message = random.choices(message_types, weights=weights)[0]

        return f"{timestamp} {hostname} sshd[{pid}]: {message}"


class AttackGeneratorFactory:
    """Factory to create attack generators based on attack type"""

    @staticmethod
    def get_generator(attack_type, options=None):
        """
        Get an attack generator based on type

        Args:
            attack_type: Type of attack (e.g., 'ssh_bruteforce', 'ssh_password_spraying')
            options: Dict of options for the generator

        Returns:
            Generator instance or None if type not supported
        """
        options = options or {}

        # Backward compat: if old mode is passed, remap to new attack type
        if attack_type == 'ssh_bruteforce' and 'mode' in options:
            old_mode = options.pop('mode')
            attack_type = MODE_TO_ATTACK_TYPE.get(old_mode, attack_type)

        # All SSH attack types use the same generator with different field_behaviors
        if attack_type in SSH_ATTACK_TYPES:
            field_behaviors = SSH_ATTACK_TYPES[attack_type]['field_behaviors']
            return SSHBruteForceGenerator(field_behaviors, options)

        return None

    @staticmethod
    def get_available_attack_types():
        """Get list of available attack types with their metadata"""
        result = {}
        for key, type_def in SSH_ATTACK_TYPES.items():
            overridable_fields = {}
            for field_name, behavior in type_def['field_behaviors'].items():
                overridable_fields[field_name] = {
                    'label': field_name.replace('_', ' ').title(),
                    'behavior': behavior
                }
            result[key] = {
                'name': type_def['name'],
                'description': type_def['description'],
                'log_type': type_def['log_type'],
                'field_behaviors': type_def['field_behaviors'],
                'overridable_fields': overridable_fields,
                'sample_logs': type_def.get('sample_logs', [])
            }
        return result
