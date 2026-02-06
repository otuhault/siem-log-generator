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


class SSHBruteForceGenerator:
    """Generate SSH brute force attack logs"""

    MODES = {
        'same_user_same_ip': 'Same user, same source IP',
        'same_user_diff_ip': 'Same user, different source IPs',
        'diff_user_same_ip': 'Different users, same source IP',
        'diff_user_diff_ip': 'Different users, different source IPs'
    }

    def __init__(self, mode='diff_user_same_ip', target_user=None, target_ip=None):
        """
        Initialize the SSH brute force generator

        Args:
            mode: One of 'same_user_same_ip', 'same_user_diff_ip',
                  'diff_user_same_ip', 'diff_user_diff_ip'
            target_user: Fixed username (for same_user modes)
            target_ip: Fixed source IP (for same_ip modes)
        """
        self.mode = mode

        # For "same" modes, pick a fixed value if not provided
        self.fixed_user = target_user or random.choice(COMMON_USERNAMES)
        self.fixed_ip = target_ip or random.choice(ATTACKER_IPS)

        self.hostname = random.choice(TARGET_HOSTNAMES)
        self.pid_base = random.randint(10000, 99999)
        self.event_count = 0

    def generate(self):
        """Generate a single SSH brute force log entry"""
        self.event_count += 1

        # Determine user and IP based on mode
        if self.mode == 'same_user_same_ip':
            user = self.fixed_user
            src_ip = self.fixed_ip
        elif self.mode == 'same_user_diff_ip':
            user = self.fixed_user
            src_ip = random.choice(ATTACKER_IPS)
        elif self.mode == 'diff_user_same_ip':
            user = random.choice(COMMON_USERNAMES)
            src_ip = self.fixed_ip
        else:  # diff_user_diff_ip
            user = random.choice(COMMON_USERNAMES)
            src_ip = random.choice(ATTACKER_IPS)

        # Generate timestamp
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')

        # Vary the PID slightly
        pid = self.pid_base + (self.event_count % 100)

        # Generate random port
        port = random.randint(30000, 65535)

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

        return f"{timestamp} {self.hostname} sshd[{pid}]: {message}"


class AttackGeneratorFactory:
    """Factory to create attack generators based on attack type"""

    @staticmethod
    def get_generator(attack_type, options=None):
        """
        Get an attack generator based on type

        Args:
            attack_type: Type of attack (e.g., 'ssh_bruteforce')
            options: Dict of options for the generator

        Returns:
            Generator instance or None if type not supported
        """
        options = options or {}

        if attack_type == 'ssh_bruteforce':
            return SSHBruteForceGenerator(
                mode=options.get('mode', 'diff_user_same_ip'),
                target_user=options.get('target_user'),
                target_ip=options.get('target_ip')
            )

        return None

    @staticmethod
    def get_available_attack_types():
        """Get list of available attack types with their options"""
        return {
            'ssh_bruteforce': {
                'name': 'SSH Brute Force',
                'description': 'Simulates SSH brute force login attempts',
                'log_type': 'ssh',
                'options': {
                    'mode': {
                        'type': 'select',
                        'label': 'Attack Mode',
                        'choices': SSHBruteForceGenerator.MODES,
                        'default': 'diff_user_same_ip'
                    }
                }
            }
        }
