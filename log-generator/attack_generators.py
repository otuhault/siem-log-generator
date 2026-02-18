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
        'category': 'SSH',
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
        'category': 'SSH',
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
        'category': 'SSH',
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
        'category': 'SSH',
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

# ============================================================================
# Palo Alto Port Scan Attack Types
# ============================================================================

# Internal IPs used as scan sources (compromised internal hosts)
INTERNAL_SCAN_SOURCES = [
    '10.0.1.50', '10.0.1.100', '10.0.2.25', '10.0.2.100', '10.0.3.15',
    '10.10.10.50', '10.10.10.200', '10.10.20.30',
    '192.168.1.100', '192.168.1.150', '192.168.1.200', '192.168.10.50',
    '172.16.0.100', '172.16.1.50', '172.16.5.30', '172.16.10.200',
]

# Internal target IP templates (last octet will be randomized)
INTERNAL_TARGET_TEMPLATES = [
    '10.0.0.{}', '10.0.1.{}', '10.0.2.{}', '10.0.3.{}',
    '10.10.10.{}', '10.10.20.{}', '10.10.30.{}',
    '192.168.1.{}', '192.168.2.{}', '192.168.10.{}',
    '172.16.0.{}', '172.16.1.{}', '172.16.5.{}',
]

# Common scan target ports (horizontal scan typically targets one of these)
HORIZONTAL_SCAN_PORTS = [22, 23, 25, 80, 135, 139, 443, 445, 3389, 5900, 8080]

# Privileged ports (< 1024) commonly scanned in vertical scans
SCAN_PORTS_PRIVILEGED = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 514, 515,
    520, 523, 548, 554, 587, 631, 636, 873, 902, 993, 995,
]

# High ports (>= 1024) commonly scanned in vertical scans
SCAN_PORTS_HIGH = [
    1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376,
    3000, 3128, 3268, 3306, 3389, 4443, 4444, 5000, 5432, 5555, 5601,
    5672, 5900, 5984, 5985, 5986, 6379, 6443, 6667, 7001, 7077, 8000,
    8008, 8080, 8081, 8088, 8443, 8880, 8888, 9000, 9090, 9100, 9200,
    9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018, 28017, 50000,
]

# Firewall metadata for Palo Alto logs
PA_HOSTNAMES = ['pa-fw-01', 'pa-fw-02', 'firewall-hq', 'firewall-dc1', 'pan-edge-01', 'pan-core-01']
PA_SERIAL_NUMBERS = ['012345678901234', '098765432109876', '112233445566778', '223344556677889']
PA_LOG_PROFILES = ['ForwardToSplunk', 'default', 'siem-forward', 'log-to-panorama']
PA_INTERNAL_ZONES = ['trust', 'internal', 'lan', 'corporate']
PA_INTERFACES = ['ethernet1/1', 'ethernet1/2', 'ethernet1/3', 'ethernet1/4', 'ae1', 'ae2']

# Field defaults for Palo Alto port scan attacks
PALOALTO_FIELD_DEFAULTS = {
    'src_ip': lambda: random.choice(INTERNAL_SCAN_SOURCES),
    'dest_ip': lambda: random.choice(INTERNAL_TARGET_TEMPLATES).format(random.randint(1, 254)),
    'dest_port': lambda: random.choice(SCAN_PORTS_PRIVILEGED + SCAN_PORTS_HIGH),
    'transport': lambda: random.choice(['tcp', 'udp']),
}

PALOALTO_ATTACK_TYPES = {
    'paloalto_horizontal_port_scan': {
        'name': 'Internal Horizontal Port Scan',
        'description': 'Single source scanning many internal hosts on the same port',
        'log_type': 'paloalto',
        'category': 'Network',
        'field_behaviors': {
            'src_ip': 'fixed',
            'dest_ip': 'rotating',
            'dest_port': 'fixed',
            'transport': 'fixed',
        },
        'sample_logs': [
            '<14>Feb 17 2026 10:15:01 pa-fw-01 1,2026/02/17 10:15:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:15:01,10.0.1.50,192.168.1.42,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:15:01,0,1,49152,445,0,0,0x0,tcp,deny,62,62,0,1,...',
            '<14>Feb 17 2026 10:15:01 pa-fw-01 1,2026/02/17 10:15:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:15:01,10.0.1.50,10.10.10.87,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:15:01,0,1,49153,445,0,0,0x0,tcp,deny,62,62,0,1,...',
            '<14>Feb 17 2026 10:15:02 pa-fw-01 1,2026/02/17 10:15:02,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:15:02,10.0.1.50,172.16.0.201,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:15:02,0,1,49154,445,0,0,0x0,tcp,deny,62,62,0,1,...',
        ]
    },
    'paloalto_vertical_port_scan': {
        'name': 'Internal Vertical Port Scan',
        'description': 'Single source scanning many ports on one internal host',
        'log_type': 'paloalto',
        'category': 'Network',
        'field_behaviors': {
            'src_ip': 'fixed',
            'dest_ip': 'fixed',
            'dest_port': 'rotating',
            'transport': 'rotating',
        },
        'sample_logs': [
            '<14>Feb 17 2026 10:20:01 pa-fw-01 1,2026/02/17 10:20:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:20:01,10.0.1.50,10.0.2.100,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:20:01,0,1,49200,22,0,0,0x0,tcp,deny,62,62,0,1,...',
            '<14>Feb 17 2026 10:20:01 pa-fw-01 1,2026/02/17 10:20:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:20:01,10.0.1.50,10.0.2.100,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:20:01,0,1,49201,445,0,0,0x0,tcp,deny,62,62,0,1,...',
            '<14>Feb 17 2026 10:20:02 pa-fw-01 1,2026/02/17 10:20:02,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:20:02,10.0.1.50,10.0.2.100,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:20:02,0,1,49202,53,0,0,0x0,udp,deny,62,62,0,1,...',
        ]
    },
}

# Combined dict for all attack types
ALL_ATTACK_TYPES = {**SSH_ATTACK_TYPES, **PALOALTO_ATTACK_TYPES}


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


class PaloAltoPortScanGenerator:
    """Generate Palo Alto TRAFFIC logs for internal port scan attacks"""

    def __init__(self, field_behaviors, options=None):
        options = options or {}
        self.field_behaviors = field_behaviors
        self.event_count = 0

        # Initialize fixed values
        self._fixed_values = {}
        for field_name, behavior in field_behaviors.items():
            if behavior == 'fixed':
                override_key = f'target_{field_name}'
                if override_key in options and options[override_key]:
                    self._fixed_values[field_name] = options[override_key]
                else:
                    self._fixed_values[field_name] = PALOALTO_FIELD_DEFAULTS[field_name]()

        # Pre-generate unique rotating values so each event gets a distinct value
        self._rotating_queues = {}
        events_count = min(int(options.get('attack_events_count', 1000)), 10000)

        if field_behaviors.get('dest_port') == 'rotating':
            # Cap at 65535 (max possible unique ports)
            count = min(events_count, 65535)
            ports = list(SCAN_PORTS_PRIVILEGED + SCAN_PORTS_HIGH)
            random.shuffle(ports)
            if count > len(ports):
                used = set(ports)
                while len(ports) < count:
                    p = random.randint(1, 65535)
                    if p not in used:
                        used.add(p)
                        ports.append(p)
            self._rotating_queues['dest_port'] = ports[:count]

        if field_behaviors.get('dest_ip') == 'rotating':
            # Max unique IPs from templates: ~3300 (13 templates * 254)
            max_unique = len(INTERNAL_TARGET_TEMPLATES) * 254
            count = min(events_count, max_unique)
            ips = set()
            while len(ips) < count:
                ips.add(random.choice(INTERNAL_TARGET_TEMPLATES).format(random.randint(1, 254)))
            self._rotating_queues['dest_ip'] = list(ips)

        # Fixed firewall identity for the whole attack session
        self._hostname = random.choice(PA_HOSTNAMES)
        self._serial = random.choice(PA_SERIAL_NUMBERS)
        self._log_profile = random.choice(PA_LOG_PROFILES)
        self._src_zone = random.choice(PA_INTERNAL_ZONES)
        self._dst_zone = random.choice(PA_INTERNAL_ZONES)
        self._src_interface = random.choice(PA_INTERFACES)
        self._dst_interface = random.choice(PA_INTERFACES)

    def _get_field_value(self, field_name):
        if self.field_behaviors.get(field_name) == 'fixed':
            return self._fixed_values[field_name]
        # Use pre-generated unique queue if available
        if field_name in self._rotating_queues:
            queue = self._rotating_queues[field_name]
            idx = (self.event_count - 1) % len(queue)
            return queue[idx]
        return PALOALTO_FIELD_DEFAULTS[field_name]()

    def generate(self):
        """Generate a single Palo Alto TRAFFIC log entry for port scan"""
        self.event_count += 1

        src_ip = self._get_field_value('src_ip')
        dest_ip = self._get_field_value('dest_ip')
        dest_port = self._get_field_value('dest_port')
        transport = self._get_field_value('transport')

        now = datetime.now()
        syslog_header = f"<14>{now.strftime('%b %d %Y %H:%M:%S')} {self._hostname}"
        timestamp = now.strftime('%Y/%m/%d %H:%M:%S')
        iso_timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.') + f'{random.randint(100, 999)}Z'

        src_port = random.randint(1024, 65535)
        session_id = random.randint(10000, 99999)

        # Port scan: mostly denied/dropped connections
        subtype = random.choices(['drop', 'deny', 'start'], weights=[0.5, 0.4, 0.1])[0]
        action = 'deny' if subtype in ('drop', 'deny') else 'allow'
        rule = 'deny-default' if action == 'deny' else random.choice(['allow-internal', 'allow-all'])

        # Scan traffic: tiny packets (SYN or SYN+RST)
        bytes_sent = random.randint(40, 66)
        bytes_received = 0 if action == 'deny' else random.randint(40, 66)
        packets = 1 if action == 'deny' else random.randint(1, 3)
        elapsed_time = 0

        session_end_reason = 'policy-deny' if action == 'deny' else 'aged-out'

        fields = [
            '1',                          # future_use
            timestamp,                    # receive_time
            self._serial,                 # serial_number
            'TRAFFIC',                    # type
            subtype,                      # subtype
            str(random.randint(2048, 2561)),  # config_version
            timestamp,                    # generated_time
            src_ip,                       # src_ip
            dest_ip,                      # dest_ip
            '0.0.0.0',                    # nat_src_ip
            '0.0.0.0',                    # nat_dst_ip
            rule,                         # rule_name
            '',                           # src_user
            '',                           # dst_user
            'incomplete',                 # application (scan = incomplete)
            'vsys1',                      # vsys
            self._src_zone,               # src_zone
            self._dst_zone,               # dst_zone
            self._src_interface,          # inbound_interface
            self._dst_interface,          # outbound_interface
            self._log_profile,            # log_action
            timestamp,                    # time_logged
            str(session_id),              # session_id
            '1',                          # repeat_count
            str(src_port),                # src_port
            str(dest_port),               # dest_port
            '0',                          # nat_src_port
            '0',                          # nat_dst_port
            '0x0',                        # flags
            transport,                    # protocol
            action,                       # action
            str(bytes_sent + bytes_received),  # bytes
            str(bytes_sent),              # bytes_sent
            str(bytes_received),          # bytes_received
            str(packets),                 # packets
            timestamp,                    # start_time
            str(elapsed_time),            # elapsed_time
            'any',                        # category
            '0',                          # padding
            str(random.randint(100000000, 999999999)),  # sequence_number
            '0x8000000000000000',         # action_flags
            'Internal',                   # src_location
            'Internal',                   # dst_location
            '0',                          # padding
            str(packets),                 # packets_sent
            '0',                          # packets_received
            session_end_reason,           # session_end_reason
            str(random.randint(100, 999)),  # device_group_hierarchy_l1
            str(random.randint(100, 999)),  # device_group_hierarchy_l2
            str(random.randint(100, 999)),  # device_group_hierarchy_l3
            '0',                          # device_group_hierarchy_l4
            'vsys1-name',                 # vsys_name
            self._hostname,               # device_name
            'from-policy',                # action_source
            '',                           # src_vm_uuid
            '',                           # dst_vm_uuid
            '0',                          # tunnel_id
            '',                           # monitor_tag
            '0',                          # parent_session_id
            '',                           # parent_start_time
            timestamp,                    # tunnel_type
            '0',                          # sctp_assoc_id
            'N/A',                        # sctp_chunks
            '0',                          # sctp_chunks_sent
            '0',                          # sctp_chunks_received
            '0',                          # rule_uuid
            '0',                          # http2_connection
            '0x0',                        # link_change_count
            '',                           # policy_id
            '',                           # link_switches
            '',                           # sdwan_cluster
            '',                           # sdwan_device_type
            '',                           # sdwan_cluster_type
            '',                           # sdwan_site
            '',                           # dynusergroup_name
            '',                           # xff_address
            '',                           # src_dvc_category
            '',                           # src_dvc_profile
            '',                           # src_dvc_model
            '',                           # src_dvc_vendor
            '',                           # src_dvc_os_family
            '',                           # src_dvc_os_version
            '',                           # src_hostname
            '',                           # src_mac_addr
            '',                           # dst_dvc_category
            '',                           # dst_dvc_profile
            '',                           # dst_dvc_model
            '',                           # dst_dvc_vendor
            '',                           # dst_dvc_os_family
            '',                           # dst_dvc_os_version
            '',                           # dst_hostname
            '',                           # dst_mac_addr
            '0',                          # container_id
            '0',                          # pod_namespace
            '0',                          # pod_name
            '0',                          # src_edl
            '0',                          # dst_edl
            '0',                          # hostid
            '0',                          # serial_number
            '0',                          # domain_edl
            'any',                        # src_dag
            'any',                        # dst_dag
            '0',                          # session_owner
            iso_timestamp,                # high_res_timestamp
            '0'                           # nsdsai_sst
        ]

        return f'{syslog_header} {",".join(fields)}'


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

        # Palo Alto port scan attack types
        if attack_type in PALOALTO_ATTACK_TYPES:
            field_behaviors = PALOALTO_ATTACK_TYPES[attack_type]['field_behaviors']
            return PaloAltoPortScanGenerator(field_behaviors, options)

        return None

    @staticmethod
    def get_available_attack_types():
        """Get list of available attack types with their metadata"""
        result = {}
        for key, type_def in ALL_ATTACK_TYPES.items():
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
                'category': type_def.get('category', type_def['log_type'].upper()),
                'field_behaviors': type_def['field_behaviors'],
                'overridable_fields': overridable_fields,
                'sample_logs': type_def.get('sample_logs', [])
            }
        return result
