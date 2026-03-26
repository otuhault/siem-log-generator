"""
Attack Generators — dynamic log generation for attack simulations.

Architecture
------------
- BaseAttackGenerator  : shared __init__ / _get_field_value logic
- SSHBruteForceGenerator, PaloAltoPortScanGenerator, WindowsTorClientGenerator
  : concrete generators, each defines FIELD_DEFAULTS
- ATTACK_REGISTRY      : dict[attack_type -> {**metadata, 'generator_class': cls}]
- ALL_ATTACK_TYPES     : alias of ATTACK_REGISTRY (backward-compat for log_senders)
- AttackGeneratorFactory : thin wrapper around the registry

To add a new attack:
  1. Define its metadata dict (same shape as existing entries).
  2. Implement or reuse a generator class (subclass BaseAttackGenerator).
  3. Call _register(attack_dict, GeneratorClass) at module level.
"""

import random
from datetime import datetime

# ============================================================================
# Shared data
# ============================================================================

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
    'security', 'audit', 'compliance', 'legal', 'ceo', 'cto', 'cfo', 'ciso',
]

ATTACKER_IPS = [
    # Russia
    '185.220.101.45', '185.220.101.46', '185.220.101.47', '185.220.101.48',
    '91.240.118.10',  '91.240.118.11',  '91.240.118.12',  '91.240.118.13',
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
    '141.98.10.50',   '141.98.10.51',   '141.98.10.52',
    '45.155.205.30',  '45.155.205.31',  '45.155.205.32',
    # Tor exit nodes
    '185.220.100.240', '185.220.100.241', '185.220.100.242',
    '185.220.102.8',   '185.220.102.9',   '185.220.102.10',
    '23.129.64.100',   '23.129.64.101',   '23.129.64.102',
    # VPN/Proxy services often abused
    '104.244.76.50', '104.244.76.51', '104.244.76.52',
    '198.98.56.10',  '198.98.56.11',  '198.98.56.12',
    '209.141.55.20', '209.141.55.21', '209.141.55.22',
    # Random international
    '177.54.150.100', '177.54.150.101',  # Brazil
    '41.215.241.50',  '41.215.241.51',   # Africa
    '103.75.118.20',  '103.75.118.21',   # India
    '185.156.73.30',  '185.156.73.31',   # Netherlands (bulletproof hosting)
]

TARGET_HOSTNAMES = [
    'vmi829310', 'prod-web-01', 'srv-app-01', 'db-master', 'jump-server',
    'bastion-01', 'gateway-01', 'mail-server', 'file-server', 'backup-srv',
]


# ============================================================================
# Base generator
# ============================================================================

class BaseAttackGenerator:
    """Shared initialization logic for all attack generators.

    Subclasses must define:
        FIELD_DEFAULTS: dict[field_name -> callable()]
    """

    FIELD_DEFAULTS: dict = {}

    def __init__(self, field_behaviors: dict, options: dict = None):
        options = options or {}
        self.field_behaviors = field_behaviors
        self.event_count = 0
        self._fixed_values = {}

        for field, behavior in field_behaviors.items():
            if behavior == 'fixed':
                override = options.get(f'target_{field}')
                self._fixed_values[field] = override if override else self.FIELD_DEFAULTS[field]()

    def _get_field_value(self, field_name: str):
        """Return cached fixed value or generate a fresh rotating one."""
        if self.field_behaviors.get(field_name) == 'fixed':
            return self._fixed_values[field_name]
        return self.FIELD_DEFAULTS[field_name]()

    def generate(self) -> str:
        raise NotImplementedError


# ============================================================================
# SSH attack generators
# ============================================================================

SSH_FIELD_DEFAULTS = {
    'user':     lambda: random.choice(COMMON_USERNAMES),
    'src_ip':   lambda: random.choice(ATTACKER_IPS),
    'hostname': lambda: random.choice(TARGET_HOSTNAMES),
    'port':     lambda: random.randint(30000, 65535),
}

SSH_ATTACK_TYPES = {
    'ssh_bruteforce': {
        'name': 'SSH Brute Force',
        'description': 'Single attacker targeting one account with repeated password attempts',
        'log_type': 'ssh',
        'category': 'SSH',
        'field_behaviors': {'user': 'fixed', 'src_ip': 'fixed', 'hostname': 'fixed', 'port': 'rotating'},
        'sample_logs': [
            'Feb 10 14:23:01 vmi829310 sshd[12345]: Failed password for root from 185.220.101.45 port 43210 ssh2',
            'Feb 10 14:23:02 vmi829310 sshd[12346]: Failed password for root from 185.220.101.45 port 43211 ssh2',
            'Feb 10 14:23:03 vmi829310 sshd[12347]: Failed password for root from 185.220.101.45 port 43212 ssh2',
        ],
    },
    'ssh_password_spraying': {
        'name': 'SSH Password Spraying',
        'description': 'Single attacker trying multiple usernames from one IP',
        'log_type': 'ssh',
        'category': 'SSH',
        'field_behaviors': {'user': 'rotating', 'src_ip': 'fixed', 'hostname': 'fixed', 'port': 'rotating'},
        'sample_logs': [
            'Feb 10 14:23:01 vmi829310 sshd[12345]: Failed password for admin from 91.240.118.10 port 52100 ssh2',
            'Feb 10 14:23:02 vmi829310 sshd[12346]: Failed password for invalid user oracle from 91.240.118.10 port 52101 ssh2',
            'Feb 10 14:23:03 vmi829310 sshd[12347]: Failed password for root from 91.240.118.10 port 52102 ssh2',
        ],
    },
    'ssh_credential_stuffing': {
        'name': 'SSH Credential Stuffing',
        'description': 'Distributed attack with rotating users and IPs (leaked credentials)',
        'log_type': 'ssh',
        'category': 'SSH',
        'field_behaviors': {'user': 'rotating', 'src_ip': 'rotating', 'hostname': 'fixed', 'port': 'rotating'},
        'sample_logs': [
            'Feb 10 14:23:01 vmi829310 sshd[12345]: Failed password for admin from 218.92.0.100 port 39400 ssh2',
            'Feb 10 14:23:02 vmi829310 sshd[12346]: Failed password for invalid user jsmith from 89.248.167.131 port 41200 ssh2',
            'Feb 10 14:23:03 vmi829310 sshd[12347]: Failed password for root from 175.45.176.10 port 55300 ssh2',
        ],
    },
    'ssh_distributed_bruteforce': {
        'name': 'SSH Distributed Brute Force',
        'description': 'Botnet targeting one account from multiple source IPs',
        'log_type': 'ssh',
        'category': 'SSH',
        'field_behaviors': {'user': 'fixed', 'src_ip': 'rotating', 'hostname': 'fixed', 'port': 'rotating'},
        'sample_logs': [
            'Feb 10 14:23:01 vmi829310 sshd[12345]: Failed password for admin from 185.220.101.45 port 43210 ssh2',
            'Feb 10 14:23:02 vmi829310 sshd[12346]: Failed password for admin from 61.177.172.51 port 38100 ssh2',
            'Feb 10 14:23:03 vmi829310 sshd[12347]: Failed password for admin from 141.98.10.50 port 44500 ssh2',
        ],
    },
}


class SSHBruteForceGenerator(BaseAttackGenerator):
    """Generate SSH brute-force / spraying / credential-stuffing logs."""

    FIELD_DEFAULTS = SSH_FIELD_DEFAULTS

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        self.pid_base = random.randint(10000, 99999)

    def generate(self) -> str:
        self.event_count += 1

        user     = self._get_field_value('user')
        src_ip   = self._get_field_value('src_ip')
        hostname = self._get_field_value('hostname')
        port     = self._get_field_value('port')

        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        pid = self.pid_base + (self.event_count % 100)

        message_types = [
            f"Failed password for invalid user {user} from {src_ip} port {port} ssh2",
            f"Failed password for {user} from {src_ip} port {port} ssh2",
            f"Invalid user {user} from {src_ip} port {port}",
            f"Connection closed by invalid user {user} {src_ip} port {port} [preauth]",
            f"Disconnected from invalid user {user} {src_ip} port {port} [preauth]",
        ]
        message = random.choices(message_types, weights=[0.4, 0.3, 0.15, 0.1, 0.05])[0]

        return f"{timestamp} {hostname} sshd[{pid}]: {message}"


# ============================================================================
# Palo Alto port scan generators
# ============================================================================

INTERNAL_SCAN_SOURCES = [
    '10.0.1.50', '10.0.1.100', '10.0.2.25', '10.0.2.100', '10.0.3.15',
    '10.10.10.50', '10.10.10.200', '10.10.20.30',
    '192.168.1.100', '192.168.1.150', '192.168.1.200', '192.168.10.50',
    '172.16.0.100', '172.16.1.50', '172.16.5.30', '172.16.10.200',
]

INTERNAL_TARGET_TEMPLATES = [
    '10.0.0.{}', '10.0.1.{}', '10.0.2.{}', '10.0.3.{}',
    '10.10.10.{}', '10.10.20.{}', '10.10.30.{}',
    '192.168.1.{}', '192.168.2.{}', '192.168.10.{}',
    '172.16.0.{}', '172.16.1.{}', '172.16.5.{}',
]

HORIZONTAL_SCAN_PORTS = [22, 23, 25, 80, 135, 139, 443, 445, 3389, 5900, 8080]

SCAN_PORTS_PRIVILEGED = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 514, 515,
    520, 523, 548, 554, 587, 631, 636, 873, 902, 993, 995,
]

SCAN_PORTS_HIGH = [
    1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2181, 2375, 2376,
    3000, 3128, 3268, 3306, 3389, 4443, 4444, 5000, 5432, 5555, 5601,
    5672, 5900, 5984, 5985, 5986, 6379, 6443, 6667, 7001, 7077, 8000,
    8008, 8080, 8081, 8088, 8443, 8880, 8888, 9000, 9090, 9100, 9200,
    9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018, 28017, 50000,
]

PA_HOSTNAMES       = ['pa-fw-01', 'pa-fw-02', 'firewall-hq', 'firewall-dc1', 'pan-edge-01', 'pan-core-01']
PA_SERIAL_NUMBERS  = ['012345678901234', '098765432109876', '112233445566778', '223344556677889']
PA_LOG_PROFILES    = ['ForwardToSplunk', 'default', 'siem-forward', 'log-to-panorama']
PA_INTERNAL_ZONES  = ['trust', 'internal', 'lan', 'corporate']
PA_INTERFACES      = ['ethernet1/1', 'ethernet1/2', 'ethernet1/3', 'ethernet1/4', 'ae1', 'ae2']

PALOALTO_FIELD_DEFAULTS = {
    'src_ip':    lambda: random.choice(INTERNAL_SCAN_SOURCES),
    'dest_ip':   lambda: random.choice(INTERNAL_TARGET_TEMPLATES).format(random.randint(1, 254)),
    'dest_port': lambda: random.choice(SCAN_PORTS_PRIVILEGED + SCAN_PORTS_HIGH),
    'transport': lambda: random.choice(['tcp', 'udp']),
}

PALOALTO_ATTACK_TYPES = {
    'paloalto_horizontal_port_scan': {
        'name': 'Internal Horizontal Port Scan',
        'description': 'Single source scanning many internal hosts on the same port',
        'log_type': 'paloalto',
        'category': 'Network',
        'field_behaviors': {'src_ip': 'fixed', 'dest_ip': 'rotating', 'dest_port': 'fixed', 'transport': 'fixed'},
        'sample_logs': [
            '<14>Feb 17 2026 10:15:01 pa-fw-01 1,2026/02/17 10:15:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:15:01,10.0.1.50,192.168.1.42,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:15:01,0,1,49152,445,0,0,0x0,tcp,deny,62,62,0,1,...',
            '<14>Feb 17 2026 10:15:01 pa-fw-01 1,2026/02/17 10:15:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:15:01,10.0.1.50,10.10.10.87,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:15:01,0,1,49153,445,0,0,0x0,tcp,deny,62,62,0,1,...',
            '<14>Feb 17 2026 10:15:02 pa-fw-01 1,2026/02/17 10:15:02,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:15:02,10.0.1.50,172.16.0.201,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:15:02,0,1,49154,445,0,0,0x0,tcp,deny,62,62,0,1,...',
        ],
    },
    'paloalto_vertical_port_scan': {
        'name': 'Internal Vertical Port Scan',
        'description': 'Single source scanning many ports on one internal host',
        'log_type': 'paloalto',
        'category': 'Network',
        'field_behaviors': {'src_ip': 'fixed', 'dest_ip': 'fixed', 'dest_port': 'rotating', 'transport': 'rotating'},
        'sample_logs': [
            '<14>Feb 17 2026 10:20:01 pa-fw-01 1,2026/02/17 10:20:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:20:01,10.0.1.50,10.0.2.100,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:20:01,0,1,49200,22,0,0,0x0,tcp,deny,62,62,0,1,...',
            '<14>Feb 17 2026 10:20:01 pa-fw-01 1,2026/02/17 10:20:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:20:01,10.0.1.50,10.0.2.100,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:20:01,0,1,49201,445,0,0,0x0,tcp,deny,62,62,0,1,...',
            '<14>Feb 17 2026 10:20:02 pa-fw-01 1,2026/02/17 10:20:02,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:20:02,10.0.1.50,10.0.2.100,0.0.0.0,0.0.0.0,deny-default,,,,incomplete,vsys1,trust,trust,ethernet1/1,ethernet1/2,siem-forward,2026/02/17 10:20:02,0,1,49202,53,0,0,0x0,udp,deny,62,62,0,1,...',
        ],
    },
}


class PaloAltoPortScanGenerator(BaseAttackGenerator):
    """Generate Palo Alto TRAFFIC logs for internal port scan attacks."""

    FIELD_DEFAULTS = PALOALTO_FIELD_DEFAULTS

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)

        # Pre-generate unique rotating values so each event gets a distinct value
        events_count = min(int((options or {}).get('attack_events_count', 1000)), 10000)
        self._rotating_queues = {}

        if field_behaviors.get('dest_port') == 'rotating':
            ports = list(SCAN_PORTS_PRIVILEGED + SCAN_PORTS_HIGH)
            random.shuffle(ports)
            count = min(events_count, 65535)
            if count > len(ports):
                used = set(ports)
                while len(ports) < count:
                    p = random.randint(1, 65535)
                    if p not in used:
                        used.add(p)
                        ports.append(p)
            self._rotating_queues['dest_port'] = ports[:count]

        if field_behaviors.get('dest_ip') == 'rotating':
            max_unique = len(INTERNAL_TARGET_TEMPLATES) * 254
            count = min(events_count, max_unique)
            ips: set = set()
            while len(ips) < count:
                ips.add(random.choice(INTERNAL_TARGET_TEMPLATES).format(random.randint(1, 254)))
            self._rotating_queues['dest_ip'] = list(ips)

        # Fixed firewall identity for the whole attack session
        self._hostname  = random.choice(PA_HOSTNAMES)
        self._serial    = random.choice(PA_SERIAL_NUMBERS)
        self._log_profile   = random.choice(PA_LOG_PROFILES)
        self._src_zone  = random.choice(PA_INTERNAL_ZONES)
        self._dst_zone  = random.choice(PA_INTERNAL_ZONES)
        self._src_iface = random.choice(PA_INTERFACES)
        self._dst_iface = random.choice(PA_INTERFACES)

    def _get_field_value(self, field_name: str):
        if self.field_behaviors.get(field_name) == 'fixed':
            return self._fixed_values[field_name]
        if field_name in self._rotating_queues:
            idx = (self.event_count - 1) % len(self._rotating_queues[field_name])
            return self._rotating_queues[field_name][idx]
        return self.FIELD_DEFAULTS[field_name]()

    def generate(self) -> str:
        self.event_count += 1

        src_ip    = self._get_field_value('src_ip')
        dest_ip   = self._get_field_value('dest_ip')
        dest_port = self._get_field_value('dest_port')
        transport = self._get_field_value('transport')

        now = datetime.now()
        syslog_header = f"<14>{now.strftime('%b %d %Y %H:%M:%S')} {self._hostname}"
        timestamp     = now.strftime('%Y/%m/%d %H:%M:%S')
        iso_timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.') + f'{random.randint(100, 999)}Z'

        src_port   = random.randint(1024, 65535)
        session_id = random.randint(10000, 99999)

        subtype  = random.choices(['drop', 'deny', 'start'], weights=[0.5, 0.4, 0.1])[0]
        action   = 'deny' if subtype in ('drop', 'deny') else 'allow'
        rule     = 'deny-default' if action == 'deny' else random.choice(['allow-internal', 'allow-all'])

        bytes_sent     = random.randint(40, 66)
        bytes_received = 0 if action == 'deny' else random.randint(40, 66)
        packets        = 1 if action == 'deny' else random.randint(1, 3)
        elapsed_time   = 0
        session_end    = 'policy-deny' if action == 'deny' else 'aged-out'

        fields = [
            '1', timestamp, self._serial, 'TRAFFIC', subtype,
            str(random.randint(2048, 2561)), timestamp,
            src_ip, dest_ip, '0.0.0.0', '0.0.0.0',
            rule, '', '', 'incomplete', 'vsys1',
            self._src_zone, self._dst_zone, self._src_iface, self._dst_iface,
            self._log_profile, timestamp, str(session_id), '1',
            str(src_port), str(dest_port), '0', '0', '0x0', transport, action,
            str(bytes_sent + bytes_received), str(bytes_sent), str(bytes_received),
            str(packets), timestamp, str(elapsed_time), 'any', '0',
            str(random.randint(100000000, 999999999)), '0x8000000000000000',
            'Internal', 'Internal', '0', str(packets), '0', session_end,
            str(random.randint(100, 999)), str(random.randint(100, 999)),
            str(random.randint(100, 999)), '0', 'vsys1-name', self._hostname,
            'from-policy', '', '', '0', '', '0', '', timestamp, '0', 'N/A',
            '0', '0', '0', '0', '0x0', '', '', '', '', '', '', '', '',
            '', '', '', '', '', '', '', '', '', '', '', '',
            '0', '0', '0', '0', '0', '0', '0', 'any', 'any', '0',
            iso_timestamp, '0',
        ]

        return f'{syslog_header} {",".join(fields)}'


# ============================================================================
# Windows attack generators
# ============================================================================

WINDOWS_WORKSTATIONS = [
    'DESKTOP-ABC123', 'DESKTOP-XYZ789', 'DESKTOP-QRS456', 'LAPTOP-DEV01',
    'LAPTOP-MKT02', 'WKS-FIN01', 'WKS-HR02', 'WKS-ENG03', 'WKS-SEC01',
    'DESKTOP-ADMIN1', 'LAPTOP-EXEC1', 'WKS-IT01', 'DESKTOP-LAB01',
]

WINDOWS_DOMAINS = ['CONTOSO', 'CORP', 'LAB', 'PROD', 'WORKGROUP']

WINDOWS_ATTACK_USERS = [
    'jsmith', 'mdoe', 'admin', 'jdoe', 'bwilson', 'agarcia', 'clee',
    'dmartin', 'ejohnson', 'ftaylor', 'sysadmin', 'developer', 'analyst',
]

TOR_PROCESS_VARIANTS = [
    {
        'process_name': 'tor.exe',
        'process_path': 'C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe',
        'command_line': '"C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"',
        'parent_process_name': 'firefox.exe',
        'parent_process_path': 'C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\firefox.exe',
        'original_file_name': 'tor.exe',
    },
    {
        'process_name': 'tor.exe',
        'process_path': 'C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe',
        'command_line': '"C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe" --defaults-torrc "C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor\\torrc-defaults" -f "C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Data\\Tor\\torrc"',
        'parent_process_name': 'firefox.exe',
        'parent_process_path': 'C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\firefox.exe',
        'original_file_name': 'tor.exe',
    },
    {
        'process_name': 'tor.exe',
        'process_path': 'C:\\Users\\{user}\\AppData\\Local\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe',
        'command_line': '"C:\\Users\\{user}\\AppData\\Local\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"',
        'parent_process_name': 'firefox.exe',
        'parent_process_path': 'C:\\Users\\{user}\\AppData\\Local\\Tor Browser\\Browser\\firefox.exe',
        'original_file_name': 'tor.exe',
    },
    {
        'process_name': 'tor.exe',
        'process_path': 'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\tor-{tor_version}\\tor.exe',
        'command_line': '"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\tor-{tor_version}\\tor.exe" --SOCKSPort 9350',
        'parent_process_name': 'brave.exe',
        'parent_process_path': 'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
        'original_file_name': 'tor.exe',
    },
    {
        'process_name': 'tor.exe',
        'process_path': 'C:\\Users\\{user}\\Downloads\\tor.exe',
        'command_line': 'C:\\Users\\{user}\\Downloads\\tor.exe',
        'parent_process_name': 'cmd.exe',
        'parent_process_path': 'C:\\Windows\\System32\\cmd.exe',
        'original_file_name': 'tor.exe',
    },
    {
        'process_name': 'tor.exe',
        'process_path': 'C:\\Temp\\tor\\tor.exe',
        'command_line': 'C:\\Temp\\tor\\tor.exe --SocksPort 9150 --DataDirectory C:\\Temp\\tor\\data',
        'parent_process_name': 'powershell.exe',
        'parent_process_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        'original_file_name': 'tor.exe',
    },
]

TOR_VERSIONS = ['0.4.7.13', '0.4.7.16', '0.4.8.7', '0.4.8.10', '0.4.8.12']

WINDOWS_TOR_FIELD_DEFAULTS = {
    'user': lambda: random.choice(WINDOWS_ATTACK_USERS),
    'dest': lambda: random.choice(WINDOWS_WORKSTATIONS),
}

WINDOWS_ATTACK_TYPES = {
    'windows_tor_client_execution': {
        'name': 'Windows TOR Client Execution',
        'description': 'TOR browser or client execution detected on Windows endpoint (T1090.003)',
        'log_type': 'windows',
        'category': 'Endpoint',
        'field_behaviors': {'user': 'fixed', 'dest': 'fixed'},
        'sample_logs': [
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="2026-02-18T10:30:01.000Z" /><EventRecordID>456789</EventRecordID><Channel>Security</Channel><Computer>DESKTOP-ABC123</Computer></System><EventData><Data Name="SubjectUserName">jsmith</Data><Data Name="NewProcessName">C:\\Users\\jsmith\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe</Data><Data Name="ParentProcessName">C:\\Users\\jsmith\\Desktop\\Tor Browser\\Browser\\firefox.exe</Data><Data Name="CommandLine">"C:\\Users\\jsmith\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"</Data></EventData></Event>',
        ],
    },
}


class WindowsTorClientGenerator(BaseAttackGenerator):
    """Generate Windows 4688 Process Creation logs for TOR client execution."""

    FIELD_DEFAULTS = WINDOWS_TOR_FIELD_DEFAULTS

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        self._domain = random.choice(WINDOWS_DOMAINS)

    def generate(self) -> str:
        self.event_count += 1

        user = self._get_field_value('user')
        dest = self._get_field_value('dest')

        variant     = random.choice(TOR_PROCESS_VARIANTS)
        tor_version = random.choice(TOR_VERSIONS)

        process_path        = variant['process_path'].format(user=user, tor_version=tor_version)
        command_line        = variant['command_line'].format(user=user, tor_version=tor_version)
        parent_process_path = variant['parent_process_path'].format(user=user)
        original_file_name  = variant['original_file_name']

        timestamp    = datetime.now().isoformat()
        sid_parts    = (f'S-1-5-21-{random.randint(1000000000, 9999999999)}'
                        f'-{random.randint(1000000000, 9999999999)}'
                        f'-{random.randint(1000000000, 9999999999)}'
                        f'-{random.randint(1000, 9999)}')
        logon_id          = f'0x{random.randint(100000, 999999):x}'
        new_process_id    = f'0x{random.randint(1000, 9999):x}'
        parent_process_id = f'0x{random.randint(500, 5000):x}'

        def _guid():
            return ('{'
                    + f'{random.randint(10000000, 99999999):08X}'
                    + f'-{random.randint(1000, 9999):04X}'
                    + f'-{random.randint(1000, 9999):04X}'
                    + f'-{random.randint(1000, 9999):04X}'
                    + f'-{random.randint(100000000000, 999999999999):012X}'
                    + '}')

        process_hash = ''.join(random.choices('0123456789abcdef', k=64))
        token_elevation = random.choice(['%%1936', '%%1937'])
        integrity_levels = [('S-1-16-8192', 'Medium'), ('S-1-16-12288', 'High'), ('S-1-16-4096', 'Low')]
        integrity_sid, _ = random.choices(integrity_levels, weights=[0.7, 0.2, 0.1])[0]

        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>Security</Channel>
    <Computer>{dest}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">{sid_parts}</Data>
    <Data Name="SubjectUserName">{user}</Data>
    <Data Name="SubjectDomainName">{self._domain}</Data>
    <Data Name="SubjectLogonId">{logon_id}</Data>
    <Data Name="NewProcessId">{new_process_id}</Data>
    <Data Name="NewProcessName">{process_path}</Data>
    <Data Name="TokenElevationType">{token_elevation}</Data>
    <Data Name="ProcessId">{parent_process_id}</Data>
    <Data Name="CommandLine">{command_line}</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">{parent_process_path}</Data>
    <Data Name="MandatoryLabel">{integrity_sid}</Data>
    <Data Name="ProcessGuid">{_guid()}</Data>
    <Data Name="ParentProcessGuid">{_guid()}</Data>
    <Data Name="OriginalFileName">{original_file_name}</Data>
    <Data Name="ProcessHash">SHA256={process_hash}</Data>
    <Data Name="ProcessIntegrityLevel">{integrity_sid}</Data>
  </EventData>
</Event>'''

        return event_xml.strip()


# ============================================================================
# Registry and factory
# ============================================================================

# Internal registry: attack_type -> {**metadata, 'generator_class': cls}
ATTACK_REGISTRY: dict = {}


def _register(attack_types_dict: dict, generator_class) -> None:
    """Register a group of attack-type definitions with their generator class."""
    for key, defn in attack_types_dict.items():
        ATTACK_REGISTRY[key] = {**defn, 'generator_class': generator_class}


_register(SSH_ATTACK_TYPES,      SSHBruteForceGenerator)
_register(PALOALTO_ATTACK_TYPES, PaloAltoPortScanGenerator)
_register(WINDOWS_ATTACK_TYPES,  WindowsTorClientGenerator)

# Backward-compat alias used by log_senders.py
ALL_ATTACK_TYPES = ATTACK_REGISTRY


class AttackGeneratorFactory:
    """Thin registry-based factory — no if/elif chains needed."""

    @staticmethod
    def get_generator(attack_type: str, options: dict = None):
        """Return an instantiated generator for attack_type, or None."""
        defn = ATTACK_REGISTRY.get(attack_type)
        if not defn:
            return None
        return defn['generator_class'](defn['field_behaviors'], options or {})

    @staticmethod
    def get_available_attack_types() -> dict:
        """Return metadata for all registered attack types (used by API)."""
        result = {}
        for key, defn in ATTACK_REGISTRY.items():
            overridable_fields = {
                field: {'label': field.replace('_', ' ').title(), 'behavior': behavior}
                for field, behavior in defn['field_behaviors'].items()
            }
            result[key] = {
                'name':              defn['name'],
                'description':       defn['description'],
                'log_type':          defn['log_type'],
                'category':          defn.get('category', defn['log_type'].upper()),
                'field_behaviors':   defn['field_behaviors'],
                'overridable_fields': overridable_fields,
                'sample_logs':       defn.get('sample_logs', []),
            }
        return result
