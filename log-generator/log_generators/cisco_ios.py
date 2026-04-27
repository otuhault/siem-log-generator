"""
Cisco IOS Log Generator
Generates realistic Cisco IOS syslog messages (cisco:ios sourcetype)
Format: <seq>: <timestamp>: %<FACILITY>-<SEVERITY>-<MNEMONIC>: <message>
"""

import random
from datetime import datetime


class CiscoIOSLogGenerator:
    """Generates Cisco IOS syslog messages with various facilities and event types"""

    LOG_TYPE = 'cisco_ios'
    AVG_LOG_SIZE = 150
    SOURCETYPE_CONFIG = {
        'param_key': 'event_categories',
        'defaults': ['interface', 'system', 'authentication', 'acl_security', 'routing', 'redundancy', 'spanning_tree', 'hardware'],
        'multi_instance': False,
    }
    METADATA = {
        'name': 'Cisco IOS',
        'description': 'Cisco IOS syslog messages (cisco:ios sourcetype)',
        'example': 'Interface status, AAA authentication, ACL logs, routing protocols, HSRP, STP',
        'sources': [
            {'id': 'interface',      'name': 'Interface & Link Status', 'description': 'Interface and line protocol state changes (LINK, LINEPROTO)'},
            {'id': 'system',         'name': 'System Events',           'description': 'Configuration changes, restarts, memory/CPU events (SYS, PARSER)'},
            {'id': 'authentication', 'name': 'Authentication & AAA',    'description': 'Login success/failed, user sessions, 802.1X (SEC_LOGIN, AAA, AUTHMGR)'},
            {'id': 'acl_security',   'name': 'ACL & Security',          'description': 'Access list permit/deny, zone-based firewall sessions (SEC, FW)'},
            {'id': 'routing',        'name': 'Routing Protocols',       'description': 'OSPF, BGP, EIGRP adjacency and neighbor changes'},
            {'id': 'redundancy',     'name': 'HSRP/VRRP',              'description': 'Hot Standby Router Protocol state transitions (STANDBY)'},
            {'id': 'spanning_tree',  'name': 'Spanning Tree',           'description': 'Topology changes, root guard, PVID inconsistency (SPANTREE)'},
            {'id': 'hardware',       'name': 'Hardware & Environment',  'description': 'SNMP events, NTP sync, fan failures, card insert/remove (SNMP, NTP, ENV, OIR)'},
        ],
    }

    def __init__(self, event_categories=None):
        if event_categories is None:
            event_categories = [
                'interface', 'system', 'authentication', 'acl_security',
                'routing', 'redundancy', 'spanning_tree', 'hardware'
            ]

        self.event_categories = event_categories
        self.sequence_number = random.randint(1, 9999)

        # Cisco device hostnames
        self.hostnames = [
            'RTR-CORE-01', 'RTR-CORE-02', 'RTR-EDGE-GW',
            'SW-ACCESS-01', 'SW-ACCESS-02', 'SW-ACCESS-03',
            'SW-DIST-01', 'SW-DIST-02',
            'FW-DMZ-01', 'RTR-BRANCH-01'
        ]

        # Interfaces
        self.interfaces = [
            'GigabitEthernet0/0', 'GigabitEthernet0/1', 'GigabitEthernet0/2',
            'GigabitEthernet1/0/1', 'GigabitEthernet1/0/12', 'GigabitEthernet1/0/24',
            'GigabitEthernet1/0/48', 'TenGigabitEthernet1/1/1',
            'Serial0/0/0', 'Serial0/0/1',
            'Vlan1', 'Vlan10', 'Vlan100', 'Vlan200',
            'Port-channel1', 'Port-channel2',
            'Loopback0'
        ]

        # Internal IPs
        self.internal_ips = [
            '10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.1.1', '10.0.1.2',
            '10.1.1.1', '10.1.1.2', '10.1.1.10', '10.1.1.50', '10.1.1.100',
            '10.10.10.1', '10.10.10.2', '10.10.10.50',
            '172.16.0.1', '172.16.0.2', '172.16.1.1', '172.25.2.1',
            '192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.0.5',
            '192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.100'
        ]

        # External IPs
        self.external_ips = [
            '203.0.113.10', '203.0.113.45', '203.0.113.100',
            '198.51.100.23', '198.51.100.55',
            '185.220.101.44', '185.220.101.99',
            '91.208.184.12', '45.33.32.156'
        ]

        # Usernames
        self.admin_users = ['admin', 'netops', 'cisco', 'monitor', 'ec2-user']
        self.attack_users = ['root', 'test', 'guest', 'admin123', 'user']

        # ACL names
        self.acl_names = ['OUTSIDE-IN', 'INSIDE-OUT', 'MGMT-ACCESS', 'VTY-ACL', 'DMZ-FILTER']

        # VLANs
        self.vlans = [1, 10, 20, 50, 100, 200, 300]

        # OSPF/BGP neighbor IPs
        self.ospf_neighbors = ['10.0.0.1', '10.0.0.2', '192.168.0.2', '192.168.0.3', '172.16.0.2']
        self.bgp_neighbors = ['10.0.0.2', '10.0.0.3', '172.16.0.1', '203.0.113.10']
        self.eigrp_neighbors = ['172.25.2.1', '10.1.1.2', '192.168.1.3']

        # NTP servers
        self.ntp_servers = ['10.10.10.1', '10.10.10.2', '172.16.0.10']

        # SNMP hosts
        self.snmp_hosts = ['10.1.1.50', '10.10.10.100', '192.168.1.200']

        # MAC addresses — used in 802.1X AUTHMGR events (Cisco dot notation)
        # Injected from A&I store if available; falls back to random generation
        self.mac_addresses = []

        # IOS versions
        self.ios_versions = [
            'Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.1(4)M4, RELEASE SOFTWARE (fc1)',
            'Cisco IOS Software, ISR Software (ISR4300-UNIVERSALK9-M), Version 16.9.6, RELEASE SOFTWARE (fc2)',
            'Cisco IOS Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 16.12.4, RELEASE SOFTWARE (fc5)'
        ]

        # SSH ciphers/hmacs
        self.ssh_ciphers = ['aes256-ctr', 'aes128-ctr', 'aes256-cbc', 'aes128-cbc']
        self.ssh_hmacs = ['hmac-sha2-256', 'hmac-sha2-512', 'hmac-sha1']

        # Log event types organized by category with weighted probabilities
        self.all_event_types = {
            'interface': [
                ('link_updown_up', 25),
                ('link_updown_down', 20),
                ('link_changed_admin_down', 10),
                ('lineproto_updown_up', 25),
                ('lineproto_updown_down', 20),
            ],
            'system': [
                ('sys_config_console', 20),
                ('sys_config_vty', 25),
                ('sys_restart', 5),
                ('sys_logginghost', 5),
                ('parser_cfglog', 25),
                ('sys_mallocfail', 5),
                ('sys_cpuhog', 5),
                ('sys_log_config_change', 10),
            ],
            'authentication': [
                ('sec_login_success', 30),
                ('sec_login_failed', 25),
                ('sec_login_quiet_mode', 5),
                ('aaa_connect', 15),
                ('aaa_username_config', 10),
                ('aaa_privilege_update', 10),
                ('authmgr_start', 3),
                ('authmgr_success', 2),
            ],
            'acl_security': [
                ('sec_ipaccesslogp_denied', 35),
                ('sec_ipaccesslogp_permitted', 15),
                ('sec_ipaccesslogdp_denied', 15),
                ('fw_sess_audit_trail_deny', 20),
                ('fw_sess_audit_trail_permit', 15),
            ],
            'routing': [
                ('ospf_adjchg_full', 15),
                ('ospf_adjchg_down', 15),
                ('ospf_errrcv', 5),
                ('ospf_duprid', 3),
                ('bgp_adjchange_up', 15),
                ('bgp_adjchange_down', 15),
                ('bgp_notification', 5),
                ('eigrp_nbrchange_up', 12),
                ('eigrp_nbrchange_down', 12),
                ('bgp_nbr_reset', 3),
            ],
            'redundancy': [
                ('standby_active', 25),
                ('standby_standby', 25),
                ('standby_speak', 15),
                ('standby_listen', 15),
                ('standby_init', 20),
            ],
            'spanning_tree': [
                ('spantree_topotrap', 35),
                ('spantree_rootguard', 20),
                ('spantree_block_pvid', 15),
                ('spantree_extended_sysid', 15),
                ('spantree_port_fwd', 15),
            ],
            'hardware': [
                ('snmp_authfail', 15),
                ('snmp_coldstart', 10),
                ('snmp_warmstart', 10),
                ('snmp_link_trap', 10),
                ('ntp_peerreach', 15),
                ('ntp_peerunreach', 10),
                ('ntp_peersync', 10),
                ('env_fan_failed', 5),
                ('oir_inscard', 5),
                ('oir_remcard', 5),
                ('platform_memory', 5),
            ],
        }

        # Build event_types list based on enabled categories
        self.event_types = []
        for category in self.event_categories:
            if category in self.all_event_types:
                self.event_types.extend(self.all_event_types[category])

    def generate(self):
        """Generate a single Cisco IOS syslog message"""
        types = [t for t, _ in self.event_types]
        weights = [w for _, w in self.event_types]
        event_type = random.choices(types, weights=weights)[0]
        return self._generate_event(event_type)

    def _next_seq(self):
        """Get next sequence number"""
        self.sequence_number += 1
        return f'{self.sequence_number:06d}'

    def _timestamp(self):
        """Generate Cisco IOS timestamp: MMM DD HH:MM:SS.mmm"""
        now = datetime.now()
        ms = random.randint(0, 999)
        return now.strftime(f'%b %d %H:%M:%S.{ms:03d}')

    def _random_interface(self):
        return random.choice(self.interfaces)

    def _random_internal_ip(self):
        return random.choice(self.internal_ips)

    def _random_external_ip(self):
        return random.choice(self.external_ips)

    def _random_admin_user(self):
        return random.choice(self.admin_users)

    def _pick_mac(self):
        """Return a MAC in Cisco dot notation. Uses A&I pool if available, else random."""
        if self.mac_addresses:
            raw = random.choice(self.mac_addresses).replace(':', '').replace('-', '').replace('.', '')
            return f'{raw[0:4]}.{raw[4:8]}.{raw[8:12]}'
        raw = ''.join([f'{random.randint(0,255):02x}' for _ in range(6)])
        return f'{raw[0:4]}.{raw[4:8]}.{raw[8:12]}'

    def _format_log(self, facility, severity, mnemonic, message):
        """Format a Cisco IOS syslog message"""
        seq = self._next_seq()
        ts = self._timestamp()
        return f'{seq}: {ts}: %{facility}-{severity}-{mnemonic}: {message}'

    def _generate_event(self, event_type):
        """Generate specific event type"""

        # --- INTERFACE ---
        if event_type == 'link_updown_up':
            iface = self._random_interface()
            return self._format_log('LINK', 3, 'UPDOWN', f'Interface {iface}, changed state to up')

        elif event_type == 'link_updown_down':
            iface = self._random_interface()
            return self._format_log('LINK', 3, 'UPDOWN', f'Interface {iface}, changed state to down')

        elif event_type == 'link_changed_admin_down':
            iface = self._random_interface()
            return self._format_log('LINK', 5, 'CHANGED', f'Interface {iface}, changed state to administratively down')

        elif event_type == 'lineproto_updown_up':
            iface = self._random_interface()
            return self._format_log('LINEPROTO', 5, 'UPDOWN', f'Line protocol on Interface {iface}, changed state to up')

        elif event_type == 'lineproto_updown_down':
            iface = self._random_interface()
            return self._format_log('LINEPROTO', 5, 'UPDOWN', f'Line protocol on Interface {iface}, changed state to down')

        # --- SYSTEM ---
        elif event_type == 'sys_config_console':
            return self._format_log('SYS', 5, 'CONFIG_I', 'Configured from console by console')

        elif event_type == 'sys_config_vty':
            user = self._random_admin_user()
            src_ip = self._random_internal_ip()
            vty = random.randint(0, 4)
            return self._format_log('SYS', 5, 'CONFIG_I', f'Configured from console by {user} on vty{vty} ({src_ip})')

        elif event_type == 'sys_restart':
            version = random.choice(self.ios_versions)
            return self._format_log('SYS', 5, 'RESTART', f'System restarted -- {version}')

        elif event_type == 'sys_logginghost':
            action = random.choice(['started', 'stopped'])
            ip = self._random_internal_ip()
            return self._format_log('SYS', 6, 'LOGGINGHOST_STARTSTOP', f'Logging to host {ip} port 514 {action} - CLI initiated')

        elif event_type == 'parser_cfglog':
            user = self._random_admin_user()
            commands = [
                f'interface {self._random_interface()}',
                'router ospf 1',
                'ip route 0.0.0.0 0.0.0.0 10.0.0.1',
                f'no shutdown',
                f'ip access-list extended {random.choice(self.acl_names)}',
                f'username {random.choice(self.attack_users)} privilege 15 secret *',
                'logging buffered 16384',
                'ntp server 10.10.10.1',
                '!config: USER TABLE MODIFIED',
            ]
            cmd = random.choice(commands)
            return self._format_log('PARSER', 5, 'CFGLOG_LOGGEDCMD', f'User:{user} logged command:{cmd}')

        elif event_type == 'sys_mallocfail':
            size = random.choice([4096, 8192, 16384, 32768, 65536])
            addr = f'0x{random.randint(0x10000000, 0xFFFFFFFF):08X}'
            return self._format_log('SYS', 2, 'MALLOCFAIL', f'Memory allocation of {size} bytes failed from {addr}, alignment 0, Pool: Processor')

        elif event_type == 'sys_cpuhog':
            ms = random.randint(500, 4000)
            processes = ['IP Input', 'ARP Input', 'CEF process', 'Virtual Exec', 'OSPF Router']
            process = random.choice(processes)
            pc = f'0x{random.randint(0x10000000, 0xFFFFFFFF):08X}'
            return self._format_log('SYS', 3, 'CPUHOG', f'Task ran for {ms} msec (4/0), process = {process}, PC = {pc}')

        elif event_type == 'sys_log_config_change':
            return self._format_log('SYS', 5, 'LOG_CONFIG_CHANGE', random.choice([
                'Console logging disabled',
                'Buffer logging: level debugging, xml disabled, filtering disabled',
                'Trap logging: level informational, 2587 message lines logged',
            ]))

        # --- AUTHENTICATION ---
        elif event_type == 'sec_login_success':
            user = self._random_admin_user()
            src_ip = self._random_internal_ip()
            ts_str = datetime.now().strftime('%H:%M:%S %Z %a %b %d %Y').strip()
            port = random.choice([22, 23])
            return self._format_log('SEC_LOGIN', 5, 'LOGIN_SUCCESS',
                f'Login Success [user: {user}] [Source: {src_ip}] [localport: {port}] at {ts_str}')

        elif event_type == 'sec_login_failed':
            user = random.choice(self.attack_users + self.admin_users[:2])
            src_ip = random.choice(self.external_ips + self.internal_ips[:3])
            ts_str = datetime.now().strftime('%H:%M:%S %Z %a %b %d %Y').strip()
            port = random.choice([22, 23])
            return self._format_log('SEC_LOGIN', 4, 'LOGIN_FAILED',
                f'Login failed [user: {user}] [Source: {src_ip}] [localport: {port}] [Reason: Login Authentication Failed] at {ts_str}')

        elif event_type == 'sec_login_quiet_mode':
            user = random.choice(self.attack_users)
            src_ip = random.choice(self.external_ips)
            secs = random.randint(0, 600)
            return self._format_log('SEC_LOGIN', 1, 'QUIET_MODE_ON',
                f'Still timeleft for watching failures is {secs} secs, [user: {user}] [Source: {src_ip}] [localport: 22] [Reason: Login Authentication Failed] [ACL: sl_def_acl] at {datetime.now().strftime("%H:%M:%S %Z %a %b %d %Y").strip()}')

        elif event_type == 'aaa_connect':
            user = self._random_admin_user()
            src_ip = self._random_internal_ip()
            vty = random.randint(0, 4)
            return self._format_log('AAA', 5, 'CONNECT', f'New user {user} on vty{vty} from {src_ip} ({src_ip})')

        elif event_type == 'aaa_username_config':
            user = random.choice(self.attack_users + self.admin_users)
            return self._format_log('AAA', 6, 'USERNAME_CONFIGURATION', f'user with username: {user} configured')

        elif event_type == 'aaa_privilege_update':
            user = random.choice(self.admin_users)
            priv = random.choice([1, 7, 15])
            return self._format_log('AAA', 6, 'USER_PRIVILEGE_UPDATE', f'username: {user} privilege updated with priv-{priv}')

        elif event_type == 'authmgr_start':
            mac_formatted = self._pick_mac()
            iface = random.choice(['GigabitEthernet1/0/5', 'GigabitEthernet1/0/12', 'GigabitEthernet1/0/24'])
            session_id = f'{random.randint(0x0A000000, 0x0AFFFFFF):08X}{random.randint(0x00000001, 0x0000FFFF):08X}{random.randint(0x10000000, 0xFFFFFFFF):08X}'
            return self._format_log('AUTHMGR', 5, 'START',
                f"Starting 'dot1x' for client ({mac_formatted}) on Interface {iface} AuditSessionID {session_id}")

        elif event_type == 'authmgr_success':
            mac_formatted = self._pick_mac()
            iface = random.choice(['GigabitEthernet1/0/5', 'GigabitEthernet1/0/12', 'GigabitEthernet1/0/24'])
            session_id = f'{random.randint(0x0A000000, 0x0AFFFFFF):08X}{random.randint(0x00000001, 0x0000FFFF):08X}{random.randint(0x10000000, 0xFFFFFFFF):08X}'
            return self._format_log('AUTHMGR', 5, 'SUCCESS',
                f"Authorization succeeded for client ({mac_formatted}) on Interface {iface} AuditSessionID {session_id}")

        # --- ACL & SECURITY ---
        elif event_type == 'sec_ipaccesslogp_denied':
            acl = random.choice(self.acl_names)
            proto = random.choice(['tcp', 'udp'])
            src_ip = random.choice(self.external_ips)
            src_port = random.randint(1024, 65535)
            dst_ip = self._random_internal_ip()
            dst_port = random.choice([22, 23, 80, 443, 445, 3389, 8080])
            packets = random.randint(1, 50)
            return self._format_log('SEC', 6, 'IPACCESSLOGP',
                f'list {acl} denied {proto} {src_ip}({src_port}) -> {dst_ip}({dst_port}), {packets} packet{"s" if packets > 1 else ""}')

        elif event_type == 'sec_ipaccesslogp_permitted':
            acl = random.choice(self.acl_names)
            proto = random.choice(['tcp', 'udp'])
            src_ip = self._random_internal_ip()
            src_port = random.randint(1024, 65535)
            dst_ip = self._random_internal_ip()
            dst_port = random.choice([22, 80, 443, 53, 8443])
            packets = random.randint(1, 20)
            return self._format_log('SEC', 6, 'IPACCESSLOGP',
                f'list {acl} permitted {proto} {src_ip}({src_port}) -> {dst_ip}({dst_port}), {packets} packet{"s" if packets > 1 else ""}')

        elif event_type == 'sec_ipaccesslogdp_denied':
            acl = random.choice(self.acl_names)
            src_ip = random.choice(self.external_ips)
            dst_ip = self._random_internal_ip()
            icmp_type = random.choice(['(8/0)', '(3/3)', '(3/1)', '(11/0)'])
            packets = random.randint(1, 30)
            return self._format_log('SEC', 6, 'IPACCESSLOGDP',
                f'list {acl} denied icmp {src_ip} -> {dst_ip} {icmp_type}, {packets} packet{"s" if packets > 1 else ""}')

        elif event_type == 'fw_sess_audit_trail_deny':
            src_ip = random.choice(self.external_ips)
            src_port = random.randint(1024, 65535)
            dst_ip = self._random_internal_ip()
            dst_port = random.choice([22, 23, 80, 443, 3389])
            return self._format_log('FW', 6, 'SESS_AUDIT_TRAIL',
                f'(target:class)-(ZP_OUT_TO_IN:CM_DENY_ALL):Stop tcp session: initiator ({src_ip}:{src_port}) sent 0 bytes -- responder ({dst_ip}:{dst_port}) sent 0 bytes')

        elif event_type == 'fw_sess_audit_trail_permit':
            src_ip = self._random_internal_ip()
            src_port = random.randint(1024, 65535)
            dst_ip = random.choice(self.external_ips + ['8.8.8.8', '1.1.1.1'])
            dst_port = random.choice([53, 80, 443])
            sent = random.randint(100, 50000)
            recv = random.randint(100, 50000)
            return self._format_log('FW', 6, 'SESS_AUDIT_TRAIL',
                f'(target:class)-(ZP_IN_TO_OUT:CM_PERMIT_ALL):Stop tcp session: initiator ({src_ip}:{src_port}) sent {sent} bytes -- responder ({dst_ip}:{dst_port}) sent {recv} bytes')

        # --- ROUTING ---
        elif event_type == 'ospf_adjchg_full':
            nbr = random.choice(self.ospf_neighbors)
            iface = random.choice(['GigabitEthernet0/0', 'GigabitEthernet0/1', 'GigabitEthernet0/2', 'Vlan100'])
            process_id = random.choice([1, 10, 100])
            return self._format_log('OSPF', 5, 'ADJCHG',
                f'Process {process_id}, Nbr {nbr} on {iface} from LOADING to FULL, Loading Done')

        elif event_type == 'ospf_adjchg_down':
            nbr = random.choice(self.ospf_neighbors)
            iface = random.choice(['GigabitEthernet0/0', 'GigabitEthernet0/1', 'GigabitEthernet0/2', 'Vlan100'])
            process_id = random.choice([1, 10, 100])
            reason = random.choice(['Dead timer expired', 'Interface down or detached', 'Neighbor Down: BFD node down'])
            return self._format_log('OSPF', 5, 'ADJCHG',
                f'Process {process_id}, Nbr {nbr} on {iface} from FULL to DOWN, {reason}')

        elif event_type == 'ospf_errrcv':
            src = random.choice(self.ospf_neighbors)
            iface = random.choice(['GigabitEthernet0/0', 'GigabitEthernet0/1'])
            return self._format_log('OSPF', 4, 'ERRRCV',
                f'Received invalid packet: mismatch area ID, from backbone area must be virtual-link but not found from {src}, {iface}')

        elif event_type == 'ospf_duprid':
            rid = random.choice(self.ospf_neighbors)
            src = random.choice(self.internal_ips)
            iface = random.choice(['GigabitEthernet0/0', 'GigabitEthernet0/1'])
            return self._format_log('OSPF', 4, 'DUPRID',
                f'OSPF detected duplicate router-id {rid} from {src} on interface {iface}')

        elif event_type == 'bgp_adjchange_up':
            nbr = random.choice(self.bgp_neighbors)
            return self._format_log('BGP', 5, 'ADJCHANGE', f'neighbor {nbr} Up')

        elif event_type == 'bgp_adjchange_down':
            nbr = random.choice(self.bgp_neighbors)
            reason = random.choice(['BGP Notification sent', 'Peer closed the session', 'Hold Timer Expired', 'Admin. shutdown'])
            return self._format_log('BGP', 5, 'ADJCHANGE', f'neighbor {nbr} Down {reason}')

        elif event_type == 'bgp_notification':
            nbr = random.choice(self.bgp_neighbors)
            code = random.choice(['4/0 (hold time expired)', '6/4 (administrative reset)', '2/2 (bad AS peer)'])
            return self._format_log('BGP', 3, 'NOTIFICATION', f'sent to neighbor {nbr} {code} 0 bytes')

        elif event_type == 'bgp_nbr_reset':
            nbr = random.choice(self.bgp_neighbors)
            reason = random.choice(['Peer closed the session', 'Admin. shutdown', 'Configuration change'])
            return self._format_log('BGP', 5, 'NBR_RESET', f'Neighbor {nbr} reset ({reason})')

        elif event_type == 'eigrp_nbrchange_up':
            nbr = random.choice(self.eigrp_neighbors)
            iface = random.choice(['GigabitEthernet0/1', 'Serial0/0/0', 'Vlan200'])
            as_num = random.choice([100, 200, 65000])
            reason = random.choice(['new adjacency', 'peer restarted'])
            return self._format_log('DUAL', 5, 'NBRCHANGE',
                f'EIGRP-IPv4 {as_num}: Neighbor {nbr} ({iface}) is up: {reason}')

        elif event_type == 'eigrp_nbrchange_down':
            nbr = random.choice(self.eigrp_neighbors)
            iface = random.choice(['GigabitEthernet0/1', 'Serial0/0/0', 'Vlan200'])
            as_num = random.choice([100, 200, 65000])
            reason = random.choice(['holding time expired', 'Interface Goodbye received', 'retry limit exceeded'])
            return self._format_log('DUAL', 5, 'NBRCHANGE',
                f'EIGRP-IPv4 {as_num}: Neighbor {nbr} ({iface}) is down: {reason}')

        # --- REDUNDANCY (HSRP) ---
        elif event_type in ('standby_active', 'standby_standby', 'standby_speak', 'standby_listen', 'standby_init'):
            state_map = {
                'standby_active': ('Standby', 'Active'),
                'standby_standby': ('Listen', 'Standby'),
                'standby_speak': ('Active', 'Speak'),
                'standby_listen': ('Init', 'Listen'),
                'standby_init': ('Active', 'Init'),
            }
            from_state, to_state = state_map[event_type]
            group = random.choice([1, 2, 10, 20])
            iface = random.choice(['GigabitEthernet0/1', 'Vlan100', 'Vlan200'])
            return self._format_log('STANDBY', 6, 'STATECHANGE',
                f'Standby: {group}: {iface} state {from_state} -> {to_state}')

        # --- SPANNING TREE ---
        elif event_type == 'spantree_topotrap':
            vlan = random.choice(self.vlans)
            return self._format_log('SPANTREE', 5, 'TOPOTRAP', f'Topology change trap for vlan {vlan}')

        elif event_type == 'spantree_rootguard':
            iface = random.choice(['GigabitEthernet1/0/24', 'GigabitEthernet1/0/48', 'GigabitEthernet1/0/1'])
            vlan = random.choice(self.vlans)
            return self._format_log('SPANTREE', 2, 'ROOTGUARD_BLOCK',
                f'Root guard blocking port {iface} on VLAN {vlan}')

        elif event_type == 'spantree_block_pvid':
            iface = random.choice(['GigabitEthernet0/1', 'GigabitEthernet1/0/24'])
            vlan = random.choice(self.vlans)
            return self._format_log('SPANTREE', 2, 'BLOCK_PVID_LOCAL',
                f'Blocking {iface} on VLAN {vlan:04d}. Inconsistent local vlan.')

        elif event_type == 'spantree_extended_sysid':
            return self._format_log('SPANTREE', 5, 'EXTENDED_SYSID', 'Extended SysId enabled for type vlan')

        elif event_type == 'spantree_port_fwd':
            vlan = random.choice(self.vlans)
            iface = random.choice(['GigabitEthernet1/0/1', 'GigabitEthernet1/0/12'])
            return self._format_log('SPANTREE_FAST', 7, 'PORT_FWD_UPLINK',
                f'VLAN{vlan:04d} {iface} moved to Forwarding (UplinkFast)')

        # --- HARDWARE ---
        elif event_type == 'snmp_authfail':
            host = random.choice(self.snmp_hosts)
            return self._format_log('SNMP', 3, 'AUTHFAIL', f'Authentication failure for SNMP req from host {host}')

        elif event_type == 'snmp_coldstart':
            hostname = random.choice(self.hostnames)
            return self._format_log('SNMP', 5, 'COLDSTART', f'SNMP agent on host {hostname} is undergoing a cold start')

        elif event_type == 'snmp_warmstart':
            hostname = random.choice(self.hostnames)
            return self._format_log('SNMP', 5, 'WARMSTART', f'SNMP agent on host {hostname} is undergoing a warm start')

        elif event_type == 'snmp_link_trap':
            iface = self._random_interface()
            trap_type = random.choice(['LinkDown', 'LinkUp'])
            return self._format_log('SNMP', 5, 'LINK_TRAP', f'{trap_type} Trap for interface {iface}')

        elif event_type == 'ntp_peerreach':
            server = random.choice(self.ntp_servers)
            return self._format_log('NTP', 6, 'PEERREACH', f'Peer {server} is reachable')

        elif event_type == 'ntp_peerunreach':
            server = random.choice(self.ntp_servers)
            return self._format_log('NTP', 6, 'PEERUNREACH', f'Peer {server} is unreachable')

        elif event_type == 'ntp_peersync':
            server = random.choice(self.ntp_servers)
            stratum = random.choice([1, 2, 3])
            return self._format_log('NTP', 5, 'PEERSYNC', f'NTP synchronized to peer {server}, stratum {stratum}')

        elif event_type == 'env_fan_failed':
            fan = random.randint(1, 4)
            return self._format_log('ENV', 3, 'FAN_FAILED', f'Fan {fan} has failed')

        elif event_type == 'oir_inscard':
            slot = random.randint(0, 4)
            return self._format_log('OIR', 6, 'INSCARD', f'Card inserted in slot {slot}, interfaces are now online')

        elif event_type == 'oir_remcard':
            slot = random.randint(0, 4)
            return self._format_log('OIR', 6, 'REMCARD', f'Card removed from slot {slot}, interfaces disabled')

        elif event_type == 'platform_memory':
            pct = random.randint(80, 98)
            return self._format_log('PLATFORM', 4, 'ELEMENT_WARNING', f'Switch 1 R0/0: memory usage is at {pct}%')

        else:
            return self._format_log('SYS', 6, 'INFO', 'Unknown event type')
