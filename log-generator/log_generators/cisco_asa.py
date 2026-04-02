"""
Cisco Adaptive Security Appliance (ASA) Log Generator

Generates ASA syslog messages in BSD format.
Format: <PRI>Mmm DD HH:MM:SS hostname : %ASA-severity-msgid: message
Sourcetype: cisco:asa  →  index: netfw

Note: FTD EMBLEM format (%FTD-) belongs to cisco:ftd.
      Firepower Unified Events (430xxx) belong to cisco:firepower:syslog.
      This generator covers %ASA- system messages only.
"""

import random
from datetime import datetime


class CiscoASALogGenerator:

    LOG_TYPE = 'cisco_asa'
    AVG_LOG_SIZE = 200
    SOURCETYPE_CONFIG = {
        'param_key': 'event_categories',
        'defaults': ['connection', 'vpn', 'auth', 'acl', 'system'],
        'multi_instance': False,
    }
    ASSET_IDENTITY_MAPPING = {
        'devices':      {'type': 'asset',    'field': 'nt_host', 'categories': ['cisco_asa'], 'cim_field': 'dvc'},
        'internal_ips': {'type': 'asset',    'field': 'ip',      'categories': ['cisco_asa'], 'cim_field': 'src_ip'},
        'external_ips': {'type': 'asset',    'field': 'ip',      'categories': ['external'],  'cim_field': 'dest_ip'},
        'users':        {'type': 'identity', 'field': 'identity',                             'cim_field': 'user'},
    }
    METADATA = {
        'name': 'Cisco ASA',
        'description': 'Cisco ASA BSD syslog — %ASA- system messages (cisco:asa, index: netfw)',
        'example': 'TCP/UDP connections, VPN sessions, AAA auth, ACL decisions, system events',
        'sources': [
            {'id': 'connection', 'name': 'Connection Events', 'description': 'TCP/UDP session built/teardown (302013–302016)'},
            {'id': 'vpn',        'name': 'VPN Events',        'description': 'IPsec/SSL VPN connect, disconnect, NAT-T (713xxx, 716xxx)'},
            {'id': 'auth',       'name': 'Authentication',    'description': 'AAA success/failure, SSH/HTTPS login (113xxx, 605xxx)'},
            {'id': 'acl',        'name': 'ACL & Policy',      'description': 'Access-list permit/deny decisions (106xxx)'},
            {'id': 'system',     'name': 'System Events',     'description': 'CLI commands, SSL handshake, HA, config (111xxx, 725xxx)'},
        ],
    }

    def __init__(self, event_categories=None):
        self.event_categories = event_categories or ['connection', 'vpn', 'auth', 'acl', 'system']
        self._conn_id = random.randint(100000, 999999)

        self.devices = [
            'asa-primary', 'asa-secondary', 'asa-dc-01', 'asa-edge-gw', 'asa-dmz',
        ]
        self.internal_ips = [
            '10.0.0.{}', '10.1.9.{}', '10.100.20.{}', '192.168.1.{}', '172.16.10.{}',
        ]
        self.external_ips = [
            '93.157.158.{}', '185.220.101.{}', '45.33.32.{}', '89.248.165.{}', '203.0.113.{}',
        ]
        self.interfaces   = ['inside', 'outside', 'dmz', 'management', 'guest']
        self.users        = ['admin', 'john.doe', 'vpn_user', 'svc_account', 'sec.analyst']
        self.vpn_groups   = ['VPN-Users', 'Remote-Access', 'SSL-VPN', 'Contractors']
        self.protocols    = ['TCP', 'UDP']

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _bsd_ts(self):
        return datetime.now().strftime('%b %d %H:%M:%S')

    def _ip(self, pool):
        return random.choice(pool).format(random.randint(1, 254))

    def _conn(self):
        self._conn_id += 1
        return self._conn_id

    def _pri(self, severity):
        # facility 20 (local4) → base 160
        sev_map = {'1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6}
        return 160 + sev_map.get(str(severity), 6)

    def _line(self, severity, msgid, message):
        device = random.choice(self.devices)
        return f'<{self._pri(severity)}>{self._bsd_ts()} {device} : %ASA-{severity}-{msgid}: {message}'

    # ------------------------------------------------------------------
    # Categories
    # ------------------------------------------------------------------

    def generate(self):
        weights = {'connection': 40, 'vpn': 20, 'auth': 15, 'acl': 15, 'system': 10}
        active  = {k: v for k, v in weights.items() if k in self.event_categories} or weights
        cat     = random.choices(list(active), weights=list(active.values()), k=1)[0]
        return getattr(self, f'_gen_{cat}')()\

    def _gen_connection(self):
        proto    = random.choice(self.protocols)
        src_ip   = self._ip(self.internal_ips)
        dst_ip   = self._ip(self.external_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 25, 53, 3389, 8443])
        iface_in = random.choice(self.interfaces)
        iface_out= random.choice(self.interfaces)
        conn_id  = self._conn()

        if random.random() > 0.4:
            duration = random.randint(1, 3600)
            sent     = random.randint(0, 500000)
            rcvd     = random.randint(0, 500000)
            msgid    = '302014' if proto == 'TCP' else '302016'
            reason   = random.choice(['TCP FINs', 'TCP Reset-I', 'TCP Reset-O', 'Conn-Timeout', 'UDP Timeout'])
            msg = (f'Teardown {proto} connection {conn_id} for {iface_in}:{src_ip}/{src_port} '
                   f'to {iface_out}:{dst_ip}/{dst_port} duration {duration//3600:02d}:{(duration%3600)//60:02d}:{duration%60:02d} '
                   f'bytes {sent+rcvd} {reason}')
            return self._line(6, msgid, msg)
        else:
            msgid     = '302013' if proto == 'TCP' else '302015'
            direction = random.choice(['inbound', 'outbound'])
            msg = (f'Built {direction} {proto} connection {conn_id} for {iface_in}:{src_ip}/{src_port} '
                   f'({src_ip}/{src_port}) to {iface_out}:{dst_ip}/{dst_port} ({dst_ip}/{dst_port})')
            return self._line(6, msgid, msg)

    def _gen_vpn(self):
        user  = random.choice(self.users)
        group = random.choice(self.vpn_groups)
        ip    = self._ip(self.external_ips)
        events = [
            (5, '713172', f'Group = {group}, Username = {user}, IP = {ip}, '
                          f'Automatic NAT Detection Status: Remote end is{random.choice(["", " NOT"])} behind a NAT device'),
            (4, '713903', f'Group = {group} Username = {user} IP = {ip} '
                          f'Session disconnected. Session Type: IPsec, Duration: {random.randint(60,7200)}s, '
                          f'Bytes xmt: {random.randint(1000,1000000)}, Bytes rcv: {random.randint(1000,1000000)}, Reason: User Requested'),
            (6, '716001', f'Group = {group} User = {user} IP = {ip} WebVPN session started.'),
            (6, '716002', f'Group = {group} User = {user} IP = {ip} WebVPN session terminated. '
                          f'User Requested, SVC not asked to reconnect: {random.randint(1,5)}'),
            (5, '713049', f'Group = {group}, Username = {user}, IP = {ip}, '
                          f'Security negotiation complete for LAN-to-LAN Group ({group}) '
                          f'Responder, Inbound SPI = 0x{random.randint(0,0xFFFFFFFF):08x}, '
                          f'Outbound SPI = 0x{random.randint(0,0xFFFFFFFF):08x}'),
        ]
        sev, msgid, msg = random.choice(events)
        return self._line(sev, msgid, msg)

    def _gen_auth(self):
        user = random.choice(self.users)
        ip   = self._ip(self.internal_ips)
        srv  = self._ip(self.internal_ips)
        iface= random.choice(self.interfaces)
        events = [
            (6, '113004', f'AAA user authentication Successful : server = {srv} : user = {user}'),
            (4, '113005', f'AAA user authentication Rejected : reason = Invalid password : server = {srv} : user = {user}'),
            (6, '605005', f'Login permitted from {ip}/{random.randint(1024,65535)} to {iface}:{self._ip(self.internal_ips)}/ssh for user "{user}"'),
            (5, '605004', f'Login denied from {ip}/{random.randint(1024,65535)} to {iface}:{self._ip(self.internal_ips)}/ssh for user "{user}"'),
            (6, '113008', f'AAA transaction status ACCEPT : user = {user}'),
        ]
        sev, msgid, msg = random.choice(events)
        return self._line(sev, msgid, msg)

    def _gen_acl(self):
        proto    = random.choice(['TCP', 'UDP', 'ICMP'])
        src_ip   = self._ip(self.external_ips)
        dst_ip   = self._ip(self.internal_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 25, 3389, 53, 8080])
        iface    = random.choice(self.interfaces)
        acl_name = random.choice(['OUTSIDE_IN', 'DMZ_ACCESS', 'BLOCK_LIST', 'sl_def_acl'])
        hit_cnt  = random.randint(1, 5000)
        events = [
            (2, '106001', f'Inbound {proto} connection denied from {src_ip}/{src_port} to {dst_ip}/{dst_port} flags SYN on interface {iface}'),
            (6, '106100', f'access-list {acl_name} {"permitted" if random.random()>0.3 else "denied"} {proto} '
                          f'{iface}/{src_ip}({src_port}) -> {iface}/{dst_ip}({dst_port}) hit-cnt {hit_cnt} '
                          f'first hit [0x{random.randint(0,0xFFFFFFFF):08x}, 0x{random.randint(0,0xFFFFFF):06x}]'),
            (3, '106010', f'Deny inbound {proto} src {iface}:{src_ip}/{src_port} dst {iface}:{dst_ip}/{dst_port}'),
        ]
        sev, msgid, msg = random.choice(events)
        return self._line(sev, msgid, msg)

    def _gen_system(self):
        user  = random.choice(self.users)
        ip    = self._ip(self.internal_ips)
        iface = random.choice(self.interfaces)
        events = [
            (5, '111008', f"User '{user}' executed the '{random.choice(['show run', 'show version', 'write mem', 'copy run start'])}' command."),
            (5, '111010', f"User '{user}', running 'CLI' from IP {ip}, executed '{random.choice(['show access-list', 'show crypto isa sa', 'show conn'])}'"),
            (6, '725001', f'Starting SSL handshake with client {iface}:{ip}/{random.randint(1024,65535)} for {random.choice(["TLSv1.2","TLSv1.3"])} session.'),
            (6, '725002', f'Device completed SSL handshake with client {iface}:{ip}/{random.randint(1024,65535)}.'),
            (6, '725007', f'SSL session with client {iface}:{ip}/{random.randint(1024,65535)} terminated.'),
            (3, '210005', f'LAN Failover interface is up'),
            (2, '105003', f'(Primary) Monitoring on interface {iface} waiting'),
        ]
        sev, msgid, msg = random.choice(events)
        return self._line(sev, msgid, msg)
