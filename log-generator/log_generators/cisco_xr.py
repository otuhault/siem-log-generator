"""
Cisco IOS XR Log Generator

Generates IOS XR syslog messages.
Format: <PRI>Mmm DD HH:MM:SS.mmm TZ: hostname: process[pid]: %FACILITY-SEVERITY-MNEMONIC: message
Sourcetype: cisco:xr  →  index: netops

Note: This is distinct from IOS/IOS-XE (cisco:ios, cisco:ios-xe).
      XR uses millisecond-precision timestamps, timezone label, and process/PID in the header.
"""

import random
from datetime import datetime


class CiscoXRLogGenerator:

    LOG_TYPE = 'cisco_xr'
    AVG_LOG_SIZE = 220
    SOURCETYPE_CONFIG = {
        'param_key': 'event_categories',
        'defaults': ['routing', 'mpls', 'interface', 'system', 'security'],
        'multi_instance': False,
    }
    ASSET_IDENTITY_MAPPING = {
        'devices': {'type': 'asset',    'field': 'nt_host',  'categories': ['cisco_xr'],                 'cim_field': 'dvc'},
        'users':   {'type': 'identity', 'field': 'identity', 'categories': ['privileged', 'standard'],   'cim_field': 'user'},
    }
    METADATA = {
        'name': 'Cisco IOS XR',
        'description': 'Cisco IOS XR syslog — %FACILITY- messages with ms timestamps (cisco:xr, index: netops)',
        'example': 'BGP/OSPF/IS-IS adjacency changes, MPLS, interface events, system health',
        'sources': [
            {'id': 'routing',   'name': 'Routing Events',   'description': 'BGP, OSPF, IS-IS adjacency and route changes'},
            {'id': 'mpls',      'name': 'MPLS Events',      'description': 'LDP session, label binding, TE tunnel events'},
            {'id': 'interface', 'name': 'Interface Events', 'description': 'Link up/down, carrier transitions, error counters'},
            {'id': 'system',    'name': 'System Events',    'description': 'Process restarts, config commits, platform health'},
            {'id': 'security',  'name': 'Security Events',  'description': 'SSH login, AAA, ACL hits, uRPF drops'},
        ],
    }

    def __init__(self, event_categories=None):
        self.event_categories = event_categories or ['routing', 'mpls', 'interface', 'system', 'security']

        self.devices = [
            'xr-core-01', 'xr-core-02', 'xr-pe-01', 'xr-pe-02', 'xr-p-01',
        ]
        self.processes = {
            'routing':   ['bgp', 'ospf', 'isis', 'rib'],
            'mpls':      ['ldp', 'rsvp', 'mpls_te'],
            'interface': ['ifmgr', 'l2vpn', 'bundlemgr'],
            'system':    ['sysdb', 'prm', 'cfgmgr', 'sysmgr'],
            'security':  ['ssh', 'aaa', 'ipv4_acl'],
        }
        self.internal_ips = [
            '10.0.0.{}', '10.1.9.{}', '10.100.20.{}',
        ]
        self.external_ips = [
            '93.157.158.{}', '185.220.101.{}', '203.0.113.{}',
        ]
        self.interfaces = [
            'GigabitEthernet0/0/0/{}', 'TenGigE0/0/0/{}', 'Bundle-Ether{}',
            'Loopback{}', 'HundredGigE0/0/0/{}',
        ]
        self.neighbors = [
            '10.0.0.{}', '10.1.0.{}', '172.16.0.{}', '192.168.100.{}',
        ]
        self.asns = [65001, 65002, 65100, 64512, 7018, 3356, 1299]
        self.timezones = ['UTC', 'EST', 'CET', 'JST']

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ts(self):
        now = datetime.now()
        ms  = now.strftime('%f')[:3]
        tz  = random.choice(self.timezones)
        return now.strftime('%b %d %H:%M:%S') + f'.{ms} {tz}'

    def _ip(self, pool):
        return random.choice(pool).format(random.randint(1, 254))

    def _iface(self):
        tmpl = random.choice(self.interfaces)
        return tmpl.format(random.randint(0, 7))

    def _neighbor(self):
        return random.choice(self.neighbors).format(random.randint(1, 254))

    def _pri(self, severity):
        # facility 23 (local7) → base 184
        sev_map = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7}
        return 184 + sev_map.get(str(severity), 6)

    def _line(self, severity, facility, mnemonic, message, category='system'):
        device  = random.choice(self.devices)
        procs   = self.processes.get(category, self.processes['system'])
        process = random.choice(procs)
        pid     = random.randint(1000, 65535)
        return (f'<{self._pri(severity)}>{self._ts()}: {device}: '
                f'{process}[{pid}]: %{facility}-{severity}-{mnemonic}: {message}')

    # ------------------------------------------------------------------
    # Categories
    # ------------------------------------------------------------------

    def generate(self):
        weights = {'routing': 35, 'mpls': 20, 'interface': 20, 'system': 15, 'security': 10}
        active  = {k: v for k, v in weights.items() if k in self.event_categories} or weights
        cat     = random.choices(list(active), weights=list(active.values()), k=1)[0]
        return getattr(self, f'_gen_{cat}')()\

    def _gen_routing(self):
        neighbor = self._neighbor()
        asn      = random.choice(self.asns)
        local_asn= random.choice(self.asns)
        vrf      = random.choice(['default', 'MGMT', 'CUST-A', 'CUST-B'])
        reason   = random.choice(['Hold Timer Expired', 'BGP Notification received', 'Interface flap',
                                   'Peer De-configured', 'TCP connection closed'])
        state    = random.choice(['Established', 'Idle', 'Active', 'OpenSent'])

        events = [
            # BGP
            (5, 'ROUTING', 'BGP_ADJCHANGE',
             f'neighbor {neighbor} Up , VRF {vrf}'),
            (3, 'ROUTING', 'BGP_ADJCHANGE',
             f'neighbor {neighbor} Down {reason} , VRF {vrf}'),
            (5, 'ROUTING', 'BGP_NOTIFICATION',
             f'sent to neighbor {neighbor} 4/{random.randint(1,11)} (hold time expired) {random.randint(0,255)} bytes'),
            (6, 'ROUTING', 'BGP_BESTPATH',
             f'VRF {vrf}, {self._ip(self.internal_ips)}/{random.randint(8,30)}: '
             f'New bestpath from neighbor {neighbor}, AS {asn}'),
            # OSPF
            (5, 'OSPF', 'ADJCHANGE',
             f'Process {random.randint(1,10)} Nbr {neighbor} on {self._iface()} from FULL to DOWN, Reason: {reason}'),
            (5, 'OSPF', 'ADJCHANGE',
             f'Process {random.randint(1,10)} Nbr {neighbor} on {self._iface()} from LOADING to FULL, {state}'),
            # IS-IS
            (4, 'ISIS', 'ADJCHANGE',
             f'Adjacency to {neighbor} (Gi0/0/0/{random.randint(0,7)}) Down, {reason}'),
            (5, 'ISIS', 'ADJCHANGE',
             f'New adjacency to {neighbor} (area {random.randint(49,49)}.{random.randint(0,9999):04d})'),
        ]
        sev, facility, mnemonic, msg = random.choice(events)
        return self._line(sev, facility, mnemonic, msg, 'routing')

    def _gen_mpls(self):
        neighbor = self._neighbor()
        label    = random.randint(16, 1048575)
        tunnel   = random.randint(1, 999)
        bw       = random.choice([100, 1000, 10000])

        events = [
            (5, 'LDP',    'NEIGHBOR_CHANGE',
             f'Neighbor {neighbor}:0 is UP'),
            (3, 'LDP',    'NEIGHBOR_CHANGE',
             f'Neighbor {neighbor}:0 is DOWN (Hold Timer Expired)'),
            (6, 'LDP',    'LABEL_BINDING',
             f'Assigned label {label} for prefix {self._ip(self.internal_ips)}/{random.randint(8,30)}'),
            (5, 'RSVP',   'TUNNEL_UP',
             f'Tunnel tunnel-te{tunnel} to {self._ip(self.internal_ips)}: signaled BW={bw}kbps'),
            (4, 'RSVP',   'TUNNEL_DOWN',
             f'Tunnel tunnel-te{tunnel} to {self._ip(self.internal_ips)}: path down — {random.choice(["no route", "preempted", "link failure"])}'),
            (6, 'MPLS_TE','FRR_ACTIVE',
             f'Tunnel tunnel-te{tunnel}: FRR activated on {self._iface()}'),
        ]
        sev, facility, mnemonic, msg = random.choice(events)
        return self._line(sev, facility, mnemonic, msg, 'mpls')

    def _gen_interface(self):
        iface = self._iface()
        events = [
            (3, 'LINK', 'UPDOWN',
             f'Interface {iface}, changed state to Down'),
            (5, 'LINK', 'UPDOWN',
             f'Interface {iface}, changed state to Up'),
            (4, 'LINEPROTO', 'UPDOWN',
             f'Line protocol on Interface {iface}, changed state to down'),
            (5, 'LINEPROTO', 'UPDOWN',
             f'Line protocol on Interface {iface}, changed state to up'),
            (4, 'ETHERNET', 'CARRIER_TRANSITION',
             f'{iface}: carrier transitions {random.randint(1,20)}'),
            (3, 'PLATFORM', 'ERR_DISABLE',
             f'{iface}: put in err-disable state due to {random.choice(["bpduguard", "loopback", "link-flap"])}'),
            (6, 'BUNDLEMGR', 'BUNDLE_ACTIVE',
             f'Bundle-Ether{random.randint(1,10)}: Member {iface} is Active'),
        ]
        sev, facility, mnemonic, msg = random.choice(events)
        return self._line(sev, facility, mnemonic, msg, 'interface')

    def _gen_system(self):
        user   = random.choice(['admin', 'noc', 'svc_monitor', 'autoback'])
        commit = f'{random.randint(1000000,9999999):07d}'
        events = [
            (5, 'SYS',    'RESTART',
             f'Process {random.choice(["bgp", "ospf", "ldp", "ipv4_rib"])} has restarted'),
            (5, 'CFGMGR', 'CFG_COMMIT',
             f'Configuration committed by user \'{user}\' — commit ID {commit}'),
            (6, 'CFGMGR', 'CFG_ROLLBACK',
             f'Configuration rollback to commit {commit} by user \'{user}\''),
            (3, 'SYSMGR', 'PROCESS_CRASH',
             f'Process {random.choice(["l2vpn_mgr", "ncs5500_fia"])} (jid {random.randint(100,999)}) crashed'),
            (5, 'PLATFORM','TEMPERATURE_NORMAL',
             f'Outlet temperature is normal ({random.randint(25,45)}C)'),
            (2, 'PLATFORM','TEMPERATURE_CRITICAL',
             f'Outlet temperature is critical ({random.randint(65,85)}C), shutdown imminent'),
            (6, 'SYS',    'NTP_SYNC',
             f'Clock synchronized to {self._ip(self.internal_ips)} stratum {random.randint(1,4)}'),
        ]
        sev, facility, mnemonic, msg = random.choice(events)
        return self._line(sev, facility, mnemonic, msg, 'system')

    def _gen_security(self):
        user = random.choice(['admin', 'noc', 'svc_account', 'readonly'])
        ip   = self._ip(self.external_ips)
        iface= self._iface()
        events = [
            (6, 'SSH',  'SESSION_START',
             f'SSH session from {ip} for user \'{user}\' started'),
            (5, 'SSH',  'SESSION_END',
             f'SSH session from {ip} for user \'{user}\' ended'),
            (4, 'SSH',  'AUTH_FAIL',
             f'Authentication failed for user \'{user}\' from {ip}'),
            (4, 'AAA',  'AUTHEN_FAIL',
             f'Authentication failed for user \'{user}\' from {ip} — reason: bad password'),
            (6, 'AAA',  'AUTHOR_PASS',
             f'Command authorization passed for user \'{user}\': {random.choice(["show run", "show bgp", "show mpls ldp"])}'),
            (4, 'IPV4_ACL', 'IPACCESSLOGP',
             f'list {random.choice(["MGMT_RESTRICT","DENY_BOGONS","COPP_POLICY"])} denied '
             f'{random.choice(["tcp","udp"])} {self._ip(self.external_ips)}({random.randint(1024,65535)}) -> '
             f'{self._ip(self.internal_ips)}({random.randint(22,8443)}), {random.randint(1,100)} packet(s)'),
            (4, 'IPV4_ACL', 'IPACCESSLOGRP',
             f'uRPF drop from {self._ip(self.external_ips)} on {iface}, {random.randint(1,50)} packet(s)'),
        ]
        sev, facility, mnemonic, msg = random.choice(events)
        return self._line(sev, facility, mnemonic, msg, 'security')
