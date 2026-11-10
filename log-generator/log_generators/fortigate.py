"""
Fortinet FortiGate (FortiOS) Log Generator

Emits the key=value line a FortiGate writes, in the FortiOS 6.2 shape the
product manual documents: string values quoted, addresses, ports and counters
bare, `date=`/`time=` first because every stanza of the add-on sets
`TIME_PREFIX = ^`.

Four sourcetypes, because the add-on has four sets of extractions and the
index-time fan-out keys on the same four values of `type=`:

    type=traffic  -> fortigate_traffic
    type=utm      -> fortigate_utm      (webfilter, ips, virus, app-ctrl)
    type=event    -> fortigate_event    (user auth, admin, vpn, config, perf)
    type=anomaly  -> fortigate_anomaly  (DoS policy)

What each category emits is not a stylistic choice: `eventtypes.conf` matches on
`subtype` plus, often, `action`/`status`/`logid`, and the two action lookups
decide whether a CIM `action` comes out at all. The add-on's own samples parse
but three of them reach no datamodel — see references/fortinet-sourcetypes.md §6
for which, and why the values below differ from them where they do.
"""

import random
import re
from datetime import datetime

from .ai_entity import AIEntityMixin

#: Values FortiOS writes without quotes. Numbers are bare by being passed as
#: numbers; these two are strings that stay bare all the same — an address, and
#: the `sent/received` pair `bandwidth` reports. An identifier that happens to be
#: all digits (`logid`, `sn`) is quoted, which is why this is not just \d+.
_BARE_VALUE = re.compile(r'^(?:\d{1,3}(?:\.\d{1,3}){3}|\d+/\d+)$')


class FortiGateLogGenerator(AIEntityMixin):
    """Generates Fortinet FortiGate logs in the FortiOS key=value format."""

    LOG_TYPE = 'fortigate'
    AVG_LOG_SIZE = 610

    SOURCETYPE_CONFIG = {
        'param_key': 'event_categories',
        'defaults': ['traffic', 'utm_webfilter', 'utm_ips', 'utm_virus',
                     'utm_appctrl', 'event_auth', 'event_admin', 'event_vpn',
                     'event_config', 'event_perf', 'anomaly'],
        'multi_instance': False,
    }

    METADATA = {
        'name': 'Fortinet FortiGate',
        'description': 'FortiOS key=value logs (traffic, UTM, event, DoS anomaly)',
        'example': 'date=2026-09-13 time=11:29:55 devname="fgt-edge-01" type="traffic" ...',
        'sources': [
            {'id': 'traffic',       'name': 'Traffic',            'sourcetype': 'fortigate_traffic',
             'description': 'Forwarded sessions through a firewall policy'},
            {'id': 'utm_webfilter', 'name': 'UTM — Web Filter',   'sourcetype': 'fortigate_utm',
             'description': 'URL verdicts from the web filter profile'},
            {'id': 'utm_ips',       'name': 'UTM — IPS',          'sourcetype': 'fortigate_utm',
             'description': 'IPS signature detections'},
            {'id': 'utm_virus',     'name': 'UTM — AntiVirus',    'sourcetype': 'fortigate_utm',
             'description': 'AntiVirus blocks (analytics submissions reach no datamodel)'},
            {'id': 'utm_appctrl',   'name': 'UTM — App Control',  'sourcetype': 'fortigate_utm',
             'description': 'Application control verdicts'},
            {'id': 'event_auth',    'name': 'User Authentication', 'sourcetype': 'fortigate_event',
             'description': 'Firewall user authentication (subtype=user)'},
            {'id': 'event_admin',   'name': 'Admin Login',        'sourcetype': 'fortigate_event',
             'description': 'Administrator login and logout on the appliance'},
            {'id': 'event_vpn',     'name': 'VPN',                'sourcetype': 'fortigate_event',
             'description': 'IPsec and SSL-VPN negotiation, tunnel up and down'},
            {'id': 'event_config',  'name': 'Configuration Change', 'sourcetype': 'fortigate_event',
             'description': 'Object add, edit and delete through the CLI or the GUI'},
            {'id': 'event_perf',    'name': 'Performance Stats',  'sourcetype': 'fortigate_event',
             'description': 'Periodic CPU, memory and session counters'},
            {'id': 'anomaly',       'name': 'DoS Anomaly',        'sourcetype': 'fortigate_anomaly',
             'description': 'DoS policy anomaly detections (type=anomaly)'},
        ],
    }

    #: Relative weight per category, so a mixed sender looks like a firewall:
    #: traffic dominates, everything else is an exception to it.
    WEIGHTS = {
        'traffic': 45, 'utm_webfilter': 15, 'utm_appctrl': 8, 'utm_ips': 5,
        'utm_virus': 3, 'anomaly': 2, 'event_auth': 8, 'event_admin': 4,
        'event_vpn': 5, 'event_config': 3, 'event_perf': 2,
    }

    #: `action` values that survive lookups/ftnt_action_info.csv. Anything else
    #: leaves the event with no CIM `action`, which is most of what
    #: Network_Traffic is searched on.
    TRAFFIC_ACTIONS = [
        ('accept', 'allowed', 65), ('close', 'allowed', 15),
        ('timeout', 'teardown', 10), ('deny', 'blocked', 10),
    ]

    def __init__(self, event_categories=None):
        self.event_categories = event_categories or list(
            self.SOURCETYPE_CONFIG['defaults'])

        # Pools A&I overrides — see ENTITY_TYPE_ROLES / ACCOUNT_TYPE_ROLES.
        # `devid` has to start with FG, FW or F<digit>K or the add-on's
        # index-time fan-out will not recognise the event as a FortiGate one
        # (transforms.conf:5).
        self.hostnames = ['fgt-edge-01', 'fgt-edge-02', 'fgt-dc-core',
                          'fgt-branch-lyon', 'fgt-dmz-01']
        self.device_ids = ['FG100F3G17801234', 'FG200E4Q16800456',
                           'FGT60FTK21005678', 'FWF60E4Q16009012']
        self.internal_ips = ['10.0.0.{}', '10.1.100.{}', '172.16.20.{}',
                             '192.168.10.{}']
        self.external_ips = ['93.184.216.{}', '104.244.42.{}', '151.101.1.{}',
                             '185.220.101.{}', '45.33.32.{}']
        self.users = ['alice.martin', 'bob.dupont', 'c.leroy', 'svc_backup',
                      'j.moreau']
        self.admin_users = ['admin', 'netadmin', 'fw_operator']

        # Phase 4c network pools — set by inject_network_pools_into().
        self.src_ip_pool: list = []
        self.dest_ip_pool: list = []

        # An interface and the role FortiOS reports for it, kept apart by end:
        # a forwarded session leaves an inside interface for an outside one, and
        # pairing them at random produced lan-to-lan sessions to the internet.
        self.inside_interfaces  = [('port1', 'lan'), ('internal', 'lan'),
                                   ('port3', 'dmz')]
        self.outside_interfaces = [('wan1', 'wan'), ('port2', 'wan')]
        self.vdoms = ['root', 'vdom1']
        self.services = [('HTTPS', 443, 6), ('HTTP', 80, 6), ('DNS', 53, 17),
                         ('SSH', 22, 6), ('SMTP', 25, 6), ('RDP', 3389, 6)]
        self.apps = [
            ('HTTPS.BROWSER', 'Web.Client', 'medium'),
            ('Microsoft.Office.365', 'Collaboration', 'elevated'),
            ('Dropbox', 'Storage.Backup', 'high'),
            ('BitTorrent', 'P2P', 'critical'),
            ('Slack', 'Collaboration', 'low'),
            ('DNS', 'Network.Service', 'elevated'),
        ]
        self.web_sites = [
            ('www.lemonde.fr', '/politique/article.html', 'News and Media', 33),
            ('docs.google.com', '/document/d/1a2b3c', 'Web-based Applications', 51),
            ('github.com', '/fortinet/fortios', 'Information Technology', 52),
            ('cdn.jsdelivr.net', '/npm/chart.js', 'Content Servers', 19),
            ('poker-online.example', '/lobby', 'Gambling', 20),
            ('malware-c2.example', '/gate.php', 'Malicious Websites', 26),
        ]
        self.attacks = [
            ('Apache.Struts.Jakarta.Multipart.Parser.Code.Execution', 40768, 'critical'),
            ('Log4j2.Remote.Code.Execution', 51006, 'critical'),
            ('MS.SMB.Server.SMB1.Trans2.Secondary.Handling.Code.Execution', 43084, 'high'),
            ('HTTP.Header.SQL.Injection', 15621, 'medium'),
            ('OpenSSL.TLS.Heartbeat.Information.Disclosure', 38307, 'high'),
        ]
        self.viruses = [
            ('EICAR_TEST_FILE', 'eicar.com'),
            ('W32/Emotet.AB!tr', 'invoice_2026.doc'),
            ('JS/Nemucod.7A19!tr.dldr', 'order.js'),
            ('W32/Agent.SVE!tr', 'setup.exe'),
        ]
        # (name, action, severity, proto, service, port) — the protocol and the
        # port a flood targets are part of the anomaly, not free variables.
        self.anomalies = [
            ('tcp_syn_flood',  'clear_session', 'critical', 6,  'HTTPS', 443),
            ('udp_flood',      'clear_session', 'critical', 17, 'DNS',   53),
            ('icmp_flood',     'clear_session', 'warning',  1,  'PING',  0),
            ('tcp_port_scan',  'clear_session', 'warning',  6,  'tcp/0', 0),
        ]
        self.config_paths = [
            ('firewall.policy', 'Edit', '17'),
            ('firewall.address', 'Add', 'SRV-WEB-01'),
            ('system.interface', 'Edit', 'port2'),
            ('user.local', 'Add', 'c.leroy'),
            ('vpn.ipsec.phase1-interface', 'Edit', 'VPN-BRANCH-LYON'),
            ('firewall.policy', 'delete', '42'),
        ]
        self.vpn_tunnels = ['VPN-BRANCH-LYON', 'VPN-PARTNER-A', 'SSL-VPN-RA']

        self._session_id = random.randint(10_000_000, 99_999_999)

        self._builders = {
            'traffic':       self._traffic,
            'utm_webfilter': self._utm_webfilter,
            'utm_ips':       self._utm_ips,
            'utm_virus':     self._utm_virus,
            'utm_appctrl':   self._utm_appctrl,
            'event_auth':    self._event_auth,
            'event_admin':   self._event_admin,
            'event_vpn':     self._event_vpn,
            'event_config':  self._event_config,
            'event_perf':    self._event_perf,
            'anomaly':       self._anomaly,
        }

    # ------------------------------------------------------------------

    def generate(self):
        """One FortiOS log line."""
        # One event describes one firewall and, when A&I pins one, the machines
        # at each end of the session plus the account behind it.
        self._new_entity()

        active = {c: w for c, w in self.WEIGHTS.items()
                  if c in self.event_categories and c in self._builders}
        if not active:
            active = dict(self.WEIGHTS)
        category = random.choices(list(active), weights=list(active.values()), k=1)[0]
        return self._builders[category]()

    # ------------------------------------------------------------------
    # Shared pieces
    # ------------------------------------------------------------------

    @staticmethod
    def _kv(**fields):
        """`key=value` pairs, quoted the way FortiOS 6.2 quotes them.

        Names, messages and identifiers are quoted; counters, ports, addresses
        and the `sent/received` pairs are bare. That is cosmetic for the add-on —
        `DELIMS` strips the quotes either way — but it is what a FortiGate puts
        on the wire, and the whole point of the generator is to look like one.
        """
        parts = []
        for key, value in fields.items():
            if value is None:
                continue
            text = str(value)
            bare = isinstance(value, (int, float)) or _BARE_VALUE.match(text)
            parts.append(f'{key}={text}' if bare else f'{key}="{text}"')
        return ' '.join(parts)

    def _head(self, log_type, subtype, logid, level, **extra):
        """The prefix every FortiOS line shares.

        `date=`/`time=` come first because all four stanzas set
        `TIME_PREFIX = ^`, and `devid` is what the add-on's index-time fan-out
        recognises a FortiGate by.
        """
        now = datetime.now()
        head = (f'date={now.strftime("%Y-%m-%d")} time={now.strftime("%H:%M:%S")} '
                + self._kv(
                    devname=self._devname(),
                    devid=random.choice(self.device_ids),
                    logid=logid, type=log_type, subtype=subtype, level=level,
                    vd=random.choice(self.vdoms))
                + f' eventtime={int(now.timestamp())}')
        return f'{head} {self._kv(**extra)}' if extra else head

    def _devname(self):
        return self._entity_field('hostnames',
                                  lambda: random.choice(self.hostnames))

    def _ip(self, pool):
        return random.choice(pool).format(random.randint(1, 254))

    def _src_ip(self):
        """The client end: a pool address when one is configured, else A&I."""
        if self.src_ip_pool:
            return random.choice(self.src_ip_pool)
        return self._entity_field('internal_ips',
                                  lambda: self._ip(self.internal_ips), side='src')

    def _dest_ip(self, internal=False):
        """The server end. `internal` for sessions that never leave the network.

        Each case reads its own roster pool, because the two are different kinds
        of machine in A&I: an internal destination is a `server` entity, an
        external one an `external` entity. Reading `internal_ips` for both would
        put an address of the estate on the far end of an outbound session.
        """
        if self.dest_ip_pool:
            return random.choice(self.dest_ip_pool)
        if not internal:
            return self._entity_field(
                'external_ips', lambda: self._ip(self.external_ips), side='dest')
        return self._entity_field('internal_ips',
                                  lambda: self._ip(self.internal_ips), side='dest')

    def _external_ip(self):
        """An address outside the estate, on the source end of an inbound event."""
        return self._entity_field('external_ips',
                                  lambda: self._ip(self.external_ips), side='src')

    def _user(self):
        return self._entity_field('users', lambda: random.choice(self.users))

    def _admin(self):
        return random.choice(self.admin_users)

    def _session(self):
        self._session_id += 1
        return self._session_id

    def _session_pair(self):
        """The five-tuple and interfaces shared by traffic and UTM events."""
        service, port, proto = random.choice(self.services)
        src_intf, src_role = random.choice(self.inside_interfaces)
        dst_intf, dst_role = random.choice(self.outside_interfaces)
        return {
            'srcip': self._src_ip(), 'srcport': random.randint(1024, 65535),
            'srcintf': src_intf, 'srcintfrole': src_role,
            'dstip': self._dest_ip(), 'dstport': port,
            'dstintf': dst_intf, 'dstintfrole': dst_role,
            'proto': proto, 'service': service,
        }

    # ------------------------------------------------------------------
    # type=traffic
    # ------------------------------------------------------------------

    def _traffic(self):
        """A forwarded session. `subtype=forward` is what [ftnt_fortigate_traffic]
        needs, and the action must be one the action lookup knows."""
        tuple_ = self._session_pair()
        action = random.choices(
            [a for a, _, _ in self.TRAFFIC_ACTIONS],
            weights=[w for _, _, w in self.TRAFFIC_ACTIONS], k=1)[0]
        sent = random.randint(200, 4_000_000)
        rcvd = random.randint(200, 40_000_000)
        app, appcat, apprisk = random.choice(self.apps)

        return self._head('traffic', 'forward', '0000000013', 'notice',
                          srcip=tuple_['srcip'], srcport=tuple_['srcport'],
                          srcintf=tuple_['srcintf'], srcintfrole=tuple_['srcintfrole'],
                          dstip=tuple_['dstip'], dstport=tuple_['dstport'],
                          dstintf=tuple_['dstintf'], dstintfrole=tuple_['dstintfrole'],
                          srccountry='France', dstcountry='United States',
                          sessionid=self._session(),
                          proto=tuple_['proto'], action=action,
                          policyid=random.randint(1, 60),
                          policytype='policy',
                          poluuid=self._uuid(),
                          service=tuple_['service'],
                          trandisp='snat', transip=self._ip(self.external_ips),
                          transport=random.randint(1024, 65535),
                          duration=random.randint(1, 3600),
                          sentbyte=sent, rcvdbyte=rcvd,
                          sentpkt=max(1, sent // 1400), rcvdpkt=max(1, rcvd // 1400),
                          appcat=appcat, app=app, apprisk=apprisk)

    @staticmethod
    def _uuid():
        """The policy UUID FortiOS puts in `poluuid`, which the add-on maps to `rule`."""
        hexes = '%032x' % random.getrandbits(128)
        return f'{hexes[:8]}-{hexes[8:12]}-{hexes[12:16]}-{hexes[16:20]}-{hexes[20:]}'

    # ------------------------------------------------------------------
    # type=utm
    # ------------------------------------------------------------------

    def _utm_webfilter(self):
        """[ftnt_fortigate_webfilter] -> tag=web -> Web. `hostname` and `url` are
        what the add-on rebuilds `url`, `url_domain`, `file_name` and `site` from."""
        tuple_ = self._session_pair()
        host, path, catdesc, cat = random.choice(self.web_sites)
        blocked = catdesc in ('Gambling', 'Malicious Websites')
        action = 'blocked' if blocked else 'passthrough'

        return self._head('utm', 'webfilter',
                          '0316013056' if blocked else '0317013312',
                          'warning' if blocked else 'notice',
                          eventtype='ftgd_blk' if blocked else 'ftgd_allow',
                          sessionid=self._session(), user=self._user(),
                          srcip=tuple_['srcip'], srcport=tuple_['srcport'],
                          srcintf=tuple_['srcintf'], srcintfrole=tuple_['srcintfrole'],
                          dstip=tuple_['dstip'], dstport=443,
                          dstintf=tuple_['dstintf'], dstintfrole=tuple_['dstintfrole'],
                          proto=6, service='HTTPS',
                          hostname=host, profile='default', action=action,
                          reqtype='direct', url=path,
                          sentbyte=random.randint(200, 8000),
                          rcvdbyte=random.randint(200, 200_000),
                          direction='outgoing',
                          msg=('URL belongs to a denied category in policy'
                               if blocked else 'URL belongs to an allowed category in policy'),
                          method='domain', cat=cat, catdesc=catdesc)

    def _utm_ips(self):
        """[ftnt_fortigate_ips] -> tags ids+attack -> Intrusion_Detection.
        `attack` and `attackid` become `signature` and `signature_id`.

        Inbound, unlike the other UTM subtypes: these signatures fire on traffic
        arriving at a published service, so the attacker is outside and the
        target is one of ours. Reversing the ends would put every detection's
        `src` inside the estate.
        """
        name, attack_id, severity = random.choice(self.attacks)
        action = random.choice(['dropped', 'detected'])
        src_intf, src_role = random.choice(self.outside_interfaces)
        dst_intf, dst_role = random.choice(self.inside_interfaces)

        return self._head('utm', 'ips', '0419016384', 'alert',
                          eventtype='signature', severity=severity,
                          srcip=self._external_ip(), srccountry='United States',
                          dstip=self._dest_ip(internal=True),
                          srcintf=src_intf, srcintfrole=src_role,
                          dstintf=dst_intf, dstintfrole=dst_role,
                          sessionid=self._session(),
                          action=action, proto=6, service='HTTP',
                          policyid=random.randint(1, 60), attack=name,
                          srcport=random.randint(1024, 65535), dstport=80,
                          hostname='', direction='incoming',
                          attackid=attack_id, profile='default',
                          ref=f'http://www.fortinet.com/ids/VID{attack_id}',
                          incidentserialno=random.randint(100_000_000, 999_999_999),
                          msg=f'applications: {name},')

    def _utm_virus(self):
        """[ftnt_fortigate_virus] excludes `action=analytics`, so this emits the
        block verdict rather than the sandbox submission both samples carry."""
        tuple_ = self._session_pair()
        virus, filename = random.choice(self.viruses)

        return self._head('utm', 'virus', '0211008192', 'warning',
                          eventtype='infected',
                          msg='File is infected.', action='blocked',
                          service='HTTP', sessionid=self._session(),
                          srcip=tuple_['srcip'], dstip=tuple_['dstip'],
                          srcport=tuple_['srcport'], dstport=80,
                          srcintf=tuple_['srcintf'], srcintfrole=tuple_['srcintfrole'],
                          dstintf=tuple_['dstintf'], dstintfrole=tuple_['dstintfrole'],
                          policyid=random.randint(1, 60), proto=6,
                          direction='incoming', filename=filename,
                          quarskip='File-was-not-quarantined',
                          virus=virus, dtype='Virus',
                          ref=f'http://www.fortinet.com/ve?vn={virus}',
                          virusid=random.randint(1_000_000, 9_999_999),
                          url=f'http://{random.choice(self.web_sites)[0]}/{filename}',
                          profile='default', user=self._user(),
                          agent='Mozilla/5.0', analyticscksum='%064x' % random.getrandbits(256),
                          analyticssubmit='false')

    def _utm_appctrl(self):
        """[ftnt_fortigate_appctrl] carries the same tags as traffic, so it lands
        in Network_Traffic — hence `sentbyte`/`rcvdbyte` rather than a bare verdict."""
        tuple_ = self._session_pair()
        app, appcat, apprisk = random.choice(self.apps)
        action = 'blocked' if appcat == 'P2P' else 'pass'

        return self._head('utm', 'app-ctrl', '1059028704', 'information',
                          eventtype='app-ctrl-all',
                          srcip=tuple_['srcip'], dstip=tuple_['dstip'],
                          srcport=tuple_['srcport'], dstport=tuple_['dstport'],
                          srcintf=tuple_['srcintf'], srcintfrole=tuple_['srcintfrole'],
                          dstintf=tuple_['dstintf'], dstintfrole=tuple_['dstintfrole'],
                          proto=tuple_['proto'], service=tuple_['service'],
                          policyid=random.randint(1, 60),
                          sessionid=self._session(), applist='default',
                          appcat=appcat, app=app, action=action,
                          hostname='', incidentserialno=random.randint(1, 999_999_999),
                          url='/', msg=f'{appcat}: {app},',
                          apprisk=apprisk, user=self._user(),
                          sentbyte=random.randint(200, 100_000),
                          rcvdbyte=random.randint(200, 900_000))

    # ------------------------------------------------------------------
    # type=event
    # ------------------------------------------------------------------

    def _event_auth(self):
        """[ftnt_fortigate_auth] needs `action=authentication` AND a status of
        exactly success or failure — the add-on's own sample says `status=logout`
        and therefore matches no eventtype at all."""
        user = self._user()
        ok = random.random() < 0.85
        status = 'success' if ok else 'failure'
        src = self._src_ip()

        return self._head('event', 'user', '0102043040', 'notice',
                          logdesc='FortiGuard authentication status',
                          srcip=src, dstip='N/A', policyid=0,
                          user=user, group='Guest-group',
                          authproto=f'HTTP({src})',
                          action='authentication', status=status,
                          reason='N/A' if ok else 'Invalid password',
                          msg=(f'User {user} succeeded in authentication' if ok
                               else f'User {user} failed in authentication'))

    def _event_admin(self):
        """Administrator login and logout. `logdesc` must match
        `^Admin log(?:in|out)` or props.conf:207 will not set `user_type=Admin`,
        and the failed form is `status=failed`, not `failure` — the event action
        lookup spells the two differently."""
        admin = self._admin()
        src = self._src_ip()
        method = random.choice(['ssh', 'https', 'jsconsole'])
        roll = random.random()

        if roll < 0.20:
            return self._head('event', 'system', '0100032002', 'alert',
                              logdesc='Admin login failed',
                              sn=random.randint(1_000_000_000, 1_999_999_999),
                              user=admin, ui=f'{method}({src})',
                              method=method, srcip=src,
                              dstip=self._ip(self.internal_ips),
                              action='login', status='failed',
                              reason='name_invalid',
                              msg=f'Administrator {admin} login failed from {method}({src})')
        if roll < 0.65:
            return self._head('event', 'system', '0100032001', 'information',
                              logdesc='Admin login successful',
                              sn=random.randint(1_000_000_000, 1_999_999_999),
                              user=admin, ui=f'{method}({src})',
                              method=method, srcip=src,
                              dstip=self._ip(self.internal_ips),
                              action='login', status='success',
                              reason='none', profile='super_admin',
                              msg=f'Administrator {admin} logged in successfully from {method}({src})')
        return self._head('event', 'system', '0100032003', 'information',
                          logdesc='Admin logout successful',
                          sn=random.randint(1_000_000_000, 1_999_999_999),
                          user=admin, ui=f'{method}({src})',
                          method=method, srcip=src,
                          dstip=self._ip(self.internal_ips),
                          action='logout', status='success',
                          duration=random.randint(30, 7200), reason='exit',
                          msg=f'Administrator {admin} logged out from {method}({src})')

    def _event_vpn(self):
        """Three eventtypes share subtype=vpn and are told apart by `action`:
        negotiate is the authentication, tunnel-up the session start,
        tunnel-down the session end."""
        user = self._user()
        tunnel = random.choice(self.vpn_tunnels)
        rem = self._ip(self.external_ips)
        loc = self._ip(self.internal_ips)
        roll = random.random()

        if roll < 0.35:
            ok = random.random() < 0.8
            return self._head('event', 'vpn', '0101037127', 'notice',
                              logdesc='Progress IPsec phase 1',
                              msg='progress IPsec phase 1',
                              action='negotiate', remip=rem, locip=loc,
                              remport=500, locport=500, outintf='wan1',
                              cookies='%016x/%016x' % (random.getrandbits(64),
                                                       random.getrandbits(64)),
                              user=user, group='N/A', xauthuser='N/A',
                              xauthgroup='N/A', assignip='N/A',
                              vpntunnel=tunnel,
                              status='success' if ok else 'failure',
                              init='remote', mode='main', dir='inbound',
                              stage=1, role='responder',
                              result='OK' if ok else 'ERROR')
        if roll < 0.70:
            return self._head('event', 'vpn', '0101039947', 'information',
                              logdesc='SSL VPN tunnel up',
                              action='tunnel-up', tunneltype='ssl-tunnel',
                              tunnelid=random.randint(100_000_000, 1_999_999_999),
                              remip=rem, tunnelip=loc, user=user,
                              group='SSLVPN-Users', dst_host='N/A',
                              reason='login', msg='SSL tunnel established')
        return self._head('event', 'vpn', '0101039948', 'information',
                          logdesc='SSL VPN tunnel down',
                          action='tunnel-down', tunneltype='ssl-tunnel',
                          tunnelid=random.randint(100_000_000, 1_999_999_999),
                          remip=rem, tunnelip=loc, user=user,
                          group='SSLVPN-Users', dst_host='N/A', reason='N/A',
                          duration=random.randint(60, 28800),
                          sentbyte=random.randint(10_000, 90_000_000),
                          rcvdbyte=random.randint(10_000, 90_000_000),
                          msg='SSL tunnel shutdown')

    def _event_config(self):
        """[ftnt_fortigate_config_change] matches on `action IN(Add, Edit, delete, …)`,
        and `cfgpath`/`cfgobj`/`cfgattr` are what become `object_path`, `object`
        and `object_attrs`."""
        path, action, obj = random.choice(self.config_paths)
        admin = self._admin()
        src = self._src_ip()

        return self._head('event', 'system', '0100044547', 'information',
                          logdesc='Object attribute configured',
                          user=admin, ui=f'GUI({src})',
                          action=action,
                          cfgtid=random.randint(1_000_000, 9_999_999),
                          cfgpath=path, cfgobj=obj,
                          cfgattr='status[enable->disable]',
                          msg=f'{action} {path} {obj}')

    def _event_perf(self):
        """[ftnt_fortigate_perf_stats] -> tags os+performance+cpu+memory.
        `cpu` becomes `cpu_load_percent` and `mem` becomes `mem_used`."""
        cpu = random.randint(1, 85)
        mem = random.randint(20, 80)
        sessions = random.randint(100, 90_000)
        setuprate = random.randint(0, 400)
        return self._head('event', 'system', '0100040704', 'notice',
                          logdesc='System performance statistics',
                          action='perf-stats', cpu=cpu, mem=mem,
                          totalsession=sessions,
                          disk=random.randint(5, 90),
                          bandwidth=f'{random.randint(100, 9000)}/{random.randint(100, 9000)}',
                          setuprate=setuprate,
                          disklograte=random.randint(0, 100),
                          fazlograte=random.randint(0, 100),
                          msg=(f'Performance statistics: average CPU: {cpu}, '
                               f'memory: {mem}, concurrent sessions: {sessions}, '
                               f'setup-rate: {setuprate}'))

    # ------------------------------------------------------------------
    # type=anomaly
    # ------------------------------------------------------------------

    def _anomaly(self):
        """DoS policy detections. Its own sourcetype through the index-time
        fan-out, and `subtype=anomaly` is what [ftnt_fortigate_anomaly] needs —
        the eventtype accepts it under fortigate_utm too."""
        attack, action, severity, proto, service, port = random.choice(self.anomalies)
        src_intf, src_role = random.choice(self.outside_interfaces)
        # A DoS policy sits on the outside interface, so the flood comes from
        # outside and lands on something of ours.

        return self._head('anomaly', 'anomaly', '0720018432', 'alert',
                          severity=severity,
                          srcip=self._external_ip(),
                          dstip=self._dest_ip(internal=True),
                          srcport=random.randint(1024, 65535), dstport=port,
                          srcintf=src_intf, srcintfrole=src_role,
                          sessionid=self._session(), action=action,
                          proto=proto, service=service,
                          count=random.randint(100, 50_000),
                          attack=attack,
                          policyid=random.randint(1, 10),
                          eventtype='anomaly',
                          crscore=random.choice([10, 30, 50]),
                          craction=random.choice([2, 4, 8]),
                          crlevel=severity,
                          attackid=random.randint(100_000_000, 200_000_000),
                          msg=f'anomaly: {attack}, {random.randint(10, 5000)} > threshold '
                              f'{random.randint(1000, 2000)}')
