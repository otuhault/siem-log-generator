"""
Palo Alto Networks Firewall Log Generator
Generates realistic PAN-OS syslog messages for Traffic, Threat, and System logs
"""

import random
from datetime import datetime, timedelta


class PaloAltoLogGenerator:
    """Generates Palo Alto Networks firewall logs in syslog CSV format"""

    LOG_TYPE = 'paloalto'
    AVG_LOG_SIZE = 400
    SOURCETYPE_CONFIG = {
        'param_key': 'log_types',
        'defaults': ['traffic', 'threat', 'system'],
        'multi_instance': False,
    }
    METADATA = {
        'name': 'Palo Alto Firewall',
        'description': 'Palo Alto Networks PAN-OS firewall logs in syslog CSV format',
        'example': 'Traffic, Threat, and System logs',
        'sources': [
            {'id': 'traffic', 'name': 'Traffic', 'description': 'Network traffic logs (sessions, bytes, packets, actions)'},
            {'id': 'threat',  'name': 'Threat',  'description': 'Security threat logs (vulnerabilities, malware, spyware, URLs)'},
            {'id': 'system',  'name': 'System',  'description': 'System events (authentication, configuration, HA, upgrades)'},
        ],
    }

    def __init__(self, log_types=None):
        """
        Initialize Palo Alto log generator
        log_types: list of types like ['traffic', 'threat', 'system']
                   If None, all types are enabled
        """
        if log_types is None:
            log_types = ['traffic', 'threat', 'system']

        self.log_types = log_types

        # Firewall hostnames
        self.hostnames = [
            'pa-fw-01',
            'pa-fw-02',
            'firewall-hq',
            'firewall-dc1',
            'pan-edge-01',
            'pan-core-01'
        ]

        # Serial numbers (14 digits)
        self.serial_numbers = [
            '012345678901234',
            '098765432109876',
            '112233445566778',
            '223344556677889',
            '334455667788990'
        ]

        # Internal IP ranges
        self.internal_ips = [
            '192.168.1.{}',
            '192.168.10.{}',
            '10.0.0.{}',
            '10.10.10.{}',
            '172.16.0.{}',
            '172.16.1.{}'
        ]

        # External IP ranges (realistic public IPs)
        self.external_ips = [
            '8.8.8.{}',
            '1.1.1.{}',
            '208.67.222.{}',
            '104.16.{}.{}',
            '151.101.{}.{}',
            '185.199.{}.{}',
            '140.82.{}.{}',
            '52.84.{}.{}',
            '13.107.{}.{}',
            '23.45.{}.{}'
        ]

        # Malicious IPs for threat logs
        self.malicious_ips = [
            '185.220.101.{}',
            '91.208.184.{}',
            '45.155.205.{}',
            '194.26.29.{}',
            '23.129.64.{}'
        ]

        # Security rules
        self.rules = [
            'allow-all',
            'allow-web',
            'allow-dns',
            'block-malicious',
            'allow-internal',
            'allow-outbound',
            'deny-default',
            'allow-vpn',
            'allow-mail'
        ]

        # Applications
        self.applications = [
            'web-browsing',
            'ssl',
            'dns',
            'google-base',
            'microsoft-365-base',
            'youtube-base',
            'facebook-base',
            'ssh',
            'ftp',
            'smtp',
            'imap',
            'ntp',
            'ldap',
            'ms-ds-smb',
            'netbios-ns',
            'ping',
            'incomplete'
        ]

        # Zones
        self.zones = {
            'internal': ['trust', 'internal', 'lan', 'corporate'],
            'external': ['untrust', 'external', 'internet', 'dmz']
        }

        # Interfaces
        self.interfaces = [
            'ethernet1/1',
            'ethernet1/2',
            'ethernet1/3',
            'ethernet1/4',
            'ae1',
            'ae2'
        ]

        # Protocols
        self.protocols = ['tcp', 'udp', 'icmp', 'gre']

        # Traffic actions
        self.traffic_actions = ['allow', 'deny', 'drop', 'reset-client', 'reset-server', 'reset-both']

        # Traffic subtypes
        self.traffic_subtypes = ['start', 'end', 'drop', 'deny']

        # Session end reasons
        self.session_end_reasons = [
            'aged-out',
            'tcp-fin',
            'tcp-rst-from-client',
            'tcp-rst-from-server',
            'resources-unavailable',
            'policy-deny',
            'decrypt-error'
        ]

        # Threat subtypes
        self.threat_subtypes = ['vulnerability', 'spyware', 'virus', 'wildfire', 'url', 'flood', 'scan']

        # Threat severities
        self.threat_severities = ['informational', 'low', 'medium', 'high', 'critical']

        # Threat categories
        self.threat_categories = [
            'malware',
            'phishing',
            'command-and-control',
            'grayware',
            'hacking',
            'data-theft',
            'code-execution',
            'brute-force'
        ]

        # Threat names/signatures
        self.threat_names = [
            'Microsoft Windows SMB Remote Code Execution',
            'Apache Log4j Remote Code Execution',
            'HTTP SQL Injection Attempt',
            'Cross-Site Scripting Attempt',
            'Malicious Executable Download',
            'Command and Control Traffic',
            'DNS Tunneling Detected',
            'Port Scan Detection',
            'Suspicious PowerShell Activity',
            'Cryptocurrency Mining Activity'
        ]

        # Malicious URLs/files
        self.malicious_urls = [
            'malware-site.com/payload.exe',
            'phishing-page.net/login.html',
            'evil-download.org/trojan.zip',
            'c2-server.ru/beacon',
            'suspicious-domain.io/script.js'
        ]

        # System event types
        self.system_event_types = ['general', 'auth', 'dhcp', 'globalprotect', 'ha', 'config', 'upgrade']

        # System event objects
        self.system_objects = ['admin-user', 'system', 'config', 'network', 'policy', 'user-id', 'certificate']

        # System event severities
        self.system_severities = ['informational', 'low', 'medium', 'high', 'critical']

        # System event messages
        self.system_messages = {
            'auth-success': "User '{}' logged in successfully from {}",
            'auth-fail': "Authentication failed for user '{}' from {}",
            'config-change': "Configuration changed by admin '{}'",
            'commit': "Configuration committed successfully by '{}'",
            'system-start': "System started successfully",
            'system-shutdown': "System shutdown initiated",
            'ha-failover': "HA failover: Device transitioned to active state",
            'certificate-expiry': "Certificate '{}' will expire in {} days",
            'upgrade-start': "Software upgrade started: {}",
            'upgrade-complete': "Software upgrade completed successfully",
            'globalprotect-connect': "GlobalProtect user '{}' connected from {}",
            'globalprotect-disconnect': "GlobalProtect user '{}' disconnected"
        }

        # User names
        self.usernames = ['admin', 'operator', 'readonly', 'netops', 'secops', 'backup-user']

        # Countries
        self.countries = [
            'United States',
            'United Kingdom',
            'Germany',
            'France',
            'Canada',
            'Australia',
            'Japan',
            'Netherlands',
            'Singapore',
            'Internal'
        ]

        # Log forwarding profiles
        self.log_profiles = ['ForwardToSplunk', 'default', 'siem-forward', 'log-to-panorama']

        # Virtual systems
        self.vsys = ['vsys1', 'vsys2', 'vsys3']

    def generate(self):
        """Generate a single Palo Alto log line"""
        log_type = random.choice(self.log_types)

        if log_type == 'traffic':
            return self._generate_traffic_log()
        elif log_type == 'threat':
            return self._generate_threat_log()
        elif log_type == 'system':
            return self._generate_system_log()
        else:
            return self._generate_traffic_log()

    def _get_syslog_header(self):
        """Generate syslog header"""
        now = datetime.now()
        hostname = random.choice(self.hostnames)
        # Syslog priority 14 = facility 1 (user) * 8 + severity 6 (informational)
        return f"<14>{now.strftime('%b %d %H:%M:%S')} {hostname}"

    def _get_timestamp(self):
        """Generate PAN-OS timestamp format"""
        now = datetime.now()
        return now.strftime('%Y/%m/%d %H:%M:%S')

    def _get_iso_timestamp(self):
        """Generate ISO 8601 timestamp with local timezone offset"""
        now = datetime.now().astimezone()
        offset = now.strftime('%z')  # e.g. +0100
        offset_fmt = offset[:3] + ':' + offset[3:]  # e.g. +01:00
        return now.strftime('%Y-%m-%dT%H:%M:%S.') + f'{random.randint(100, 999)}{offset_fmt}'

    def _get_random_ip(self, ip_list):
        """Generate random IP from template list"""
        template = random.choice(ip_list)
        count = template.count('{}')
        return template.format(*[random.randint(1, 254) for _ in range(count)])

    def _generate_traffic_log(self):
        """Generate a traffic log entry"""
        header = self._get_syslog_header()
        timestamp = self._get_timestamp()
        iso_timestamp = self._get_iso_timestamp()
        serial = random.choice(self.serial_numbers)

        # Determine traffic direction
        is_outbound = random.choice([True, False])
        if is_outbound:
            src_ip = self._get_random_ip(self.internal_ips)
            dst_ip = self._get_random_ip(self.external_ips)
            src_zone = random.choice(self.zones['internal'])
            dst_zone = random.choice(self.zones['external'])
        else:
            src_ip = self._get_random_ip(self.external_ips)
            dst_ip = self._get_random_ip(self.internal_ips)
            src_zone = random.choice(self.zones['external'])
            dst_zone = random.choice(self.zones['internal'])

        subtype = random.choice(self.traffic_subtypes)
        rule = random.choice(self.rules)
        app = random.choice(self.applications)
        vsys = random.choice(self.vsys)
        src_interface = random.choice(self.interfaces)
        dst_interface = random.choice(self.interfaces)
        log_profile = random.choice(self.log_profiles)

        session_id = random.randint(10000, 99999)
        repeat_count = random.randint(1, 5)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 22, 25, 3389, 445, 8080, 8443])
        protocol = random.choice(self.protocols)
        action = 'allow' if subtype in ['start', 'end'] else random.choice(['deny', 'drop'])

        bytes_sent = random.randint(100, 100000)
        bytes_received = random.randint(100, 100000)
        packets = random.randint(1, 1000)
        elapsed_time = random.randint(1, 300)

        src_country = random.choice(self.countries) if not is_outbound else 'Internal'
        dst_country = random.choice(self.countries) if is_outbound else 'Internal'
        session_end_reason = random.choice(self.session_end_reasons) if subtype == 'end' else ''

        # Build CSV fields (simplified but realistic traffic log)
        fields = [
            '1',                          # future_use
            timestamp,                    # receive_time
            serial,                       # serial_number
            'TRAFFIC',                    # type
            subtype,                      # subtype
            str(random.randint(2048, 2561)),  # config_version
            timestamp,                    # generated_time
            src_ip,                       # src_ip
            dst_ip,                       # dst_ip
            '0.0.0.0',                    # nat_src_ip
            '0.0.0.0',                    # nat_dst_ip
            rule,                         # rule_name
            '',                           # src_user
            '',                           # dst_user
            app,                          # application
            vsys,                         # vsys
            src_zone,                     # src_zone
            dst_zone,                     # dst_zone
            src_interface,                # inbound_interface
            dst_interface,                # outbound_interface
            log_profile,                  # log_action
            timestamp,                    # time_logged
            str(session_id),              # session_id
            str(repeat_count),            # repeat_count
            str(src_port),                # src_port
            str(dst_port),                # dst_port
            '0',                          # nat_src_port
            '0',                          # nat_dst_port
            '0x0',                        # flags
            protocol,                     # protocol
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
            src_country,                  # src_location
            dst_country,                  # dst_location
            '0',                          # padding
            str(packets // 2),            # packets_sent
            str(packets // 2),            # packets_received
            session_end_reason,           # session_end_reason
            str(random.randint(100, 999)),  # device_group_hierarchy_l1
            str(random.randint(100, 999)),  # device_group_hierarchy_l2
            str(random.randint(100, 999)),  # device_group_hierarchy_l3
            '0',                          # device_group_hierarchy_l4
            f'{vsys}-name',               # vsys_name
            random.choice(self.hostnames),  # device_name
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

        return f'{header} {",".join(fields)}'

    def _generate_threat_log(self):
        """Generate a threat log entry"""
        header = self._get_syslog_header()
        timestamp = self._get_timestamp()
        iso_timestamp = self._get_iso_timestamp()
        serial = random.choice(self.serial_numbers)

        # Threat traffic is usually inbound or suspicious outbound
        is_inbound = random.choice([True, True, False])  # 66% inbound
        if is_inbound:
            src_ip = self._get_random_ip(self.malicious_ips if random.random() > 0.5 else self.external_ips)
            dst_ip = self._get_random_ip(self.internal_ips)
            src_zone = random.choice(self.zones['external'])
            dst_zone = random.choice(self.zones['internal'])
        else:
            src_ip = self._get_random_ip(self.internal_ips)
            dst_ip = self._get_random_ip(self.malicious_ips)
            src_zone = random.choice(self.zones['internal'])
            dst_zone = random.choice(self.zones['external'])

        subtype = random.choice(self.threat_subtypes)
        rule = random.choice(self.rules)
        app = random.choice(['web-browsing', 'ssl', 'dns', 'smtp', 'ftp', 'unknown-tcp', 'unknown-udp'])
        vsys = random.choice(self.vsys)
        src_interface = random.choice(self.interfaces)
        dst_interface = random.choice(self.interfaces)
        log_profile = random.choice(self.log_profiles)

        session_id = random.randint(10000, 99999)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 22, 25, 445, 3389])
        protocol = random.choice(['tcp', 'udp'])
        action = random.choice(['alert', 'block', 'reset-client', 'reset-server', 'reset-both', 'drop'])

        severity = random.choice(self.threat_severities)
        direction = random.choice(['client-to-server', 'server-to-client'])
        category = random.choice(self.threat_categories)
        threat_name = random.choice(self.threat_names)
        threat_id = random.randint(30000, 50000)

        src_country = random.choice(self.countries)
        dst_country = random.choice(self.countries)

        # For URL threats, use a malicious URL
        misc_field = f'"{random.choice(self.malicious_urls)}"' if subtype in ['url', 'wildfire', 'virus'] else f'"{threat_name}"'

        # Build CSV fields for threat log
        fields = [
            '1',                          # future_use
            timestamp,                    # receive_time
            serial,                       # serial_number
            'THREAT',                     # type
            subtype,                      # subtype
            str(random.randint(2048, 2561)),  # config_version
            timestamp,                    # generated_time
            src_ip,                       # src_ip
            dst_ip,                       # dst_ip
            '0.0.0.0',                    # nat_src_ip
            '0.0.0.0',                    # nat_dst_ip
            rule,                         # rule_name
            '',                           # src_user
            '',                           # dst_user
            app,                          # application
            vsys,                         # vsys
            src_zone,                     # src_zone
            dst_zone,                     # dst_zone
            src_interface,                # inbound_interface
            dst_interface,                # outbound_interface
            log_profile,                  # log_action
            timestamp,                    # time_logged
            str(session_id),              # session_id
            '1',                          # repeat_count
            str(src_port),                # src_port
            str(dst_port),                # dst_port
            '0',                          # nat_src_port
            '0',                          # nat_dst_port
            '0x80000000',                 # flags
            protocol,                     # protocol
            action,                       # action
            misc_field,                   # misc (URL or filename)
            f'({threat_id})',             # threat_id
            category,                     # category
            severity,                     # severity
            direction,                    # direction
            str(random.randint(100000000, 999999999)),  # sequence_number
            '0x8000000000000000',         # action_flags
            src_country,                  # src_location
            dst_country,                  # dst_location
            '0',                          # padding
            'application/octet-stream',   # content_type
            '0',                          # pcap_id
            self._generate_hash(),        # file_digest
            'WildFireCloud',              # cloud
            '0',                          # url_index
            'Mozilla/5.0',                # user_agent
            random.choice(['exe', 'dll', 'pdf', 'doc', 'js', 'html', '']),  # file_type
            '',                           # xff
            '',                           # referer
            '',                           # sender
            '',                           # subject
            '',                           # recipient
            f'report-{random.randint(10000, 99999)}',  # report_id
            str(random.randint(100, 999)),  # device_group_hierarchy_l1
            str(random.randint(100, 999)),  # device_group_hierarchy_l2
            str(random.randint(100, 999)),  # device_group_hierarchy_l3
            '0',                          # device_group_hierarchy_l4
            f'{vsys}-name',               # vsys_name
            random.choice(self.hostnames),  # device_name
            '',                           # future_use
            '',                           # src_vm_uuid
            '',                           # dst_vm_uuid
            random.choice(['GET', 'POST', 'PUT', '']),  # http_method
            str(random.randint(1000000000, 9999999999)),  # tunnel_id
            '',                           # monitor_tag
            str(random.randint(100, 999)),  # parent_session_id
            timestamp,                    # parent_start_time
            '',                           # tunnel_type
            category,                     # threat_category
            f'content-ver-{random.randint(1000, 9999)}',  # content_version
            '0',                          # future_use
            '',                           # sctp_assoc_id
            '',                           # payload_protocol
            '',                           # http_headers
            '',                           # url_category_list
            f'rule-uuid-{random.randint(100, 999)}',  # rule_uuid
            '0',                          # http2_connection
            '',                           # dynamic_user_group
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
            '',                           # container_id
            '',                           # pod_namespace
            '',                           # pod_name
            '',                           # src_edl
            '',                           # dst_edl
            '',                           # hostid
            '',                           # serial_number
            '',                           # domain_edl
            '',                           # src_dag
            '',                           # dst_dag
            '',                           # partial_hash
            iso_timestamp,                # high_res_timestamp
            '',                           # reason
            '0',                          # justification
            '',                           # nssai_sst
            '',                           # subcategory_of_app
            '',                           # category_of_app
            '',                           # technology_of_app
            str(random.randint(1, 10)),   # risk_of_app
            '',                           # characteristic_of_app
            '',                           # container_of_app
            '',                           # tunneled_app
            str(random.randint(0, 1)),    # saas_of_app
            str(random.randint(0, 1)),    # sanctioned_state_of_app
            '',                           # cloud_report_id
            ''                            # cluster_name
        ]

        return f'{header} {",".join(fields)}'

    def _generate_system_log(self):
        """Generate a system log entry"""
        header = self._get_syslog_header()
        timestamp = self._get_timestamp()
        iso_timestamp = self._get_iso_timestamp()
        serial = random.choice(self.serial_numbers)

        event_type = random.choice(self.system_event_types)
        vsys = random.choice(self.vsys)
        severity = random.choice(self.system_severities)

        # Generate event-specific content
        username = random.choice(self.usernames)
        ip = self._get_random_ip(self.internal_ips)

        if event_type == 'auth':
            if random.random() > 0.3:
                event_id = 'auth-success'
                message = self.system_messages['auth-success'].format(username, ip)
            else:
                event_id = 'auth-fail'
                message = self.system_messages['auth-fail'].format(username, ip)
                severity = 'medium'
        elif event_type == 'config':
            event_id = random.choice(['config-change', 'commit'])
            message = self.system_messages[event_id].format(username)
        elif event_type == 'globalprotect':
            event_id = random.choice(['globalprotect-connect', 'globalprotect-disconnect'])
            message = self.system_messages[event_id].format(username, ip)
        elif event_type == 'ha':
            event_id = 'ha-failover'
            message = self.system_messages['ha-failover']
            severity = 'high'
        elif event_type == 'upgrade':
            event_id = random.choice(['upgrade-start', 'upgrade-complete'])
            message = self.system_messages.get(event_id, "System upgrade event").format('PAN-OS 10.2.3')
        else:
            event_id = random.choice(['system-start', 'system-shutdown'])
            message = self.system_messages.get(event_id, "System event")

        obj = random.choice(self.system_objects)

        # Build CSV fields for system log
        fields = [
            '1',                          # future_use
            timestamp,                    # receive_time
            serial,                       # serial_number
            'SYSTEM',                     # type
            event_type,                   # subtype
            '0',                          # future_use
            timestamp,                    # generated_time
            vsys,                         # vsys
            event_id,                     # event_id
            obj,                          # object
            '0',                          # future_use
            '0',                          # future_use
            event_type,                   # module
            severity,                     # severity
            f'"{message}"',               # description
            str(random.randint(100000000, 999999999)),  # sequence_number
            '0x8000000000000000',         # action_flags
            str(random.randint(100, 999)),  # device_group_hierarchy_l1
            str(random.randint(100, 999)),  # device_group_hierarchy_l2
            str(random.randint(100, 999)),  # device_group_hierarchy_l3
            '0',                          # device_group_hierarchy_l4
            f'{vsys}-name',               # vsys_name
            random.choice(self.hostnames),  # device_name
            '0',                          # future_use
            '0',                          # future_use
            iso_timestamp                 # high_res_timestamp
        ]

        return f'{header} {",".join(fields)}'

    def _generate_hash(self):
        """Generate a random SHA256-like hash"""
        return ''.join(random.choices('abcdef0123456789', k=64))
