"""
Cisco Secure Firewall Threat Defense (FTD) Log Generator

Generates FTD syslog messages in EMBLEM format (2026 standard).
Supports 5 main event categories with structured key:value pair format.

Format: <PRI>:Timestamp:Device-ID: %FTD-Level-Message_number: Field1: Value1, Field2: Value2...
Sourcetype: cisco:ftd
"""

import random
from datetime import datetime, timezone
import uuid


class CiscoFTDLogGenerator:
    """Generate Cisco Secure Firewall Threat Defense logs"""

    LOG_TYPE = 'cisco_ftd'
    AVG_LOG_SIZE = 250
    SOURCETYPE_CONFIG = {
        'param_key': 'event_categories',
        'defaults': ['connection', 'intrusion', 'file', 'malware', 'traditional'],
        'multi_instance': False,
    }
    METADATA = {
        'name': 'Cisco Secure Firewall Threat Defense',
        'description': 'Cisco FTD (formerly Firepower) EMBLEM syslog format (cisco:ftd sourcetype)',
        'example': 'Connection events, intrusion detection, file/malware events, traditional messages',
        'sources': [
            {'id': 'connection', 'name': 'Connection Events',    'description': 'Network connection events with source/dest, ports, protocols, actions (430002)'},
            {'id': 'intrusion',  'name': 'Intrusion Events',     'description': 'IPS/IDS detections, blocked threats, signature matches (430001, 430003)'},
            {'id': 'file',       'name': 'File Events',          'description': 'Files detected in network traffic with hashes and dispositions (430004)'},
            {'id': 'malware',    'name': 'Malware Events',       'description': 'Malware detections with threat names and blocked actions (430005)'},
            {'id': 'traditional','name': 'Traditional Messages', 'description': 'ASA-style system messages (authentication, VPN, interface, system events)'},
        ],
    }

    def __init__(self, event_categories=None):
        """
        Initialize generator with configurable event categories.

        Args:
            event_categories: List of category names to generate. If None, generates all.
                             Options: connection, intrusion, file, malware, traditional
        """
        # Default to all categories
        self.event_categories = event_categories or [
            'connection', 'intrusion', 'file', 'malware', 'traditional'
        ]

        # Device identifiers
        self.devices = [
            'ftd-primary', 'ftd-secondary', 'ftd-datacenter-01',
            'r7Firepower', 'FTD-DMZ', 'FTD-EDGE-GW'
        ]

        self.device_uuids = [
            'e8566508-eaa9-11e5-860f-de3e305d8269',
            'a1234567-bbbb-cccc-dddd-123456789abc',
            'f9876543-aaaa-bbbb-cccc-fedcba987654'
        ]

        # Network data
        self.internal_ips = [
            '10.1.9.9', '10.2.5.10', '10.100.20.50', '192.168.1.100',
            '172.16.10.25', '10.50.30.15', '192.168.100.200'
        ]
        self.external_ips = [
            '93.157.158.93', '185.220.101.50', '203.0.113.100',
            '198.51.100.25', '45.33.32.156', '89.248.165.47'
        ]

        self.interfaces = ['inside', 'outside', 'dmz', 'serversDMZ', 'guest', 'management']
        self.protocols = ['tcp', 'udp', 'icmp']
        self.users = ['admin', 'john.doe', 'security_analyst', 'web_service', 'db_admin']

        # Application data
        self.applications = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'SMTP', 'MS SQL', 'RDP']
        self.web_apps = ['Facebook', 'Gmail', 'Salesforce', 'Dropbox', 'Office365']
        self.url_categories = ['Social Networking', 'Web-based Email', 'Cloud Storage', 'Business']

        # File/Malware data
        self.file_types = ['PDF', 'MSEXE', 'MSOLE2', 'ZIP', 'JAVA', 'HTML', 'MSPDF']
        self.file_names = [
            'invoice_2026.pdf', 'document.docx', 'setup.exe', 'backup.zip',
            'malware_sample.exe', 'report_Q1.xlsx', 'attachment.pdf'
        ]
        self.sha256_hashes = [
            'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855',
            '2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE',
            'FCE0E9F75D5A86CB84D0A8BE8C7D9DAAD98A1E0E1B34C5F890A8B6C7D8E9F0A1'
        ]

        # Threat/Signature data
        self.signatures = [
            'SQL Injection Attempt',
            'Cross-Site Scripting (XSS) Attack',
            'Remote Code Execution Attempt',
            'Malware Download Detected',
            'Port Scan Activity',
            'Brute Force Login Attempt',
            'Command Injection Detected',
            'Buffer Overflow Attempt'
        ]

        # Connection counter
        self.connection_id = random.randint(10000, 99999)

    def generate(self):
        """Generate a random FTD log event"""
        # Select category based on enabled categories and weights
        category_weights = {
            'connection': 40,
            'intrusion': 25,
            'file': 15,
            'malware': 10,
            'traditional': 10
        }

        # Filter to enabled categories
        enabled = {k: v for k, v in category_weights.items() if k in self.event_categories}
        if not enabled:
            enabled = category_weights

        categories = list(enabled.keys())
        weights = list(enabled.values())

        category = random.choices(categories, weights=weights, k=1)[0]

        if category == 'connection':
            return self._generate_connection_event()
        elif category == 'intrusion':
            return self._generate_intrusion_event()
        elif category == 'file':
            return self._generate_file_event()
        elif category == 'malware':
            return self._generate_malware_event()
        else:  # traditional
            return self._generate_traditional_event()

    def _timestamp(self):
        """Generate ISO 8601 timestamp for EMBLEM format"""
        return datetime.now().astimezone().strftime('%Y-%m-%dT%H:%M:%S%z')

    def _get_connection_id(self):
        """Get incrementing connection ID"""
        self.connection_id += 1
        return self.connection_id

    def _generate_connection_event(self):
        """Generate Connection Event (Message ID: 430002)"""
        pri = random.choice([113, 114, 115])  # Local1 facility
        timestamp = self._timestamp()
        device = random.choice(self.devices)
        severity = random.choice([1, 2, 3, 4, 5, 6])

        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(self.external_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 25, 53, 3389, 1433])
        protocol = random.choice(self.protocols)

        action = random.choice(['Allow', 'Block', 'Block with reset', 'Monitor'])
        priority = random.choice(['Low', 'Medium', 'High'])

        fields = [
            f"EventPriority: {priority}",
            f"DeviceUUID: {random.choice(self.device_uuids)}",
            f"ConnectionID: {self._get_connection_id()}",
            f"AccessControlRuleAction: {action}",
            f"SrcIP: {src_ip}",
            f"DstIP: {dst_ip}",
            f"SrcPort: {src_port}",
            f"DstPort: {dst_port}",
            f"Protocol: {protocol}",
            f"IngressInterface: {random.choice(self.interfaces)}",
            f"EgressInterface: {random.choice(self.interfaces)}"
        ]

        # Optional fields
        if random.random() > 0.5:
            fields.append(f"User: {random.choice(self.users)}")
        if random.random() > 0.5:
            fields.append(f"ApplicationProtocol: {random.choice(self.applications)}")
        if random.random() > 0.6:
            fields.append(f"WebApplication: {random.choice(self.web_apps)}")
            fields.append(f"URLCategory: {random.choice(self.url_categories)}")

        message = ', '.join(fields)

        return f"<{pri}>:{timestamp}:{device}: %NGIPS-{severity}-430002: {message}"

    def _generate_intrusion_event(self):
        """Generate Intrusion Event (Message ID: 430001 or 430003)"""
        pri = random.choice([113, 114, 115])
        timestamp = self._timestamp()
        device = random.choice(self.devices)
        severity = random.choice([1, 2, 3, 4])  # Higher severity for intrusions
        msg_id = random.choice(['430001', '430003'])

        src_ip = random.choice(self.external_ips)
        dst_ip = random.choice(self.internal_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 21, 3389])
        protocol = random.choice(['tcp', 'udp'])

        action = random.choice(['Block', 'Block with reset', 'Alert', 'Drop'])
        priority = random.choice(['High', 'Medium'])

        fields = [
            f"EventPriority: {priority}",
            f"DeviceUUID: {random.choice(self.device_uuids)}",
            f"InstanceID: {random.randint(1, 10)}",
            f"FirstPacketSecond: {self._timestamp()}",
            f"ConnectionID: {self._get_connection_id()}",
            f"AccessControlRuleAction: {action}",
            f"SrcIP: {src_ip}",
            f"DstIP: {dst_ip}",
            f"SrcPort: {src_port}",
            f"DstPort: {dst_port}",
            f"Protocol: {protocol}",
            f"IngressInterface: {random.choice(self.interfaces)}",
            f"EgressInterface: {random.choice(self.interfaces)}",
            f"SignatureName: {random.choice(self.signatures)}"
        ]

        message = ', '.join(fields)

        return f"<{pri}>:{timestamp}:{device}: %NGIPS-{severity}-{msg_id}: {message}"

    def _generate_file_event(self):
        """Generate File Event (Message ID: 430004)"""
        pri = random.choice([113, 114])
        timestamp = self._timestamp()
        device = random.choice(self.devices)
        severity = random.choice([4, 5, 6])

        src_ip = random.choice(self.external_ips)
        dst_ip = random.choice(self.internal_ips)
        protocol = 'tcp'

        disposition = random.choice(['Clean', 'Malware', 'Unknown', 'Unavailable'])
        action = 'Block' if disposition == 'Malware' else random.choice(['Allow', 'Monitor'])

        fields = [
            f"EventPriority: {random.choice(['Low', 'Medium', 'High'])}",
            f"DeviceUUID: {random.choice(self.device_uuids)}",
            f"ConnectionID: {self._get_connection_id()}",
            f"AccessControlRuleAction: {action}",
            f"SrcIP: {src_ip}",
            f"DstIP: {dst_ip}",
            f"Protocol: {protocol}",
            f"IngressInterface: {random.choice(self.interfaces)}",
            f"EgressInterface: {random.choice(self.interfaces)}",
            f"FileName: {random.choice(self.file_names)}",
            f"FileType: {random.choice(self.file_types)}",
            f"FileSize: {random.randint(1024, 10485760)}",
            f"FileSHA256: {random.choice(self.sha256_hashes)}",
            f"FileDisposition: {disposition}"
        ]

        if random.random() > 0.5:
            fields.append(f"ApplicationProtocol: {random.choice(['HTTP', 'HTTPS', 'FTP', 'SMTP'])}")

        message = ', '.join(fields)

        return f"<{pri}>:{timestamp}:{device}: %NGIPS-{severity}-430004: {message}"

    def _generate_malware_event(self):
        """Generate Malware Event (Message ID: 430005)"""
        pri = random.choice([113, 114])
        timestamp = self._timestamp()
        device = random.choice(self.devices)
        severity = random.choice([1, 2, 3])  # Higher severity

        src_ip = random.choice(self.external_ips)
        dst_ip = random.choice(self.internal_ips)

        threat_names = [
            'Win.Trojan.Generic',
            'W32.Backdoor.Agent',
            'JS.Downloader.Malicious',
            'PDF.Exploit.CVE-2023-1234',
            'Android.Malware.Spyware'
        ]

        fields = [
            f"EventPriority: High",
            f"DeviceUUID: {random.choice(self.device_uuids)}",
            f"ConnectionID: {self._get_connection_id()}",
            f"AccessControlRuleAction: Block",
            f"SrcIP: {src_ip}",
            f"DstIP: {dst_ip}",
            f"Protocol: tcp",
            f"IngressInterface: {random.choice(self.interfaces)}",
            f"EgressInterface: {random.choice(self.interfaces)}",
            f"FileName: {random.choice(self.file_names)}",
            f"FileType: {random.choice(self.file_types)}",
            f"FileSHA256: {random.choice(self.sha256_hashes)}",
            f"ThreatName: {random.choice(threat_names)}",
            f"Disposition: Malware",
            f"Action: Block"
        ]

        message = ', '.join(fields)

        return f"<{pri}>:{timestamp}:{device}: %NGIPS-{severity}-430005: {message}"

    def _generate_traditional_event(self):
        """Generate traditional ASA-style messages that FTD also produces"""
        pri = random.choice([133, 134, 135, 136, 137, 138])  # Local0 facility
        timestamp = self._timestamp()
        device = random.choice(self.devices)

        # Common FTD/ASA message types
        messages = [
            # Authentication
            (5, '111008', lambda: f"User 'enable_15' executed the 'show running-config' command."),
            (5, '111010', lambda: f"User '{random.choice(self.users)}', running 'CLI' from IP {random.choice(self.internal_ips)}, executed 'show version'"),
            (6, '113004', lambda: f"AAA user authentication Successful : server = {random.choice(self.internal_ips)} : user = {random.choice(self.users)}"),
            (4, '113005', lambda: f"AAA user authentication Rejected : reason = Invalid password : server = {random.choice(self.internal_ips)} : user = {random.choice(self.users)}"),

            # VPN
            (5, '113019', lambda: f"Group = {random.choice(['VPN-Users', 'Remote-Access', 'SSL-VPN'])}, Username = {random.choice(self.users)}, IP = {random.choice(self.external_ips)}, Session disconnected. Session Type: IPsec, Duration: {random.randint(60, 7200)}s, Bytes xmt: {random.randint(1000, 1000000)}, Bytes rcv: {random.randint(1000, 1000000)}"),

            # Interface
            (3, '211003', lambda: f"LU allocate request failed for {random.choice(self.interfaces)}."),
            (5, '211008', lambda: f"The maximum number of connections for the {random.choice(self.protocols)} protocol has been reached."),

            # System
            (6, '605005', lambda: f"Login permitted from {random.choice(self.internal_ips)}/{random.randint(1024, 65535)} to {random.choice(self.interfaces)}:{random.choice(self.internal_ips)}/ssh for user \"{random.choice(self.users)}\""),
        ]

        severity, msg_id, msg_func = random.choice(messages)
        message = msg_func()

        return f"<{pri}>:{timestamp}:{device}: %FTD-{severity}-{msg_id}: {message}"


# Alias for consistency with other generators
CiscoFTDMultiCategoryGenerator = CiscoFTDLogGenerator
