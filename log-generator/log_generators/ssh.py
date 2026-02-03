"""
SSH Auth Log Generator
Generates realistic SSH authentication logs (auth.log format)
"""

import random
from datetime import datetime

class SSHAuthLogGenerator:
    """Generates SSH auth.log entries with various event types"""

    def __init__(self, event_categories=None):
        """
        Initialize SSH auth log generator
        event_categories: list of categories like ['auth_success', 'auth_failed', 'sessions', 'connections', 'errors']
                         If None, all categories are enabled
        """
        if event_categories is None:
            event_categories = ['auth_success', 'auth_failed', 'sessions', 'connections', 'errors']

        self.event_categories = event_categories

        # Realistic IP addresses (mix of attacker IPs and legitimate)
        self.ip_addresses = [
            '192.168.1.{}',
            '10.0.0.{}',
            '172.16.0.{}',
            '203.0.113.{}',
            '198.51.100.{}',
            '188.254.50.{}',
            '195.211.191.{}',
            '110.49.76.{}',
            '120.26.243.{}',
            '185.220.101.{}',
            '91.208.184.{}',
        ]

        # Hostnames
        self.hostnames = [
            'vmi829310',
            'ns327395',
            'ns3100664',
            'ubuntu-server',
            'debian-prod',
            'web-server-01',
            'db-primary',
            'app-node-{}'
        ]

        # Legitimate usernames
        self.valid_users = [
            'root',
            'admin',
            'ubuntu',
            'deploy',
            'www-data',
            'mysql',
            'postgres',
            'jenkins',
            'gitlab',
            'ansible'
        ]

        # Common invalid usernames (brute force attempts)
        self.invalid_users = [
            'kqy',
            'test',
            'oracle',
            'guest',
            'user',
            'administrator',
            'backup',
            'ftp',
            'support',
            'demo',
            'pi',
            'minecraft',
            'hadoop',
            'ftpuser',
            'test123',
            'admin123'
        ]

        # SSH services/applications
        self.services = [
            'sshd',
            'CRON',
            'systemd',
            'sudo'
        ]

        # Log event types organized by category with weighted probabilities
        # Format: category -> [(type, weight), ...]
        self.all_event_types = {
            'auth_success': [
                ('accepted_password', 40),
                ('accepted_publickey', 60),
            ],
            'auth_failed': [
                ('failed_password', 30),
                ('failed_password_invalid', 25),
                ('invalid_user', 25),
                ('max_auth_attempts', 10),
                ('not_allowed_user', 10),
            ],
            'sessions': [
                ('session_opened', 50),
                ('session_closed', 50),
            ],
            'connections': [
                ('connection_closed_invalid_user', 30),
                ('connection_closed_ip', 25),
                ('received_disconnect', 20),
                ('disconnected_auth_user', 15),
                ('connection_reset', 10),
            ],
            'errors': [
                ('did_not_receive_identification', 50),
                ('unable_negotiate', 20),
                ('bad_protocol', 15),
                ('server_listening', 15),
            ]
        }

        # Build event_types list based on enabled categories
        self.event_types = []
        for category in self.event_categories:
            if category in self.all_event_types:
                self.event_types.extend(self.all_event_types[category])

    def generate(self):
        """Generate a single SSH auth log line"""
        # Select event type with weighted probability
        types = [t for t, _ in self.event_types]
        weights = [w for _, w in self.event_types]
        event_type = random.choices(types, weights=weights)[0]

        # Generate log based on event type
        return self._generate_event(event_type)

    def _generate_event(self, event_type):
        """Generate specific event type"""
        timestamp = datetime.now().strftime('%b %d %H:%M:%S')
        hostname = self._get_random_hostname()
        pid = random.randint(100000, 999999)

        # Generate IP
        ip_template = random.choice(self.ip_addresses)
        ip = ip_template.format(random.randint(1, 254))
        port = random.randint(20000, 65000)

        if event_type == 'connection_closed_invalid_user':
            user = random.choice(self.invalid_users)
            return f'{timestamp} {hostname} sshd[{pid}]: Connection closed by invalid user {user} {ip} port {port} [preauth]'

        elif event_type == 'connection_closed_ip':
            return f'{timestamp} {hostname} sshd[{pid}]: Connection closed by {ip} port {port} [preauth]'

        elif event_type == 'received_disconnect':
            disconnect_code = random.choice([11, 14, 2])
            messages = ['Bye Bye', 'No supported authentication methods available', 'Too many authentication failures']
            message = random.choice(messages)
            return f'{timestamp} {hostname} sshd[{pid}]: Received disconnect from {ip} port {port}:{disconnect_code}: {message} [preauth]'

        elif event_type == 'failed_password':
            user = random.choice(self.valid_users)
            return f'{timestamp} {hostname} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2'

        elif event_type == 'failed_password_invalid':
            user = random.choice(self.invalid_users)
            return f'{timestamp} {hostname} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2'

        elif event_type == 'accepted_password':
            user = random.choice(self.valid_users)
            return f'{timestamp} {hostname} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2'

        elif event_type == 'accepted_publickey':
            user = random.choice(self.valid_users)
            key_types = ['RSA', 'ED25519', 'ECDSA']
            key_type = random.choice(key_types)
            fingerprint = ':'.join(['%02x' % random.randint(0, 255) for _ in range(16)])
            return f'{timestamp} {hostname} sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2: {key_type} SHA256:{fingerprint}'

        elif event_type == 'session_opened':
            user = random.choice(self.valid_users)
            uid = 0 if user == 'root' else random.randint(1000, 9999)
            service = random.choice(['sshd', 'cron'])
            return f'{timestamp} {hostname} {service.upper()}[{pid}]: pam_unix({service}:session): session opened for user {user}(uid={uid}) by (uid={uid})'

        elif event_type == 'session_closed':
            user = random.choice(self.valid_users)
            service = random.choice(['sshd', 'cron'])
            return f'{timestamp} {hostname} {service.upper()}[{pid}]: pam_unix({service}:session): session closed for user {user}'

        elif event_type == 'not_allowed_user':
            user = random.choice(self.valid_users)
            return f'{timestamp} {hostname} sshd[{pid}]: User {user} from {ip} not allowed because not listed in AllowUsers'

        elif event_type == 'did_not_receive_identification':
            return f'{timestamp} {hostname} sshd[{pid}]: Did not receive identification string from {ip} port {port}'

        elif event_type == 'invalid_user':
            user = random.choice(self.invalid_users)
            return f'{timestamp} {hostname} sshd[{pid}]: Invalid user {user} from {ip} port {port}'

        elif event_type == 'max_auth_attempts':
            user = random.choice(self.invalid_users)
            return f'{timestamp} {hostname} sshd[{pid}]: error: maximum authentication attempts exceeded for invalid user {user} from {ip} port {port} ssh2 [preauth]'

        elif event_type == 'disconnected_auth_user':
            user = random.choice(self.invalid_users)
            return f'{timestamp} {hostname} sshd[{pid}]: Disconnected from authenticating user {user} {ip} port {port} [preauth]'

        elif event_type == 'connection_reset':
            return f'{timestamp} {hostname} sshd[{pid}]: Connection reset by {ip} port {port} [preauth]'

        elif event_type == 'unable_negotiate':
            key_types = ['key exchange', 'cipher', 'MAC']
            key_type = random.choice(key_types)
            return f'{timestamp} {hostname} sshd[{pid}]: Unable to negotiate with {ip} port {port}: no matching {key_type} found. Their offer: diffie-hellman-group1-sha1 [preauth]'

        elif event_type == 'bad_protocol':
            bad_versions = ['1.5', '1.0', '2.9']
            version = random.choice(bad_versions)
            return f'{timestamp} {hostname} sshd[{pid}]: Bad protocol version identification \'{version}\' from {ip} port {port}'

        elif event_type == 'server_listening':
            return f'{timestamp} {hostname} sshd[{pid}]: Server listening on 0.0.0.0 port 22.'

        else:
            # Fallback generic event
            return f'{timestamp} {hostname} sshd[{pid}]: Unknown event from {ip}'

    def _get_random_hostname(self):
        """Generate a random hostname"""
        hostname_template = random.choice(self.hostnames)
        if '{}' in hostname_template:
            return hostname_template.format(random.randint(1, 99))
        return hostname_template
