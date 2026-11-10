"""
Apache Log Generator
Generates realistic Apache/Nginx logs in various formats
"""

import random
from datetime import datetime
from .ai_entity import AIEntityMixin

class ApacheLogGenerator(AIEntityMixin):
    """Generates Apache logs in different formats (access, error, combined)"""

    LOG_TYPE = 'apache'
    AVG_LOG_SIZE = 200  # bytes — used by SimulationManager
    SOURCETYPE_CONFIG = {
        'param_key': 'log_types',
        'defaults': ['combined'],
        'multi_instance': True,
        'single_param_name': 'log_type',
    }
    METADATA = {
        'name': 'Apache/Nginx Log',
        'description': 'Apache/Nginx web server logs in various formats',
        'example': 'Access, Error, and Combined log formats',
        'sources': [
            {'id': 'access',   'name': 'Access Log (key-value)', 'sourcetype': 'apache:access:kv',
             'description': 'The key-value LogFormat the add-on maps to CIM in full'},
            {'id': 'error',    'name': 'Error Log', 'sourcetype': 'apache:error',
             'description': 'Apache error logs with various severity levels'},
            {'id': 'combined', 'name': 'Access Log (Combined)', 'sourcetype': 'apache:access:combined',
             'description': 'Combined Log Format — extracted, but reaches no datamodel'},
        ],
    }

    def __init__(self, log_type='combined'):
        """
        Initialize Apache log generator
        log_type: 'access' (common format), 'error' (error logs), or 'combined' (combined format)
        """
        self.log_type = log_type

        # Realistic IP addresses (mix of real ranges)
        # Read by the syslog header, not by the log format: Apache does not
        # write its own hostname into access or error lines.
        self.hostnames = ['web-01', 'web-02', 'front-proxy']
        self.ip_addresses = [
            '192.168.1.{}',
            '10.0.0.{}',
            '172.16.0.{}',
            '203.0.113.{}',
            '198.51.100.{}',
        ]
        
        # Realistic user agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
        ]
        
        # Realistic request paths with weighted probabilities
        self.requests = [
            ('GET', '/', 200, 1500, 30),
            ('GET', '/index.html', 200, 2341, 25),
            ('GET', '/about.html', 200, 3456, 10),
            ('GET', '/contact.html', 200, 2890, 8),
            ('GET', '/products.html', 200, 4567, 12),
            ('GET', '/api/users', 200, 892, 5),
            ('GET', '/api/products', 200, 1234, 5),
            ('POST', '/api/login', 200, 456, 3),
            ('POST', '/api/register', 201, 523, 2),
            ('GET', '/static/css/style.css', 200, 15678, 15),
            ('GET', '/static/js/app.js', 200, 45231, 15),
            ('GET', '/static/images/logo.png', 200, 8934, 10),
            ('GET', '/favicon.ico', 200, 1234, 20),
            ('GET', '/robots.txt', 200, 234, 5),
            ('GET', '/sitemap.xml', 200, 3456, 3),
            ('GET', '/admin', 403, 0, 2),
            ('GET', '/wp-admin', 404, 0, 2),
            ('GET', '/.env', 404, 0, 1),
            ('GET', '/nonexistent-page', 404, 0, 3),
            ('POST', '/api/data', 500, 0, 1),
        ]
        
        # Referrers
        self.referrers = [
            '-',
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://www.example.com/',
            'https://github.com/',
            '-',
            '-',
        ]

        # Error log specific data
        self.error_levels = [
            ('error', 40),
            ('warn', 30),
            ('notice', 15),
            ('info', 10),
            ('crit', 3),
            ('alert', 1),
            ('emerg', 1),
        ]

        self.error_messages = [
            ('error', 'File does not exist: /var/www/html/{}'),
            ('error', 'client denied by server configuration: /var/www/html/{}'),
            ('error', '[client {}] script not found or unable to stat: /var/www/cgi-bin/{}'),
            ('error', '[client {}] PHP Fatal error:  Call to undefined function {} in /var/www/html/index.php'),
            ('error', '[client {}] ModSecurity: Access denied with code 403 (phase 2)'),
            ('warn', '[client {}] mod_fcgid: read timeout from pipe'),
            ('warn', 'RSA server certificate CommonName (CN) `localhost` does NOT match server name'),
            ('warn', '[client {}] AH01626: authorization result of Require all granted: granted'),
            ('notice', 'Apache/2.4.41 (Ubuntu) configured -- resuming normal operations'),
            ('notice', 'caught SIGTERM, shutting down'),
            ('notice', 'Digest: generating secret for digest authentication'),
            ('info', '[client {}] Connection to child 0 established'),
            ('info', 'Server built: Sep 29 2023 10:08:21'),
            ('crit', 'Apache is running a threaded MPM, but your PHP Module is not compiled to be threadsafe'),
            ('crit', '[client {}] (13)Permission denied: access to /admin denied'),
            ('alert', 'Child 2345 returned a Fatal error... Apache is exiting!'),
            ('emerg', 'No space left on device: Couldn\'t create accept lock'),
        ]

    def generate(self):
        """Generate a single Apache log line based on configured type"""
        # A request is a client talking to a server. The line names only the
        # client; the server is what `host` and the syslog header identify, so
        # both ends are drawn before the line is built.
        self._new_entity()

        if self.log_type == 'access':
            return self._generate_access()
        elif self.log_type == 'error':
            return self._generate_error()
        else:  # combined
            return self._generate_combined()

    def _generate_access(self):
        """The key-value LogFormat Splunk_TA_apache maps to CIM in full.

        Not the Common Log Format, which the add-on has no stanza for: its
        `[apache:access]` extraction expects a vhost and a port the common format
        does not carry, so those lines would parse to nothing. The add-on offers
        three access shapes — the extended one, key-value and JSON — and only
        those reach the Web datamodel. Key-value is the one an admin configures
        with a LogFormat directive, and the one `[apache_kv_events]` recognises
        by its leading `time=`.

        Field names are the add-on's, not ours: `client`/`server` are aliased to
        src/dest, `bytes_in`+`bytes_out` become bytes, and the status feeds the
        lookup that produces `action`.
        """
        client = random.choice(self.ip_addresses).format(random.randint(1, 254))
        server = self._entity_field('hostnames',
                                    lambda: random.choice(self.hostnames))

        weights = [r[4] for r in self.requests]
        method, path, status, size, _ = random.choices(self.requests, weights=weights)[0]
        uri_path, _, uri_query = path.partition('?')

        dest_port = random.choice([443, 443, 443, 80])
        referrer = random.choice(['-', 'https://www.google.com/',
                                  f'https://{server}/'])
        content_type = random.choice(['text/html', 'application/json',
                                      'image/png', 'text/css', '-'])

        # `^time=\d+` is what reroutes the event to apache:access:kv, so the
        # epoch has to lead the line.
        return (
            f'time={int(datetime.now().timestamp())} '
            f'client={client} server={server} dest_port={dest_port} '
            f'ident=- user=- '
            f'uri_path={uri_path} uri_query={uri_query or "-"} '
            f'status={status} '
            f'bytes_in={random.randint(120, 2000)} bytes_out={size} '
            f'response_time_microseconds={random.randint(500, 900000)} '
            f'http_referrer={referrer} '
            f'http_user_agent="{random.choice(self.user_agents)}" '
            f'http_content_type={content_type}'
        )

    def _generate_error(self):
        """Generate Apache Error Log Format"""
        # Format: [timestamp] [level] [pid:tid] [client IP:port] message

        # Apache 2.4 default ErrorLogFormat uses %{u}t -> microsecond precision
        # (6 digits) with a 4-digit year:
        #   [Thu May 12 08:28:57.652118 2011]
        # https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat
        timestamp = datetime.now().strftime('%a %b %d %H:%M:%S.%f %Y')

        # Select error level with weighted probability
        levels = [level for level, _ in self.error_levels]
        weights = [weight for _, weight in self.error_levels]
        level = random.choices(levels, weights=weights)[0]

        # Generate PID and TID
        pid = random.randint(1000, 9999)
        tid = random.randint(100000000, 999999999)

        # Generate random IP
        ip_template = random.choice(self.ip_addresses)
        ip = ip_template.format(random.randint(1, 254))
        port = random.randint(40000, 65000)

        # Select error message matching the level
        matching_messages = [msg for lvl, msg in self.error_messages if lvl == level]
        if not matching_messages:
            matching_messages = [msg for _, msg in self.error_messages]

        message_template = random.choice(matching_messages)

        # Fill in placeholders in message
        if '{}' in message_template:
            if 'client {}' in message_template or '[client {}]' in message_template:
                # First placeholder is client IP
                placeholders = [ip]
                # Additional placeholders for paths or function names
                if message_template.count('{}') > 1:
                    placeholders.append(random.choice(['test.php', 'script.cgi', 'admin.php', 'index.html', 'getData()']))
                message = message_template.format(*placeholders)
            else:
                # File paths or other placeholders
                message = message_template.format(random.choice(['admin.php', 'config.php', 'test.html', '.htaccess', 'getData()']))
        else:
            message = message_template

        # Build error log line
        log_line = f'[{timestamp}] [{level}] [pid {pid}:tid {tid}] [client {ip}:{port}] {message}'

        return log_line

    def _generate_combined(self):
        """Generate Combined Log Format (with referer and user-agent)"""
        # Format: IP - - [timestamp] "METHOD PATH PROTOCOL" STATUS SIZE "REFERER" "USER-AGENT"

        # Generate random IP
        ip_template = random.choice(self.ip_addresses)
        ip = ip_template.format(random.randint(1, 254))

        # Current timestamp in Apache format
        timestamp = datetime.now().astimezone().strftime('%d/%b/%Y:%H:%M:%S %z')

        # Select request with weighted probability
        weights = [r[4] for r in self.requests]
        method, path, status, size, _ = random.choices(self.requests, weights=weights)[0]
        protocol = 'HTTP/1.1'

        # Select random referer and user agent
        referer = random.choice(self.referrers)
        user_agent = random.choice(self.user_agents)

        # Build log line in exact Apache Combined Log Format
        log_line = f'{ip} - - [{timestamp}] "{method} {path} {protocol}" {status} {size} "{referer}" "{user_agent}"'

        return log_line
