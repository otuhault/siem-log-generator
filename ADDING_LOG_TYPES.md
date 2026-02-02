"""
TEMPLATE: Custom Log Generator
Copy this file and modify it to create your own log type

Example: Cisco ASA Firewall Logs, Palo Alto, AWS CloudTrail, etc.
"""

import random
from datetime import datetime

class CustomLogGenerator:
    """
    Template for creating a custom log generator.
    Replace this docstring with your log type description.
    """
    
    def __init__(self):
        """
        Initialize your generator with any data structures needed.
        Examples:
        - Lists of IP addresses, usernames, hostnames
        - Common values that appear in your logs
        - Weighted probability distributions
        """
        
        # Example data - customize for your log type
        self.source_ips = [
            '192.168.1.{}',
            '10.0.0.{}',
            '172.16.0.{}'
        ]
        
        self.actions = [
            'allow',
            'deny',
            'drop'
        ]
        
        # Add more realistic data structures here
    
    def generate(self):
        """
        Generate a single log line.
        
        IMPORTANT: This method must return a complete log line as a string.
        The string should NOT include a newline character at the end
        (it will be added automatically by the sender).
        
        Returns:
            str: A single log line matching your target format exactly
        """
        
        # Example implementation - replace with your actual log format
        timestamp = datetime.now().isoformat()
        src_ip = random.choice(self.source_ips).format(random.randint(1, 254))
        dst_ip = '8.8.8.8'
        action = random.choice(self.actions)
        
        # Build your log line in the exact format you need
        log_line = f"{timestamp} firewall[1234]: {src_ip} -> {dst_ip} action={action}"
        
        return log_line


# ============================================================================
# Real-world Example: Nginx Error Log Generator
# ============================================================================

class NginxErrorLogGenerator:
    """Generates realistic Nginx error logs"""
    
    def __init__(self):
        self.error_levels = [
            ('error', 60),    # Most common
            ('warn', 25),
            ('crit', 10),
            ('alert', 3),
            ('emerg', 2)
        ]
        
        self.error_messages = [
            'connect() failed (111: Connection refused) while connecting to upstream',
            'upstream timed out (110: Connection timed out) while reading response header',
            'no live upstreams while connecting to upstream',
            'SSL_do_handshake() failed (SSL: error:14094410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure)',
            'limiting requests, excess: 10.000 by zone "one"',
            'open() "/var/www/html/favicon.ico" failed (2: No such file or directory)',
            '404 Not Found: /wp-admin/admin-ajax.php',
        ]
        
        self.client_ips = [
            '192.168.1.{}', '10.0.0.{}', '203.0.113.{}', '198.51.100.{}'
        ]
        
        self.servers = ['example.com', 'www.example.com', 'api.example.com']
        
        self.requests = [
            'GET /api/users HTTP/1.1',
            'POST /api/login HTTP/1.1',
            'GET /index.html HTTP/1.1',
            'GET /static/app.js HTTP/1.1',
        ]
    
    def generate(self):
        """Generate a single Nginx error log line"""
        # Format: YYYY/MM/DD HH:MM:SS [level] pid#tid: *cid message, client: IP, server: DOMAIN, request: "REQUEST"
        
        timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
        
        # Select error level with weighted probability
        level_weights = [e[1] for e in self.error_levels]
        level = random.choices([e[0] for e in self.error_levels], weights=level_weights)[0]
        
        pid = random.randint(1000, 9999)
        tid = random.randint(0, 99)
        cid = random.randint(1, 99999)
        
        message = random.choice(self.error_messages)
        client_ip = random.choice(self.client_ips).format(random.randint(1, 254))
        server = random.choice(self.servers)
        request = random.choice(self.requests)
        
        log_line = (
            f'{timestamp} [{level}] {pid}#{tid}: *{cid} {message}, '
            f'client: {client_ip}, server: {server}, request: "{request}"'
        )
        
        return log_line


# ============================================================================
# How to Add Your Log Type to the Application
# ============================================================================

"""
1. Create your generator class (like the examples above)
2. Save it to a new file in log_generators/ (e.g., log_generators/cisco.py)
3. Update log_generators/__init__.py to import it:
   
   from .cisco import CiscoASALogGenerator
   __all__ = [..., 'CiscoASALogGenerator']

4. Register it in log_senders.py in the SenderManager.__init__() method:
   
   self.log_generators = {
       'apache_access': ApacheAccessLogGenerator,
       'windows_security': WindowsEventLogGenerator,
       'cisco_asa': CiscoASALogGenerator,  # Add your generator here
   }

5. Add description in get_available_log_types() method:
   
   'cisco_asa': {
       'name': 'Cisco ASA Firewall',
       'description': 'Cisco ASA firewall logs',
       'example': '...'
   }

6. Restart the application and your new log type will appear in the dropdown!

That's it! No frontend changes needed - the UI is fully dynamic.
"""
