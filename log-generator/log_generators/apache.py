"""
Apache Access Log Generator
Generates realistic Apache/Nginx access logs in Combined Log Format
"""

import random
from datetime import datetime

class ApacheAccessLogGenerator:
    """Generates Apache access logs matching real server output"""
    
    def __init__(self):
        # Realistic IP addresses (mix of real ranges)
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
    
    def generate(self):
        """Generate a single Apache access log line in Combined Log Format"""
        # Format: IP - - [timestamp] "METHOD PATH PROTOCOL" STATUS SIZE "REFERER" "USER-AGENT"
        
        # Generate random IP
        ip_template = random.choice(self.ip_addresses)
        ip = ip_template.format(random.randint(1, 254))
        
        # Current timestamp in Apache format
        timestamp = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')
        
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
