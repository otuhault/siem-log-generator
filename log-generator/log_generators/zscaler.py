"""
Zscaler NSS Log Generator
Generates realistic Zscaler NSS logs in tab-separated key=value format.
Supports: web proxy (zscalernss-web) and tunnel (zscalernss-tunnel)
Compatible with SC4S sourcetypes: zscalernss-web, zscalernss-tunnel
"""

import random
from datetime import datetime


class ZscalerLogGenerator:
    """Generates Zscaler NSS logs for web proxy and tunnel sourcetypes"""

    LOG_TYPE = 'zscaler'
    AVG_LOG_SIZE = 550
    SOURCETYPE_CONFIG = {
        'param_key': 'log_types',
        'defaults': ['web', 'tunnel'],
        'multi_instance': True,
        'single_param_name': 'log_type',
    }
    METADATA = {
        'name': 'Zscaler',
        'description': 'Zscaler logs — web proxy (zscalernss-web) and tunnel (zscalernss-tunnel)',
        'example': 'Web proxy transactions and IPSec/GRE tunnel sessions',
        'sources': [
            {'id': 'web',    'name': 'Web Proxy',  'description': 'NSS web proxy transactions (URL categories, threats, DLP, users)'},
            {'id': 'tunnel', 'name': 'Tunnel',      'description': 'IPSec/GRE tunnel session records (zscalernss-tunnel)'},
        ],
    }

    ASSET_IDENTITY_MAPPING = {
        '_USERS':        {'type': 'identity', 'field': 'email',                               'cim_field': 'user'},
        '_INTERNAL_IPS': {'type': 'asset',    'field': 'ip',      'categories': ['zscaler'], 'cim_field': 'src_ip'},
        '_device_names': {'type': 'asset',    'field': 'nt_host', 'categories': ['zscaler'], 'cim_field': 'src_nt_host'},
    }

    # --- shared data ---
    _INTERNAL_IPS  = ['192.168.0.{}', '192.168.1.{}', '10.0.0.{}', '10.10.1.{}', '172.16.0.{}']
    _EXTERNAL_IPS  = ['52.84.{}.{}', '104.16.{}.{}', '151.101.{}.{}', '185.199.{}.{}', '140.82.{}.{}']
    _PUBLIC_IPS    = ['203.0.113.{}', '198.51.100.{}', '192.0.2.{}']
    _SOURCE_IPS    = ['33.22.44.{}', '203.0.113.{}', '198.51.100.{}', '12.34.56.{}', '78.90.12.{}']
    _USERS         = [
        'john.doe@example.com', 'jane.smith@example.com', 'alice.johnson@example.com',
        'bob.williams@example.com', 'carol.brown@example.com', 'david.jones@example.com',
        'eve.garcia@example.com', 'frank.miller@example.com',
        'vpn-gw-us-east@corp.com', 'vpn-gw-eu-west@corp.com',
        'branch-sydney@company.com', 'some-one-else@nowhere.com',
    ]
    _LOCATIONS     = [
        'UK_Wynyard_VPN->other', 'US_NewYork_VPN->other', 'DE_Berlin_Office',
        'FR_Paris_Office', 'SG_Singapore_VPN->other', 'AU_Sydney_Office',
        'HQ_London->other', 'Remote_VPN->other', 'US_East', 'EU_West',
        'APAC_Singapore', 'Branch_NY', 'Branch_Paris', 'ABC',
    ]
    _HOSTNAMES_GW  = [
        'hostname', 'zscaler-gw-01', 'zscaler-gw-02',
        'zscaler-edge-us', 'zscaler-edge-eu', 'zscaler-edge-apac',
    ]

    def __init__(self, log_type='web'):
        self.log_type = log_type  # 'web' or 'tunnel'

        # --- web-specific data ---
        if log_type == 'web':
            self._departments   = [
                'Engineering', 'Sales and Marketing', 'Procurement, Generics', 'Finance',
                'Human Resources', 'Legal', 'Operations', 'IT Security', 'Executive',
            ]
            self._protocols     = ['HTTPS', 'HTTP', 'FTP', 'TUNNEL']
            self._actions       = ['Allowed', 'Blocked', 'Caution']
            self._methods       = ['GET', 'POST', 'CONNECT', 'PUT', 'DELETE', 'HEAD']
            self._statuses      = [200, 301, 302, 400, 403, 404, 407, 500, 502]
            self._url_categories = [
                'UK_ALLOW_Pharmacies', 'General Browsing', 'Business and Economy',
                'Computer and Internet Info', 'Online Shopping', 'Search Engines',
                'Social Networking', 'Streaming Media', 'Technology', 'News and Media',
                'BLOCK_Gambling', 'BLOCK_Adult_Content', 'Cloud Storage', 'SaaS and B2B',
            ]
            self._url_supers    = [
                'User-defined', 'Bandwidth Loss', 'Business Productivity',
                'Information Technology', 'Adult Material', 'Miscellaneous',
            ]
            self._url_classes   = [
                'Bandwidth Loss', 'Business Productivity', 'Adult Material',
                'Information Technology', 'Miscellaneous or Unknown',
            ]
            self._app_names     = [
                'Random', 'Google', 'Microsoft Office 365', 'Salesforce', 'Slack',
                'Zoom', 'Dropbox', 'GitHub', 'AWS Console', 'Azure Portal',
                'General Browsing', 'YouTube', 'LinkedIn',
            ]
            self._app_classes   = [
                'Sales and Marketing', 'Business Productivity', 'Cloud Storage',
                'Collaboration', 'General Browsing', 'Social Networking',
            ]
            self._threat_cats   = ['None', 'Malware', 'Phishing', 'Adware', 'Spyware', 'Ransomware']
            self._threat_names  = ['None', 'W32.Eicar_Test_File', 'Phishing.Generic', 'Adware.Generic']
            self._threat_classes = ['None', 'Malicious Content', 'Suspicious Content']
            self._file_types    = ['None', 'PDF', 'ZIP', 'EXE', 'DOCX', 'XLSX', 'JAR', 'PS1']
            self._file_classes  = ['None', 'Executable', 'Document', 'Archive', 'Script']
            self._dlp_engines   = ['None', 'DLP_PCI', 'DLP_HIPAA', 'DLP_PII', 'DLP_GDPR']
            self._dlp_dicts     = ['None', 'Credit_Cards', 'SSN', 'IBAN', 'Health_Records']
            self._user_agents   = [
                'Windows Windows 10 Enterprise ZTunnel/1.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
                'Microsoft-CryptoAPI/10.0',
                'Go-http-client/1.1',
            ]
            self._web_hostnames = [
                'example.random.com', 'api.example.com', 'static.example.net',
                'cdn.example.org', 'mail.example.com', 'login.example.io',
            ]
            self._device_models   = ['MacBookPro18,1', 'Surface Pro 9', 'ThinkPad X1 Carbon', 'Dell XPS 15']
            self._device_names    = ['CORP-LAPTOP-001', 'CORP-WS-042', 'MGMT-PC-007', 'DEV-MAC-013']
            self._device_os_types = ['iOS', 'Android', 'Windows OS', 'Mac OS']
            self._device_os_vers  = ['10.0.19044', '12.1', 'Monterey 12.6', '11']
            self._traffic_methods = ['DIRECT', 'Proxy Chaining', 'ZIA']
            self._rule_labels     = ['Default_Rule', 'Allow_Business', 'Block_Gambling', 'Caution_Social']
            self._bw_class_names  = ['Default', 'High_Priority', 'Low_Priority', 'Best_Effort']
            self._bw_rule_names   = ['BW_Default', 'BW_Streaming_Limit', 'BW_Cloud_Priority']

    @staticmethod
    def _rand_ip(templates):
        tpl = random.choice(templates)
        return tpl.format(*[random.randint(1, 254) for _ in range(tpl.count('{}'))])

    def generate(self):
        if self.log_type == 'tunnel':
            return self._generate_tunnel()
        return self._generate_web()

    # ------------------------------------------------------------------
    # Web proxy
    # ------------------------------------------------------------------

    def _generate_web(self):
        now = datetime.now()
        ts = now.strftime('%Y-%m-%d %H:%M:%S')

        user         = random.choice(self._USERS)
        department   = random.choice(self._departments)
        location     = random.choice(self._LOCATIONS)
        client_ip    = self._rand_ip(self._INTERNAL_IPS)
        server_ip    = self._rand_ip(self._EXTERNAL_IPS)
        pub_ip       = self._rand_ip(self._PUBLIC_IPS)
        protocol     = random.choice(self._protocols)
        action       = random.choice(self._actions)
        method       = random.choice(self._methods)
        status       = random.choice(self._statuses)
        url_cat      = random.choice(self._url_categories)
        url_super    = random.choice(self._url_supers)
        url_class    = random.choice(self._url_classes)
        app_name     = random.choice(self._app_names)
        app_class    = random.choice(self._app_classes)
        threat_cat   = random.choice(self._threat_cats)
        threat_name  = 'None' if threat_cat == 'None' else random.choice(self._threat_names[1:])
        threat_class = 'None' if threat_cat == 'None' else random.choice(self._threat_classes[1:])
        file_type    = random.choice(self._file_types)
        file_class   = 'None' if file_type == 'None' else random.choice(self._file_classes[1:])
        dlp_engine   = random.choice(self._dlp_engines)
        dlp_dicts    = 'None' if dlp_engine == 'None' else random.choice(self._dlp_dicts[1:])
        bwthrottle   = random.choice(['NO', 'YES'])
        hostname     = random.choice(self._web_hostnames)
        useragent    = random.choice(self._user_agents)
        page_risk    = random.randint(0, 100)
        resp_size    = random.randint(50, 100000)
        req_size     = random.randint(200, 5000)
        tx_size      = req_size + resp_size
        client_tt    = random.randint(0, 500)
        server_tt    = random.randint(0, 500)
        event_id     = random.randint(10**18, 10**19 - 1)
        port         = 443 if protocol == 'HTTPS' else 80
        url          = f'{hostname}:{port}'
        referer      = random.choice(['None', 'https://www.google.com', f'https://{hostname}/'])
        md5          = 'None' if file_type == 'None' else ''.join(random.choices('abcdef0123456789', k=32))
        content_type = random.choice(['None', 'text/html', 'application/json', 'application/octet-stream'])

        fields = [
            f'reason={action}',
            f'event_id={event_id}',
            f'protocol={protocol}',
            f'action={action}',
            f'transactionsize={tx_size}',
            f'responsesize={resp_size}',
            f'requestsize={req_size}',
            f'urlcategory={url_cat}',
            f'serverip={server_ip}',
            f'clienttranstime={client_tt}',
            f'requestmethod={method}',
            f'refererURL={referer}',
            f'useragent={useragent}',
            'product=NSS',
            f'location={location}',
            f'ClientIP={client_ip}',
            f'status={status}',
            f'user={user}',
            f'url={url}',
            'vendor=Zscaler',
            f'hostname={hostname}',
            f'clientpublicIP={pub_ip}',
            f'threatcategory={threat_cat}',
            f'threatname={threat_name}',
            f'filetype={file_type}',
            f'appname={app_name}',
            f'pagerisk={page_risk}',
            f'department={department}',
            f'urlsupercategory={url_super}',
            f'appclass={app_class}',
            f'dlpengine={dlp_engine}',
            f'urlclass={url_class}',
            f'threatclass={threat_class}',
            f'dlpdictionaries={dlp_dicts}',
            f'fileclass={file_class}',
            f'bwthrottle={bwthrottle}',
            f'servertranstime={server_tt}',
            f'md5={md5}',
            f'contenttype={content_type}',
            f'trafficredirectmethod={random.choice(self._traffic_methods)}',
            f'rulelabel={random.choice(self._rule_labels)}',
            f'devicemodel={random.choice(self._device_models)}',
            f'devicename={random.choice(self._device_names)}',
            f'deviceostype={random.choice(self._device_os_types)}',
            f'deviceosversion={random.choice(self._device_os_vers)}',
            f'bwclassname={random.choice(self._bw_class_names)}',
            f'bwrulename={random.choice(self._bw_rule_names)}',
        ]

        return ts + '\t' + '\t'.join(fields)

    # ------------------------------------------------------------------
    # Tunnel
    # ------------------------------------------------------------------

    def _generate_tunnel(self):
        now = datetime.now()
        ts = now.strftime('%Y-%m-%d %H:%M:%S')

        tunnel_type = random.choice(['IPSec', 'GRE'])
        product     = 'IKEv2' if tunnel_type == 'IPSec' else 'GRE'
        user        = random.choice(self._USERS)
        location    = random.choice(self._LOCATIONS)
        source_ip   = self._rand_ip(self._SOURCE_IPS)
        dest_ip     = self._rand_ip(self._EXTERNAL_IPS)
        server_ip   = self._rand_ip(self._INTERNAL_IPS)
        source_port = random.choice([0, 500, 4500, random.randint(1024, 65535)])
        tx_bytes    = random.randint(10000, 50000000)
        dpd_rec     = random.randint(0, 10)
        host        = random.choice(self._HOSTNAMES_GW)

        fields = [
            'Recordtype=Tunnel Samples',
            f'tunneltype={tunnel_type}',
            f'user={user}',
            f'location={location}',
            f'sourceip={source_ip}',
            f'destinationip={dest_ip}',
            f'sourceport={source_port}',
            f'txbytes={tx_bytes}',
            f'serverip={server_ip}',
            f'dpdrec={dpd_rec}',
            'vendor=Zscaler',
            f'product={product}',
            f'host={host}',
        ]

        return ts + '\t' + '\t'.join(fields)
