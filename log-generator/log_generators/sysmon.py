"""Sysmon registry events (12, 13, 14), as Splunk_TA_microsoft_sysmon reads them.

Sysmon publishes one channel, Microsoft-Windows-Sysmon/Operational, and what an
event means is its EventID. The add-on follows that: seven eventtypes split the
~29 IDs into groups, each granting different tags and so a different datamodel.
This module covers two groups so far:

  EventID 1, 7     `ms-sysmon-process`  process + report    → Endpoint.Processes
  EventID 11       `ms-sysmon-filemod`  endpoint + filesystem → Endpoint.Filesystem
  EventID 12/13/14 `ms-sysmon-regmod`   endpoint + registry → Endpoint.Registry
  EventID 3        `ms-sysmon-network`  network + communicate → Network_Traffic
  EventID 22       `ms-sysmon-dns`      network + resolution + dns → Network_Resolution

Two things about the wire matter more here than for any other source:

  sourcetype   XmlWinEventLog
  source       XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

`inputs.conf` sets no sourcetype at all — with renderXml = 1, splunkd settles on
XmlWinEventLog — and every one of the add-on's 62 EVALs lives in a
`[source::XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]` stanza, while
all seven eventtypes match on `source=`. Send these under the wrong source and
they index, parse, and produce nothing at all.

Field extraction itself is not done here either: the sourcetype stanza is
`rename = XmlWinEventLog`, so the events go through Splunk_TA_windows' generic
XML extraction — the same path the 4688 attacks already rely on.

The shapes below are modelled on real events, and a few details are load-bearing
rather than decorative:

  - `<Data Name='...'>` must use single quotes. The add-on's own transform reads
    `<Data Name='Details'>\\w+\\s\\((.+)\\)</Data>` to lift RegistryValueData out
    of a `DWORD (0x00000000)`, and double quotes would miss it.
  - EventID 12 carries no Details, and EventType decides `action`: CreateKey
    gives "created", DeleteKey and DeleteValue give "deleted".
  - `Keywords` must be 0x8000000000000000, or `status` is null for EventID 14.
  - `registry_hive` is only filled for TargetObject under HKLM\\System\\, HKU\\ or
    HKLM\\SOFTWARE\\. Other hives parse fine and simply leave it empty.
"""

import random
from datetime import datetime, timedelta, timezone

from .ai_entity import AIEntityMixin


#: The one channel Sysmon writes to.
CHANNEL = 'Microsoft-Windows-Sysmon/Operational'

#: Identifies the provider in every event's System block.
PROVIDER_GUID = '5770385F-C22A-43E0-BF4C-06F5698FFBD9'

#: Success. The add-on reads it directly: without it, `status` is null on a 14.
KEYWORDS_SUCCESS = '0x8000000000000000'

#: Process creation. Unlike a registry event it carries no EventType, and its
#: <Version> is 5 rather than 2.
PROCESS_EVENT_ID = 1

#: Image load — a DLL mapped into a running process. Same eventtype as a
#: process creation, so the same datamodel, but the add-on reads different
#: fields: ImageLoaded gives loaded_file and loaded_file_path, and Signed /
#: SignatureStatus give the two service_dll_signature_* fields. `action` is
#: "success" here, not "allowed".
IMAGE_LOAD_EVENT_ID = 7

#: DLLs that load into something all day, and the process that loads them.
LOADED_IMAGES = [
    ('C:\\Windows\\System32\\kernel32.dll', 'kernel32.dll', 'Microsoft Corporation', True),
    ('C:\\Windows\\System32\\ws2_32.dll', 'ws2_32.dll', 'Microsoft Corporation', True),
    ('C:\\Windows\\System32\\crypt32.dll', 'crypt32.dll', 'Microsoft Corporation', True),
    ('C:\\Windows\\System32\\wininet.dll', 'wininet.dll', 'Microsoft Corporation', True),
    ('C:\\Program Files\\Google\\Chrome\\Application\\chrome_elf.dll', 'chrome_elf.dll',
     'Google LLC', True),
    ('C:\\Windows\\System32\\amsi.dll', 'amsi.dll', 'Microsoft Corporation', True),
    # Unsigned modules exist and are the interesting half of the field.
    ('C:\\Users\\Public\\helper.dll', 'helper.dll', '-', False),
    ('C:\\ProgramData\\updater\\core32.dll', 'core32.dll', '-', False),
]

#: Network connection. `direction` comes from Initiated, `protocol` is the
#: constant "ip", and `transport` is the Protocol field aliased through.
NETWORK_EVENT_ID = 3

#: DNS query. The add-on pulls `answer` out of QueryResults with a repeating
#: match on `type:  <n>  <value>;` — each entry has to end with a semicolon or
#: nothing is extracted, and answer_count is mvcount(answer).
DNS_EVENT_ID = 22

#: Where connections go. The internal ones are ordinary, the rest are what a
#: proxy or a beacon would reach.
NETWORK_PEERS = [
    ('10.20.4.15', 'fileserver01.corp.local', '445', 'tcp'),
    ('10.20.1.10', 'dc01.corp.local', '389', 'tcp'),
    ('10.20.1.10', 'dc01.corp.local', '88', 'tcp'),
    ('93.184.216.34', 'cdn.example.com', '443', 'tcp'),
    ('140.82.121.4', 'github.com', '443', 'tcp'),
    ('8.8.8.8', 'dns.google', '53', 'udp'),
    ('52.109.8.22', 'outlook.office365.com', '443', 'tcp'),
]

#: Names a workstation resolves, and what comes back. `type: 1` is an A record,
#: `type: 5` a CNAME — the ids the add-on's record_type lookup reads.
DNS_QUERIES = [
    ('outlook.office365.com', 'type:  5 outlook.ha.office365.com;type:  1 52.109.8.22;'),
    ('github.com', 'type:  1 140.82.121.4;'),
    ('cdn.example.com', 'type:  5 cdn.edge.example.net;type:  1 93.184.216.34;'),
    ('dc01.corp.local', 'type:  1 10.20.1.10;'),
    ('wpad.corp.local', '-'),
    ('telemetry.example.io', 'type:  1 203.0.113.44;'),
]

#: 0 is NOERROR, 9003 is NAME_ERROR — the two a workstation sees constantly.
DNS_STATUSES = ['0', '0', '0', '9003']

#: File creation. `action` is decided by comparing two of its own timestamps:
#: the add-on reads "created" when UtcTime == CreationUtcTime and "modified"
#: otherwise, which is how Sysmon distinguishes a new file from an overwrite.
FILE_CREATE_EVENT_ID = 11

#: Where things get written, and by what. The temp and Startup paths are what
#: detections look at; the rest is ordinary traffic.
CREATED_FILES = [
    ('C:\\Users\\{user}\\AppData\\Local\\Temp\\{name}.tmp',
     'C:\\Windows\\System32\\svchost.exe'),
    ('C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\'
     'IE\\{name}.dat', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'),
    ('C:\\Windows\\Temp\\{name}.log', 'C:\\Windows\\System32\\services.exe'),
    ('C:\\Users\\{user}\\Documents\\{name}.docx',
     'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'),
    ('C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\{name}.dat',
     'C:\\Program Files\\Windows Defender\\MsMpEng.exe'),
    ('C:\\Users\\{user}\\Downloads\\{name}.zip',
     'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'),
]

FILE_STEMS = ['report', 'cache3f2a', 'update', 'tmp9a1c', 'invoice', 'session', 'wd-scan']

#: What each registry EventID is called, and the EventType values it can carry.
#: EventType is not cosmetic — `EVAL-action` switches on it for EventID 12.
REGISTRY_EVENTS = {
    12: ('Registry object added or deleted', ['CreateKey', 'DeleteKey', 'DeleteValue']),
    13: ('Registry value set', ['SetValue']),
    14: ('Registry object renamed', ['RenameKey', 'RenameValue']),
}

#: Keys that ordinary Windows activity touches constantly.
BENIGN_KEYS = [
    ('HKLM\\System\\CurrentControlSet\\Services\\{service}\\Start', 'DWORD (0x00000002)'),
    ('HKLM\\System\\CurrentControlSet\\Services\\{service}\\ErrorControl', 'DWORD (0x00000001)'),
    ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\'
     'LastSuccessTime', '{timestamp}'),
    ('HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\SignatureLastUpdated',
     'Binary Data'),
    ('HKU\\{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\'
     'RecentDocs\\MRUListEx', 'Binary Data'),
    ('HKU\\{sid}\\Software\\Microsoft\\Office\\16.0\\Common\\Identity\\'
     'EnableADAL', 'DWORD (0x00000001)'),
    ('HKLM\\SOFTWARE\\Microsoft\\Cryptography\\RNG\\Seed', 'Binary Data'),
    ('HKU\\{sid}\\Control Panel\\Desktop\\ScreenSaveTimeOut', '900'),
]

#: Processes that legitimately write to the registry all day.
BENIGN_WRITERS = [
    'C:\\Windows\\system32\\services.exe',
    'C:\\Windows\\system32\\svchost.exe',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'C:\\Windows\\system32\\reg.exe',
    'C:\\Program Files\\Windows Defender\\MsMpEng.exe',
    'C:\\Windows\\explorer.exe',
    'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE',
]

#: Ordinary process creations, with the metadata Sysmon reads off the binary.
#: OriginalFileName has to be a real name: the add-on drops "-".
BENIGN_PROCESSES = [
    ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe',
     'C:\\Windows\\system32\\svchost.exe -k netsvcs -p',
     'Host Process for Windows Services'),
    ('C:\\Windows\\System32\\taskhostw.exe', 'taskhostw.exe',
     'taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}', 'Host Process for Windows Tasks'),
    ('C:\\Windows\\System32\\conhost.exe', 'CONHOST.EXE',
     '\\??\\C:\\Windows\\system32\\conhost.exe 0x4', 'Console Window Host'),
    ('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'chrome.exe',
     '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" --type=renderer',
     'Google Chrome'),
    ('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'PowerShell.EXE',
     'powershell.exe -NoProfile -Command Get-Service', 'Windows PowerShell'),
    ('C:\\Windows\\System32\\cmd.exe', 'Cmd.Exe',
     'cmd.exe /c "dir C:\\Users"', 'Windows Command Processor'),
]

#: What launches them.
PARENT_PROCESSES = [
    ('C:\\Windows\\System32\\services.exe', 'C:\\Windows\\system32\\services.exe'),
    ('C:\\Windows\\explorer.exe', 'C:\\Windows\\Explorer.EXE'),
    ('C:\\Windows\\System32\\svchost.exe',
     'C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p'),
    ('C:\\Windows\\System32\\userinit.exe', 'C:\\Windows\\system32\\userinit.exe'),
]

#: Sysmon reports the token's integrity level verbatim.
INTEGRITY_LEVELS = ['System', 'High', 'Medium', 'Low']

SERVICES = ['wuauserv', 'BITS', 'Dnscache', 'Spooler', 'WinDefend', 'Netlogon', 'LanmanServer']

WORKSTATIONS = ['WKS-FIN01', 'WKS-HR04', 'WIN10-21H1', 'WIN11-22H2', 'DESKTOP-K2M8QP1']
DOMAIN = 'CORP'
USERS = ['jsmith', 'a.moreau', 'mdupont', 'localuser', 'svc_backup']


def _sid():
    """A plausible per-user SID, for an HKU path."""
    return (f'S-1-5-21-{random.randint(1000000000, 3999999999)}'
            f'-{random.randint(1000000000, 3999999999)}'
            f'-{random.randint(1000000000, 3999999999)}-{random.randint(1000, 1999)}')


def process_guid(when=None):
    """Sysmon's process GUID: a machine part, the process start time, and a counter.

    The shape matters more than the arithmetic — the add-on passes it through to
    `process_guid` untouched, and a detection groups by it.
    """
    when = when or datetime.now(timezone.utc)
    stamp = int(when.timestamp()) & 0xFFFFFFFF
    return (f'{random.randint(0, 0xFFFFFFFF):08X}-{stamp >> 16:04X}-{stamp & 0xFFFF:04X}-'
            f'{random.randint(0, 0xFFFF):04X}-{random.randint(0, 0xFFFFFFFFFFFF):012X}')


class SysmonLogGenerator(AIEntityMixin):
    """Sysmon registry events, rendered as the forwarder sends them."""

    LOG_TYPE = 'sysmon'
    AVG_LOG_SIZE = 1150

    SOURCETYPE_CONFIG = {
        'param_key': 'event_categories',
        'defaults': ['process_creation', 'image_load', 'network_connect',
                     'dns_query', 'file_create', 'registry_set', 'registry_key',
                     'registry_rename'],
        'multi_instance': False,
    }

    METADATA = {
        'name': 'Sysmon',
        'description': 'Sysinternals Sysmon — registry activity (EventID 12, 13, 14)',
        'example': "EventID 13 - Registry value set (HKLM\\System\\...\\Start)",
        'sources': [
            {'id': 'process_creation', 'name': 'Process creation',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'description': 'EventID 1 — a process started, with its command line, '
                            'hashes and parent'},
            {'id': 'image_load', 'name': 'Image loaded',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'description': 'EventID 7 — a DLL was mapped into a process, with its '
                            'hashes and signature'},
            {'id': 'network_connect', 'name': 'Network connection',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'description': 'EventID 3 — a process opened a connection'},
            {'id': 'dns_query', 'name': 'DNS query',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'description': 'EventID 22 — a process resolved a name'},
            {'id': 'file_create', 'name': 'File created',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'description': 'EventID 11 — a file was written. Sysmon carries no '
                            'hash, size or ACL on it; the datamodel defaults those'},
            {'id': 'registry_set', 'name': 'Registry value set',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'description': 'EventID 13 — a value was written'},
            {'id': 'registry_key', 'name': 'Registry key added or deleted',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'description': 'EventID 12 — CreateKey, DeleteKey or DeleteValue'},
            {'id': 'registry_rename', 'name': 'Registry object renamed',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
             'description': 'EventID 14 — RenameKey or RenameValue'},
        ],
    }

    #: Which EventID each selectable category emits.
    CATEGORY_EVENT_ID = {'process_creation': 1, 'image_load': 7, 'network_connect': 3,
                         'dns_query': 22, 'file_create': 11, 'registry_set': 13,
                         'registry_key': 12, 'registry_rename': 14}

    def __init__(self, event_categories=None):
        chosen = event_categories or list(self.SOURCETYPE_CONFIG['defaults'])
        self.event_categories = [c for c in chosen if c in self.CATEGORY_EVENT_ID] \
            or list(self.CATEGORY_EVENT_ID)
        self.event_count = 0
        self._record_id = random.randint(1000, 90000)

        # Pools A&I overrides, read through the mixin so a host and the account
        # on it come from the same entity rather than from two unrelated ones.
        self.hostnames = list(WORKSTATIONS)
        self.usernames = list(USERS)

        # One builder per selectable category, the way auditd and fortigate do
        # it: the dispatch is data, so what produced an event is observable.
        self._builders = {
            category: ((lambda: self.process_event()) if event_id == PROCESS_EVENT_ID
                       else (lambda: self.image_load_event()) if event_id == IMAGE_LOAD_EVENT_ID
                       else (lambda: self.network_event()) if event_id == NETWORK_EVENT_ID
                       else (lambda: self.dns_event()) if event_id == DNS_EVENT_ID
                       else (lambda: self.file_event()) if event_id == FILE_CREATE_EVENT_ID
                       else (lambda event_id=event_id: self.registry_event(event_id)))
            for category, event_id in self.CATEGORY_EVENT_ID.items()
            if category in self.event_categories
        }

    # ── rendering ───────────────────────────────────────────────────────────

    def generate(self) -> str:
        self.event_count += 1
        build = self._builders[random.choice(list(self._builders))]
        return self.render(build())

    def registry_event(self, event_id, *, target_object=None, image=None,
                       details=None, event_type=None, dest=None, user=None):
        """One registry event's fields, benign unless the caller says otherwise."""
        _label, event_types = REGISTRY_EVENTS[event_id]
        sid = _sid()

        if target_object is None:
            template, default_details = random.choice(BENIGN_KEYS)
            target_object = template.format(
                service=random.choice(SERVICES), sid=sid)
            if details is None:
                details = default_details.format(
                    timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))

        self._new_entity()
        host = dest or self._entity_field(
            'hostnames', lambda: random.choice(self.hostnames))
        account = user or self._entity_field(
            'usernames', lambda: random.choice(self.usernames))
        started = datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 600))

        return {
            'event_id': event_id,
            'event_type': event_type or random.choice(event_types),
            'dest': host,
            'user': account if '\\' in str(account) else f'{DOMAIN}\\{account}',
            'image': image or random.choice(BENIGN_WRITERS),
            'target_object': target_object,
            # EventID 12 carries no Details at all; 14 only on a RenameValue.
            'details': details,
            'process_id': random.randint(400, 12000),
            'process_guid': process_guid(started),
            'utc_time': datetime.now(timezone.utc),
        }

    def process_event(self, *, image=None, command_line=None, parent_image=None,
                      parent_command_line=None, original_file_name=None,
                      dest=None, user=None):
        """One EventID 1, benign unless the caller says otherwise.

        Every field the add-on reads for Endpoint.Processes is present:
        Hashes feeds process_hash, IntegrityLevel feeds process_integrity_level,
        OriginalFileName feeds original_file_name — and the add-on drops that
        last one when it is "-", so it is always a real name here.
        """
        self._new_entity()
        default_image, default_original, default_command, description = \
            random.choice(BENIGN_PROCESSES)
        parent_default, parent_command_default = random.choice(PARENT_PROCESSES)
        started = datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 600))

        host = dest or self._entity_field('hostnames', lambda: random.choice(self.hostnames))
        account = user or self._entity_field('usernames', lambda: random.choice(self.usernames))

        return {
            'event_id': PROCESS_EVENT_ID,
            'dest': host,
            'user': account if '\\' in str(account) else f'{DOMAIN}\\{account}',
            'image': image or default_image,
            'command_line': command_line or default_command,
            'original_file_name': original_file_name or default_original,
            'description': description,
            'parent_image': parent_image or parent_default,
            'parent_command_line': parent_command_line or parent_command_default,
            'parent_process_guid': process_guid(started),
            'parent_process_id': random.randint(400, 2000),
            'process_id': random.randint(2000, 12000),
            'process_guid': process_guid(started),
            'integrity_level': random.choice(INTEGRITY_LEVELS),
            'hashes': ('MD5=%032X,SHA256=%064X,IMPHASH=%032X'
                       % (random.getrandbits(128), random.getrandbits(256),
                          random.getrandbits(128))),
            'utc_time': datetime.now(timezone.utc),
        }

    def image_load_event(self, *, image=None, image_loaded=None, signed=None,
                         dest=None, user=None):
        """One EventID 7, benign unless the caller says otherwise.

        Signed / SignatureStatus are the pair the add-on reads for
        service_dll_signature_exists and _verified, and an unsigned module is
        the half worth having — both occur.
        """
        self._new_entity()
        loaded, original, company, is_signed = random.choice(LOADED_IMAGES)
        if image_loaded is not None:
            loaded = image_loaded
        if signed is not None:
            is_signed = signed

        host = dest or self._entity_field('hostnames', lambda: random.choice(self.hostnames))
        account = user or self._entity_field('usernames', lambda: random.choice(self.usernames))
        loader, _original, _command, _description = random.choice(BENIGN_PROCESSES)

        return {
            'event_id': IMAGE_LOAD_EVENT_ID,
            'dest': host,
            'user': account if '\\' in str(account) else f'{DOMAIN}\\{account}',
            'image': image or loader,
            'image_loaded': loaded,
            'original_file_name': original,
            'company': company,
            'signed': 'true' if is_signed else 'false',
            # Sysmon writes the status even when nothing is signed.
            'signature': company if is_signed else '-',
            'signature_status': 'Valid' if is_signed else 'Unavailable',
            'process_id': random.randint(400, 12000),
            'process_guid': process_guid(
                datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 600))),
            'hashes': ('MD5=%032X,SHA256=%064X,IMPHASH=%032X'
                       % (random.getrandbits(128), random.getrandbits(256),
                          random.getrandbits(128))),
            'utc_time': datetime.now(timezone.utc),
        }

    def network_event(self, *, dest_ip=None, dest_port=None, image=None,
                      initiated=None, dest=None, user=None):
        """One EventID 3, benign unless the caller says otherwise.

        `direction` is read off Initiated, so both values occur: a workstation
        opens connections and also receives them.
        """
        self._new_entity()
        peer_ip, peer_name, peer_port, transport = random.choice(NETWORK_PEERS)
        host = dest or self._entity_field('hostnames', lambda: random.choice(self.hostnames))
        account = user or self._entity_field('usernames', lambda: random.choice(self.usernames))
        loader, _o, _c, _d = random.choice(BENIGN_PROCESSES)

        return {
            'event_id': NETWORK_EVENT_ID,
            'dest': host,
            'user': account if '\\' in str(account) else f'{DOMAIN}\\{account}',
            'image': image or loader,
            'protocol': transport,
            'initiated': 'true' if (random.random() < 0.85 if initiated is None
                                    else initiated) else 'false',
            'source_ip': f'10.20.{random.randint(1, 30)}.{random.randint(10, 250)}',
            'source_hostname': f'{host}.corp.local',
            'source_port': str(random.randint(49152, 65535)),
            'dest_ip': dest_ip or peer_ip,
            'dest_hostname': peer_name,
            'dest_port': str(dest_port or peer_port),
            'process_id': random.randint(400, 12000),
            'process_guid': process_guid(
                datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 600))),
            'utc_time': datetime.now(timezone.utc),
        }

    def dns_event(self, *, query_name=None, query_results=None, query_status=None,
                  image=None, dest=None, user=None):
        """One EventID 22, benign unless the caller says otherwise.

        QueryResults has to keep its shape: the add-on extracts `answer` with a
        repeating match on `type:  <n>  <value>;`, so every entry ends with a
        semicolon or nothing comes out and answer_count is zero.
        """
        self._new_entity()
        name, results = random.choice(DNS_QUERIES)
        host = dest or self._entity_field('hostnames', lambda: random.choice(self.hostnames))
        account = user or self._entity_field('usernames', lambda: random.choice(self.usernames))
        loader, _o, _c, _d = random.choice(BENIGN_PROCESSES)

        return {
            'event_id': DNS_EVENT_ID,
            'dest': host,
            'user': account if '\\' in str(account) else f'{DOMAIN}\\{account}',
            'image': image or loader,
            'query_name': query_name or name,
            'query_results': query_results if query_results is not None else results,
            'query_status': query_status or random.choice(DNS_STATUSES),
            'process_id': random.randint(400, 12000),
            'process_guid': process_guid(
                datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 600))),
            'utc_time': datetime.now(timezone.utc),
        }

    def file_event(self, *, target_filename=None, image=None, overwrite=None,
                   dest=None, user=None):
        """One EventID 11, benign unless the caller says otherwise.

        `overwrite` decides `action`. The add-on compares the event's two
        timestamps — UtcTime against CreationUtcTime — so a file written for the
        first time reads as "created" and one replaced in place as "modified".
        Left to chance, both occur.
        """
        self._new_entity()
        host = dest or self._entity_field('hostnames', lambda: random.choice(self.hostnames))
        account = user or self._entity_field('usernames', lambda: random.choice(self.usernames))
        bare = str(account).split('\\')[-1]

        if target_filename is None:
            template, default_image = random.choice(CREATED_FILES)
            target_filename = template.format(
                user=bare, name=f'{random.choice(FILE_STEMS)}{random.randint(1, 999)}')
            image = image or default_image

        now = datetime.now(timezone.utc)
        if overwrite is None:
            overwrite = random.random() < 0.4
        # An overwrite keeps the original creation time, so the two differ.
        created = now - timedelta(days=random.randint(1, 90)) if overwrite else now

        return {
            'event_id': FILE_CREATE_EVENT_ID,
            'dest': host,
            'user': account if '\\' in str(account) else f'{DOMAIN}\\{account}',
            'image': image or random.choice(BENIGN_WRITERS),
            'target_filename': target_filename,
            'creation_utc_time': created,
            'process_id': random.randint(400, 12000),
            'process_guid': process_guid(now - timedelta(minutes=random.randint(1, 600))),
            'utc_time': now,
        }

    def render(self, event) -> str:
        """The event as the forwarder puts it on the wire: one line of XML."""
        event_id = event['event_id']
        when = event['utc_time']
        self._record_id += random.randint(1, 40)

        utc = when.strftime('%Y-%m-%d %H:%M:%S.') + f'{when.microsecond // 1000:03d}'

        if event_id == NETWORK_EVENT_ID:
            data = [('RuleName', '-'), ('UtcTime', utc),
                    ('ProcessGuid', event['process_guid']),
                    ('ProcessId', str(event['process_id'])),
                    ('Image', event['image']),
                    ('User', event['user']),
                    ('Protocol', event['protocol']),
                    ('Initiated', event['initiated']),
                    ('SourceIsIpv6', 'false'),
                    ('SourceIp', event['source_ip']),
                    ('SourceHostname', event['source_hostname']),
                    ('SourcePort', event['source_port']),
                    ('SourcePortName', '-'),
                    ('DestinationIsIpv6', 'false'),
                    ('DestinationIp', event['dest_ip']),
                    ('DestinationHostname', event['dest_hostname']),
                    ('DestinationPort', event['dest_port']),
                    ('DestinationPortName', '-')]
        elif event_id == DNS_EVENT_ID:
            data = [('RuleName', '-'), ('UtcTime', utc),
                    ('ProcessGuid', event['process_guid']),
                    ('ProcessId', str(event['process_id'])),
                    ('QueryName', event['query_name']),
                    ('QueryStatus', event['query_status']),
                    ('QueryResults', event['query_results']),
                    ('Image', event['image']),
                    ('User', event['user'])]
        elif event_id == IMAGE_LOAD_EVENT_ID:
            data = [('RuleName', '-'), ('UtcTime', utc),
                    ('ProcessGuid', event['process_guid']),
                    ('ProcessId', str(event['process_id'])),
                    ('Image', event['image']),
                    ('ImageLoaded', event['image_loaded']),
                    ('FileVersion', '10.0.19041.1'),
                    ('Description', event['original_file_name']),
                    ('Product', 'Microsoft\u00ae Windows\u00ae Operating System'),
                    ('Company', event['company']),
                    ('OriginalFileName', event['original_file_name']),
                    ('Hashes', event['hashes']),
                    ('Signed', event['signed']),
                    ('Signature', event['signature']),
                    ('SignatureStatus', event['signature_status']),
                    ('User', event['user'])]
        elif event_id == FILE_CREATE_EVENT_ID:
            created = event['creation_utc_time']
            data = [('RuleName', '-'), ('UtcTime', utc),
                    ('ProcessGuid', event['process_guid']),
                    ('ProcessId', str(event['process_id'])),
                    ('Image', event['image']),
                    ('TargetFilename', event['target_filename']),
                    ('CreationUtcTime', created.strftime('%Y-%m-%d %H:%M:%S.')
                     + f'{created.microsecond // 1000:03d}'),
                    ('User', event['user'])]
        elif event_id == PROCESS_EVENT_ID:
            # A process creation carries no EventType, and the fields the
            # add-on reads for Endpoint.Processes are all here.
            data = [('RuleName', '-'), ('UtcTime', utc),
                    ('ProcessGuid', event['process_guid']),
                    ('ProcessId', str(event['process_id'])),
                    ('Image', event['image']),
                    ('FileVersion', '10.0.19041.1'),
                    ('Description', event['description']),
                    ('Product', 'Microsoft\u00ae Windows\u00ae Operating System'),
                    ('Company', 'Microsoft Corporation'),
                    ('OriginalFileName', event['original_file_name']),
                    ('CommandLine', event['command_line']),
                    ('CurrentDirectory', 'C:\\Windows\\system32\\'),
                    ('User', event['user']),
                    ('LogonGuid', event['parent_process_guid']),
                    ('LogonId', f"0x{random.randint(0x1000, 0xFFFFF):x}"),
                    ('TerminalSessionId', '1'),
                    ('IntegrityLevel', event['integrity_level']),
                    ('Hashes', event['hashes']),
                    ('ParentProcessGuid', event['parent_process_guid']),
                    ('ParentProcessId', str(event['parent_process_id'])),
                    ('ParentImage', event['parent_image']),
                    ('ParentCommandLine', event['parent_command_line']),
                    ('ParentUser', event['user'])]
        else:
            data = [('RuleName', '-'), ('EventType', event['event_type']),
                    ('UtcTime', utc),
                    ('ProcessGuid', event['process_guid']),
                    ('ProcessId', str(event['process_id'])),
                    ('Image', event['image']),
                    ('TargetObject', event['target_object'])]
            # Only EventID 13 always carries Details; a 12 never does.
            if event_id != 12 and event.get('details') is not None:
                data.append(('Details', event['details']))
            data.append(('User', event['user']))

        # Single quotes on Data Name: the add-on's RegistryValueData transform
        # reads `<Data Name='Details'>`, and double quotes would not match.
        event_data = ''.join(f"<Data Name='{name}'>{value}</Data>" for name, value in data)

        return (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f'<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{PROVIDER_GUID}"/>'
            f'<EventID>{event_id}</EventID>'
            f'<Version>{5 if event_id == PROCESS_EVENT_ID else 2}</Version><Level>4</Level>'
            f'<Task>{event_id}</Task><Opcode>0</Opcode>'
            f'<Keywords>{KEYWORDS_SUCCESS}</Keywords>'
            f"<TimeCreated SystemTime='{when.strftime('%Y-%m-%dT%H:%M:%S.%f')}Z'/>"
            f'<EventRecordID>{self._record_id}</EventRecordID><Correlation/>'
            f'<Execution ProcessID="{random.randint(2000, 4000)}" '
            f'ThreadID="{random.randint(3000, 9000)}"/>'
            f'<Channel>{CHANNEL}</Channel>'
            f"<Computer>{event['dest']}</Computer>"
            '<Security UserID="S-1-5-18"/>'
            f'</System><EventData>{event_data}</EventData></Event>'
        )
