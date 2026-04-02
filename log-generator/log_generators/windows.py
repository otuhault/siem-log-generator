"""
Windows Event Log Generator
Generates realistic Windows Event Logs in XML or Classic format
Supports Security, Application, and System log sources
"""

import random
from datetime import datetime
import xml.etree.ElementTree as ET
from xml.dom import minidom

class WindowsEventLogGenerator:
    """Generates Windows Event Logs for different sources (Security, Application, System)"""

    LOG_TYPE = 'windows'
    AVG_LOG_SIZE = 600
    SOURCETYPE_CONFIG = {
        'param_key': 'sources',
        'defaults': ['Security'],
        'multi_instance': True,
        'single_param_name': 'source',
        'extra_params_keys': {'render_format': 'xml'},
    }
    ASSET_IDENTITY_MAPPING = {
        'usernames':    {'type': 'identity', 'field': 'identity',                               'cim_field': 'user'},
        'workstations': {'type': 'asset',    'field': 'nt_host', 'categories': ['windows'],    'cim_field': 'src_nt_host'},
    }
    METADATA = {
        'name': 'Windows Event Log',
        'description': 'Windows Event Logs - Security, Application, and System sources',
        'example': 'Event ID 4624 - Successful Logon (Security)',
        'sources': [
            {'id': 'Security',    'name': 'Security',    'description': 'Authentication, privileges, processes (4624, 4625, 4688, etc.)'},
            {'id': 'Application', 'name': 'Application', 'description': 'Application errors, installations, updates (1000, 1001, 11707, etc.)'},
            {'id': 'System',      'name': 'System',      'description': 'Service management, system events (6005, 7036, 7034, etc.)'},
        ],
    }

    def __init__(self, source='Security', render_format='xml'):
        self.source = source  # 'Security', 'Application', or 'System'
        self.render_format = render_format  # 'xml' or 'classic'

        # Define event types based on source
        self._setup_event_types()

    def _setup_event_types(self):
        """Setup event types based on the source"""
        if self.source == 'Security':
            self.event_types = [
                (4624, 'Successful Logon', 40),
                (4625, 'Failed Logon', 10),
                (4634, 'Logoff', 35),
                (4672, 'Special Privileges Assigned', 8),
                (4688, 'Process Created', 20),
                (4689, 'Process Terminated', 18),
                (4698, 'Scheduled Task Created', 2),
                (4699, 'Scheduled Task Deleted', 1),
                (4720, 'User Account Created', 1),
                (4726, 'User Account Deleted', 1),
                (4732, 'Member Added to Security Group', 2),
                (4756, 'Member Added to Universal Security Group', 1),
            ]
            self.provider_name = 'Microsoft-Windows-Security-Auditing'
            self.provider_guid = '{54849625-5478-4994-A5BA-3E3B0328C30D}'

        elif self.source == 'Application':
            self.event_types = [
                (1000, 'Application Error', 15),
                (1001, 'Application Hang', 10),
                (1002, 'Application Recovery', 5),
                (1033, 'Installation Success', 8),
                (1034, 'Installation Failure', 3),
                (1040, 'Application Update', 12),
                (11707, 'Install Operation Completed', 20),
                (11708, 'Install Operation Failed', 8),
                (11724, 'Application Configuration Changed', 15),
                (1530, 'User Profile Service Warning', 4),
            ]
            self.provider_name = 'Application'
            self.provider_guid = '{00000000-0000-0000-0000-000000000000}'

        elif self.source == 'System':
            self.event_types = [
                (6005, 'Event Log Service Started', 3),
                (6006, 'Event Log Service Stopped', 2),
                (6008, 'Unexpected System Shutdown', 1),
                (6009, 'System Started', 3),
                (7034, 'Service Crashed', 5),
                (7035, 'Service Control Request', 20),
                (7036, 'Service State Change', 35),
                (7040, 'Service Start Type Changed', 8),
                (10016, 'DCOM Error', 10),
                (1074, 'System Shutdown Initiated', 2),
                (41, 'System Kernel Power', 5),
            ]
            self.provider_name = 'Service Control Manager'
            self.provider_guid = '{555908d1-a6d7-4695-8e1e-26931d2012f4}'

        else:
            raise ValueError(f"Unknown source: {self.source}. Must be 'Security', 'Application', or 'System'")
        
        # Logon types for Event ID 4624/4625
        self.logon_types = {
            2: 'Interactive',
            3: 'Network',
            4: 'Batch',
            5: 'Service',
            7: 'Unlock',
            10: 'RemoteInteractive',
            11: 'CachedInteractive'
        }
        
        # Realistic usernames
        self.usernames = [
            'Administrator', 'jsmith', 'mdoe', 'sysadmin', 'serviceaccount',
            'backup_user', 'dbadmin', 'webserver', 'jenkins', 'SYSTEM'
        ]
        
        # Realistic domains
        self.domains = ['WORKGROUP', 'CONTOSO', 'CORP', 'LAB', 'PROD']
        
        # Realistic workstation names
        self.workstations = [
            'DESKTOP-{}', 'LAPTOP-{}', 'SRV-{}', 'WKS-{}'
        ]
        
        # Common processes
        self.processes = [
            ('C:\\Windows\\System32\\cmd.exe', 'cmd.exe'),
            ('C:\\Windows\\System32\\powershell.exe', 'powershell.exe'),
            ('C:\\Windows\\explorer.exe', 'explorer.exe'),
            ('C:\\Windows\\System32\\svchost.exe', 'svchost.exe'),
            ('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'chrome.exe'),
            ('C:\\Windows\\System32\\notepad.exe', 'notepad.exe'),
            ('C:\\Windows\\System32\\msiexec.exe', 'msiexec.exe'),
        ]
    
    def generate(self):
        """Generate a single Windows Event Log in specified format"""
        # Select event type with weighted probability
        weights = [e[2] for e in self.event_types]
        event_id, description, _ = random.choices(self.event_types, weights=weights)[0]

        # Generate based on event type and format
        if self.render_format == 'classic':
            return self._generate_classic_format(event_id, description)
        else:
            # Generate XML format based on source and event type
            if self.source == 'Security':
                return self._generate_security_event(event_id, description)
            elif self.source == 'Application':
                return self._generate_application_event(event_id, description)
            elif self.source == 'System':
                return self._generate_system_event(event_id, description)
            else:
                return self._generate_generic_event(event_id, description)

    def _generate_security_event(self, event_id, description):
        """Generate Security event in XML format"""
        if event_id in [4624, 4625]:
            return self._generate_logon_event(event_id)
        elif event_id == 4634:
            return self._generate_logoff_event()
        elif event_id == 4672:
            return self._generate_special_privileges_event()
        elif event_id == 4688:
            return self._generate_process_creation_event()
        elif event_id == 4689:
            return self._generate_process_termination_event()
        else:
            return self._generate_generic_event(event_id, description)

    def _generate_application_event(self, event_id, description):
        """Generate Application event in XML format"""
        timestamp = datetime.now().isoformat()
        computer = self._get_random_workstation()

        # Common application names
        app_names = ['Microsoft Office', 'Google Chrome', 'Firefox', 'Visual Studio',
                    'Adobe Reader', 'Outlook', 'Teams', 'OneDrive']
        app_name = random.choice(app_names)

        level_map = {
            1000: 2,  # Error
            1001: 2,  # Error
            1002: 4,  # Information
            1033: 4,  # Information
            1034: 2,  # Error
            1040: 4,  # Information
            11707: 4, # Information
            11708: 2, # Error
            11724: 4, # Information
            1530: 3,  # Warning
        }
        level = level_map.get(event_id, 4)

        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{app_name}" />
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>{level}</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x80000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>Application</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>
  <EventData>
    <Data>{description}</Data>
    <Data>Application: {app_name}</Data>
    <Data>Version: {random.randint(1, 20)}.{random.randint(0, 9)}.{random.randint(0, 9999)}</Data>
  </EventData>
</Event>'''

        return event_xml.strip()

    def _generate_system_event(self, event_id, description):
        """Generate System event in XML format"""
        timestamp = datetime.now().isoformat()
        computer = self._get_random_workstation()

        # Common service names
        services = ['wuauserv', 'MSSQLSERVER', 'W32Time', 'Spooler', 'Netlogon',
                   'DNS', 'DHCP', 'EventLog', 'WinRM', 'TermService']
        service = random.choice(services)

        level_map = {
            6005: 4,  # Information
            6006: 4,  # Information
            6008: 1,  # Critical
            6009: 4,  # Information
            7034: 2,  # Error
            7035: 4,  # Information
            7036: 4,  # Information
            7040: 4,  # Information
            10016: 2, # Error
            1074: 4,  # Information
            41: 1,    # Critical
        }
        level = level_map.get(event_id, 4)

        state = random.choice(['running', 'stopped'])

        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{self.provider_name}" Guid="{self.provider_guid}" />
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>{level}</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8080000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>System</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="param1">{service}</Data>
    <Data Name="param2">{state}</Data>
    <Data Name="Description">{description}</Data>
  </EventData>
</Event>'''

        return event_xml.strip()

    def _generate_classic_format(self, event_id, description):
        """Generate event in classic text format (like Event Viewer)"""
        timestamp = datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')
        computer = self._get_random_workstation()
        domain = random.choice(self.domains)
        username = random.choice(self.usernames)

        # Handle Security events
        if self.source == 'Security' and event_id in [4624, 4625]:
            logon_type = random.choice(list(self.logon_types.keys()))
            logon_type_desc = self.logon_types[logon_type]
            source_ip = f'192.168.{random.randint(1,255)}.{random.randint(1,254)}'
            status = 'Success' if event_id == 4624 else 'Failure'

            return f'''Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          {timestamp}
Event ID:      {event_id}
Task Category: Logon
Level:         Information
Keywords:      Audit {status}
User:          N/A
Computer:      {computer}
Description:
An account was successfully logged on.

Subject:
\tSecurity ID:\t\tS-1-5-18
\tAccount Name:\t\t{computer}$
\tAccount Domain:\t\t{domain}
\tLogon ID:\t\t0x{random.randint(100000, 999999):x}

Logon Information:
\tLogon Type:\t\t{logon_type}
\tRestricted Admin Mode:\t-
\tVirtual Account:\t\tNo
\tElevated Token:\t\tNo

Impersonation Level:\t\tImpersonation

New Logon:
\tSecurity ID:\t\t{domain}\\{username}
\tAccount Name:\t\t{username}
\tAccount Domain:\t\t{domain}
\tLogon ID:\t\t0x{random.randint(100000, 999999):x}
\tLinked Logon ID:\t\t0x0
\tNetwork Account Name:\t-
\tNetwork Account Domain:\t-
\tLogon GUID:\t\t{{00000000-0000-0000-0000-000000000000}}

Process Information:
\tProcess ID:\t\t0x{random.randint(500, 5000):x}
\tProcess Name:\t\t-

Network Information:
\tWorkstation Name:\t{computer}
\tSource Network Address:\t{source_ip}
\tSource Port:\t\t{random.randint(49152, 65535)}

Detailed Authentication Information:
\tLogon Process:\t\tNtLmSsp
\tAuthentication Package:\tNTLM
\tTransited Services:\t-
\tPackage Name (NTLM only):\tNTLM V2
\tKey Length:\t\t128'''

        elif self.source == 'Security' and event_id == 4688:
            process_path, process_name = random.choice(self.processes)
            return f'''Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Date:          {timestamp}
Event ID:      4688
Task Category: Process Creation
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      {computer}
Description:
A new process has been created.

Creator Subject:
\tSecurity ID:\t\t{domain}\\{username}
\tAccount Name:\t\t{username}
\tAccount Domain:\t\t{domain}
\tLogon ID:\t\t0x{random.randint(100000, 999999):x}

Target Subject:
\tSecurity ID:\t\tNULL SID
\tAccount Name:\t\t-
\tAccount Domain:\t\t-
\tLogon ID:\t\t0x0

Process Information:
\tNew Process ID:\t\t0x{random.randint(1000, 9999):x}
\tNew Process Name:\t{process_path}
\tToken Elevation Type:\t%%1936
\tMandatory Label:\t\tMandatory Label\\Medium Mandatory Level
\tCreator Process ID:\t0x{random.randint(500, 5000):x}
\tCreator Process Name:\tC:\\Windows\\explorer.exe
\tProcess Command Line:\t{process_path}'''

        # Handle Application events
        elif self.source == 'Application':
            app_names = ['Microsoft Office', 'Google Chrome', 'Firefox', 'Visual Studio']
            app_name = random.choice(app_names)
            level = 'Error' if event_id in [1000, 1001, 1034, 11708] else 'Information'

            return f'''Log Name:      Application
Source:        {app_name}
Date:          {timestamp}
Event ID:      {event_id}
Task Category: None
Level:         {level}
Keywords:      Classic
User:          N/A
Computer:      {computer}
Description:
{description}

Application: {app_name}
Version: {random.randint(1, 20)}.{random.randint(0, 9)}.{random.randint(0, 9999)}
Process ID: {random.randint(1000, 9999)}'''

        # Handle System events
        elif self.source == 'System':
            services = ['wuauserv', 'MSSQLSERVER', 'W32Time', 'Spooler', 'Netlogon']
            service = random.choice(services)
            level = 'Error' if event_id in [6008, 7034, 10016] else 'Information'
            state = random.choice(['running', 'stopped'])

            return f'''Log Name:      System
Source:        {self.provider_name}
Date:          {timestamp}
Event ID:      {event_id}
Task Category: None
Level:         {level}
Keywords:      Classic
User:          N/A
Computer:      {computer}
Description:
{description}

Service: {service}
State: {state}'''

        # Default Security event
        else:
            return f'''Log Name:      {self.source}
Source:        {self.provider_name}
Date:          {timestamp}
Event ID:      {event_id}
Task Category: {description}
Level:         Information
Keywords:      Audit Success
User:          N/A
Computer:      {computer}
Description:
{description}

Subject:
\tSecurity ID:\t\t{domain}\\{username}
\tAccount Name:\t\t{username}
\tAccount Domain:\t\t{domain}
\tLogon ID:\t\t0x{random.randint(100000, 999999):x}'''
    
    def _generate_logon_event(self, event_id):
        """Generate Event ID 4624 (success) or 4625 (failure)"""
        timestamp = datetime.now().isoformat()
        computer = self._get_random_workstation()
        domain = random.choice(self.domains)
        username = random.choice(self.usernames)
        logon_type = random.choice(list(self.logon_types.keys()))
        source_ip = f'192.168.{random.randint(1,255)}.{random.randint(1,254)}'

        status = 'Success' if event_id == 4624 else 'Failure'

        # Simplified Windows Event Log XML format
        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{self.provider_name}" Guid="{self.provider_guid}" />
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>{self.source}</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">{username}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
    <Data Name="SubjectLogonId">0x{random.randint(100000, 999999):x}</Data>
    <Data Name="TargetUserSid">S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}</Data>
    <Data Name="TargetUserName">{username}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="Status">{status}</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="LogonProcessName">User32</Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">{computer}</Data>
    <Data Name="LogonGuid">{{00000000-0000-0000-0000-000000000000}}</Data>
    <Data Name="IpAddress">{source_ip}</Data>
    <Data Name="IpPort">{random.randint(49152, 65535)}</Data>
  </EventData>
</Event>'''
        
        return event_xml.strip()
    
    def _generate_logoff_event(self):
        """Generate Event ID 4634 (Logoff)"""
        timestamp = datetime.now().isoformat()
        computer = self._get_random_workstation()
        domain = random.choice(self.domains)
        username = random.choice(self.usernames)
        logon_type = random.choice(list(self.logon_types.keys()))
        
        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{self.provider_name}" Guid="{self.provider_guid}" />
    <EventID>4634</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12545</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>{self.source}</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="TargetUserSid">S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}</Data>
    <Data Name="TargetUserName">{username}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="TargetLogonId">0x{random.randint(100000, 999999):x}</Data>
    <Data Name="LogonType">{logon_type}</Data>
  </EventData>
</Event>'''
        
        return event_xml.strip()
    
    def _generate_special_privileges_event(self):
        """Generate Event ID 4672 (Special Privileges Assigned)"""
        timestamp = datetime.now().isoformat()
        computer = self._get_random_workstation()
        domain = random.choice(self.domains)
        username = random.choice(self.usernames)
        
        privileges = [
            'SeSecurityPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
            'SeTakeOwnershipPrivilege', 'SeDebugPrivilege', 'SeSystemEnvironmentPrivilege',
            'SeLoadDriverPrivilege', 'SeImpersonatePrivilege'
        ]
        selected_privileges = '\n    '.join(random.sample(privileges, random.randint(2, 5)))
        
        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{self.provider_name}" Guid="{self.provider_guid}" />
    <EventID>4672</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12548</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>{self.source}</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}</Data>
    <Data Name="SubjectUserName">{username}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
    <Data Name="SubjectLogonId">0x{random.randint(100000, 999999):x}</Data>
    <Data Name="PrivilegeList">{selected_privileges}</Data>
  </EventData>
</Event>'''
        
        return event_xml.strip()
    
    def _generate_process_creation_event(self):
        """Generate Event ID 4688 (Process Created)"""
        timestamp = datetime.now().isoformat()
        computer = self._get_random_workstation()
        domain = random.choice(self.domains)
        username = random.choice(self.usernames)
        process_path, process_name = random.choice(self.processes)
        
        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{self.provider_name}" Guid="{self.provider_guid}" />
    <EventID>4688</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>13312</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>{self.source}</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}</Data>
    <Data Name="SubjectUserName">{username}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
    <Data Name="SubjectLogonId">0x{random.randint(100000, 999999):x}</Data>
    <Data Name="NewProcessId">0x{random.randint(1000, 9999):x}</Data>
    <Data Name="NewProcessName">{process_path}</Data>
    <Data Name="TokenElevationType">%%1936</Data>
    <Data Name="ProcessId">0x{random.randint(500, 5000):x}</Data>
    <Data Name="CommandLine">{process_path}</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">-</Data>
    <Data Name="TargetDomainName">-</Data>
    <Data Name="TargetLogonId">0x0</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-8192</Data>
  </EventData>
</Event>'''
        
        return event_xml.strip()
    
    def _generate_process_termination_event(self):
        """Generate Event ID 4689 (Process Terminated)"""
        timestamp = datetime.now().isoformat()
        computer = self._get_random_workstation()
        domain = random.choice(self.domains)
        username = random.choice(self.usernames)
        process_path, process_name = random.choice(self.processes)
        
        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{self.provider_name}" Guid="{self.provider_guid}" />
    <EventID>4689</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13313</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>{self.source}</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}</Data>
    <Data Name="SubjectUserName">{username}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
    <Data Name="SubjectLogonId">0x{random.randint(100000, 999999):x}</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="ProcessId">0x{random.randint(1000, 9999):x}</Data>
    <Data Name="ProcessName">{process_path}</Data>
  </EventData>
</Event>'''
        
        return event_xml.strip()
    
    def _generate_generic_event(self, event_id, description):
        """Generate a generic event for other Event IDs"""
        timestamp = datetime.now().isoformat()
        computer = self._get_random_workstation()
        domain = random.choice(self.domains)
        username = random.choice(self.usernames)
        
        event_xml = f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{self.provider_name}" Guid="{self.provider_guid}" />
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 5000)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>{self.source}</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}</Data>
    <Data Name="SubjectUserName">{username}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
    <Data Name="SubjectLogonId">0x{random.randint(100000, 999999):x}</Data>
  </EventData>
</Event>'''
        
        return event_xml.strip()
    
    def _get_random_workstation(self):
        """Generate a random workstation name"""
        template = random.choice(self.workstations)
        suffix = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=6))
        return template.format(suffix)
