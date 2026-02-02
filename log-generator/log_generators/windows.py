"""
Windows Security Event Log Generator
Generates realistic Windows Security Event Logs in XML format
Focuses on the most common Event IDs
"""

import random
from datetime import datetime
import xml.etree.ElementTree as ET
from xml.dom import minidom

class WindowsEventLogGenerator:
    """Generates Windows Security Event Logs matching real endpoint output"""

    def __init__(self, render_format='xml'):
        self.render_format = render_format  # 'xml' or 'classic'

        # Common Event IDs with descriptions and weights
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
            # Generate based on event type
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

    def _generate_classic_format(self, event_id, description):
        """Generate event in classic text format (like Event Viewer)"""
        timestamp = datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')
        computer = self._get_random_workstation()
        domain = random.choice(self.domains)
        username = random.choice(self.usernames)

        if event_id in [4624, 4625]:
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

        elif event_id == 4688:
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

        else:
            return f'''Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
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
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
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
    <Channel>Security</Channel>
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
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
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
    <Channel>Security</Channel>
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
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
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
    <Channel>Security</Channel>
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
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
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
    <Channel>Security</Channel>
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
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
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
    <Channel>Security</Channel>
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
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}" />
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
    <Channel>Security</Channel>
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
