"""
Active Directory Event Log Generator
Generates realistic Windows Event Logs (XmlWinEventLog) for Active Directory
Domain Controller security events.
"""

import random
from datetime import datetime, timedelta


class ActiveDirectoryLogGenerator:
    """Generates Active Directory domain controller event logs in XML format"""

    def __init__(self, event_categories=None):
        """
        Initialize the AD log generator.

        Args:
            event_categories: list of categories to generate from.
                Options: 'account_management', 'group_management',
                         'directory_service', 'authentication', 'computer_management'
        """
        self.event_categories = event_categories or [
            'account_management', 'group_management',
            'directory_service', 'authentication', 'computer_management'
        ]

        self.provider_name = 'Microsoft-Windows-Security-Auditing'
        self.provider_guid = '{54849625-5478-4994-A5BA-3E3B0328C30D}'

        # Domain controllers
        self.domain_controllers = [
            'DC01.contoso.local', 'DC02.contoso.local', 'DC03.corp.local',
            'AD-DC01.prod.local', 'DC-PRIMARY.contoso.local',
        ]

        self.domains = ['CONTOSO', 'CORP', 'PROD']
        self.domain_dns = ['contoso.local', 'corp.local', 'prod.local']

        # Admin accounts that perform AD operations
        self.admin_users = [
            'dadmin', 'svc_ad', 'admin', 'domainadmin', 'tier0admin',
            'svc_sccm', 'svc_exchange', 'adm_jsmith', 'adm_mdoe',
        ]

        # Regular users (targets of AD operations)
        self.target_users = [
            'jsmith', 'mdoe', 'bwilson', 'agarcia', 'clee', 'dmartin',
            'ejohnson', 'ftaylor', 'gwhite', 'hbrown', 'ijones', 'klewis',
            'lclark', 'mhall', 'nallen', 'oyoung', 'pking', 'qwright',
            'rlopez', 'scott', 'thill', 'ugreen', 'vadams', 'wnelson',
            'xbaker', 'yrivera', 'zcarter', 'new_employee', 'temp_user',
            'intern01', 'contractor01', 'vendor_access',
        ]

        # Computer accounts
        self.computer_accounts = [
            'DESKTOP-ABC123$', 'DESKTOP-XYZ789$', 'LAPTOP-DEV01$',
            'WKS-FIN01$', 'WKS-HR02$', 'SRV-APP01$', 'SRV-DB01$',
            'SRV-WEB01$', 'SRV-FILE01$', 'LAPTOP-EXEC1$', 'WKS-IT01$',
            'SRV-EXCH01$', 'SRV-SQL01$', 'SRV-PRINT01$',
        ]

        # Security groups
        self.groups = [
            ('Domain Admins', 'S-1-5-21-DOMAIN-512', 'group'),
            ('Enterprise Admins', 'S-1-5-21-DOMAIN-519', 'group'),
            ('Schema Admins', 'S-1-5-21-DOMAIN-518', 'group'),
            ('Domain Users', 'S-1-5-21-DOMAIN-513', 'group'),
            ('Domain Computers', 'S-1-5-21-DOMAIN-515', 'group'),
            ('Administrators', 'S-1-5-32-544', 'group'),
            ('Remote Desktop Users', 'S-1-5-32-555', 'group'),
            ('Backup Operators', 'S-1-5-32-551', 'group'),
            ('IT-Support', 'S-1-5-21-DOMAIN-1201', 'group'),
            ('VPN-Users', 'S-1-5-21-DOMAIN-1301', 'group'),
            ('Finance-Team', 'S-1-5-21-DOMAIN-1401', 'group'),
            ('HR-Team', 'S-1-5-21-DOMAIN-1501', 'group'),
            ('Developers', 'S-1-5-21-DOMAIN-1601', 'group'),
        ]

        # OUs for object placement
        self.ous = [
            'CN=Users,DC=contoso,DC=local',
            'OU=Employees,DC=contoso,DC=local',
            'OU=IT,OU=Employees,DC=contoso,DC=local',
            'OU=Finance,OU=Employees,DC=contoso,DC=local',
            'OU=HR,OU=Employees,DC=contoso,DC=local',
            'OU=Servers,DC=contoso,DC=local',
            'OU=Workstations,DC=contoso,DC=local',
            'OU=Service Accounts,DC=contoso,DC=local',
            'OU=Disabled Accounts,DC=contoso,DC=local',
        ]

        # LDAP attributes commonly modified
        self.ldap_attributes = [
            ('userAccountControl', '2.5.5.9', '512'),
            ('memberOf', '2.5.5.1', None),
            ('description', '2.5.5.12', None),
            ('displayName', '2.5.5.12', None),
            ('mail', '2.5.5.12', None),
            ('telephoneNumber', '2.5.5.12', None),
            ('title', '2.5.5.12', None),
            ('department', '2.5.5.12', None),
            ('manager', '2.5.5.1', None),
            ('userPassword', '2.5.5.10', None),
            ('lockoutTime', '2.5.5.16', '0'),
            ('pwdLastSet', '2.5.5.16', None),
            ('servicePrincipalName', '2.5.5.12', None),
            ('msDS-AllowedToDelegateTo', '2.5.5.12', None),
        ]

        # AD object type GUIDs
        self.object_type_guids = {
            'user': '%{bf967aba-0de6-11d0-a285-00aa003049e2}',
            'group': '%{bf967a9c-0de6-11d0-a285-00aa003049e2}',
            'computer': '%{bf967a86-0de6-11d0-a285-00aa003049e2}',
            'organizationalUnit': '%{bf967aa5-0de6-11d0-a285-00aa003049e2}',
            'domainDNS': '%{19195a5b-6da0-11d0-afd3-00c04fd930c9}',
        }

        # Replication property GUIDs (important for DCSync detection)
        self.replication_guids = {
            'DS-Replication-Get-Changes': '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}',
            'DS-Replication-Get-Changes-All': '{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}',
            'DS-Replication-Get-Changes-In-Filtered-Set': '{89e95b76-444d-4c62-991a-0facbeda640c}',
        }

        # Build weighted event list per category
        self._event_generators = {
            'account_management': [
                (self._generate_4720, 15),   # User Account Created
                (self._generate_4722, 10),   # User Account Enabled
                (self._generate_4725, 8),    # User Account Disabled
                (self._generate_4726, 5),    # User Account Deleted
                (self._generate_4738, 20),   # User Account Changed
                (self._generate_4740, 12),   # User Account Locked Out
                (self._generate_4767, 10),   # User Account Unlocked
                (self._generate_4781, 3),    # Account Name Changed
            ],
            'group_management': [
                (self._generate_4728, 25),   # Member Added to Global Security Group
                (self._generate_4729, 15),   # Member Removed from Global Security Group
                (self._generate_4732, 20),   # Member Added to Local Security Group
                (self._generate_4733, 10),   # Member Removed from Local Security Group
                (self._generate_4756, 15),   # Member Added to Universal Security Group
                (self._generate_4757, 10),   # Member Removed from Universal Security Group
            ],
            'directory_service': [
                (self._generate_5136, 40),   # Directory Service Object Modified
                (self._generate_5137, 10),   # Directory Service Object Created
                (self._generate_4662, 50),   # Operation Performed on Object
            ],
            'authentication': [
                (self._generate_4768, 35),   # Kerberos TGT Requested
                (self._generate_4769, 40),   # Kerberos Service Ticket Requested
                (self._generate_4771, 15),   # Kerberos Pre-Auth Failed
                (self._generate_4776, 10),   # NTLM Authentication
            ],
            'computer_management': [
                (self._generate_4741, 30),   # Computer Account Created
                (self._generate_4742, 45),   # Computer Account Changed
                (self._generate_4743, 10),   # Computer Account Deleted
            ],
        }

    def _random_sid(self):
        """Generate a realistic SID"""
        base = random.choice([
            '3457937927-2839227994-823803824',
            '1234567890-9876543210-1122334455',
            '5678901234-4321098765-6677889900',
        ])
        rid = random.randint(1000, 9999)
        return f'S-1-5-21-{base}-{rid}'

    def _random_guid(self):
        """Generate a random GUID"""
        parts = [
            f'{random.randint(0, 0xFFFFFFFF):08x}',
            f'{random.randint(0, 0xFFFF):04x}',
            f'{random.randint(0, 0xFFFF):04x}',
            f'{random.randint(0, 0xFFFF):04x}',
            f'{random.randint(0, 0xFFFFFFFFFFFF):012x}',
        ]
        return f'{{{parts[0]}-{parts[1]}-{parts[2]}-{parts[3]}-{parts[4]}}}'

    def _system_block(self, event_id, task, computer=None):
        """Generate the System block common to all events"""
        timestamp = datetime.now().isoformat() + 'Z'
        computer = computer or random.choice(self.domain_controllers)
        return f'''  <System>
    <Provider Name="{self.provider_name}" Guid="{self.provider_guid}" />
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>{task}</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{timestamp}" />
    <EventRecordID>{random.randint(100000, 999999)}</EventRecordID>
    <Correlation />
    <Execution ProcessID="{random.randint(500, 1200)}" ThreadID="{random.randint(1000, 9000)}" />
    <Channel>Security</Channel>
    <Computer>{computer}</Computer>
    <Security />
  </System>'''

    def _subject_block(self, admin_user=None):
        """Generate Subject EventData fields"""
        user = admin_user or random.choice(self.admin_users)
        domain = random.choice(self.domains)
        return f'''    <Data Name="SubjectUserSid">{self._random_sid()}</Data>
    <Data Name="SubjectUserName">{user}</Data>
    <Data Name="SubjectDomainName">{domain}</Data>
    <Data Name="SubjectLogonId">0x{random.randint(0x10000, 0xFFFFF):x}</Data>'''

    # ===== Account Management (4720, 4722, 4725, 4726, 4738, 4740, 4767, 4781) =====

    def _user_account_fields(self, target_user=None):
        """Common fields for user account events"""
        user = target_user or random.choice(self.target_users)
        domain = random.choice(self.domains)
        return user, domain, f'''    <Data Name="TargetUserName">{user}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="TargetSid">{self._random_sid()}</Data>'''

    def _generate_4720(self):
        """Event 4720 - A user account was created"""
        user, domain, target = self._user_account_fields()
        ou = random.choice(self.ous)
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4720, 13824)}
  <EventData>
{self._subject_block()}
{target}
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">{user}</Data>
    <Data Name="DisplayName">{user.replace("_", " ").title()}</Data>
    <Data Name="UserPrincipalName">{user}@{random.choice(self.domain_dns)}</Data>
    <Data Name="HomeDirectory">-</Data>
    <Data Name="HomePath">-</Data>
    <Data Name="ScriptPath">-</Data>
    <Data Name="ProfilePath">-</Data>
    <Data Name="UserWorkstations">-</Data>
    <Data Name="PasswordLastSet">{datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')}</Data>
    <Data Name="AccountExpires">%%1794</Data>
    <Data Name="PrimaryGroupId">513</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">0x0</Data>
    <Data Name="NewUacValue">0x210</Data>
    <Data Name="UserAccountControl">%%2080 %%2082</Data>
    <Data Name="UserParameters">-</Data>
    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">%%1793</Data>
  </EventData>
</Event>'''

    def _generate_4722(self):
        """Event 4722 - A user account was enabled"""
        _, _, target = self._user_account_fields()
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4722, 13824)}
  <EventData>
{self._subject_block()}
{target}
  </EventData>
</Event>'''

    def _generate_4725(self):
        """Event 4725 - A user account was disabled"""
        _, _, target = self._user_account_fields()
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4725, 13824)}
  <EventData>
{self._subject_block()}
{target}
  </EventData>
</Event>'''

    def _generate_4726(self):
        """Event 4726 - A user account was deleted"""
        _, _, target = self._user_account_fields()
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4726, 13824)}
  <EventData>
{self._subject_block()}
{target}
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>'''

    def _generate_4738(self):
        """Event 4738 - A user account was changed"""
        user, domain, target = self._user_account_fields()
        uac_old = random.choice(['0x210', '0x200', '0x10200'])
        uac_new = random.choice(['0x210', '0x200', '0x10200', '0x10210'])
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4738, 13824)}
  <EventData>
{self._subject_block()}
{target}
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">{user}</Data>
    <Data Name="DisplayName">{user.replace("_", " ").title()}</Data>
    <Data Name="UserPrincipalName">{user}@{random.choice(self.domain_dns)}</Data>
    <Data Name="HomeDirectory">-</Data>
    <Data Name="HomePath">-</Data>
    <Data Name="ScriptPath">-</Data>
    <Data Name="ProfilePath">-</Data>
    <Data Name="UserWorkstations">-</Data>
    <Data Name="PasswordLastSet">-</Data>
    <Data Name="AccountExpires">-</Data>
    <Data Name="PrimaryGroupId">-</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">{uac_old}</Data>
    <Data Name="NewUacValue">{uac_new}</Data>
    <Data Name="UserAccountControl">-</Data>
    <Data Name="UserParameters">-</Data>
    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">-</Data>
  </EventData>
</Event>'''

    def _generate_4740(self):
        """Event 4740 - A user account was locked out"""
        _, _, target = self._user_account_fields()
        caller = random.choice(self.computer_accounts).replace('$', '')
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4740, 13824)}
  <EventData>
{self._subject_block()}
{target}
    <Data Name="TargetDomainName">{random.choice(self.domains)}</Data>
  </EventData>
</Event>'''

    def _generate_4767(self):
        """Event 4767 - A user account was unlocked"""
        _, _, target = self._user_account_fields()
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4767, 13824)}
  <EventData>
{self._subject_block()}
{target}
  </EventData>
</Event>'''

    def _generate_4781(self):
        """Event 4781 - The name of an account was changed"""
        old_name = random.choice(self.target_users)
        new_name = f'{old_name}_renamed'
        domain = random.choice(self.domains)
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4781, 13824)}
  <EventData>
{self._subject_block()}
    <Data Name="OldTargetUserName">{old_name}</Data>
    <Data Name="NewTargetUserName">{new_name}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="TargetSid">{self._random_sid()}</Data>
  </EventData>
</Event>'''

    # ===== Group Management (4728, 4729, 4732, 4733, 4756, 4757) =====

    def _group_membership_event(self, event_id):
        """Generate group membership change event"""
        group_name, group_sid, _ = random.choice(self.groups)
        member = random.choice(self.target_users)
        member_sid = self._random_sid()
        domain = random.choice(self.domains)
        # Task 13826 = Security Group Management
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(event_id, 13826)}
  <EventData>
{self._subject_block()}
    <Data Name="MemberName">CN={member},{random.choice(self.ous)}</Data>
    <Data Name="MemberSid">{member_sid}</Data>
    <Data Name="TargetUserName">{group_name}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="TargetSid">{group_sid.replace("DOMAIN", "3457937927-2839227994-823803824")}</Data>
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>'''

    def _generate_4728(self):
        """Event 4728 - Member Added to Global Security Group"""
        return self._group_membership_event(4728)

    def _generate_4729(self):
        """Event 4729 - Member Removed from Global Security Group"""
        return self._group_membership_event(4729)

    def _generate_4732(self):
        """Event 4732 - Member Added to Local Security Group"""
        return self._group_membership_event(4732)

    def _generate_4733(self):
        """Event 4733 - Member Removed from Local Security Group"""
        return self._group_membership_event(4733)

    def _generate_4756(self):
        """Event 4756 - Member Added to Universal Security Group"""
        return self._group_membership_event(4756)

    def _generate_4757(self):
        """Event 4757 - Member Removed from Universal Security Group"""
        return self._group_membership_event(4757)

    # ===== Directory Service (5136, 5137, 4662) =====

    def _generate_5136(self):
        """Event 5136 - A directory service object was modified"""
        target_user = random.choice(self.target_users)
        attr_name, attr_oid, default_val = random.choice(self.ldap_attributes)
        domain_dns = random.choice(self.domain_dns)
        dc_parts = ','.join(f'DC={p}' for p in domain_dns.split('.'))
        obj_dn = f'CN={target_user},{random.choice(self.ous)}'

        if attr_name == 'mail':
            attr_value = f'{target_user}@{domain_dns}'
        elif attr_name == 'telephoneNumber':
            attr_value = f'+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}'
        elif attr_name == 'title':
            attr_value = random.choice(['Engineer', 'Manager', 'Director', 'Analyst', 'Administrator'])
        elif attr_name == 'department':
            attr_value = random.choice(['IT', 'Finance', 'HR', 'Engineering', 'Sales', 'Marketing'])
        elif attr_name == 'description':
            attr_value = random.choice(['Standard user account', 'Service account', 'Temporary access', 'Contractor'])
        elif default_val:
            attr_value = default_val
        else:
            attr_value = '-'

        op_type = random.choice([('%%14674', 'Value Added'), ('%%14675', 'Value Deleted')])

        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(5136, 14081)}
  <EventData>
    <Data Name="OpCorrelationID">{self._random_guid()}</Data>
    <Data Name="AppCorrelationID">-</Data>
{self._subject_block()}
    <Data Name="DSName">{domain_dns}</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">{obj_dn}</Data>
    <Data Name="ObjectGUID">{self._random_guid()}</Data>
    <Data Name="ObjectClass">user</Data>
    <Data Name="AttributeLDAPDisplayName">{attr_name}</Data>
    <Data Name="AttributeSyntaxOID">{attr_oid}</Data>
    <Data Name="AttributeValue">{attr_value}</Data>
    <Data Name="OperationType">{op_type[0]}</Data>
  </EventData>
</Event>'''

    def _generate_5137(self):
        """Event 5137 - A directory service object was created"""
        target = random.choice(self.target_users)
        domain_dns = random.choice(self.domain_dns)
        obj_class = random.choice(['user', 'group', 'organizationalUnit', 'computer'])

        if obj_class == 'computer':
            target = random.choice(self.computer_accounts).replace('$', '')
        elif obj_class == 'group':
            target = random.choice([g[0] for g in self.groups])

        obj_dn = f'CN={target},{random.choice(self.ous)}'

        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(5137, 14081)}
  <EventData>
    <Data Name="OpCorrelationID">{self._random_guid()}</Data>
    <Data Name="AppCorrelationID">-</Data>
{self._subject_block()}
    <Data Name="DSName">{domain_dns}</Data>
    <Data Name="DSType">%%14676</Data>
    <Data Name="ObjectDN">{obj_dn}</Data>
    <Data Name="ObjectGUID">{self._random_guid()}</Data>
    <Data Name="ObjectClass">{obj_class}</Data>
  </EventData>
</Event>'''

    def _generate_4662(self):
        """Event 4662 - An operation was performed on an object"""
        obj_type_key = random.choice(list(self.object_type_guids.keys()))
        obj_type_guid = self.object_type_guids[obj_type_key]
        obj_name_guid = self._random_guid()

        # Access types
        access_types = [
            ('%%1537', '0x10000'),   # DELETE
            ('%%1538', '0x20000'),   # READ_CONTROL
            ('%%1539', '0x40000'),   # WRITE_DAC
            ('%%1540', '0x80000'),   # WRITE_OWNER
            ('%%7685', '0x100'),     # List Contents / Read Property
            ('%%7688', '0x10'),      # Write Property
        ]
        access_code, access_mask = random.choice(access_types)

        # Sometimes include replication GUIDs (important for DCSync detection)
        properties = f'{access_code} {obj_type_guid}'
        if random.random() < 0.05:
            repl_key = random.choice(list(self.replication_guids.keys()))
            properties = f'{access_code} {self.replication_guids[repl_key]} {obj_type_guid}'

        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4662, 14080)}
  <EventData>
{self._subject_block()}
    <Data Name="ObjectServer">DS</Data>
    <Data Name="ObjectType">{obj_type_guid}</Data>
    <Data Name="ObjectName">{obj_name_guid}</Data>
    <Data Name="OperationType">Object Access</Data>
    <Data Name="HandleId">0x0</Data>
    <Data Name="AccessList">{access_code}</Data>
    <Data Name="AccessMask">{access_mask}</Data>
    <Data Name="Properties">{properties}</Data>
    <Data Name="AdditionalInfo">-</Data>
    <Data Name="AdditionalInfo2"></Data>
  </EventData>
</Event>'''

    # ===== Authentication (4768, 4769, 4771, 4776) =====

    def _generate_4768(self):
        """Event 4768 - A Kerberos authentication ticket (TGT) was requested"""
        user = random.choice(self.target_users + self.admin_users)
        domain = random.choice(self.domain_dns)
        # Result: 0x0 = success, 0x6 = client not found, 0x12 = disabled, 0x17 = expired, 0x18 = pre-auth failed
        results = [('0x0', 30), ('0x6', 5), ('0x12', 2), ('0x17', 1), ('0x18', 10)]
        result_code = random.choices([r[0] for r in results], weights=[r[1] for r in results])[0]

        # Encryption types
        enc_types = ['0x12', '0x17', '0x18']  # AES256, RC4, RC4-old

        client_ip = f'::ffff:192.168.{random.randint(1, 254)}.{random.randint(1, 254)}'

        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4768, 14339)}
  <EventData>
    <Data Name="TargetUserName">{user}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="TargetSid">{self._random_sid()}</Data>
    <Data Name="ServiceName">krbtgt</Data>
    <Data Name="ServiceSid">{self._random_sid()}</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="Status">{result_code}</Data>
    <Data Name="TicketEncryptionType">{random.choice(enc_types)}</Data>
    <Data Name="PreAuthType">15</Data>
    <Data Name="IpAddress">{client_ip}</Data>
    <Data Name="IpPort">{random.randint(49152, 65535)}</Data>
    <Data Name="CertIssuerName"></Data>
    <Data Name="CertSerialNumber"></Data>
    <Data Name="CertThumbprint"></Data>
  </EventData>
</Event>'''

    def _generate_4769(self):
        """Event 4769 - A Kerberos service ticket was requested"""
        user = random.choice(self.target_users + self.admin_users)
        domain = random.choice(self.domain_dns)
        services = [
            f'cifs/{random.choice(self.computer_accounts).replace("$", "")}.{domain}',
            f'HTTP/{random.choice(self.computer_accounts).replace("$", "")}.{domain}',
            f'ldap/{random.choice(self.domain_controllers)}',
            f'MSSQLSvc/{random.choice(self.computer_accounts).replace("$", "")}.{domain}:1433',
            f'HOST/{random.choice(self.computer_accounts).replace("$", "")}.{domain}',
        ]
        result_code = random.choices(['0x0', '0xD', '0x20'], weights=[85, 10, 5])[0]
        client_ip = f'::ffff:192.168.{random.randint(1, 254)}.{random.randint(1, 254)}'

        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4769, 14337)}
  <EventData>
    <Data Name="TargetUserName">{user}@{domain}</Data>
    <Data Name="TargetDomainName">{domain.upper()}</Data>
    <Data Name="ServiceName">{random.choice(services)}</Data>
    <Data Name="ServiceSid">{self._random_sid()}</Data>
    <Data Name="TicketOptions">0x40810000</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="IpAddress">{client_ip}</Data>
    <Data Name="IpPort">{random.randint(49152, 65535)}</Data>
    <Data Name="Status">{result_code}</Data>
    <Data Name="LogonGuid">{self._random_guid()}</Data>
    <Data Name="TransmittedServices">-</Data>
  </EventData>
</Event>'''

    def _generate_4771(self):
        """Event 4771 - Kerberos pre-authentication failed"""
        user = random.choice(self.target_users)
        domain = random.choice(self.domain_dns)
        # Failure codes: 0x18 = bad password, 0x12 = disabled, 0x25 = clock skew
        failure_codes = [('0x18', 70), ('0x12', 15), ('0x25', 15)]
        failure = random.choices([f[0] for f in failure_codes], weights=[f[1] for f in failure_codes])[0]
        client_ip = f'::ffff:192.168.{random.randint(1, 254)}.{random.randint(1, 254)}'

        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4771, 14339)}
  <EventData>
    <Data Name="TargetUserName">{user}</Data>
    <Data Name="TargetSid">{self._random_sid()}</Data>
    <Data Name="ServiceName">krbtgt/{domain.upper()}</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="Status">{failure}</Data>
    <Data Name="PreAuthType">15</Data>
    <Data Name="IpAddress">{client_ip}</Data>
    <Data Name="IpPort">{random.randint(49152, 65535)}</Data>
    <Data Name="CertIssuerName"></Data>
    <Data Name="CertSerialNumber"></Data>
    <Data Name="CertThumbprint"></Data>
  </EventData>
</Event>'''

    def _generate_4776(self):
        """Event 4776 - The computer attempted to validate the credentials for an account (NTLM)"""
        user = random.choice(self.target_users)
        workstation = random.choice(self.computer_accounts).replace('$', '')
        # Error codes: 0x0 = success, 0xC000006A = bad password, 0xC0000234 = locked out
        errors = [('0x0', 60), ('0xC000006A', 25), ('0xC0000234', 10), ('0xC0000072', 5)]
        error = random.choices([e[0] for e in errors], weights=[e[1] for e in errors])[0]

        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4776, 14336)}
  <EventData>
    <Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>
    <Data Name="TargetUserName">{user}</Data>
    <Data Name="Workstation">{workstation}</Data>
    <Data Name="Status">{error}</Data>
  </EventData>
</Event>'''

    # ===== Computer Management (4741, 4742, 4743) =====

    def _generate_4741(self):
        """Event 4741 - A computer account was created"""
        computer = random.choice(self.computer_accounts)
        computer_name = computer.replace('$', '')
        domain = random.choice(self.domains)
        domain_dns = random.choice(self.domain_dns)
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4741, 13825)}
  <EventData>
    <Data Name="TargetUserName">{computer}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="TargetSid">{self._random_sid()}</Data>
{self._subject_block()}
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">{computer}</Data>
    <Data Name="DisplayName">-</Data>
    <Data Name="UserPrincipalName">-</Data>
    <Data Name="HomeDirectory">-</Data>
    <Data Name="HomePath">-</Data>
    <Data Name="ScriptPath">-</Data>
    <Data Name="ProfilePath">-</Data>
    <Data Name="UserWorkstations">-</Data>
    <Data Name="PasswordLastSet">{datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')}</Data>
    <Data Name="AccountExpires">%%1794</Data>
    <Data Name="PrimaryGroupId">515</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">0x0</Data>
    <Data Name="NewUacValue">0x80</Data>
    <Data Name="UserAccountControl">%%2087</Data>
    <Data Name="UserParameters">-</Data>
    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">%%1793</Data>
    <Data Name="DnsHostName">{computer_name}.{domain_dns}</Data>
    <Data Name="ServicePrincipalNames">HOST/{computer_name}.{domain_dns} RestrictedKrbHost/{computer_name}.{domain_dns} HOST/{computer_name} RestrictedKrbHost/{computer_name}</Data>
  </EventData>
</Event>'''

    def _generate_4742(self):
        """Event 4742 - A computer account was changed"""
        computer = random.choice(self.computer_accounts)
        domain = random.choice(self.domains)
        domain_dns = random.choice(self.domain_dns)
        computer_name = computer.replace('$', '')
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4742, 13825)}
  <EventData>
    <Data Name="TargetUserName">{computer}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="TargetSid">{self._random_sid()}</Data>
{self._subject_block()}
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">{computer}</Data>
    <Data Name="DisplayName">-</Data>
    <Data Name="UserPrincipalName">-</Data>
    <Data Name="HomeDirectory">-</Data>
    <Data Name="HomePath">-</Data>
    <Data Name="ScriptPath">-</Data>
    <Data Name="ProfilePath">-</Data>
    <Data Name="UserWorkstations">-</Data>
    <Data Name="PasswordLastSet">{datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')}</Data>
    <Data Name="AccountExpires">-</Data>
    <Data Name="PrimaryGroupId">-</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">0x80</Data>
    <Data Name="NewUacValue">0x80</Data>
    <Data Name="UserAccountControl">-</Data>
    <Data Name="UserParameters">-</Data>
    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">-</Data>
    <Data Name="DnsHostName">{computer_name}.{domain_dns}</Data>
    <Data Name="ServicePrincipalNames">HOST/{computer_name}.{domain_dns} RestrictedKrbHost/{computer_name}.{domain_dns} HOST/{computer_name} RestrictedKrbHost/{computer_name}</Data>
  </EventData>
</Event>'''

    def _generate_4743(self):
        """Event 4743 - A computer account was deleted"""
        computer = random.choice(self.computer_accounts)
        domain = random.choice(self.domains)
        return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
{self._system_block(4743, 13825)}
  <EventData>
    <Data Name="TargetUserName">{computer}</Data>
    <Data Name="TargetDomainName">{domain}</Data>
    <Data Name="TargetSid">{self._random_sid()}</Data>
{self._subject_block()}
    <Data Name="PrivilegeList">-</Data>
  </EventData>
</Event>'''

    # ===== Main generate method =====

    def generate(self):
        """Generate a single AD event log from configured categories"""
        # Pick a random configured category
        category = random.choice(self.event_categories)
        generators = self._event_generators.get(category, [])

        if not generators:
            category = random.choice(list(self._event_generators.keys()))
            generators = self._event_generators[category]

        # Weighted selection
        funcs = [g[0] for g in generators]
        weights = [g[1] for g in generators]
        selected = random.choices(funcs, weights=weights)[0]

        return selected().strip()
