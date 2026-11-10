r"""PowerShell Script Block Logging (EventID 4104), as Splunk_TA_windows reads it.

When Script Block Logging is enabled, the PowerShell engine writes every block of
code it compiles to Microsoft-Windows-PowerShell/Operational as a 4104. That is
the whole channel's value: the *source text* is on the wire, before any
obfuscation the caller applied at the command line is undone by the parser. 121
published Splunk detections read it, more than any other single Windows field.

Two things about the wire matter, exactly as for Sysmon:

  sourcetype   XmlWinEventLog
  source       XmlWinEventLog:Microsoft-Windows-PowerShell/Operational

Everything the add-on grants this channel lives in a
`[source::XmlWinEventLog:Microsoft-Windows-PowerShell/Operational]` stanza — two
lines, no more:

    REPORT-dest_for_microsoft_windows_powershell = Computer_as_dest
    EVAL-signature = case(EventCode==4103,"...Executing Pipeline",
                          EventCode==4104,"...Execute a Remote Command")

Send these under the wrong source and `dest` and `signature` are both empty.

No datamodel. This is the part worth stating plainly, because it differs from
every other Windows source here. The channel matches two eventtypes —
`windows_event_signature` (sourcetype=XmlWinEventLog) and `windows_ta_data`
(source=XmlWinEventLog:*) — and between them they carry one tag,
`track_event_signatures`, which is not a CIM tag. So a 4104 reaches no
datamodel at all, and every one of the 121 detections is a raw search. The
add-on's own data_sources entry agrees: `supported_TA:` is empty.

The rest of the fields come from Splunk_TA_windows' generic `[XmlWinEventLog]`
handling, which is why the shape below is load-bearing:

  - `<Data Name='...'>` in single quotes. The add-on's `eventdata_xml_data`
    transform reads `<(?:\w+)\sName='([^>]*)'\/?>([^<]*)`, so double quotes
    extract nothing — and it captures `[^<]*`, which is why the script text has
    to be XML-escaped rather than sent raw.
  - The `<System>` attributes feed `Name` (the provider), `Guid`, `ProcessID`
    and `UserID` through `system_props_xml_attributes`; `UserID` then becomes
    `user_id`. 107 of the 121 detections group by all four.
  - `<Security UserID='...'/>` is a SID. This channel carries no user *name*
    anywhere, so there is no `user` field to build and the two detections that
    report one get it by renaming `UserID`.
  - `Path` is the script file a block came from, and is empty for anything typed
    at a prompt. Both happen on a real host, so both are generated here; one
    detection groups by `Path` with no `fillnull` in front of it.

Script blocks over roughly 20 KB are split across several events sharing one
ScriptBlockId, with MessageNumber counting up to MessageTotal. Nothing generated
here comes close to that size, so every event is 1 of 1 — as it would be on a
real host.

One deliberate departure from the wire. A real 4104 carries the script's own
line breaks inside ScriptBlockText — 14 of the 25 attack_data datasets for this
source are multi-line, with bare LFs, which is why the add-on sets
`LINE_BREAKER=([\r\n]+)<Event\sxmlns` rather than relying on the default. This
app's contract is one event per line, for every source and every destination, so
the blocks below are all one-liners. That is a real shape — an interactive
command or a `;`-separated script is exactly this — but it is not the only one,
and carrying multi-line text would be a delivery-layer change, not a source one.

The benign corpus is deliberately kept clear of all 121 published detections on
this data source. `tests/test_powershell_4104.py` re-checks that by evaluating
each detection's own filter against every block generated here, so noise cannot
quietly start firing rules — it is what caught `Re`+`start-Service` matching
`*start-service*` and `Get-LocalGroup`+`Member` matching `*get-localgroup*`.
"""

import hashlib
import random
from datetime import datetime, timedelta, timezone

from .ai_entity import AIEntityMixin


#: The one channel PowerShell writes compiled script blocks to.
CHANNEL = 'Microsoft-Windows-PowerShell/Operational'

#: Provider identity, straight off a real event. `Name` and `Guid` are both
#: extracted by the add-on and both grouped by, so neither is decorative.
PROVIDER_NAME = 'Microsoft-Windows-PowerShell'
PROVIDER_GUID = '{A0C1853B-5C40-4B15-8766-3CF1C58F985A}'

#: Script block logging. The other ID this add-on stanza names is 4103,
#: "Executing Pipeline", which carries a different EventData and is not
#: generated yet.
SCRIPT_BLOCK_EVENT_ID = 4104

#: The System block of a 4104, as the engine writes it: verbose level, task 2,
#: opcode 15, and no keywords at all.
VERSION = '1'
LEVEL = '5'
TASK = '2'
OPCODE = '15'
KEYWORDS = '0x0'

#: SYSTEM. Scheduled tasks and management agents run their scripts as this.
SYSTEM_SID = 'S-1-5-18'

WORKSTATIONS = ['WKS-FIN01', 'WKS-HR04', 'WIN10-21H1', 'WIN11-22H2', 'DESKTOP-K2M8QP1']
USERS = ['jsmith', 'a.moreau', 'mdupont', 'localuser', 'svc_backup']

#: Typed at a prompt or pasted into a console: Path is empty for all of these.
#: Ordinary fleet administration, and none of it matches a published detection.
INTERACTIVE_BLOCKS = [
    "prompt",
    '"PS $($executionContext.SessionState.Path.CurrentLocation)'
    "$('>' * ($nestedPromptLevel + 1)) \"",
    "Get-Service -Name BITS | Select-Object Status, StartType",
    "Get-Volume | Where-Object { $_.DriveLetter -eq 'C' } | "
    "Select-Object SizeRemaining, Size",
    "Get-EventLog -LogName System -Newest 20 | Format-Table TimeGenerated, Source",
    "Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address",
    "Get-ChildItem -Path 'C:\\ProgramData\\Corp\\reports' -File | "
    "Sort-Object LastWriteTime -Descending",
    "Get-Content -Path 'C:\\ProgramData\\Corp\\agent.log' -Tail 50",
    "Import-Module Microsoft.PowerShell.Management",
    "Set-Location C:\\Temp; Get-Date -Format o",
    "$PSVersionTable.PSVersion",
    "Get-Printer | Where-Object { $_.PrinterStatus -ne 'Normal' }",
    "Get-ScheduledTask -TaskPath '\\Corp\\' | Select-Object TaskName, State",
    "Get-Disk | Select-Object Number, FriendlyName, HealthStatus",
    "Get-ChildItem Env: | Sort-Object Name | Select-Object Name, Value",
    "Set-Service -Name Spooler -StartupType Automatic",
    "Test-Path -Path 'C:\\Program Files\\Corp\\Agent\\agent.exe'",
    "[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName",
]

#: Blocks compiled out of a file. Path carries the file, which is what makes a
#: script-backed 4104 different from an interactive one.
SCRIPT_FILES = [
    ("C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\PSReadLine\\PSReadLine.psm1",
     "function Get-PSReadLineOption { [CmdletBinding()] param() "
     "[Microsoft.PowerShell.PSConsoleReadLine]::GetOptions() }"),
    ("C:\\Program Files\\WindowsPowerShell\\Modules\\PowerShellGet\\2.2.5\\PSModule.psm1",
     "function Get-ModuleDependencies { param([PSModuleInfo]$Module) "
     "$Module.RequiredModules | ForEach-Object { $_.Name } }"),
    ("C:\\ProgramData\\chocolatey\\helpers\\chocolateyInstaller.psm1",
     "function Get-ChocolateyPath { param([string]$Name) "
     "Join-Path $env:ChocolateyInstall (Join-Path 'lib' $Name) }"),
    ("C:\\Scripts\\Rotate-Logs.ps1",
     "$cutoff = (Get-Date).AddDays(-30); "
     "Get-ChildItem -Path 'D:\\Logs' -Filter *.log | "
     "Where-Object { $_.LastWriteTime -lt $cutoff } | Remove-Item -Force"),
    ("C:\\Scripts\\Report-DiskSpace.ps1",
     "$rows = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } | "
     "Select-Object DriveLetter, "
     "@{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}}; "
     "$rows | Export-Csv -Path 'D:\\Reports\\disk.csv' -NoTypeInformation"),
    ("C:\\Users\\Public\\Documents\\Set-Locale.ps1",
     "Set-WinSystemLocale -SystemLocale fr-FR; "
     "Set-TimeZone -Id 'Romance Standard Time'"),
]

#: Management agents compile their own scripts, and run them as SYSTEM.
MACHINE_SCRIPTS = [
    ("C:\\Windows\\CCM\\SystemTemp\\{guid}.ps1",
     "$app = Get-CimInstance -ClassName Win32_Product -Filter "
     "\"Name LIKE 'Corp %'\"; "
     "if ($null -eq $app) { exit 1 } else { exit 0 }"),
    ("C:\\Windows\\CCM\\SystemTemp\\{guid}.ps1",
     "Get-CimInstance -ClassName Win32_QuickFixEngineering | "
     "Select-Object HotFixID, InstalledOn"),
    ("C:\\Program Files\\Corp\\Agent\\tasks\\inventory.ps1",
     "$data = @{ host = $env:COMPUTERNAME; "
     "os = [System.Environment]::OSVersion.VersionString }; "
     "$data | ConvertTo-Json -Compress | "
     "Set-Content -Path 'C:\\ProgramData\\Corp\\inventory.json'"),
    ("C:\\Windows\\TEMP\\Update-Defs.ps1",
     "Update-MpSignature -UpdateSource MicrosoftUpdateServer"),
]


def _xml_escape(text) -> str:
    """Escape element text.

    Required, not cosmetic: `eventdata_xml_data` captures `([^<]*)`, so a raw
    `<` in a script block would truncate the extracted value at that character.
    """
    return (str(text).replace('&', '&amp;')
                     .replace('<', '&lt;')
                     .replace('>', '&gt;'))


def user_sid(account: str) -> str:
    """A stable SID for an account name.

    The channel identifies the caller by SID only — there is no user name
    anywhere in a 4104 — so an account has to be represented as one. Deriving it
    from the name rather than drawing at random keeps the same account on the
    same SID across events, which is what the detections group by.
    """
    digest = hashlib.sha256(account.encode('utf-8')).digest()
    parts = [int.from_bytes(digest[i:i + 4], 'big') for i in range(0, 12, 4)]
    rid = 1000 + int.from_bytes(digest[12:14], 'big') % 9000
    return f"S-1-5-21-{'-'.join(str(p) for p in parts)}-{rid}"


def script_block_id() -> str:
    """The engine's per-block GUID, in the lower-case form it writes."""
    return (f'{random.randint(0, 0xFFFFFFFF):08x}-{random.randint(0, 0xFFFF):04x}-'
            f'{random.randint(0, 0xFFFF):04x}-{random.randint(0, 0xFFFF):04x}-'
            f'{random.randint(0, 0xFFFFFFFFFFFF):012x}')


def activity_id() -> str:
    """The Correlation ActivityID, in the upper-case braced form."""
    return (f'{{{random.randint(0, 0xFFFFFFFF):08X}-{random.randint(0, 0xFFFF):04X}-'
            f'{random.randint(0, 0xFFFF):04X}-{random.randint(0, 0xFFFF):04X}-'
            f'{random.randint(0, 0xFFFFFFFFFFFF):012X}}}')


class PowerShellLogGenerator(AIEntityMixin):
    """PowerShell script block logging, rendered as the forwarder sends it."""

    LOG_TYPE = 'powershell'
    AVG_LOG_SIZE = 1000

    SOURCETYPE_CONFIG = {
        'param_key': 'event_categories',
        'defaults': ['script_block'],
        'multi_instance': False,
    }

    METADATA = {
        'name': 'PowerShell',
        'description': 'Windows PowerShell script block logging (EventID 4104)',
        'example': "EventID 4104 - Creating Scriptblock text (1 of 1)",
        'sources': [
            {'id': 'script_block', 'name': 'Script block logging',
             'sourcetype': 'XmlWinEventLog:Microsoft-Windows-PowerShell/Operational',
             'description': 'EventID 4104 — the source text of every block the '
                            'engine compiled, with the script it came from'},
        ],
    }

    #: Which EventID each selectable category emits. 4103 belongs here too, in
    #: the same add-on stanza, once its EventData is modelled.
    CATEGORY_EVENT_ID = {'script_block': SCRIPT_BLOCK_EVENT_ID}

    def __init__(self, event_categories=None):
        chosen = event_categories or list(self.SOURCETYPE_CONFIG['defaults'])
        self.event_categories = [c for c in chosen if c in self.CATEGORY_EVENT_ID] \
            or list(self.CATEGORY_EVENT_ID)
        self.event_count = 0
        self._record_id = random.randint(1000, 90000)

        # Pools A&I overrides, read through the mixin so the host and the
        # account on it come from the same entity.
        self.hostnames = list(WORKSTATIONS)
        self.usernames = list(USERS)

        # One builder per selectable category, as auditd, fortigate and sysmon
        # do it: the dispatch is data, so what produced an event is observable.
        self._builders = {
            category: (lambda: self.script_block_event())
            for category in self.event_categories
        }

    # ── rendering ───────────────────────────────────────────────────────────

    def generate(self) -> str:
        self.event_count += 1
        build = self._builders[random.choice(list(self._builders))]
        return self.render(build())

    def script_block_event(self, *, script_block_text=None, path=None, dest=None,
                           user=None, as_system=None):
        """One EventID 4104, benign unless the caller says otherwise.

        `path` is honoured as given, including an empty string — that is what an
        interactive block looks like, and it is a real state, not a missing one.
        """
        if script_block_text is None:
            # Roughly a quarter of the blocks on a managed host are compiled by
            # a management agent running as SYSTEM, and those always come from a
            # file. The rest split between scripts and the console.
            roll = random.random()
            if roll < 0.25:
                path_template, script_block_text = random.choice(MACHINE_SCRIPTS)
                path = path if path is not None else path_template.format(
                    guid=script_block_id())
                # A caller that named a user meant that user, so only default to
                # SYSTEM when none was given.
                if as_system is None:
                    as_system = user is None
            elif roll < 0.60:
                file_path, script_block_text = random.choice(SCRIPT_FILES)
                path = file_path if path is None else path
            else:
                script_block_text = random.choice(INTERACTIVE_BLOCKS)
                path = '' if path is None else path

        self._new_entity()
        host = dest or self._entity_field(
            'hostnames', lambda: random.choice(self.hostnames))
        account = user or self._entity_field(
            'usernames', lambda: random.choice(self.usernames))

        return {
            'event_id': SCRIPT_BLOCK_EVENT_ID,
            'dest': host,
            # No user name travels on this channel; the account is carried as
            # the SID the engine recorded.
            'user_id': SYSTEM_SID if as_system else user_sid(str(account)),
            'script_block_text': script_block_text,
            'script_block_id': script_block_id(),
            'path': '' if path is None else path,
            # Nothing generated here is anywhere near the ~20 KB the engine
            # splits a block at, so every event is part 1 of 1.
            'message_number': 1,
            'message_total': 1,
            'process_id': random.randint(400, 12000),
            'thread_id': random.randint(600, 9000),
            'utc_time': datetime.now(timezone.utc)
            - timedelta(seconds=random.randint(0, 300)),
        }

    def render(self, event) -> str:
        """The event as the forwarder puts it on the wire: one line of XML."""
        when = event['utc_time']
        self._record_id += random.randint(1, 40)

        data = [('MessageNumber', event['message_number']),
                ('MessageTotal', event['message_total']),
                ('ScriptBlockText', event['script_block_text']),
                ('ScriptBlockId', event['script_block_id']),
                ('Path', event['path'])]

        # Single quotes on Data Name: the add-on's eventdata_xml_data transform
        # reads `Name='...'`, and double quotes would extract nothing.
        event_data = ''.join(
            f"<Data Name='{name}'>{_xml_escape(value)}</Data>" for name, value in data)

        return (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System><Provider Name='{PROVIDER_NAME}' Guid='{PROVIDER_GUID}'/>"
            f"<EventID>{event['event_id']}</EventID>"
            f'<Version>{VERSION}</Version><Level>{LEVEL}</Level>'
            f'<Task>{TASK}</Task><Opcode>{OPCODE}</Opcode>'
            f'<Keywords>{KEYWORDS}</Keywords>'
            # Nine fractional digits, as every one of the 127 real 4104 events
            # checked carries — %f gives six of them.
            f"<TimeCreated SystemTime='{when.strftime('%Y-%m-%dT%H:%M:%S.%f')}000Z'/>"
            f'<EventRecordID>{self._record_id}</EventRecordID>'
            f"<Correlation ActivityID='{activity_id()}'/>"
            f"<Execution ProcessID='{event['process_id']}' "
            f"ThreadID='{event['thread_id']}'/>"
            f'<Channel>{CHANNEL}</Channel>'
            f"<Computer>{event['dest']}</Computer>"
            f"<Security UserID='{event['user_id']}'/>"
            f'</System><EventData>{event_data}</EventData></Event>'
        )
