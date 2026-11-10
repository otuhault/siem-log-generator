- 4624/4625: These are logon and log off codes. These may help with identifying brute-force attempts, or other instances of compromised account usage on a network.
- 4672: This code indicates that elevated/administrative privileges have been granted, which may indicate privilege escalation.
- 4688: This code tracks new processes being created, which may be the result of commands, or program execution. Watching for cmd.exe or Powershell activity involving this code can be important.
- 4776: This code indicates Authentication through NTLM, which could indicate pass the hash attacks, or lateral movement through a network.
- 4738: This event is logged whenever a user account is altered, such as when an account is granted Administrator privileges.
- 4732: This event is logged when user accounts are added to a security enabled local group (usually groups with elevated privileges).
- 1102: signifies the security audit log has been cleared


Settings > Fields > Workflow actions +Add new
 This opens a configuration page for a new Workflow action. Enter the following information in the configuration page:
---
- **Destination app**: SplunkEnterpriseSecuritySuite
- **Name**: WinEventCodeLookup
- **Label**: Windows Event Code Lookup
- **Apply only to the following fields**: EventCode
- **Apply only to the following event types**: *
- **Show action in**: Event menu
- **Action type**: link
- **URI**: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-$EventCode$
- **Open link in**: New window
- **Link method**: get

The Logon_Type 3 in Windows Events logs indicate that a user accessed a computer or resource over the network. In other words, not sitting directly at the computer that has those resources.