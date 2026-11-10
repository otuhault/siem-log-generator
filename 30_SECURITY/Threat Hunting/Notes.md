# PEAK Framework
Prepare, Execute, Act with Knowledge

# ABLE Table
- Actor
- Behavior
- Location
- Evidence
### Example
**1. Actor:** Multiple threat actors have used this technique, there is not a particular actor we have in mind for this example.

**2. Behavior:** For this hunt, we are looking for hidden malicious activity on Windows hosts, run through Encoded Powershell Commands. While there are other types of obfuscation techniques, it is important to narrow down our hunting specifications.

**3. Location:** Since we are looking for Powershell Commands, we should be searching across all our Windows Systems. Because we are looking at process activities we will be working with the Windows Sysmon (System Monitor) logs.

**4. Evidence:** Powershell commands with variations of the -encodedcommand flag in Sysmon Process creation logs would confirm Powershell encoded command activity in our network. We should be looking for those. If you are not familiar with variations of the -encodedcommand or what this command may look like, this is a good time to do some research!

