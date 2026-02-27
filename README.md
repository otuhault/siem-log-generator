# SIEM Log Generator

A log generation tool for testing SIEM systems. Generate realistic logs from multiple sources and simulate attack scenarios to validate detection rules.

## Features

- **Multiple Log Sources**: Apache, Windows Security Event Logs, SSH, Palo Alto firewall, Active Directory, Cisco IOS
- **Built-in Attack Simulations**: SSH brute force, port scans, TOR client execution, and more
- **Dual Output**: Write to local files or send directly to Splunk via HEC (HTTP Event Collector)
- **HEC Configurations**: Create, test, and reuse Splunk HEC connection profiles
- **Web UI**: Create, edit, clone, enable/disable, and delete senders from a single dashboard
- **Real-time Monitoring**: Live log count per sender
- **Multi-threaded**: Run multiple senders and attacks simultaneously

## Installation

```bash
cd log-generator
pip install -r requirements.txt
python app.py
```

Open your browser to `http://localhost:5001`

## Log Sources (Sourcetypes)

### Apache
Generates logs in Combined Log Format (access, error, combined):
```
192.168.1.100 - - [18/Feb/2026:14:32:10 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://www.google.com/" "Mozilla/5.0 ..."
```

### Windows Security Event Log
Generates authentic Windows Event Logs in XML or Classic (text) format with 12 common Event IDs:

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4634 | Logoff |
| 4672 | Special Privileges Assigned |
| 4688 | Process Created |
| 4689 | Process Terminated |
| 4698 | Scheduled Task Created |
| 4699 | Scheduled Task Deleted |
| 4720 | User Account Created |
| 4726 | User Account Deleted |
| 4732 | Member Added to Security Group |
| 4756 | Member Added to Universal Security Group |

### SSH
Generates syslog-format SSH logs with configurable event categories:
- Authentication (success/failure), sessions, connections, errors

### Palo Alto Firewall
Generates Palo Alto PAN-OS logs in CSV syslog format:
- TRAFFIC, THREAT, SYSTEM subtypes

### Active Directory
Generates XmlWinEventLog format domain controller logs with 22 event types across 5 configurable categories:

**Account Management**

| Event ID | Description |
|----------|-------------|
| 4720 | User Account Created |
| 4722 | User Account Enabled |
| 4725 | User Account Disabled |
| 4726 | User Account Deleted |
| 4738 | User Account Changed |
| 4740 | User Account Locked Out |
| 4767 | User Account Unlocked |
| 4781 | Account Name Changed |

**Group Management**

| Event ID | Description |
|----------|-------------|
| 4728 | Member Added to Global Security Group |
| 4729 | Member Removed from Global Security Group |
| 4732 | Member Added to Local Security Group |
| 4733 | Member Removed from Local Security Group |
| 4756 | Member Added to Universal Security Group |
| 4757 | Member Removed from Universal Security Group |

**Directory Service**

| Event ID | Description |
|----------|-------------|
| 4662 | Object Access (includes DCSync replication GUIDs) |
| 5136 | Directory Service Object Modified (LDAP attributes) |
| 5137 | Directory Service Object Created |

**Authentication**

| Event ID | Description |
|----------|-------------|
| 4768 | Kerberos TGT Request |
| 4769 | Kerberos Service Ticket Request |
| 4771 | Kerberos Pre-Authentication Failed |
| 4776 | NTLM Credential Validation |

**Computer Management**

| Event ID | Description |
|----------|-------------|
| 4741 | Computer Account Created |
| 4742 | Computer Account Changed |
| 4743 | Computer Account Deleted |

### Cisco IOS
Generates Cisco IOS syslog messages (`cisco:ios` sourcetype) with 8 configurable event categories:

| Category | Facilities | Description |
|----------|-----------|-------------|
| Interface & Link Status | LINK, LINEPROTO | Interface and line protocol state changes |
| System Events | SYS, PARSER | Configuration changes, restarts, memory/CPU |
| Authentication & AAA | SEC_LOGIN, AAA, AUTHMGR | Login success/failed, user sessions, 802.1X |
| ACL & Security | SEC, FW | Access list permit/deny, zone-based firewall sessions |
| Routing Protocols | OSPF, BGP, DUAL (EIGRP) | Adjacency and neighbor changes |
| HSRP/VRRP | STANDBY | Hot Standby Router Protocol state transitions |
| Spanning Tree | SPANTREE | Topology changes, root guard, PVID inconsistency |
| Hardware & Environment | SNMP, NTP, ENV, OIR | SNMP events, NTP sync, fan failures, card insert/remove |

Format: `<seq>: <timestamp>: %<FACILITY>-<SEVERITY>-<MNEMONIC>: <message>`
```
000042: Feb 19 08:12:34.482: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up
```

## Attack Simulations

Attacks generate a finite number of events over a configurable duration, designed to trigger specific SIEM detection rules.

### SSH Attacks

| Attack | Description | Field Behaviors |
|--------|-------------|-----------------|
| SSH Brute Force | Single attacker targeting one account with repeated password attempts | user: fixed, src_ip: fixed |
| SSH Password Spraying | Single attacker trying multiple usernames from one IP | user: rotating, src_ip: fixed |
| SSH Credential Stuffing | Distributed attack with rotating users and IPs (leaked credentials) | user: rotating, src_ip: rotating |
| SSH Distributed Brute Force | Botnet targeting one account from multiple source IPs | user: fixed, src_ip: rotating |

### Network Attacks

| Attack | Description | Field Behaviors |
|--------|-------------|-----------------|
| Internal Horizontal Port Scan | Single source scanning many internal hosts on the same port (dc(dest_ip) >= 250) | src_ip: fixed, dest_ip: rotating, dest_port: fixed |
| Internal Vertical Port Scan | Single source scanning many ports on one internal host (totalDestPortCount >= 500) | src_ip: fixed, dest_ip: fixed, dest_port: rotating |

- Generates Palo Alto TRAFFIC CSV logs
- Each event produces a unique rotating value (no duplicates)
- Overridable fixed fields (src_ip, dest_ip, dest_port) via the sender form

### Endpoint Attacks

| Attack | Description | Field Behaviors |
|--------|-------------|-----------------|
| Windows TOR Client Execution | TOR browser or client execution detected on Windows endpoint (T1090.003 - Multi-hop Proxy) | user: fixed, dest: fixed |

- Generates Windows 4688 (Process Creation) XML events
- 6 TOR execution variants: Tor Browser bundle, AppData install, Brave Browser TOR, standalone from Downloads/Temp
- Overridable user and destination hostname via the sender form

### Attack Configuration

- **Events Count**: Number of events to generate (1 - 10,000)
- **Duration**: Time span over which events are spread (1 - 3,600 seconds)
- **Field Overrides**: Fixed fields can be set to a specific value or left as "Random"

## Output Destinations

### File
Write logs to a local file path (e.g., `/tmp/logs/apache.log`).

### Splunk HEC
Send logs to Splunk via HTTP Event Collector. Create a HEC configuration with:
- URL and port
- HEC token
- Optional: index, sourcetype, host, source

Test the connection before using it with senders.

## Project Structure

```
log-generator/
├── app.py                      # Flask web application (API routes)
├── log_senders.py              # Sender management, threading, attack execution
├── attack_generators.py        # Attack type definitions and generators
├── configuration_manager.py    # HEC configuration CRUD
├── hec_sender.py               # Splunk HEC client
├── log_generators/
│   ├── apache.py               # Apache log generator
│   ├── ssh.py                  # SSH log generator
│   ├── windows.py              # Windows Event Log generator
│   ├── paloalto.py             # Palo Alto PAN-OS log generator
│   ├── active_directory.py     # Active Directory log generator
│   └── cisco_ios.py            # Cisco IOS syslog generator
├── templates/
│   └── index.html              # Web UI
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── app.js              # Main app (tabs, event listeners)
│       └── modules/
│           ├── api.js           # API client
│           ├── attacks.js       # Attacks tab view
│           ├── configurations.js # HEC configurations management
│           ├── senders.js       # Sender CRUD and table
│           ├── sourcetypes.js   # Sourcetypes tab + dropdown
│           ├── state.js         # Shared state
│           ├── utils.js         # Notifications, helpers
│           └── validation.js    # Form validation
├── senders_config.json          # Persisted sender state
├── configurations.json          # Persisted HEC configurations
├── requirements.txt
├── start.sh / stop.sh           # Convenience scripts
```

## Technical Details

- **Backend**: Python 3 / Flask
- **Frontend**: Vanilla JavaScript (ES modules), responsive CSS
- **Threading**: Multi-threaded log generation with per-sender threads
- **Storage**: JSON files for senders and HEC configurations
- **Architecture**: Attack types are built-in constants with field behavior metadata; sourcetypes are discovered from generators

## Adding a New Attack Type

1. Define the attack type dict in `attack_generators.py` with `name`, `description`, `log_type`, `category`, `field_behaviors`, and `sample_logs`
2. Create a generator class with `__init__(self, field_behaviors, options)` and `generate()` methods
3. Add it to the combined `ALL_ATTACK_TYPES` dict
4. Register it in `AttackGeneratorFactory.get_generator()`

The frontend (dropdown, Attacks tab, field overrides) is fully dynamic and requires no changes.

## Adding a New Log Source

1. Create a generator class in `log_generators/` with a `generate()` method
2. Register it in `SenderManager` (log_senders.py)
3. Add it to the log types API response

## License

MIT License
