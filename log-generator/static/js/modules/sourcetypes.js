/**
 * Sourcetypes display module
 */

import { LogTypesApi, AttacksApi } from './api.js';
import { state, setLogTypes, setAttackTypes } from './state.js';
import { showNotification } from './utils.js';

// value → display name map, used by setLogTypeValue to restore trigger text
const _displayMap = {};

/**
 * Load log types and attacks, build the custom dropdown panel.
 * Also initialises click-outside and keyboard handlers on first call.
 */
export async function loadLogTypes() {
    try {
        const [logTypesMeta, attackTypes, envCountsRes] = await Promise.all([
            LogTypesApi.getAll(),
            AttacksApi.getTypes(),
            fetch('/api/environment/counts'),
        ]);
        const envCounts = await envCountsRes.json();

        setLogTypes(logTypesMeta);
        setAttackTypes(attackTypes);

        // Build display map and panel HTML
        const optionsEl = document.getElementById('logTypeOptions');
        optionsEl.innerHTML = '';

        // Sourcetypes group
        optionsEl.appendChild(_buildGroupLabel('Sourcetypes'));
        Object.keys(logTypesMeta).sort().forEach(key => {
            const name = logTypesMeta[key].name;
            _displayMap[key] = name;
            const counts = envCounts[key];
            optionsEl.appendChild(_buildOption(key, name, counts));
        });

        // Attack groups
        if (Object.keys(attackTypes).length > 0) {
            const categories = {};
            Object.entries(attackTypes).forEach(([key, type]) => {
                const cat = type.category || type.log_type.toUpperCase();
                if (!categories[cat]) categories[cat] = [];
                categories[cat].push({ key, ...type });
            });
            Object.keys(categories).sort().forEach(cat => {
                optionsEl.appendChild(_buildGroupLabel(`Attacks — ${cat}`));
                categories[cat].forEach(type => {
                    const label = `${type.name} — ${type.description}`;
                    _displayMap[type.key] = `${type.name} — ${type.description}`;
                    const counts    = envCounts[type.key] ?? envCounts[type.log_type];
                    // Resolve human-readable sourcetype name(s) for this attack
                    const srcTypes = type.log_type
                        ? [].concat(type.log_type).map(lt => logTypesMeta[lt]?.name || lt)
                        : [];
                    optionsEl.appendChild(_buildOption(type.key, label, counts, srcTypes));
                });
            });
        }

        _initDropdown();
    } catch (error) {
        console.error('Error loading log types:', error);
    }
}

/** Build an optgroup-style label row */
function _buildGroupLabel(text) {
    const div = document.createElement('div');
    div.className = 'csd-group-label';
    div.textContent = text;
    return div;
}

/** Build a clickable option row with optional sourcetype + env-count badges */
function _buildOption(value, name, counts, srcTypes = []) {
    const div = document.createElement('div');
    div.className = 'csd-option';
    div.dataset.value = value;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'csd-option-name';
    nameSpan.textContent = name;
    div.appendChild(nameSpan);

    const allBadges = [
        ...srcTypes.map(st => {
            const b = document.createElement('span');
            b.className = 'env-badge env-badge-sourcetype';
            b.textContent = st;
            return b;
        }),
        ..._buildBadges(counts),
    ];

    if (allBadges.length) {
        const badgeWrap = document.createElement('span');
        badgeWrap.className = 'env-badges';
        allBadges.forEach(b => badgeWrap.appendChild(b));
        div.appendChild(badgeWrap);
    }

    div.addEventListener('click', () => _selectOption(value));
    return div;
}

/** Return array of env-count badge nodes (entities + accounts), empty if nothing to show */
function _buildBadges(counts) {
    if (!counts) return [];
    const parts = [];
    if (counts.entities > 0) {
        const b = document.createElement('span');
        b.className = 'env-badge env-badge-entity';
        b.textContent = `entities (${counts.entities})`;
        parts.push(b);
    }
    if (counts.accounts > 0) {
        const b = document.createElement('span');
        b.className = 'env-badge env-badge-account';
        b.textContent = `accounts (${counts.accounts})`;
        parts.push(b);
    }
    return parts;
}

/** Select an option: update hidden input, trigger text, close panel, fire change */
function _selectOption(value) {
    const hidden  = document.getElementById('logType');
    const display = document.getElementById('logTypeDisplay');
    hidden.value  = value;
    display.textContent = _displayMap[value] || value;
    document.getElementById('logTypeWrapper').classList.remove('open');
    document.getElementById('logTypePanel').style.display = 'none';
    hidden.dispatchEvent(new Event('change', { bubbles: true }));
}

/** Wire up open/close behaviour — idempotent */
let _dropdownInited = false;
function _initDropdown() {
    if (_dropdownInited) return;
    _dropdownInited = true;

    const wrapper = document.getElementById('logTypeWrapper');
    const trigger = document.getElementById('logTypeTrigger');
    const panel   = document.getElementById('logTypePanel');

    trigger.addEventListener('click', () => {
        const open = wrapper.classList.toggle('open');
        panel.style.display = open ? 'block' : 'none';
    });

    document.addEventListener('click', (e) => {
        if (!wrapper.contains(e.target)) {
            wrapper.classList.remove('open');
            panel.style.display = 'none';
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            wrapper.classList.remove('open');
            panel.style.display = 'none';
        }
    });
}

/**
 * Set the dropdown value programmatically (used by senders.js on edit restore).
 * Updates hidden input, trigger text, and dispatches change.
 */
window.setLogTypeValue = function(value) {
    const hidden  = document.getElementById('logType');
    const display = document.getElementById('logTypeDisplay');
    hidden.value  = value;
    display.textContent = _displayMap[value] || value || 'Select a sourcetype or attack…';
    hidden.dispatchEvent(new Event('change', { bubbles: true }));
};

/**
 * Load and display sourcetypes in the Sourcetypes tab
 */
export async function loadSourcetypes() {
    try {
        const container = document.getElementById('sourcetypesContainer');

        if (!state.logTypes || Object.keys(state.logTypes).length === 0) {
            await loadLogTypes();
        }

        // Sort log types alphabetically by name
        const sortedTypes = Object.entries(state.logTypes).sort((a, b) => {
            return a[1].name.localeCompare(b[1].name);
        });

        // Create sourcetype list
        const listDiv = document.createElement('div');
        listDiv.className = 'sourcetype-list';

        sortedTypes.forEach(([key, type]) => {
            const item = document.createElement('div');
            item.className = 'sourcetype-item';
            item.dataset.type = key;

            const content = document.createElement('div');
            const name = document.createElement('div');
            name.className = 'sourcetype-name';
            name.textContent = type.name;

            const description = document.createElement('div');
            description.className = 'sourcetype-description';
            description.textContent = type.description;

            content.appendChild(name);
            content.appendChild(description);
            item.appendChild(content);

            // Check if this type has sources (e.g., Windows)
            if (type.sources && type.sources.length > 0) {
                // Add expandable arrow indicator
                const arrow = document.createElement('span');
                arrow.className = 'sourcetype-arrow';
                arrow.textContent = '›';
                item.appendChild(arrow);

                // Create sub-list for sources
                const subList = document.createElement('div');
                subList.className = 'sourcetype-sublist';
                subList.style.display = 'none';

                type.sources.forEach(source => {
                    const subItem = document.createElement('div');
                    subItem.className = 'sourcetype-subitem';
                    subItem.dataset.sourceId = source.id;

                    const subName = document.createElement('div');
                    subName.className = 'sourcetype-subname';
                    subName.textContent = source.name;

                    const subDesc = document.createElement('div');
                    subDesc.className = 'sourcetype-subdesc';
                    subDesc.textContent = source.description;

                    subItem.appendChild(subName);
                    subItem.appendChild(subDesc);

                    // Add click event to show source-specific example inline
                    subItem.addEventListener('click', (e) => {
                        e.stopPropagation();
                        toggleInlineLogExample(subItem, key, type, source.id);
                    });

                    subList.appendChild(subItem);
                });

                item.appendChild(subList);

                // Toggle sub-list on parent click
                item.addEventListener('click', () => {
                    const isExpanded = subList.style.display === 'block';
                    subList.style.display = isExpanded ? 'none' : 'block';
                    arrow.textContent = isExpanded ? '›' : '⌄';
                    item.classList.toggle('expanded', !isExpanded);
                });
            } else {
                // For non-Windows types, show example directly inline
                item.addEventListener('click', () => toggleInlineLogExample(item, key, type));
            }

            listDiv.appendChild(item);
        });

        container.innerHTML = '';
        container.appendChild(listDiv);
    } catch (error) {
        console.error('Error loading sourcetypes:', error);
        document.getElementById('sourcetypesContainer').innerHTML = '<p class="error">Error loading sourcetypes</p>';
    }
}

/**
 * Toggle inline log example display
 * @param {HTMLElement} parentElement - Parent element to append example to
 * @param {string} typeKey - Log type key
 * @param {object} type - Log type data
 * @param {string} sourceId - Optional source ID for sub-types
 */
async function toggleInlineLogExample(parentElement, typeKey, type, sourceId = null) {
    try {
        // Check if example already exists and is visible
        const existingExample = parentElement.querySelector('.inline-log-example');

        if (existingExample) {
            // Toggle visibility
            if (existingExample.style.display === 'none') {
                existingExample.style.display = 'block';
            } else {
                existingExample.style.display = 'none';
            }
            return;
        }

        // Create new inline example
        const exampleDiv = document.createElement('div');
        exampleDiv.className = 'inline-log-example';

        const titleDiv = document.createElement('div');
        titleDiv.className = 'inline-example-title';
        if (sourceId) {
            titleDiv.textContent = `Example Log - ${sourceId}`;
        } else {
            titleDiv.textContent = 'Example Log';
        }

        const contentDiv = document.createElement('pre');
        contentDiv.className = 'inline-example-content';

        // Generate or fetch example log
        const example = await fetchLogExample(typeKey, sourceId);
        contentDiv.textContent = example;

        exampleDiv.appendChild(titleDiv);
        exampleDiv.appendChild(contentDiv);

        // Insert after the parent element
        parentElement.appendChild(exampleDiv);

    } catch (error) {
        console.error('Error showing log example:', error);
        showNotification('Error loading log example', 'error');
    }
}

/**
 * Fetch a log example for a given type
 * @param {string} typeKey - Log type key
 * @param {string} sourceId - Optional source ID
 * @returns {Promise<string>} Example log content
 */
async function fetchLogExample(typeKey, sourceId = null) {
    // Static examples for different log types and sources
    const examples = {
        'apache': {
            'access': '192.168.1.100 - - [03/Feb/2026:14:32:10 +0000] "GET /api/users HTTP/1.1" 200 1234',
            'error': '[Mon Feb 03 14:32:10.123456 2026] [error] [pid 1234:tid 987654321] [client 192.168.1.100:49152] File does not exist: /var/www/html/admin.php',
            'combined': '192.168.1.100 - - [03/Feb/2026:14:32:10 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://www.google.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"'
        },
        'ssh': {
            'auth_success': 'Feb  3 17:32:15 vmi829310 sshd[813270]: Accepted publickey for root from 192.168.1.100 port 45678 ssh2: RSA SHA256:1a2b3c4d5e6f7g8h9i0j',
            'auth_failed': 'Feb  3 17:32:15 vmi829310 sshd[813270]: Failed password for invalid user admin from 195.211.191.206 port 20090 ssh2',
            'sessions': 'Feb  3 17:32:15 vmi829310 CRON[813270]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)',
            'connections': 'Feb  3 17:32:15 vmi829310 sshd[813270]: Connection closed by invalid user test 195.211.191.206 port 20090 [preauth]',
            'errors': 'Feb  3 17:32:15 vmi829310 sshd[813270]: Did not receive identification string from 120.26.243.81 port 54766'
        },
        'windows': {
            'Security': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4624</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-02-03T15:30:00.000Z" />
    <EventRecordID>123456</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">DESKTOP-ABC123$</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">192.168.1.50</Data>
    <Data Name="IpPort">49152</Data>
  </EventData>
</Event>`,
            'Application': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Google Chrome" />
    <EventID>1000</EventID>
    <Version>0</Version>
    <Level>2</Level>
    <Task>0</Task>
    <Keywords>0x80000000000000</Keywords>
    <TimeCreated SystemTime="2026-02-03T15:30:00.000Z" />
    <EventRecordID>234567</EventRecordID>
    <Channel>Application</Channel>
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data>Application Error</Data>
    <Data>Application: Google Chrome</Data>
    <Data>Version: 120.0.6099</Data>
  </EventData>
</Event>`,
            'System': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" />
    <EventID>7036</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>0</Task>
    <Keywords>0x8080000000000000</Keywords>
    <TimeCreated SystemTime="2026-02-03T15:30:00.000Z" />
    <EventRecordID>345678</EventRecordID>
    <Channel>System</Channel>
    <Computer>SRV-PROD01</Computer>
  </System>
  <EventData>
    <Data Name="param1">wuauserv</Data>
    <Data Name="param2">running</Data>
    <Data Name="Description">Service State Change</Data>
  </EventData>
</Event>`
        },
        'paloalto': {
            'traffic': '<14>Feb 04 2026 12:34:56 pa-fw-01 1,2026/02/04 12:34:56,012345678901234,TRAFFIC,end,2049,2026/02/04 12:34:56,192.168.1.10,8.8.8.8,0.0.0.0,0.0.0.0,allow-web,,,web-browsing,vsys1,trust,untrust,ethernet1/1,ethernet1/2,ForwardToSplunk,2026/02/04 12:34:56,12345,1,54321,443,0,0,0x0,tcp,allow,15234,8192,7042,42,2026/02/04 12:34:50,6,any,0,987654321,0x8000000000000000,Internal,United States,0,24,18,aged-out,123,456,789,0,vsys1-name,pa-fw-01,from-policy,,,0,,0,,2026/02/04 12:34:50,0,N/A,0,0,0,0,0x0,,,,,,,,,,,,0,0,0,0,0,0,0,any,any,0,2026-02-04T12:34:56.789Z,0',
            'threat': '<14>Feb 04 2026 13:45:22 pa-fw-01 1,2026/02/04 13:45:22,012345678901234,THREAT,vulnerability,2049,2026/02/04 13:45:22,185.220.101.45,192.168.1.100,0.0.0.0,0.0.0.0,block-malicious,,,web-browsing,vsys1,untrust,trust,ethernet1/2,ethernet1/1,ForwardToSplunk,2026/02/04 13:45:22,54321,1,80,54321,0,0,0x80000000,tcp,reset-both,"malware-site.com/payload.exe",(41001),malware,high,client-to-server,987654321,0x8000000000000000,Germany,Internal,0,application/octet-stream,0,abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890,WildFireCloud,0,Mozilla/5.0,exe,,,,,report-12345,123,456,789,0,vsys1-name,pa-fw-01,,,,GET,1234567890,,999,2026/02/04 13:45:00,,malware,content-ver-1234,0,,,,,rule-uuid-123,0,,,,,,,,,,,,,,,,,,,,,,,,,,,2026-02-04T13:45:22.890Z,,0,,,,5,,,,1,1,,',
            'system': '<14>Feb 04 2026 14:56:33 pa-fw-01 1,2026/02/04 14:56:33,012345678901234,SYSTEM,auth,0,2026/02/04 14:56:33,vsys1,auth-fail,admin-user,0,0,auth,medium,"Authentication failed for user \'admin-user\' from 192.168.1.50",987654321,0x8000000000000000,123,456,789,0,vsys1-name,pa-fw-01,0,0,2026-02-04T14:56:33.901Z'
        },
        'active_directory': {
            'account_management': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4720</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13824</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-02-18T10:00:00.000Z" />
    <Channel>Security</Channel>
    <Computer>DC01.contoso.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">dadmin</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="TargetUserName">new_employee</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="SamAccountName">new_employee</Data>
    <Data Name="UserPrincipalName">new_employee@contoso.local</Data>
  </EventData>
</Event>`,
            'group_management': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4728</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13826</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-02-18T10:05:00.000Z" />
    <Channel>Security</Channel>
    <Computer>DC01.contoso.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">dadmin</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="MemberName">CN=jsmith,OU=Employees,DC=contoso,DC=local</Data>
    <Data Name="TargetUserName">Domain Admins</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
  </EventData>
</Event>`,
            'directory_service': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>5136</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14081</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-02-18T10:10:00.000Z" />
    <Channel>Security</Channel>
    <Computer>DC01.contoso.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">dadmin</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="DSName">contoso.local</Data>
    <Data Name="ObjectDN">CN=jsmith,OU=Employees,DC=contoso,DC=local</Data>
    <Data Name="ObjectClass">user</Data>
    <Data Name="AttributeLDAPDisplayName">title</Data>
    <Data Name="AttributeValue">Senior Engineer</Data>
    <Data Name="OperationType">%%14674</Data>
  </EventData>
</Event>`,
            'authentication': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4768</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>14339</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-02-18T10:15:00.000Z" />
    <Channel>Security</Channel>
    <Computer>DC01.contoso.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">contoso.local</Data>
    <Data Name="ServiceName">krbtgt</Data>
    <Data Name="TicketOptions">0x40810010</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="TicketEncryptionType">0x12</Data>
    <Data Name="IpAddress">::ffff:192.168.1.100</Data>
    <Data Name="IpPort">52345</Data>
  </EventData>
</Event>`,
            'computer_management': `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4741</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>13825</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-02-18T10:20:00.000Z" />
    <Channel>Security</Channel>
    <Computer>DC01.contoso.local</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">dadmin</Data>
    <Data Name="SubjectDomainName">CONTOSO</Data>
    <Data Name="TargetUserName">DESKTOP-NEW01$</Data>
    <Data Name="TargetDomainName">CONTOSO</Data>
    <Data Name="SamAccountName">DESKTOP-NEW01$</Data>
    <Data Name="DnsHostName">DESKTOP-NEW01.contoso.local</Data>
    <Data Name="ServicePrincipalNames">HOST/DESKTOP-NEW01.contoso.local RestrictedKrbHost/DESKTOP-NEW01.contoso.local</Data>
  </EventData>
</Event>`
        },
        'cisco_ios': {
            'interface': '000042: Feb 19 08:12:34.482: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up',
            'system': '000103: Feb 19 09:01:12.882: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.1.1.100)',
            'authentication': '000050: Feb 19 10:15:33.201: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.1.1.100] [localport: 22] at 10:15:33 UTC Thu Feb 19 2026',
            'acl_security': '000110: Feb 19 16:00:01.110: %SEC-6-IPACCESSLOGP: list OUTSIDE-IN denied tcp 203.0.113.45(44231) -> 10.1.1.10(22), 1 packet',
            'routing': '000070: Feb 19 12:00:01.110: %OSPF-5-ADJCHG: Process 1, Nbr 192.168.0.2 on GigabitEthernet0/1 from LOADING to FULL, Loading Done',
            'redundancy': '000100: Feb 19 15:00:01.110: %STANDBY-6-STATECHANGE: Standby: 1: GigabitEthernet0/1 state Standby -> Active',
            'spanning_tree': '000130: Feb 19 18:00:01.110: %SPANTREE-5-TOPOTRAP: Topology change trap for vlan 1',
            'hardware': '000142: Feb 19 19:10:33.332: %SNMP-3-AUTHFAIL: Authentication failure for SNMP req from host 10.1.1.50'
        },
        'cisco_ftd': {
            'connection': '<113>:2026-03-04T10:15:42Z:ftd-primary: %NGIPS-4-430002: EventPriority: Medium, DeviceUUID: e8566508-eaa9-11e5-860f-de3e305d8269, ConnectionID: 12345, AccessControlRuleAction: Allow, SrcIP: 10.1.9.9, DstIP: 93.157.158.93, SrcPort: 13723, DstPort: 443, Protocol: tcp, IngressInterface: inside, EgressInterface: outside, User: john.doe, ApplicationProtocol: HTTPS',
            'intrusion': '<113>:2026-03-04T10:20:15Z:ftd-primary: %NGIPS-2-430003: EventPriority: High, DeviceUUID: e8566508-eaa9-11e5-860f-de3e305d8269, InstanceID: 3, FirstPacketSecond: 2026-03-04T10:20:15Z, ConnectionID: 12346, AccessControlRuleAction: Block with reset, SrcIP: 93.157.158.93, DstIP: 10.1.9.9, SrcPort: 45678, DstPort: 22, Protocol: tcp, IngressInterface: outside, EgressInterface: inside, SignatureName: SSH Brute Force Login Attempt',
            'file': '<114>:2026-03-04T10:25:30Z:ftd-datacenter-01: %NGIPS-5-430004: EventPriority: Low, DeviceUUID: a1234567-bbbb-cccc-dddd-123456789abc, ConnectionID: 12347, AccessControlRuleAction: Allow, SrcIP: 185.220.101.50, DstIP: 10.2.5.10, Protocol: tcp, IngressInterface: outside, EgressInterface: dmz, FileName: invoice_2026.pdf, FileType: PDF, FileSize: 524288, FileSHA256: E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855, FileDisposition: Clean, ApplicationProtocol: HTTP',
            'malware': '<113>:2026-03-04T10:30:45Z:ftd-edge-gw: %NGIPS-1-430005: EventPriority: High, DeviceUUID: f9876543-aaaa-bbbb-cccc-fedcba987654, ConnectionID: 12348, AccessControlRuleAction: Block, SrcIP: 45.33.32.156, DstIP: 10.100.20.50, Protocol: tcp, IngressInterface: outside, EgressInterface: inside, FileName: malware_sample.exe, FileType: MSEXE, FileSHA256: 2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE, ThreatName: Win.Trojan.Generic, Disposition: Malware, Action: Block',
            'traditional': '<135>:2026-03-04T10:35:00Z:ftd-dmz: %FTD-5-111010: User \'admin\', running \'CLI\' from IP 10.1.1.100, executed \'show version\''
        }
    };

    // Handle Apache with specific log type
    if (typeKey === 'apache' && sourceId) {
        return examples.apache[sourceId] || 'No example available for this log type.';
    }

    // Handle SSH with specific event category
    if (typeKey === 'ssh' && sourceId) {
        return examples.ssh[sourceId] || 'No example available for this category.';
    }

    // Handle Windows with specific source
    if (typeKey === 'windows' && sourceId) {
        return examples.windows[sourceId] || 'No example available for this source.';
    }

    // Handle Palo Alto with specific log type
    if (typeKey === 'paloalto' && sourceId) {
        return examples.paloalto[sourceId] || 'No example available for this log type.';
    }

    // Handle Active Directory with specific event category
    if (typeKey === 'active_directory' && sourceId) {
        return examples.active_directory[sourceId] || 'No example available for this category.';
    }

    // Handle Cisco IOS with specific event category
    if (typeKey === 'cisco_ios' && sourceId) {
        return examples.cisco_ios[sourceId] || 'No example available for this category.';
    }

    // Handle Cisco FTD with specific event category
    if (typeKey === 'cisco_ftd' && sourceId) {
        return examples.cisco_ftd[sourceId] || 'No example available for this category.';
    }

    // Handle regular log types (fallback)
    return examples[typeKey] || 'No example available for this log type.';
}
