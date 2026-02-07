/**
 * Sourcetypes display module
 */

import { LogTypesApi, AttacksApi } from './api.js';
import { state, setLogTypes, setAttacks } from './state.js';
import { showNotification } from './utils.js';

/**
 * Load log types and attacks into the state and populate the select dropdown
 */
export async function loadLogTypes() {
    try {
        // Fetch both log types and attacks
        const [logTypes, attacks] = await Promise.all([
            LogTypesApi.getAll(),
            AttacksApi.getAll()
        ]);

        setLogTypes(logTypes);
        setAttacks(attacks);

        // Populate log type select with optgroups
        const select = document.getElementById('logType');
        select.innerHTML = '<option value="">Select a sourcetype or attack...</option>';

        // Add Sourcetypes optgroup
        const sourcetypesGroup = document.createElement('optgroup');
        sourcetypesGroup.label = 'Sourcetypes';

        Object.keys(logTypes).sort().forEach(key => {
            const option = document.createElement('option');
            option.value = key;
            option.textContent = logTypes[key].name;
            sourcetypesGroup.appendChild(option);
        });
        select.appendChild(sourcetypesGroup);

        // Add Attacks optgroup if there are attacks
        if (attacks.length > 0) {
            const attacksGroup = document.createElement('optgroup');
            attacksGroup.label = 'Attacks';

            attacks.forEach(attack => {
                const option = document.createElement('option');
                option.value = 'attack:' + attack.id;
                option.textContent = attack.name;
                attacksGroup.appendChild(option);
            });
            select.appendChild(attacksGroup);
        }
    } catch (error) {
        console.error('Error loading log types:', error);
    }
}

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

    // Handle regular log types (fallback)
    return examples[typeKey] || 'No example available for this log type.';
}
