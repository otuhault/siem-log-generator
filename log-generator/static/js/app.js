// Log Generator UI - Main JavaScript

let logTypes = {};
let configurations = [];
let attacks = [];
let attackTypes = {};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadLogTypes();
    loadSenders();
    loadConfigurations();
    loadAttacks();
    loadAttackTypes();
    setupEventListeners();
    setupTabs();

    // Refresh senders every 2 seconds to update counts
    setInterval(loadSenders, 2000);
});

function setupEventListeners() {
    // Form submission
    document.getElementById('createSenderForm').addEventListener('submit', handleCreateSender);
    document.getElementById('createConfigurationForm').addEventListener('submit', handleCreateConfiguration);

    // Add Sender button
    document.getElementById('addSenderBtn').addEventListener('click', function() {
        document.getElementById('senderFormCard').style.display = 'block';
        loadConfigurations(); // Reload configurations for dropdown
    });

    // Close/Cancel sender form
    document.getElementById('closeSenderForm').addEventListener('click', closeSenderForm);
    document.getElementById('cancelSenderForm').addEventListener('click', closeSenderForm);

    // Add Configuration button
    document.getElementById('addConfigurationBtn').addEventListener('click', function() {
        document.getElementById('configurationFormCard').style.display = 'block';
    });

    // Close/Cancel configuration form
    document.getElementById('closeConfigurationForm').addEventListener('click', closeConfigurationForm);
    document.getElementById('cancelConfigurationForm').addEventListener('click', closeConfigurationForm);

    // Attack form handling
    document.getElementById('createAttackForm').addEventListener('submit', handleCreateAttack);

    // Add Attack button
    document.getElementById('addAttackBtn').addEventListener('click', function() {
        document.getElementById('attackFormCard').style.display = 'block';
        populateAttackLogTypes();
        populateAttackTypeSelect();
    });

    // Close/Cancel attack form
    document.getElementById('closeAttackForm').addEventListener('click', closeAttackForm);
    document.getElementById('cancelAttackForm').addEventListener('click', closeAttackForm);

    // Attack type selection - no mode options needed here, they are in the Sender form

    // Destination type radio buttons
    document.querySelectorAll('input[name="destination_type"]').forEach(radio => {
        radio.addEventListener('change', function() {
            const fileGroup = document.getElementById('fileDestinationGroup');
            const configGroup = document.getElementById('configurationDestinationGroup');
            const destinationInput = document.getElementById('destination');

            if (this.value === 'file') {
                fileGroup.style.display = 'block';
                configGroup.style.display = 'none';
                destinationInput.required = true;
                document.getElementById('configurationSelect').required = false;
            } else {
                fileGroup.style.display = 'none';
                configGroup.style.display = 'block';
                destinationInput.required = false;
                document.getElementById('configurationSelect').required = true;
            }
        });
    });

    // Close log example
    const closeLogExample = document.getElementById('closeLogExample');
    if (closeLogExample) {
        closeLogExample.addEventListener('click', function() {
            document.getElementById('logExampleCard').style.display = 'none';
        });
    }

    // Log type selection - show description and format options
    document.getElementById('logType').addEventListener('change', function(e) {
        const description = document.getElementById('logTypeDescription');
        const selectedType = e.target.value;
        const renderFormatGroup = document.getElementById('renderFormatGroup');
        const windowsSourcesGroup = document.getElementById('windowsSourcesGroup');
        const apacheLogTypesGroup = document.getElementById('apacheLogTypesGroup');
        const sshEventCategoriesGroup = document.getElementById('sshEventCategoriesGroup');
        const paloaltoLogTypesGroup = document.getElementById('paloaltoLogTypesGroup');
        const frequencyGroup = document.getElementById('frequencyGroup');
        const attackOptionsGroup = document.getElementById('attackOptionsGroup');
        const senderSshBruteForceOptions = document.getElementById('senderSshBruteForceOptions');
        const frequencyInput = document.getElementById('frequency');

        // Hide all specific options by default
        const hideAllOptions = () => {
            windowsSourcesGroup.style.display = 'none';
            renderFormatGroup.style.display = 'none';
            apacheLogTypesGroup.style.display = 'none';
            sshEventCategoriesGroup.style.display = 'none';
            paloaltoLogTypesGroup.style.display = 'none';
            senderSshBruteForceOptions.style.display = 'none';
        };

        // Check if it's an attack
        if (selectedType && selectedType.startsWith('attack:')) {
            const attackId = selectedType.replace('attack:', '');
            const attack = attacks.find(a => a.id === attackId);
            if (attack) {
                description.textContent = attack.description;
                description.classList.add('show');

                // Set default values based on attack type
                const eventsInput = document.getElementById('attackEventsCount');
                const durationInput = document.getElementById('attackDuration');

                // Default values for different attack types (based on log_type of attack)
                if (attack.log_type === 'ssh') {
                    eventsInput.value = 50;  // SSH brute force typically has many attempts
                    durationInput.value = 30; // Over 30 seconds
                } else if (attack.log_type === 'paloalto') {
                    eventsInput.value = 20;
                    durationInput.value = 60;
                } else {
                    eventsInput.value = 100;
                    durationInput.value = 60;
                }

                // Show SSH brute force mode options if this attack uses the ssh_bruteforce generator
                if (attack.attack_type === 'ssh_bruteforce') {
                    senderSshBruteForceOptions.style.display = 'block';
                    // Pre-select the mode defined in the attack if available
                    if (attack.attack_options && attack.attack_options.mode) {
                        const modeRadio = document.querySelector(`input[name="sender_ssh_bruteforce_mode"][value="${attack.attack_options.mode}"]`);
                        if (modeRadio) {
                            modeRadio.checked = true;
                        }
                    }
                } else {
                    senderSshBruteForceOptions.style.display = 'none';
                }
            }
            hideAllOptions();
            // Re-show SSH options if it's an SSH brute force attack (hideAllOptions hides it)
            if (attack && attack.attack_type === 'ssh_bruteforce') {
                senderSshBruteForceOptions.style.display = 'block';
            }

            // Show attack options, hide frequency for attacks
            attackOptionsGroup.style.display = 'block';
            frequencyGroup.style.display = 'none';
        }
        // Check if it's a sourcetype
        else if (selectedType && logTypes[selectedType]) {
            description.textContent = logTypes[selectedType].description;
            description.classList.add('show');

            // Hide attack options, show frequency for sourcetypes
            attackOptionsGroup.style.display = 'none';
            frequencyGroup.style.display = 'block';
            frequencyInput.disabled = false;

            // Show Windows-specific options
            if (selectedType === 'windows') {
                windowsSourcesGroup.style.display = 'block';
                renderFormatGroup.style.display = 'block';
                apacheLogTypesGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
                paloaltoLogTypesGroup.style.display = 'none';
            }
            // Show Apache-specific options
            else if (selectedType === 'apache') {
                apacheLogTypesGroup.style.display = 'block';
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
                paloaltoLogTypesGroup.style.display = 'none';
            }
            // Show SSH-specific options
            else if (selectedType === 'ssh') {
                sshEventCategoriesGroup.style.display = 'block';
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                apacheLogTypesGroup.style.display = 'none';
                paloaltoLogTypesGroup.style.display = 'none';
            }
            // Show Palo Alto-specific options
            else if (selectedType === 'paloalto') {
                paloaltoLogTypesGroup.style.display = 'block';
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                apacheLogTypesGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
            }
            else {
                hideAllOptions();
            }
        } else {
            description.classList.remove('show');
            hideAllOptions();

            // Reset to default state - hide both frequency and attack options
            attackOptionsGroup.style.display = 'none';
            frequencyGroup.style.display = 'none';
        }
    });
}

function closeSenderForm() {
    document.getElementById('senderFormCard').style.display = 'none';
    document.getElementById('createSenderForm').reset();
    document.getElementById('senderId').value = '';
    document.getElementById('senderFormTitle').textContent = 'Create New Sender';
    document.getElementById('submitSenderBtn').textContent = 'Create Sender';
    document.getElementById('logTypeDescription').classList.remove('show');
    document.getElementById('windowsSourcesGroup').style.display = 'none';
    document.getElementById('renderFormatGroup').style.display = 'none';
    document.getElementById('apacheLogTypesGroup').style.display = 'none';
    document.getElementById('sshEventCategoriesGroup').style.display = 'none';
    document.getElementById('paloaltoLogTypesGroup').style.display = 'none';

    // Reset attack options and frequency
    document.getElementById('attackOptionsGroup').style.display = 'none';
    document.getElementById('frequencyGroup').style.display = 'none';
    document.getElementById('frequency').disabled = false;
    document.getElementById('attackEventsCount').value = 100;
    document.getElementById('attackDuration').value = 60;

    // Reset sender SSH brute force options
    document.getElementById('senderSshBruteForceOptions').style.display = 'none';
    const defaultSenderMode = document.querySelector('input[name="sender_ssh_bruteforce_mode"][value="diff_user_same_ip"]');
    if (defaultSenderMode) {
        defaultSenderMode.checked = true;
    }

    // Reset destination type to file
    document.querySelector('input[name="destination_type"][value="file"]').checked = true;
    document.getElementById('fileDestinationGroup').style.display = 'block';
    document.getElementById('configurationDestinationGroup').style.display = 'none';
    document.getElementById('destination').required = true;
    document.getElementById('configurationSelect').required = false;

    // Reset all Windows source checkboxes to checked by default
    document.querySelectorAll('input[name="windows_sources"]').forEach(cb => cb.checked = true);

    // Reset all Apache log type checkboxes to checked by default
    document.querySelectorAll('input[name="apache_log_types"]').forEach(cb => cb.checked = true);

    // Reset all SSH event category checkboxes to checked by default
    document.querySelectorAll('input[name="ssh_event_categories"]').forEach(cb => cb.checked = true);

    // Reset all Palo Alto log type checkboxes to checked by default
    document.querySelectorAll('input[name="paloalto_log_types"]').forEach(cb => cb.checked = true);
}

function closeConfigurationForm() {
    document.getElementById('configurationFormCard').style.display = 'none';
    document.getElementById('createConfigurationForm').reset();
    document.getElementById('configurationId').value = '';
    document.getElementById('configurationFormTitle').textContent = 'Create New HEC Destination';
    document.getElementById('submitConfigurationBtn').textContent = 'Create HEC Destination';
}

function closeAttackForm() {
    document.getElementById('attackFormCard').style.display = 'none';
    document.getElementById('createAttackForm').reset();
    document.getElementById('attackId').value = '';
    document.getElementById('attackFormTitle').textContent = 'Create New Attack';
    document.getElementById('submitAttackBtn').textContent = 'Create Attack';

    // Reset attack type selector
    document.getElementById('attackType').value = '';
}

function populateAttackLogTypes() {
    const select = document.getElementById('attackLogType');
    select.innerHTML = '<option value="">Select a log type...</option>';

    Object.keys(logTypes).sort().forEach(key => {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = logTypes[key].name;
        select.appendChild(option);
    });
}

async function loadAttackTypes() {
    try {
        const response = await fetch('/api/attack-types');
        attackTypes = await response.json();
    } catch (error) {
        console.error('Error loading attack types:', error);
    }
}

function populateAttackTypeSelect() {
    const select = document.getElementById('attackType');
    select.innerHTML = '<option value="">Static (use example log only)</option>';

    Object.keys(attackTypes).forEach(key => {
        const type = attackTypes[key];
        const option = document.createElement('option');
        option.value = key;
        option.textContent = type.name;
        select.appendChild(option);
    });
}

function setupTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');

    tabButtons.forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.dataset.tab;

            // Remove active class from all buttons and contents
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

            // Add active class to clicked button and corresponding content
            this.classList.add('active');
            document.getElementById(tabName + 'Tab').classList.add('active');

            // Load data based on tab
            if (tabName === 'sourcetypes') {
                loadSourcetypes();
            } else if (tabName === 'configurations') {
                loadConfigurations();
            } else if (tabName === 'attacks') {
                loadAttacks();
            }
        });
    });
}

async function loadLogTypes() {
    try {
        // Fetch both log types and attacks
        const [logTypesResponse, attacksResponse] = await Promise.all([
            fetch('/api/log-types'),
            fetch('/api/attacks')
        ]);

        logTypes = await logTypesResponse.json();
        attacks = await attacksResponse.json();

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

async function loadSourcetypes() {
    try {
        const container = document.getElementById('sourcetypesContainer');

        if (!logTypes || Object.keys(logTypes).length === 0) {
            await loadLogTypes();
        }

        // Sort log types alphabetically by name
        const sortedTypes = Object.entries(logTypes).sort((a, b) => {
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

async function showLogExample(typeKey, type, sourceId = null) {
    try {
        const exampleCard = document.getElementById('logExampleCard');
        const titleElement = document.getElementById('logExampleTitle');
        const contentElement = document.getElementById('logExampleContent');

        // Set title based on whether we have a specific source
        if (sourceId) {
            titleElement.textContent = `${type.name} - ${sourceId} - Example Log`;
        } else {
            titleElement.textContent = `${type.name} - Example Log`;
        }

        // Generate or fetch example log
        const example = await fetchLogExample(typeKey, sourceId);
        contentElement.textContent = example;

        exampleCard.style.display = 'block';
    } catch (error) {
        console.error('Error showing log example:', error);
        showNotification('Error loading log example', 'error');
    }
}

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

async function loadSenders() {
    try {
        const response = await fetch('/api/senders');
        const senders = await response.json();

        const container = document.getElementById('sendersContainer');

        // Update statistics
        const totalSenders = senders.length;
        const enabledSenders = senders.filter(s => s.enabled).length;
        const disabledSenders = totalSenders - enabledSenders;

        document.getElementById('totalSenders').textContent = totalSenders;
        document.getElementById('enabledSenders').textContent = enabledSenders;
        document.getElementById('disabledSenders').textContent = disabledSenders;

        if (senders.length === 0) {
            container.innerHTML = '<p class="no-senders">No senders created yet. Click "Add Sender" to create one!</p>';
            return;
        }

        // Create table
        const table = document.createElement('table');
        table.className = 'senders-table';

        // Create table header
        const thead = document.createElement('thead');
        thead.innerHTML = `
            <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Status</th>
                <th>Destination</th>
                <th>Frequency</th>
                <th>Logs Generated</th>
                <th>Created</th>
                <th>Actions</th>
            </tr>
        `;
        table.appendChild(thead);

        // Create table body
        const tbody = document.createElement('tbody');
        senders.forEach(sender => {
            tbody.appendChild(createSenderRow(sender));
        });
        table.appendChild(tbody);

        // Clear container and add table
        container.innerHTML = '';
        container.appendChild(table);

    } catch (error) {
        console.error('Error loading senders:', error);
    }
}

function createSenderRow(sender) {
    const row = document.createElement('tr');
    row.dataset.senderId = sender.id;

    // Check if this is an attack
    const isAttack = sender.log_type && sender.log_type.startsWith('attack:');
    if (isAttack) {
        row.classList.add('attack-sender-row');
    }

    // Name
    const nameCell = document.createElement('td');
    nameCell.textContent = sender.name;
    nameCell.className = 'sender-name';
    row.appendChild(nameCell);

    // Type
    const typeCell = document.createElement('td');
    typeCell.textContent = getLogTypeName(sender.log_type);
    typeCell.className = 'sender-type';
    row.appendChild(typeCell);

    // Status
    const statusCell = document.createElement('td');
    if (isAttack) {
        // Attack-specific status: Running / Done (timestamp) / Disabled
        const attackStatus = sender.attack_status || 'Disabled';
        if (attackStatus === 'Running') {
            statusCell.innerHTML = '<span class="status-running">Running</span>';
        } else if (attackStatus.startsWith('Done')) {
            statusCell.innerHTML = `<span class="status-done">${attackStatus}</span>`;
        } else {
            statusCell.innerHTML = '<span class="status-disabled">Disabled</span>';
        }
    } else {
        statusCell.textContent = sender.enabled ? 'Running' : 'Stopped';
    }
    statusCell.className = 'sender-status';
    row.appendChild(statusCell);

    // Destination
    const destCell = document.createElement('td');
    if (sender.destination_type === 'configuration' && sender.configuration_id) {
        // Find configuration name
        const config = configurations.find(c => c.id === sender.configuration_id);
        destCell.textContent = config ? `HEC: ${config.name}` : 'HEC (Configuration not found)';
    } else {
        destCell.textContent = sender.destination;
    }
    destCell.className = 'sender-destination';
    row.appendChild(destCell);

    // Frequency (or events/duration for attacks)
    const freqCell = document.createElement('td');
    if (isAttack && sender.options) {
        const events = sender.options.attack_events_count || 0;
        const duration = sender.options.attack_duration || 0;
        freqCell.textContent = `${events} events / ${duration}s`;
    } else {
        freqCell.textContent = `${sender.frequency} logs/sec`;
    }
    row.appendChild(freqCell);

    // Logs Generated
    const logsCell = document.createElement('td');
    logsCell.textContent = sender.logs_generated.toLocaleString();
    logsCell.className = 'sender-logs-count';
    row.appendChild(logsCell);

    // Created
    const createdCell = document.createElement('td');
    createdCell.textContent = formatDate(sender.created_at);
    createdCell.className = 'sender-created';
    row.appendChild(createdCell);

    // Actions
    const actionsCell = document.createElement('td');
    actionsCell.className = 'sender-actions';

    // Toggle button
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'btn btn-small btn-toggle';
    toggleBtn.title = 'Enable/Disable';
    toggleBtn.textContent = sender.enabled ? '⏸' : '▶';
    toggleBtn.addEventListener('click', () => toggleSender(sender.id));

    // Edit button (only enabled when sender is stopped)
    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-small btn-secondary';
    editBtn.title = sender.enabled ? 'Stop sender to edit' : 'Edit';
    editBtn.textContent = '✎';
    editBtn.disabled = sender.enabled;
    editBtn.addEventListener('click', () => editSender(sender.id));

    // Clone button
    const cloneBtn = document.createElement('button');
    cloneBtn.className = 'btn btn-small btn-clone';
    cloneBtn.title = 'Clone';
    cloneBtn.textContent = '⎘';
    cloneBtn.addEventListener('click', () => cloneSender(sender.id));

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-small btn-delete';
    deleteBtn.title = 'Delete';
    deleteBtn.textContent = '×';
    deleteBtn.addEventListener('click', () => deleteSender(sender.id));

    actionsCell.appendChild(toggleBtn);
    actionsCell.appendChild(editBtn);
    actionsCell.appendChild(cloneBtn);
    actionsCell.appendChild(deleteBtn);
    row.appendChild(actionsCell);

    return row;
}

function getLogTypeName(logType) {
    // Handle attack types
    if (logType && logType.startsWith('attack:')) {
        const attackId = logType.replace('attack:', '');
        const attack = attacks.find(a => a.id === attackId);
        if (attack) {
            return '⚔ ' + attack.name;
        }
        return 'Attack';
    }
    // Handle sourcetypes
    if (logTypes[logType]) {
        return logTypes[logType].name;
    }
    return logType;
}

function formatDate(dateString) {
    const date = new Date(dateString);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}/${month}/${day}`;
}

async function handleCreateSender(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const senderId = formData.get('id');
    const logType = formData.get('log_type');
    const destinationType = formData.get('destination_type');

    const data = {
        name: formData.get('name'),
        log_type: logType,
        frequency: parseInt(formData.get('frequency')),
        enabled: document.getElementById('enabledOnCreate').checked
    };

    // Set destination based on type
    if (destinationType === 'file') {
        data.destination = formData.get('destination');
        data.destination_type = 'file';
    } else {
        const configId = formData.get('configuration_id');
        if (!configId) {
            showNotification('Please select a configuration', 'error');
            return;
        }
        data.configuration_id = configId;
        data.destination_type = 'configuration';
    }

    // Add options for Windows logs
    if (logType === 'windows') {
        // Get selected sources
        const selectedSources = Array.from(
            document.querySelectorAll('input[name="windows_sources"]:checked')
        ).map(cb => cb.value);

        // Validate at least one source is selected
        if (selectedSources.length === 0) {
            showNotification('Please select at least one Windows source', 'error');
            return;
        }

        data.options = {
            sources: selectedSources,
            render_format: formData.get('render_format') || 'xml'
        };
    }
    // Add options for Apache logs
    else if (logType === 'apache') {
        // Get selected log types
        const selectedLogTypes = Array.from(
            document.querySelectorAll('input[name="apache_log_types"]:checked')
        ).map(cb => cb.value);

        // Validate at least one log type is selected
        if (selectedLogTypes.length === 0) {
            showNotification('Please select at least one Apache log type', 'error');
            return;
        }

        data.options = {
            log_types: selectedLogTypes
        };
    }
    // Add options for SSH logs
    else if (logType === 'ssh') {
        // Get selected event categories
        const selectedCategories = Array.from(
            document.querySelectorAll('input[name="ssh_event_categories"]:checked')
        ).map(cb => cb.value);

        // Validate at least one category is selected
        if (selectedCategories.length === 0) {
            showNotification('Please select at least one SSH event category', 'error');
            return;
        }

        data.options = {
            event_categories: selectedCategories
        };
    }
    // Add options for Palo Alto logs
    else if (logType === 'paloalto') {
        // Get selected log types
        const selectedLogTypes = Array.from(
            document.querySelectorAll('input[name="paloalto_log_types"]:checked')
        ).map(cb => cb.value);

        // Validate at least one log type is selected
        if (selectedLogTypes.length === 0) {
            showNotification('Please select at least one Palo Alto log type', 'error');
            return;
        }

        data.options = {
            log_types: selectedLogTypes
        };
    }
    // Add options for attacks
    else if (logType && logType.startsWith('attack:')) {
        const eventsCount = parseInt(document.getElementById('attackEventsCount').value);
        const duration = parseInt(document.getElementById('attackDuration').value);

        data.options = {
            attack_events_count: eventsCount,
            attack_duration: duration
        };

        // Add SSH brute force mode if applicable
        const attackId = logType.replace('attack:', '');
        const attack = attacks.find(a => a.id === attackId);
        if (attack && attack.attack_type === 'ssh_bruteforce') {
            const sshMode = formData.get('sender_ssh_bruteforce_mode');
            if (sshMode) {
                data.options.ssh_bruteforce_mode = sshMode;
            }
        }

        // Override frequency to 0 for attacks (it's computed from events/duration)
        data.frequency = 0;
        // Attacks start as 'Disabled' status (never launched)
        data.attack_status = 'Disabled';
    }

    try {
        let response;
        let successMessage;

        if (senderId) {
            // Edit mode
            response = await fetch(`/api/senders/${senderId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            successMessage = 'Sender updated successfully!';
        } else {
            // Create mode
            response = await fetch('/api/senders', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            successMessage = 'Sender created successfully!';
        }

        const result = await response.json();

        if (result.success) {
            // Close and reset form
            closeSenderForm();

            // Reload senders
            await loadSenders();

            showNotification(successMessage, 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error saving sender: ' + error.message, 'error');
    }
}

async function toggleSender(senderId) {
    try {
        const response = await fetch(`/api/senders/${senderId}/toggle`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (result.success) {
            await loadSenders();
            showNotification('Sender toggled', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error toggling sender: ' + error.message, 'error');
    }
}

async function editSender(senderId) {
    try {
        const response = await fetch(`/api/senders/${senderId}`);
        const sender = await response.json();

        if (sender) {
            // Populate form with sender data
            document.getElementById('senderId').value = sender.id;
            document.getElementById('senderName').value = sender.name;
            document.getElementById('logType').value = sender.log_type;
            document.getElementById('frequency').value = sender.frequency;
            document.getElementById('enabledOnCreate').checked = sender.enabled;

            // Trigger log type change event to show appropriate options
            const logTypeSelect = document.getElementById('logType');
            const changeEvent = new Event('change', { bubbles: true });
            logTypeSelect.dispatchEvent(changeEvent);

            // Set destination type
            if (sender.destination_type === 'configuration') {
                document.querySelector('input[name="destination_type"][value="configuration"]').checked = true;
                document.getElementById('fileDestinationGroup').style.display = 'none';
                document.getElementById('configurationDestinationGroup').style.display = 'block';
                document.getElementById('destination').required = false;
                document.getElementById('configurationSelect').required = true;
                document.getElementById('configurationSelect').value = sender.configuration_id;
            } else {
                document.querySelector('input[name="destination_type"][value="file"]').checked = true;
                document.getElementById('fileDestinationGroup').style.display = 'block';
                document.getElementById('configurationDestinationGroup').style.display = 'none';
                document.getElementById('destination').required = true;
                document.getElementById('configurationSelect').required = false;
                document.getElementById('destination').value = sender.destination;
            }

            // Set options based on log type
            if (sender.log_type === 'windows' && sender.options) {
                // Set Windows sources
                if (sender.options.sources) {
                    document.querySelectorAll('input[name="windows_sources"]').forEach(cb => {
                        cb.checked = sender.options.sources.includes(cb.value);
                    });
                }
                // Set render format
                if (sender.options.render_format) {
                    document.getElementById('renderFormat').value = sender.options.render_format;
                }
            } else if (sender.log_type === 'apache' && sender.options) {
                // Set Apache log types
                if (sender.options.log_types) {
                    document.querySelectorAll('input[name="apache_log_types"]').forEach(cb => {
                        cb.checked = sender.options.log_types.includes(cb.value);
                    });
                }
            } else if (sender.log_type === 'ssh' && sender.options) {
                // Set SSH event categories
                if (sender.options.event_categories) {
                    document.querySelectorAll('input[name="ssh_event_categories"]').forEach(cb => {
                        cb.checked = sender.options.event_categories.includes(cb.value);
                    });
                }
            } else if (sender.log_type === 'paloalto' && sender.options) {
                // Set Palo Alto log types
                if (sender.options.log_types) {
                    document.querySelectorAll('input[name="paloalto_log_types"]').forEach(cb => {
                        cb.checked = sender.options.log_types.includes(cb.value);
                    });
                }
            } else if (sender.log_type && sender.log_type.startsWith('attack:') && sender.options) {
                // Set attack options
                if (sender.options.attack_events_count) {
                    document.getElementById('attackEventsCount').value = sender.options.attack_events_count;
                }
                if (sender.options.attack_duration) {
                    document.getElementById('attackDuration').value = sender.options.attack_duration;
                }
                // Set SSH brute force mode if applicable
                if (sender.options.ssh_bruteforce_mode) {
                    const attackId = sender.log_type.replace('attack:', '');
                    const attack = attacks.find(a => a.id === attackId);
                    if (attack && attack.attack_type === 'ssh_bruteforce') {
                        document.getElementById('senderSshBruteForceOptions').style.display = 'block';
                        const modeRadio = document.querySelector(`input[name="sender_ssh_bruteforce_mode"][value="${sender.options.ssh_bruteforce_mode}"]`);
                        if (modeRadio) {
                            modeRadio.checked = true;
                        }
                    }
                }
            }

            // Update form title and button
            document.getElementById('senderFormTitle').textContent = 'Edit Sender';
            document.getElementById('submitSenderBtn').textContent = 'Update Sender';

            // Show the form
            document.getElementById('senderFormCard').style.display = 'block';

            // Reload configurations to populate dropdown
            await loadConfigurations();
        }
    } catch (error) {
        showNotification('Error loading sender: ' + error.message, 'error');
    }
}

async function cloneSender(senderId) {
    try {
        const response = await fetch(`/api/senders/${senderId}/clone`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (result.success) {
            await loadSenders();
            showNotification('Sender cloned successfully!', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error cloning sender: ' + error.message, 'error');
    }
}

async function deleteSender(senderId) {
    if (!confirm('Are you sure you want to delete this sender?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/senders/${senderId}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (result.success) {
            await loadSenders();
            showNotification('Sender deleted', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error deleting sender: ' + error.message, 'error');
    }
}

function showNotification(message, type = 'info') {
    // Simple notification system
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : '#3b82f6'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add animation styles
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Configuration Management Functions

async function loadConfigurations() {
    try {
        const response = await fetch('/api/configurations');
        configurations = await response.json();

        const container = document.getElementById('configurationsContainer');
        const totalConfigurations = document.getElementById('totalConfigurations');

        if (totalConfigurations) {
            totalConfigurations.textContent = configurations.length;
        }

        // Update configuration select dropdown in sender form
        const configSelect = document.getElementById('configurationSelect');
        if (configSelect) {
            configSelect.innerHTML = '<option value="">Select a configuration...</option>';
            configurations.forEach(config => {
                const option = document.createElement('option');
                option.value = config.id;
                option.textContent = `${config.name} (${config.url}:${config.port})`;
                configSelect.appendChild(option);
            });
        }

        if (!container) return;

        if (configurations.length === 0) {
            container.innerHTML = '<p class="no-senders">No configurations created yet. Click "Add Configuration" to create one!</p>';
            return;
        }

        // Create table
        const table = document.createElement('table');
        table.className = 'senders-table';

        // Create table header
        const thead = document.createElement('thead');
        thead.innerHTML = `
            <tr>
                <th>Name</th>
                <th>URL</th>
                <th>Port</th>
                <th>Index</th>
                <th>Sourcetype</th>
                <th>Host</th>
                <th>Source</th>
                <th>Created</th>
                <th>Actions</th>
            </tr>
        `;
        table.appendChild(thead);

        // Create table body
        const tbody = document.createElement('tbody');
        configurations.forEach(config => {
            tbody.appendChild(createConfigurationRow(config));
        });
        table.appendChild(tbody);

        // Clear container and add table
        container.innerHTML = '';
        container.appendChild(table);

    } catch (error) {
        console.error('Error loading configurations:', error);
    }
}

function createConfigurationRow(config) {
    const row = document.createElement('tr');
    row.dataset.configId = config.id;

    // Name
    const nameCell = document.createElement('td');
    nameCell.textContent = config.name;
    nameCell.className = 'sender-name';
    row.appendChild(nameCell);

    // URL
    const urlCell = document.createElement('td');
    urlCell.textContent = config.url;
    urlCell.className = 'sender-destination';
    row.appendChild(urlCell);

    // Port
    const portCell = document.createElement('td');
    portCell.textContent = config.port;
    row.appendChild(portCell);

    // Index
    const indexCell = document.createElement('td');
    indexCell.textContent = config.index || '-';
    row.appendChild(indexCell);

    // Sourcetype
    const sourcetypeCell = document.createElement('td');
    sourcetypeCell.textContent = config.sourcetype || '-';
    row.appendChild(sourcetypeCell);

    // Host
    const hostCell = document.createElement('td');
    hostCell.textContent = config.host || '-';
    row.appendChild(hostCell);

    // Source
    const sourceCell = document.createElement('td');
    sourceCell.textContent = config.source || '-';
    row.appendChild(sourceCell);

    // Created
    const createdCell = document.createElement('td');
    createdCell.textContent = formatDate(config.created_at);
    createdCell.className = 'sender-created';
    row.appendChild(createdCell);

    // Actions
    const actionsCell = document.createElement('td');
    actionsCell.className = 'sender-actions';

    // Edit button
    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-small btn-secondary';
    editBtn.title = 'Edit';
    editBtn.textContent = '✎';
    editBtn.addEventListener('click', () => editConfiguration(config.id));

    // Clone button
    const cloneBtn = document.createElement('button');
    cloneBtn.className = 'btn btn-small btn-clone';
    cloneBtn.title = 'Clone';
    cloneBtn.textContent = '⎘';
    cloneBtn.addEventListener('click', () => cloneConfiguration(config.id));

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-small btn-delete';
    deleteBtn.title = 'Delete';
    deleteBtn.textContent = '×';
    deleteBtn.addEventListener('click', () => deleteConfiguration(config.id));

    actionsCell.appendChild(editBtn);
    actionsCell.appendChild(cloneBtn);
    actionsCell.appendChild(deleteBtn);
    row.appendChild(actionsCell);

    return row;
}

async function handleCreateConfiguration(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const configId = formData.get('id');

    const data = {
        name: formData.get('name'),
        url: formData.get('url'),
        port: parseInt(formData.get('port')),
        token: formData.get('token'),
        index: formData.get('index') || undefined,
        sourcetype: formData.get('sourcetype') || undefined,
        host: formData.get('host') || undefined,
        source: formData.get('source') || undefined
    };

    try {
        let response;
        let successMessage;

        if (configId) {
            // Edit mode
            response = await fetch(`/api/configurations/${configId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            successMessage = 'Configuration updated successfully!';
        } else {
            // Create mode
            response = await fetch('/api/configurations', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            successMessage = 'Configuration created successfully!';
        }

        const result = await response.json();

        if (result.success) {
            closeConfigurationForm();
            await loadConfigurations();
            showNotification(successMessage, 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error saving configuration: ' + error.message, 'error');
    }
}

async function editConfiguration(configId) {
    try {
        const response = await fetch(`/api/configurations/${configId}`);
        const config = await response.json();

        if (config) {
            // Populate form with configuration data
            document.getElementById('configurationId').value = config.id;
            document.getElementById('configurationName').value = config.name;
            document.getElementById('configurationUrl').value = config.url;
            document.getElementById('configurationPort').value = config.port;
            document.getElementById('configurationToken').value = config.token;
            document.getElementById('configurationIndex').value = config.index || '';
            document.getElementById('configurationSourcetype').value = config.sourcetype || '';
            document.getElementById('configurationHost').value = config.host || '';
            document.getElementById('configurationSource').value = config.source || '';

            // Update form title and button
            document.getElementById('configurationFormTitle').textContent = 'Edit HEC Destination';
            document.getElementById('submitConfigurationBtn').textContent = 'Update HEC Destination';

            // Show the form
            document.getElementById('configurationFormCard').style.display = 'block';
        }
    } catch (error) {
        showNotification('Error loading configuration: ' + error.message, 'error');
    }
}

async function cloneConfiguration(configId) {
    try {
        const response = await fetch(`/api/configurations/${configId}/clone`, {
            method: 'POST'
        });

        const result = await response.json();

        if (result.success) {
            await loadConfigurations();
            showNotification('Configuration cloned successfully!', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error cloning configuration: ' + error.message, 'error');
    }
}

async function deleteConfiguration(configId) {
    if (!confirm('Are you sure you want to delete this configuration?')) {
        return;
    }

    try {
        const response = await fetch(`/api/configurations/${configId}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            await loadConfigurations();
            showNotification('Configuration deleted', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error deleting configuration: ' + error.message, 'error');
    }
}

// ============== Attacks Functions ==============

async function loadAttacks() {
    try {
        const response = await fetch('/api/attacks');
        attacks = await response.json();

        const container = document.getElementById('attacksContainer');
        const totalAttacks = document.getElementById('totalAttacks');

        if (totalAttacks) {
            totalAttacks.textContent = attacks.length;
        }

        if (!container) return;

        if (attacks.length === 0) {
            container.innerHTML = '<p class="no-senders">No attacks created yet. Click "Add Attack" to create one!</p>';
            return;
        }

        // Create table
        const table = document.createElement('table');
        table.className = 'senders-table';

        // Create table header
        const thead = document.createElement('thead');
        thead.innerHTML = `
            <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Log Type</th>
                <th>Generator</th>
                <th>Created</th>
                <th>Actions</th>
            </tr>
        `;
        table.appendChild(thead);

        // Create table body
        const tbody = document.createElement('tbody');
        attacks.forEach(attack => {
            tbody.appendChild(createAttackRow(attack));
        });
        table.appendChild(tbody);

        // Clear container and add table
        container.innerHTML = '';
        container.appendChild(table);

    } catch (error) {
        console.error('Error loading attacks:', error);
    }
}

function createAttackRow(attack) {
    const row = document.createElement('tr');
    row.dataset.attackId = attack.id;
    row.style.cursor = 'pointer';

    // Name
    const nameCell = document.createElement('td');
    nameCell.textContent = attack.name;
    nameCell.className = 'sender-name';
    row.appendChild(nameCell);

    // Description
    const descCell = document.createElement('td');
    descCell.textContent = attack.description;
    descCell.style.maxWidth = '300px';
    descCell.style.overflow = 'hidden';
    descCell.style.textOverflow = 'ellipsis';
    descCell.style.whiteSpace = 'nowrap';
    row.appendChild(descCell);

    // Log Type
    const logTypeCell = document.createElement('td');
    logTypeCell.textContent = getLogTypeName(attack.log_type);
    row.appendChild(logTypeCell);

    // Generator (Attack Type)
    const generatorCell = document.createElement('td');
    if (attack.attack_type && attackTypes[attack.attack_type]) {
        const attackType = attackTypes[attack.attack_type];
        generatorCell.textContent = attackType.name;
        generatorCell.style.color = '#22c55e'; // Green for dynamic
    } else {
        generatorCell.textContent = 'Static';
        generatorCell.style.color = '#6b7280'; // Gray for static
    }
    row.appendChild(generatorCell);

    // Created
    const createdCell = document.createElement('td');
    createdCell.textContent = formatDate(attack.created_at);
    createdCell.className = 'sender-created';
    row.appendChild(createdCell);

    // Actions
    const actionsCell = document.createElement('td');
    actionsCell.className = 'sender-actions';

    // Edit button
    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-small btn-secondary';
    editBtn.title = 'Edit';
    editBtn.textContent = '✎';
    editBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        editAttack(attack.id);
    });

    // Clone button
    const cloneBtn = document.createElement('button');
    cloneBtn.className = 'btn btn-small btn-clone';
    cloneBtn.title = 'Clone';
    cloneBtn.textContent = '⎘';
    cloneBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        cloneAttack(attack.id);
    });

    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-small btn-delete';
    deleteBtn.title = 'Delete';
    deleteBtn.textContent = '×';
    deleteBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        deleteAttack(attack.id);
    });

    actionsCell.appendChild(editBtn);
    actionsCell.appendChild(cloneBtn);
    actionsCell.appendChild(deleteBtn);
    row.appendChild(actionsCell);

    // Add click event to toggle inline example
    row.addEventListener('click', () => toggleAttackExample(row, attack));

    return row;
}

function toggleAttackExample(row, attack) {
    // Check if example row already exists
    const existingExample = row.nextElementSibling;
    if (existingExample && existingExample.classList.contains('attack-example-row')) {
        // Toggle visibility
        if (existingExample.style.display === 'none') {
            existingExample.style.display = 'table-row';
        } else {
            existingExample.style.display = 'none';
        }
        return;
    }

    // Build options HTML based on attack type
    let optionsHtml = '';
    if (attack.attack_type === 'ssh_bruteforce') {
        optionsHtml = `
            <div class="attack-options-section">
                <div class="inline-example-title" style="margin-top: 15px;">Available Modes</div>
                <div class="attack-modes-list">
                    <div class="attack-mode-item">
                        <strong>Different users, same source IP</strong>
                        <span class="mode-desc">Single attacker trying multiple usernames (~100 common usernames)</span>
                    </div>
                    <div class="attack-mode-item">
                        <strong>Same user, same source IP</strong>
                        <span class="mode-desc">Single attacker targeting one account with password attempts</span>
                    </div>
                    <div class="attack-mode-item">
                        <strong>Same user, different source IPs</strong>
                        <span class="mode-desc">Distributed attack (botnet) targeting one account (~50 attacker IPs)</span>
                    </div>
                    <div class="attack-mode-item">
                        <strong>Different users, different source IPs</strong>
                        <span class="mode-desc">Distributed credential stuffing attack</span>
                    </div>
                </div>
            </div>
        `;
    }

    // Create new example row
    const exampleRow = document.createElement('tr');
    exampleRow.className = 'attack-example-row';

    const exampleCell = document.createElement('td');
    exampleCell.colSpan = 6;
    exampleCell.innerHTML = `
        <div class="inline-log-example">
            <div class="inline-example-title">Example Log</div>
            <pre class="inline-example-content">${escapeHtml(attack.example)}</pre>
            ${optionsHtml}
        </div>
    `;

    exampleRow.appendChild(exampleCell);
    row.parentNode.insertBefore(exampleRow, row.nextSibling);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function handleCreateAttack(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const attackId = formData.get('id');

    const data = {
        name: formData.get('name'),
        description: formData.get('description'),
        log_type: formData.get('log_type'),
        example: formData.get('example')
    };

    // Add attack type if selected (mode is configured in Sender, not here)
    const attackType = formData.get('attack_type');
    if (attackType) {
        data.attack_type = attackType;
    }

    try {
        let response;
        let successMessage;

        if (attackId) {
            // Edit mode
            response = await fetch(`/api/attacks/${attackId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            successMessage = 'Attack updated successfully!';
        } else {
            // Create mode
            response = await fetch('/api/attacks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            successMessage = 'Attack created successfully!';
        }

        const result = await response.json();

        if (result.success) {
            closeAttackForm();
            await loadAttacks();
            showNotification(successMessage, 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error saving attack: ' + error.message, 'error');
    }
}

async function editAttack(attackId) {
    try {
        const response = await fetch(`/api/attacks/${attackId}`);
        const attack = await response.json();

        if (attack) {
            // Populate form with attack data
            document.getElementById('attackId').value = attack.id;
            document.getElementById('attackName').value = attack.name;
            document.getElementById('attackDescription').value = attack.description;

            // Populate log types and select the right one
            populateAttackLogTypes();
            document.getElementById('attackLogType').value = attack.log_type;

            document.getElementById('attackExample').value = attack.example;

            // Populate attack types and select the right one
            populateAttackTypeSelect();
            const attackType = attack.attack_type || '';
            document.getElementById('attackType').value = attackType;

            // Update form title and button
            document.getElementById('attackFormTitle').textContent = 'Edit Attack';
            document.getElementById('submitAttackBtn').textContent = 'Update Attack';

            // Show the form
            document.getElementById('attackFormCard').style.display = 'block';
        }
    } catch (error) {
        showNotification('Error loading attack: ' + error.message, 'error');
    }
}

async function cloneAttack(attackId) {
    try {
        const response = await fetch(`/api/attacks/${attackId}/clone`, {
            method: 'POST'
        });

        const result = await response.json();

        if (result.success) {
            await loadAttacks();
            showNotification('Attack cloned successfully!', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error cloning attack: ' + error.message, 'error');
    }
}

async function deleteAttack(attackId) {
    if (!confirm('Are you sure you want to delete this attack?')) {
        return;
    }

    try {
        const response = await fetch(`/api/attacks/${attackId}`, {
            method: 'DELETE'
        });

        const result = await response.json();

        if (result.success) {
            await loadAttacks();
            showNotification('Attack deleted', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error deleting attack: ' + error.message, 'error');
    }
}
