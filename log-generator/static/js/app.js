// Log Generator UI - Main JavaScript

let logTypes = {};
let configurations = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadLogTypes();
    loadSenders();
    loadConfigurations();
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

        if (selectedType && logTypes[selectedType]) {
            description.textContent = logTypes[selectedType].description;
            description.classList.add('show');

            // Show Windows-specific options
            if (selectedType === 'windows') {
                windowsSourcesGroup.style.display = 'block';
                renderFormatGroup.style.display = 'block';
                apacheLogTypesGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
            }
            // Show Apache-specific options
            else if (selectedType === 'apache') {
                apacheLogTypesGroup.style.display = 'block';
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
            }
            // Show SSH-specific options
            else if (selectedType === 'ssh') {
                sshEventCategoriesGroup.style.display = 'block';
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                apacheLogTypesGroup.style.display = 'none';
            }
            else {
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                apacheLogTypesGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
            }
        } else {
            description.classList.remove('show');
            windowsSourcesGroup.style.display = 'none';
            renderFormatGroup.style.display = 'none';
            apacheLogTypesGroup.style.display = 'none';
            sshEventCategoriesGroup.style.display = 'none';
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
}

function closeConfigurationForm() {
    document.getElementById('configurationFormCard').style.display = 'none';
    document.getElementById('createConfigurationForm').reset();
    document.getElementById('configurationId').value = '';
    document.getElementById('configurationFormTitle').textContent = 'Create New HEC Destination';
    document.getElementById('submitConfigurationBtn').textContent = 'Create HEC Destination';
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
            }
        });
    });
}

async function loadLogTypes() {
    try {
        const response = await fetch('/api/log-types');
        logTypes = await response.json();

        // Populate log type select
        const select = document.getElementById('logType');
        select.innerHTML = '<option value="">Select a log type...</option>';

        Object.keys(logTypes).sort().forEach(key => {
            const option = document.createElement('option');
            option.value = key;
            option.textContent = logTypes[key].name;
            select.appendChild(option);
        });
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

                    const subName = document.createElement('div');
                    subName.className = 'sourcetype-subname';
                    subName.textContent = source.name;

                    const subDesc = document.createElement('div');
                    subDesc.className = 'sourcetype-subdesc';
                    subDesc.textContent = source.description;

                    subItem.appendChild(subName);
                    subItem.appendChild(subDesc);

                    // Add click event to show source-specific example
                    subItem.addEventListener('click', (e) => {
                        e.stopPropagation();
                        showLogExample(key, type, source.id);
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
                // For non-Windows types, show example directly
                item.addEventListener('click', () => showLogExample(key, type));
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
    statusCell.textContent = sender.enabled ? 'Running' : 'Stopped';
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

    // Frequency
    const freqCell = document.createElement('td');
    freqCell.textContent = `${sender.frequency} logs/sec`;
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
