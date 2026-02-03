// Log Generator UI - Main JavaScript

let logTypes = {};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadLogTypes();
    loadSenders();
    setupEventListeners();
    setupTabs();

    // Refresh senders every 2 seconds to update counts
    setInterval(loadSenders, 2000);
});

function setupEventListeners() {
    // Form submission
    document.getElementById('createSenderForm').addEventListener('submit', handleCreateSender);

    // Add Sender button
    document.getElementById('addSenderBtn').addEventListener('click', function() {
        document.getElementById('senderFormCard').style.display = 'block';
    });

    // Close/Cancel sender form
    document.getElementById('closeSenderForm').addEventListener('click', closeSenderForm);
    document.getElementById('cancelSenderForm').addEventListener('click', closeSenderForm);

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
    document.getElementById('logTypeDescription').classList.remove('show');
    document.getElementById('windowsSourcesGroup').style.display = 'none';
    document.getElementById('renderFormatGroup').style.display = 'none';
    document.getElementById('apacheLogTypesGroup').style.display = 'none';
    document.getElementById('sshEventCategoriesGroup').style.display = 'none';

    // Reset all Windows source checkboxes to checked by default
    document.querySelectorAll('input[name="windows_sources"]').forEach(cb => cb.checked = true);

    // Reset all Apache log type checkboxes to checked by default
    document.querySelectorAll('input[name="apache_log_types"]').forEach(cb => cb.checked = true);

    // Reset all SSH event category checkboxes to checked by default
    document.querySelectorAll('input[name="ssh_event_categories"]').forEach(cb => cb.checked = true);
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

            // Load sourcetypes if switching to sourcetypes tab
            if (tabName === 'sourcetypes') {
                loadSourcetypes();
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
    destCell.textContent = sender.destination;
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
    createdCell.textContent = new Date(sender.created_at).toLocaleString();
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

async function handleCreateSender(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const logType = formData.get('log_type');

    const data = {
        name: formData.get('name'),
        log_type: logType,
        destination: formData.get('destination'),
        frequency: parseInt(formData.get('frequency')),
        enabled: document.getElementById('enabledOnCreate').checked
    };

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
        const response = await fetch('/api/senders', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Close and reset form
            closeSenderForm();

            // Reload senders
            await loadSenders();

            showNotification('Sender created successfully!', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error creating sender: ' + error.message, 'error');
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
