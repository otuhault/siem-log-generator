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

        if (selectedType && logTypes[selectedType]) {
            description.textContent = logTypes[selectedType].description;
            description.classList.add('show');

            // Show render format option only for Windows logs
            if (selectedType === 'windows_security') {
                renderFormatGroup.style.display = 'block';
            } else {
                renderFormatGroup.style.display = 'none';
            }
        } else {
            description.classList.remove('show');
            renderFormatGroup.style.display = 'none';
        }
    });
}

function closeSenderForm() {
    document.getElementById('senderFormCard').style.display = 'none';
    document.getElementById('createSenderForm').reset();
    document.getElementById('logTypeDescription').classList.remove('show');
    document.getElementById('renderFormatGroup').style.display = 'none';
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

            // Add click event to show example
            item.addEventListener('click', () => showLogExample(key, type));

            listDiv.appendChild(item);
        });

        container.innerHTML = '';
        container.appendChild(listDiv);
    } catch (error) {
        console.error('Error loading sourcetypes:', error);
        document.getElementById('sourcetypesContainer').innerHTML = '<p class="error">Error loading sourcetypes</p>';
    }
}

async function showLogExample(typeKey, type) {
    try {
        // For now, we'll generate a sample log on the client side
        // In a real implementation, you might want to fetch this from the server
        const exampleCard = document.getElementById('logExampleCard');
        const titleElement = document.getElementById('logExampleTitle');
        const contentElement = document.getElementById('logExampleContent');

        titleElement.textContent = `${type.name} - Example Log`;

        // Generate or fetch example log
        const example = await fetchLogExample(typeKey);
        contentElement.textContent = example;

        exampleCard.style.display = 'block';
    } catch (error) {
        console.error('Error showing log example:', error);
        showNotification('Error loading log example', 'error');
    }
}

async function fetchLogExample(typeKey) {
    // Return static examples for now
    const examples = {
        'apache_access': '192.168.1.100 - - [02/Feb/2026:14:32:10 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        'windows_security': 'EventID: 4624\nTimestamp: 2026-02-02 14:32:10\nLogon Type: 3\nAccount Name: admin\nAccount Domain: DOMAIN\nLogon ID: 0x1A2B3C\nSource Network Address: 192.168.1.50\nSource Port: 49152'
    };

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
    if (logType === 'windows_security') {
        data.options = {
            render_format: formData.get('render_format') || 'xml'
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
