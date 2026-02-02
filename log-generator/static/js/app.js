// Log Generator UI - Main JavaScript

let logTypes = {};

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    loadLogTypes();
    loadSenders();
    setupEventListeners();
    
    // Refresh senders every 2 seconds to update counts
    setInterval(loadSenders, 2000);
});

function setupEventListeners() {
    // Form submission
    document.getElementById('createSenderForm').addEventListener('submit', handleCreateSender);
    
    // Log type selection - show description
    document.getElementById('logType').addEventListener('change', function(e) {
        const description = document.getElementById('logTypeDescription');
        const selectedType = e.target.value;
        
        if (selectedType && logTypes[selectedType]) {
            description.textContent = logTypes[selectedType].description;
            description.classList.add('show');
        } else {
            description.classList.remove('show');
        }
    });
}

async function loadLogTypes() {
    try {
        const response = await fetch('/api/log-types');
        logTypes = await response.json();
    } catch (error) {
        console.error('Error loading log types:', error);
    }
}

async function loadSenders() {
    try {
        const response = await fetch('/api/senders');
        const senders = await response.json();

        const container = document.getElementById('sendersContainer');

        if (senders.length === 0) {
            container.innerHTML = '<p class="no-senders">No senders created yet. Create your first sender above!</p>';
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
    const data = {
        name: formData.get('name'),
        log_type: formData.get('log_type'),
        destination: formData.get('destination'),
        frequency: parseInt(formData.get('frequency')),
        enabled: document.getElementById('enabledOnCreate').checked
    };
    
    try {
        const response = await fetch('/api/senders', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Reset form
            e.target.reset();
            document.getElementById('logTypeDescription').classList.remove('show');
            
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
