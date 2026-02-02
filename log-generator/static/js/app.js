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
        
        // Clear container
        container.innerHTML = '';
        
        // Render each sender
        senders.forEach(sender => {
            container.appendChild(createSenderCard(sender));
        });
        
    } catch (error) {
        console.error('Error loading senders:', error);
    }
}

function createSenderCard(sender) {
    const template = document.getElementById('senderTemplate');
    const clone = template.content.cloneNode(true);
    
    const card = clone.querySelector('.sender-card');
    card.dataset.senderId = sender.id;
    
    // Set sender info
    clone.querySelector('.sender-name').textContent = sender.name;
    clone.querySelector('.sender-type').textContent = getLogTypeName(sender.log_type);
    
    const statusBadge = clone.querySelector('.sender-status');
    statusBadge.textContent = sender.enabled ? 'Running' : 'Stopped';
    statusBadge.classList.add(sender.enabled ? 'enabled' : 'disabled');
    
    // Set details
    clone.querySelector('.sender-destination').textContent = sender.destination;
    clone.querySelector('.sender-frequency').textContent = `${sender.frequency} logs/sec`;
    clone.querySelector('.sender-logs-count').textContent = sender.logs_generated.toLocaleString();
    clone.querySelector('.sender-created').textContent = new Date(sender.created_at).toLocaleString();
    
    // Set toggle button icon
    const toggleBtn = clone.querySelector('.btn-toggle');
    const toggleIcon = toggleBtn.querySelector('.toggle-icon');
    toggleIcon.textContent = sender.enabled ? '⏸️' : '▶️';
    
    // Event listeners
    toggleBtn.addEventListener('click', () => toggleSender(sender.id));
    clone.querySelector('.btn-clone').addEventListener('click', () => cloneSender(sender.id));
    clone.querySelector('.btn-delete').addEventListener('click', () => deleteSender(sender.id));
    
    return clone;
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
