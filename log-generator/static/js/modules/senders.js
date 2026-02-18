/**
 * Senders management module
 */

import { SendersApi } from './api.js';
import { state, getLogTypeName } from './state.js';
import { formatDate, showNotification } from './utils.js';
import { validateSenderForm, clearFormErrors } from './validation.js';

/**
 * Load all senders and update the UI
 */
export async function loadSenders() {
    try {
        const senders = await SendersApi.getAll();

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

/**
 * Create a table row for a sender
 * @param {object} sender - Sender data
 * @returns {HTMLElement} Table row element
 */
function createSenderRow(sender) {
    const row = document.createElement('tr');
    row.dataset.senderId = sender.id;

    // Check if this is an attack type
    const isAttack = !!(sender.log_type && state.attackTypes[sender.log_type]);
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
        const config = state.configurations.find(c => c.id === sender.configuration_id);
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

/**
 * Toggle a sender's enabled state
 * @param {string} senderId - Sender ID
 */
export async function toggleSender(senderId) {
    try {
        const result = await SendersApi.toggle(senderId);

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

/**
 * Edit a sender - populate form with sender data
 * @param {string} senderId - Sender ID
 */
export async function editSender(senderId) {
    try {
        const sender = await SendersApi.get(senderId);

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
                if (sender.options.sources) {
                    document.querySelectorAll('input[name="windows_sources"]').forEach(cb => {
                        cb.checked = sender.options.sources.includes(cb.value);
                    });
                }
                if (sender.options.render_format) {
                    document.getElementById('renderFormat').value = sender.options.render_format;
                }
            } else if (sender.log_type === 'apache' && sender.options) {
                if (sender.options.log_types) {
                    document.querySelectorAll('input[name="apache_log_types"]').forEach(cb => {
                        cb.checked = sender.options.log_types.includes(cb.value);
                    });
                }
            } else if (sender.log_type === 'ssh' && sender.options) {
                if (sender.options.event_categories) {
                    document.querySelectorAll('input[name="ssh_event_categories"]').forEach(cb => {
                        cb.checked = sender.options.event_categories.includes(cb.value);
                    });
                }
            } else if (sender.log_type === 'paloalto' && sender.options) {
                if (sender.options.log_types) {
                    document.querySelectorAll('input[name="paloalto_log_types"]').forEach(cb => {
                        cb.checked = sender.options.log_types.includes(cb.value);
                    });
                }
            } else if (sender.log_type && state.attackTypes[sender.log_type] && sender.options) {
                if (sender.options.attack_events_count) {
                    document.getElementById('attackEventsCount').value = sender.options.attack_events_count;
                }
                if (sender.options.attack_duration) {
                    document.getElementById('attackDuration').value = sender.options.attack_duration;
                }
                // Restore field overrides for paloalto attacks
                document.getElementById('attackSrcIp').value = sender.options.target_src_ip || '';
                document.getElementById('attackDestIp').value = sender.options.target_dest_ip || '';
                document.getElementById('attackDestPort').value = sender.options.target_dest_port || '';
            }

            // Update form title and button
            document.getElementById('senderFormTitle').textContent = 'Edit Sender';
            document.getElementById('submitSenderBtn').textContent = 'Update Sender';

            // Show the form
            document.getElementById('senderFormCard').style.display = 'block';

            // Import and call loadConfigurations to populate dropdown
            const { loadConfigurations } = await import('./configurations.js');
            await loadConfigurations();

            // Set configuration select value AFTER loadConfigurations rebuilds the dropdown
            if (sender.destination_type === 'configuration' && sender.configuration_id) {
                document.getElementById('configurationSelect').value = sender.configuration_id;
            }
        }
    } catch (error) {
        showNotification('Error loading sender: ' + error.message, 'error');
    }
}

/**
 * Clone a sender
 * @param {string} senderId - Sender ID
 */
export async function cloneSender(senderId) {
    try {
        const result = await SendersApi.clone(senderId);

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

/**
 * Delete a sender
 * @param {string} senderId - Sender ID
 */
export async function deleteSender(senderId) {
    if (!confirm('Are you sure you want to delete this sender?')) {
        return;
    }

    try {
        const result = await SendersApi.delete(senderId);

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

/**
 * Handle sender form submission (create or update)
 * @param {Event} e - Form submit event
 */
export async function handleCreateSender(e) {
    e.preventDefault();

    // Validate form before processing
    const validation = validateSenderForm(e.target);
    if (!validation.isValid) {
        showNotification(validation.errors[0] || 'Please fix the form errors', 'error');
        return;
    }

    const formData = new FormData(e.target);
    const senderId = formData.get('id');
    const logType = formData.get('log_type');
    const destinationType = formData.get('destination_type');

    const data = {
        name: formData.get('name').trim(),
        log_type: logType,
        frequency: parseInt(formData.get('frequency')),
        enabled: document.getElementById('enabledOnCreate').checked
    };

    // Set destination based on type
    if (destinationType === 'file') {
        data.destination = formData.get('destination').trim();
        data.destination_type = 'file';
    } else {
        data.configuration_id = formData.get('configuration_id');
        data.destination_type = 'configuration';
    }

    // Add options for Windows logs
    if (logType === 'windows') {
        const selectedSources = Array.from(
            document.querySelectorAll('input[name="windows_sources"]:checked')
        ).map(cb => cb.value);

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
        const selectedLogTypes = Array.from(
            document.querySelectorAll('input[name="apache_log_types"]:checked')
        ).map(cb => cb.value);

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
        const selectedCategories = Array.from(
            document.querySelectorAll('input[name="ssh_event_categories"]:checked')
        ).map(cb => cb.value);

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
        const selectedLogTypes = Array.from(
            document.querySelectorAll('input[name="paloalto_log_types"]:checked')
        ).map(cb => cb.value);

        if (selectedLogTypes.length === 0) {
            showNotification('Please select at least one Palo Alto log type', 'error');
            return;
        }

        data.options = {
            log_types: selectedLogTypes
        };
    }
    // Add options for attacks
    else if (logType && state.attackTypes[logType]) {
        const eventsCount = parseInt(document.getElementById('attackEventsCount').value);
        const duration = parseInt(document.getElementById('attackDuration').value);

        data.options = {
            attack_events_count: eventsCount,
            attack_duration: duration
        };

        // Add field overrides for paloalto attacks
        const attackType = state.attackTypes[logType];
        if (attackType.log_type === 'paloalto') {
            const srcIp = document.getElementById('attackSrcIp').value.trim();
            const destIp = document.getElementById('attackDestIp').value.trim();
            const destPort = document.getElementById('attackDestPort').value.trim();
            if (srcIp) data.options.target_src_ip = srcIp;
            if (destIp) data.options.target_dest_ip = destIp;
            if (destPort) data.options.target_dest_port = parseInt(destPort);
        }

        data.frequency = 0;
        data.attack_status = 'Disabled';
    }

    try {
        let result;
        let successMessage;

        if (senderId) {
            result = await SendersApi.update(senderId, data);
            successMessage = 'Sender updated successfully!';
        } else {
            result = await SendersApi.create(data);
            successMessage = 'Sender created successfully!';
        }

        if (result.success) {
            closeSenderForm();
            await loadSenders();
            showNotification(successMessage, 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error saving sender: ' + error.message, 'error');
    }
}

/**
 * Close and reset the sender form
 */
export function closeSenderForm() {
    const form = document.getElementById('createSenderForm');
    document.getElementById('senderFormCard').style.display = 'none';
    form.reset();
    clearFormErrors(form);
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
    document.getElementById('attackFieldOverrides').style.display = 'none';
    document.getElementById('attackSrcIpGroup').style.display = 'none';
    document.getElementById('attackDestIpGroup').style.display = 'none';
    document.getElementById('attackDestPortGroup').style.display = 'none';
    document.getElementById('frequencyGroup').style.display = 'none';
    document.getElementById('frequency').disabled = false;
    document.getElementById('attackEventsCount').value = 100;
    document.getElementById('attackDuration').value = 60;
    document.getElementById('attackSrcIp').value = '';
    document.getElementById('attackDestIp').value = '';
    document.getElementById('attackDestPort').value = '';


    // Reset destination type to file
    document.querySelector('input[name="destination_type"][value="file"]').checked = true;
    document.getElementById('fileDestinationGroup').style.display = 'block';
    document.getElementById('configurationDestinationGroup').style.display = 'none';
    document.getElementById('destination').required = true;
    document.getElementById('configurationSelect').required = false;

    // Reset all checkboxes to checked by default
    document.querySelectorAll('input[name="windows_sources"]').forEach(cb => cb.checked = true);
    document.querySelectorAll('input[name="apache_log_types"]').forEach(cb => cb.checked = true);
    document.querySelectorAll('input[name="ssh_event_categories"]').forEach(cb => cb.checked = true);
    document.querySelectorAll('input[name="paloalto_log_types"]').forEach(cb => cb.checked = true);
}
