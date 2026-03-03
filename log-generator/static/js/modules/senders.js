/**
 * Senders management module
 */

import { SendersApi } from './api.js';
import { state, getLogTypeName } from './state.js';
import { formatDate, showNotification } from './utils.js';
import { validateSenderForm, clearFormErrors } from './validation.js';
import { SOURCETYPE_CONFIG } from './sourcetype-config.js';

/**
 * Helper: Get selected checkbox values
 * @param {string} name - Checkbox group name attribute
 * @returns {Array<string>} Selected values
 */
function getSelectedCheckboxes(name) {
    return Array.from(
        document.querySelectorAll(`input[name="${name}"]:checked`)
    ).map(cb => cb.value);
}

/**
 * Helper: Restore checkbox selections
 * @param {string} name - Checkbox group name attribute
 * @param {Array<string>} values - Values to select
 */
function restoreCheckboxes(name, values) {
    document.querySelectorAll(`input[name="${name}"]`).forEach(cb => {
        cb.checked = values.includes(cb.value);
    });
}

/**
 * Helper: Reset checkboxes to all checked
 * @param {string} name - Checkbox group name attribute
 */
function resetCheckboxes(name) {
    document.querySelectorAll(`input[name="${name}"]`).forEach(cb => {
        cb.checked = true;
    });
}

// Original position of the sender form in the DOM
let originalFormParent = null;
let originalFormNextSibling = null;

/**
 * Save the original DOM position of the sender form (called once)
 */
function saveOriginalFormPosition() {
    if (!originalFormParent) {
        const formCard = document.getElementById('senderFormCard');
        originalFormParent = formCard.parentNode;
        originalFormNextSibling = formCard.nextSibling;
    }
}

/**
 * Restore the sender form to its original position in the DOM
 */
export function restoreFormToOriginalPosition() {
    saveOriginalFormPosition();
    const formCard = document.getElementById('senderFormCard');

    // Remove any existing inline form row
    const existingFormRow = document.querySelector('tr.sender-form-row');
    if (existingFormRow) {
        existingFormRow.remove();
    }

    // Move form back to its original position
    if (formCard.parentNode !== originalFormParent) {
        originalFormParent.insertBefore(formCard, originalFormNextSibling);
    }
}

/**
 * Move the sender form inline below a specific sender row
 */
function moveFormBelowRow(senderId) {
    saveOriginalFormPosition();
    const formCard = document.getElementById('senderFormCard');
    const senderRow = document.querySelector(`tr[data-sender-id="${senderId}"]`);

    if (!senderRow) return;

    // Remove any existing inline form row
    const existingFormRow = document.querySelector('tr.sender-form-row');
    if (existingFormRow) {
        existingFormRow.remove();
    }

    // Create a new table row to hold the form
    const formRow = document.createElement('tr');
    formRow.className = 'sender-form-row';
    const formCell = document.createElement('td');
    formCell.colSpan = 8;
    formCell.appendChild(formCard);
    formRow.appendChild(formCell);

    // Insert after the sender row
    senderRow.after(formRow);

    // Scroll into view
    setTimeout(() => {
        formCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 50);
}

/**
 * Load all senders and update the UI
 */
export async function loadSenders() {
    try {
        const senders = await SendersApi.getAll();

        const activeContainer = document.getElementById('activeSendersContainer');
        const inactiveContainer = document.getElementById('inactiveSendersContainer');

        // Split senders into active and inactive
        const activeSenders = senders.filter(s => s.enabled);
        const inactiveSenders = senders.filter(s => !s.enabled);

        // Update statistics
        document.getElementById('totalSenders').textContent = senders.length;
        document.getElementById('enabledSenders').textContent = activeSenders.length;
        document.getElementById('disabledSenders').textContent = inactiveSenders.length;

        // Skip table rebuild if the inline edit form is open (to avoid destroying it)
        if (document.querySelector('tr.sender-form-row')) {
            // Still update log counts and status in existing rows
            senders.forEach(sender => {
                const row = document.querySelector(`tr[data-sender-id="${sender.id}"]`);
                if (row) {
                    const logsCell = row.querySelector('.sender-logs-count');
                    if (logsCell) logsCell.textContent = (sender.logs_generated || 0).toLocaleString();
                    const statusCell = row.querySelector('.sender-status');
                    if (statusCell) {
                        const isAttack = !!(sender.log_type && state.attackTypes[sender.log_type]);
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
                    }
                }
            });
            return;
        }

        // Render active senders table
        renderSendersTable(activeContainer, activeSenders, 'No active senders.');

        // Render inactive senders table
        renderSendersTable(inactiveContainer, inactiveSenders, 'No inactive senders.');

    } catch (error) {
        console.error('Error loading senders:', error);
    }
}

/**
 * Render a senders table into a container
 */
function renderSendersTable(container, senders, emptyMessage) {
    if (senders.length === 0) {
        container.innerHTML = `<p class="no-senders">${emptyMessage}</p>`;
        return;
    }

    const table = document.createElement('table');
    table.className = 'senders-table';

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

    const tbody = document.createElement('tbody');
    senders.forEach(sender => {
        tbody.appendChild(createSenderRow(sender));
    });
    table.appendChild(tbody);

    container.innerHTML = '';
    container.appendChild(table);
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

            // Set options based on log type using configuration mapping
            const config = SOURCETYPE_CONFIG[sender.log_type];
            if (config && sender.options) {
                // Restore checkbox selections
                const optionValue = sender.options[config.optionKey];
                if (optionValue) {
                    restoreCheckboxes(config.checkboxGroup, optionValue);
                }

                // Restore additional fields if any
                if (config.additionalFields) {
                    Object.entries(config.additionalFields).forEach(([optKey, elemId]) => {
                        if (sender.options[optKey]) {
                            document.getElementById(elemId).value = sender.options[optKey];
                        }
                    });
                }
            } else if (sender.log_type && state.attackTypes[sender.log_type] && sender.options) {
                if (sender.options.attack_events_count) {
                    document.getElementById('attackEventsCount').value = sender.options.attack_events_count;
                }
                if (sender.options.attack_duration) {
                    document.getElementById('attackDuration').value = sender.options.attack_duration;
                }
                // Restore field overrides for all attack types
                document.getElementById('attackUser').value = sender.options.target_user || '';
                document.getElementById('attackDest').value = sender.options.target_dest || '';
                document.getElementById('attackSrcIp').value = sender.options.target_src_ip || '';
                document.getElementById('attackDestIp').value = sender.options.target_dest_ip || '';
                document.getElementById('attackDestPort').value = sender.options.target_dest_port || '';
            }

            // Update form title and button
            document.getElementById('senderFormTitle').textContent = 'Edit Sender';
            document.getElementById('submitSenderBtn').textContent = 'Update Sender';

            // Move form below the sender row and show it
            moveFormBelowRow(senderId);
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

    // Add options for log sourcetypes using configuration mapping
    const config = SOURCETYPE_CONFIG[logType];
    if (config) {
        const selectedValues = getSelectedCheckboxes(config.checkboxGroup);

        if (selectedValues.length === 0) {
            const typeName = logType.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
            showNotification(`Please select at least one ${typeName} option`, 'error');
            return;
        }

        data.options = {
            [config.optionKey]: selectedValues
        };

        // Add additional fields if configured
        if (config.additionalFields) {
            Object.entries(config.additionalFields).forEach(([optKey, elemId]) => {
                const value = formData.get(elemId) || document.getElementById(elemId)?.value;
                if (value) {
                    data.options[optKey] = value;
                }
            });
        }
    }
    // Add options for attacks
    else if (logType && state.attackTypes[logType]) {
        const eventsCount = parseInt(document.getElementById('attackEventsCount').value);
        const duration = parseInt(document.getElementById('attackDuration').value);

        data.options = {
            attack_events_count: eventsCount,
            attack_duration: duration
        };

        // Add field overrides for all attack types with fixed fields
        const attackUser = document.getElementById('attackUser').value.trim();
        const attackDest = document.getElementById('attackDest').value.trim();
        const srcIp = document.getElementById('attackSrcIp').value.trim();
        const destIp = document.getElementById('attackDestIp').value.trim();
        const destPort = document.getElementById('attackDestPort').value.trim();
        if (attackUser) data.options.target_user = attackUser;
        if (attackDest) data.options.target_dest = attackDest;
        if (srcIp) data.options.target_src_ip = srcIp;
        if (destIp) data.options.target_dest_ip = destIp;
        if (destPort) data.options.target_dest_port = parseInt(destPort);

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
    restoreFormToOriginalPosition();
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
    document.getElementById('adEventCategoriesGroup').style.display = 'none';
    document.getElementById('ciscoIOSEventCategoriesGroup').style.display = 'none';

    // Reset attack options and frequency
    document.getElementById('attackOptionsGroup').style.display = 'none';
    document.getElementById('attackFieldOverrides').style.display = 'none';
    document.getElementById('attackUserGroup').style.display = 'none';
    document.getElementById('attackDestGroup').style.display = 'none';
    document.getElementById('attackSrcIpGroup').style.display = 'none';
    document.getElementById('attackDestIpGroup').style.display = 'none';
    document.getElementById('attackDestPortGroup').style.display = 'none';
    document.getElementById('frequencyGroup').style.display = 'none';
    document.getElementById('frequency').disabled = false;
    document.getElementById('attackEventsCount').value = 100;
    document.getElementById('attackDuration').value = 60;
    document.getElementById('attackUser').value = '';
    document.getElementById('attackDest').value = '';
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
    Object.values(SOURCETYPE_CONFIG).forEach(config => {
        resetCheckboxes(config.checkboxGroup);
    });
}
