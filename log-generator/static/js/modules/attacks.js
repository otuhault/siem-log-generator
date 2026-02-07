/**
 * Attacks management module
 */

import { AttacksApi } from './api.js';
import { state, setAttacks, setAttackTypes, getLogTypeName } from './state.js';
import { formatDate, showNotification, escapeHtml } from './utils.js';
import { validateAttackForm, clearFormErrors } from './validation.js';

/**
 * Load attack types from the API
 */
export async function loadAttackTypes() {
    try {
        const attackTypes = await AttacksApi.getTypes();
        setAttackTypes(attackTypes);
    } catch (error) {
        console.error('Error loading attack types:', error);
    }
}

/**
 * Populate the attack type select dropdown
 */
export function populateAttackTypeSelect() {
    const select = document.getElementById('attackType');
    select.innerHTML = '<option value="">Static (use example log only)</option>';

    Object.keys(state.attackTypes).forEach(key => {
        const type = state.attackTypes[key];
        const option = document.createElement('option');
        option.value = key;
        option.textContent = type.name;
        select.appendChild(option);
    });
}

/**
 * Populate the attack log type dropdown
 */
export function populateAttackLogTypes() {
    const select = document.getElementById('attackLogType');
    select.innerHTML = '<option value="">Select a log type...</option>';

    Object.keys(state.logTypes).sort().forEach(key => {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = state.logTypes[key].name;
        select.appendChild(option);
    });
}

/**
 * Load all attacks and update the UI
 */
export async function loadAttacks() {
    try {
        const attacks = await AttacksApi.getAll();
        setAttacks(attacks);

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

/**
 * Create a table row for an attack
 * @param {object} attack - Attack data
 * @returns {HTMLElement} Table row element
 */
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
    if (attack.attack_type && state.attackTypes[attack.attack_type]) {
        const attackType = state.attackTypes[attack.attack_type];
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

/**
 * Toggle the attack example display
 * @param {HTMLElement} row - Table row element
 * @param {object} attack - Attack data
 */
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

/**
 * Handle attack form submission
 * @param {Event} e - Form submit event
 */
export async function handleCreateAttack(e) {
    e.preventDefault();

    // Validate form before processing
    const validation = validateAttackForm(e.target);
    if (!validation.isValid) {
        showNotification(validation.errors[0] || 'Please fix the form errors', 'error');
        return;
    }

    const formData = new FormData(e.target);
    const attackId = formData.get('id');

    const data = {
        name: formData.get('name').trim(),
        description: formData.get('description').trim(),
        log_type: formData.get('log_type'),
        example: formData.get('example').trim()
    };

    // Add attack type if selected
    const attackType = formData.get('attack_type');
    if (attackType) {
        data.attack_type = attackType;
    }

    try {
        let result;
        let successMessage;

        if (attackId) {
            result = await AttacksApi.update(attackId, data);
            successMessage = 'Attack updated successfully!';
        } else {
            result = await AttacksApi.create(data);
            successMessage = 'Attack created successfully!';
        }

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

/**
 * Edit an attack
 * @param {string} attackId - Attack ID
 */
export async function editAttack(attackId) {
    try {
        const attack = await AttacksApi.get(attackId);

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

/**
 * Clone an attack
 * @param {string} attackId - Attack ID
 */
export async function cloneAttack(attackId) {
    try {
        const result = await AttacksApi.clone(attackId);

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

/**
 * Delete an attack
 * @param {string} attackId - Attack ID
 */
export async function deleteAttack(attackId) {
    if (!confirm('Are you sure you want to delete this attack?')) {
        return;
    }

    try {
        const result = await AttacksApi.delete(attackId);

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

/**
 * Close and reset the attack form
 */
export function closeAttackForm() {
    const form = document.getElementById('createAttackForm');
    document.getElementById('attackFormCard').style.display = 'none';
    form.reset();
    clearFormErrors(form);
    document.getElementById('attackId').value = '';
    document.getElementById('attackFormTitle').textContent = 'Create New Attack';
    document.getElementById('submitAttackBtn').textContent = 'Create Attack';

    // Reset attack type selector
    document.getElementById('attackType').value = '';
}
