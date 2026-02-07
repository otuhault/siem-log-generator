/**
 * Configurations management module
 */

import { ConfigurationsApi } from './api.js';
import { state, setConfigurations } from './state.js';
import { formatDate, showNotification } from './utils.js';
import { validateConfigurationForm, clearFormErrors } from './validation.js';

/**
 * Load all configurations and update the UI
 */
export async function loadConfigurations() {
    try {
        const configurations = await ConfigurationsApi.getAll();
        setConfigurations(configurations);

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

/**
 * Create a table row for a configuration
 * @param {object} config - Configuration data
 * @returns {HTMLElement} Table row element
 */
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

/**
 * Handle configuration form submission
 * @param {Event} e - Form submit event
 */
export async function handleCreateConfiguration(e) {
    e.preventDefault();

    // Validate form before processing
    const validation = validateConfigurationForm(e.target);
    if (!validation.isValid) {
        showNotification(validation.errors[0] || 'Please fix the form errors', 'error');
        return;
    }

    const formData = new FormData(e.target);
    const configId = formData.get('id');

    const data = {
        name: formData.get('name').trim(),
        url: formData.get('url').trim(),
        port: parseInt(formData.get('port')),
        token: formData.get('token').trim(),
        index: formData.get('index')?.trim() || undefined,
        sourcetype: formData.get('sourcetype')?.trim() || undefined,
        host: formData.get('host')?.trim() || undefined,
        source: formData.get('source')?.trim() || undefined
    };

    try {
        let result;
        let successMessage;

        if (configId) {
            result = await ConfigurationsApi.update(configId, data);
            successMessage = 'Configuration updated successfully!';
        } else {
            result = await ConfigurationsApi.create(data);
            successMessage = 'Configuration created successfully!';
        }

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

/**
 * Edit a configuration
 * @param {string} configId - Configuration ID
 */
export async function editConfiguration(configId) {
    try {
        const config = await ConfigurationsApi.get(configId);

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

/**
 * Clone a configuration
 * @param {string} configId - Configuration ID
 */
export async function cloneConfiguration(configId) {
    try {
        const result = await ConfigurationsApi.clone(configId);

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

/**
 * Delete a configuration
 * @param {string} configId - Configuration ID
 */
export async function deleteConfiguration(configId) {
    if (!confirm('Are you sure you want to delete this configuration?')) {
        return;
    }

    try {
        const result = await ConfigurationsApi.delete(configId);

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

/**
 * Close and reset the configuration form
 */
export function closeConfigurationForm() {
    const form = document.getElementById('createConfigurationForm');
    document.getElementById('configurationFormCard').style.display = 'none';
    form.reset();
    clearFormErrors(form);
    document.getElementById('configurationId').value = '';
    document.getElementById('configurationFormTitle').textContent = 'Create New HEC Destination';
    document.getElementById('submitConfigurationBtn').textContent = 'Create HEC Destination';
    // Reset test button state
    const testBtn = document.getElementById('testConnectionBtn');
    if (testBtn) {
        testBtn.disabled = false;
        testBtn.textContent = 'Test Connection';
    }
}

/**
 * Test HEC connection with current form values
 */
export async function testConnection() {
    const form = document.getElementById('createConfigurationForm');
    const testBtn = document.getElementById('testConnectionBtn');

    // Get form values
    const url = document.getElementById('configurationUrl').value.trim();
    const port = document.getElementById('configurationPort').value;
    const token = document.getElementById('configurationToken').value.trim();

    // Basic validation
    if (!url || !port || !token) {
        showNotification('Please fill in URL, Port, and Token fields first', 'error');
        return;
    }

    // Show loading state
    testBtn.disabled = true;
    testBtn.textContent = 'Testing...';

    try {
        const data = {
            url: url,
            port: parseInt(port),
            token: token,
            index: document.getElementById('configurationIndex').value.trim() || undefined,
            sourcetype: document.getElementById('configurationSourcetype').value.trim() || undefined,
            host: document.getElementById('configurationHost').value.trim() || undefined,
            source: document.getElementById('configurationSource').value.trim() || undefined
        };

        const result = await ConfigurationsApi.test(data);

        if (result.success) {
            showNotification(result.message || 'Connection successful!', 'success');
            testBtn.textContent = 'Connection OK';
            testBtn.classList.add('btn-success');
        } else {
            showNotification('Connection failed: ' + result.error, 'error');
            testBtn.textContent = 'Test Failed';
            testBtn.classList.add('btn-error');
        }
    } catch (error) {
        showNotification('Connection error: ' + error.message, 'error');
        testBtn.textContent = 'Test Failed';
        testBtn.classList.add('btn-error');
    }

    // Reset button after delay
    setTimeout(() => {
        testBtn.disabled = false;
        testBtn.textContent = 'Test Connection';
        testBtn.classList.remove('btn-success', 'btn-error');
    }, 3000);
}
