/**
 * Attacks documentation module
 * Displays built-in attack types (read-only, like sourcetypes)
 */

import { AttacksApi } from './api.js';
import { state, setAttackTypes } from './state.js';
import { escapeHtml } from './utils.js';

/**
 * Load and display attack types in the Attacks tab
 */
export async function loadAttackTypesView() {
    try {
        const container = document.getElementById('attacksContainer');

        // Load attack types if not already loaded
        if (!state.attackTypes || Object.keys(state.attackTypes).length === 0) {
            const attackTypes = await AttacksApi.getTypes();
            setAttackTypes(attackTypes);
        }

        // Group attack types by log_type
        const groups = {};
        Object.entries(state.attackTypes).forEach(([key, type]) => {
            const logType = type.log_type || 'other';
            if (!groups[logType]) {
                groups[logType] = [];
            }
            groups[logType].push({ key, ...type });
        });

        // Create attack types list
        const listDiv = document.createElement('div');
        listDiv.className = 'sourcetype-list';

        Object.keys(groups).sort().forEach(logType => {
            // Add group header
            const groupHeader = document.createElement('div');
            groupHeader.className = 'sourcetype-group-header';
            groupHeader.textContent = logType.toUpperCase();
            listDiv.appendChild(groupHeader);

            // Add each attack type in the group
            groups[logType].forEach(type => {
                const item = document.createElement('div');
                item.className = 'sourcetype-item';
                item.dataset.type = type.key;

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

                // Toggle inline details on click
                item.addEventListener('click', () => toggleAttackTypeDetails(item, type));

                listDiv.appendChild(item);
            });
        });

        container.innerHTML = '';
        container.appendChild(listDiv);

    } catch (error) {
        console.error('Error loading attack types:', error);
        document.getElementById('attacksContainer').innerHTML = '<p class="error">Error loading attack types</p>';
    }
}

/**
 * Toggle inline details for an attack type
 * @param {HTMLElement} parentElement - Parent element
 * @param {object} type - Attack type data
 */
function toggleAttackTypeDetails(parentElement, type) {
    const existingDetails = parentElement.querySelector('.inline-log-example');

    if (existingDetails) {
        existingDetails.style.display = existingDetails.style.display === 'none' ? 'block' : 'none';
        return;
    }

    // Build field behaviors HTML
    let fieldsHtml = '';
    if (type.field_behaviors) {
        Object.entries(type.field_behaviors).forEach(([field, behavior]) => {
            const badgeClass = behavior === 'fixed' ? 'behavior-fixed' : 'behavior-rotating';
            fieldsHtml += `
                <div class="attack-mode-item">
                    <strong>${field.replace('_', ' ')}</strong>
                    <span class="field-behavior-badge ${badgeClass}">${behavior}</span>
                </div>
            `;
        });
    }

    // Build sample logs HTML
    let sampleHtml = '';
    if (type.sample_logs && type.sample_logs.length > 0) {
        sampleHtml = `
            <div style="margin-top: 15px;">
                <div class="inline-example-title">Sample Logs</div>
                <pre class="inline-example-content">${type.sample_logs.map(l => escapeHtml(l)).join('\n')}</pre>
            </div>
        `;
    }

    // Create details element
    const detailsDiv = document.createElement('div');
    detailsDiv.className = 'inline-log-example';
    detailsDiv.innerHTML = `
        <div class="inline-example-title">Field Behaviors</div>
        <div class="attack-modes-list">
            ${fieldsHtml}
        </div>
        ${sampleHtml}
    `;

    parentElement.appendChild(detailsDiv);
}
