/**
 * Log Generator UI - Main Application
 *
 * This is the main entry point that orchestrates all modules.
 * Each feature is separated into its own module for maintainability.
 */

import { state } from './modules/state.js';
import { initNotificationStyles } from './modules/utils.js';
import { loadSenders, handleCreateSender, closeSenderForm, restoreFormToOriginalPosition } from './modules/senders.js';
import { loadConfigurations, handleCreateConfiguration, closeConfigurationForm, testConnection } from './modules/configurations.js';
import { loadAttackTypesView } from './modules/attacks.js';
import { loadLogTypes, loadSourcetypes } from './modules/sourcetypes.js';
import { SOURCETYPE_CONFIG, getAllFormGroupIds } from './modules/sourcetype-config.js';
import { loadSimulations, initSimulation } from './modules/simulation.js';

/**
 * Initialize the application on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize notification styles
    initNotificationStyles();

    // Load initial data
    loadLogTypes();
    loadSenders();
    loadConfigurations();

    // Setup event listeners and tabs
    setupEventListeners();
    setupTabs();
    initSimulation();

    // Refresh senders every 2 seconds to update counts
    setInterval(loadSenders, 2000);
});

/**
 * Setup all event listeners for the UI
 */
function setupEventListeners() {
    // Form submissions
    document.getElementById('createSenderForm').addEventListener('submit', handleCreateSender);
    document.getElementById('createConfigurationForm').addEventListener('submit', handleCreateConfiguration);

    // Add Sender button
    document.getElementById('addSenderBtn').addEventListener('click', function() {
        closeSenderForm();
        document.getElementById('senderFormCard').style.display = 'block';
        loadConfigurations();
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

    // Test connection button
    document.getElementById('testConnectionBtn').addEventListener('click', testConnection);

    // Destination type radio buttons
    setupDestinationTypeListeners();

    // Close log example
    const closeLogExample = document.getElementById('closeLogExample');
    if (closeLogExample) {
        closeLogExample.addEventListener('click', function() {
            document.getElementById('logExampleCard').style.display = 'none';
        });
    }

    // Log type selection handler
    setupLogTypeListener();

    // A&I toggle → show/hide slider + impact panel
    document.getElementById('useAssetsIdentities').addEventListener('change', function() {
        const ratioGroup  = document.getElementById('aiRatioGroup');
        const impactPanel = document.getElementById('aiImpactPanel');
        if (this.checked) {
            ratioGroup.style.display = 'block';
            document.getElementById('aiRatio').value = 100;
            document.getElementById('aiRatioValue').textContent = '100%';
            const logType = document.getElementById('logType').value;
            if (logType) loadAIImpact(logType);
        } else {
            ratioGroup.style.display = 'none';
            impactPanel.style.display = 'none';
        }
    });

    // A&I slider → live label update
    document.getElementById('aiRatio').addEventListener('input', function() {
        document.getElementById('aiRatioValue').textContent = this.value + '%';
        // Update gradient fill to reflect position
        const pct = this.value;
        this.style.background = `linear-gradient(to right, #d0d7de 0%, #d0d7de ${100-pct}%, #0969da ${100-pct}%, #0969da 100%)`;
    });
}

/**
 * Setup destination type radio button listeners
 */
function setupDestinationTypeListeners() {
    document.querySelectorAll('input[name="destination_type"]').forEach(radio => {
        radio.addEventListener('change', function() {
            const fileGroup        = document.getElementById('fileDestinationGroup');
            const configGroup      = document.getElementById('configurationDestinationGroup');
            const syslogGroup      = document.getElementById('syslogDestinationGroup');
            const hecOverridesGroup = document.getElementById('hecOverridesGroup');
            const destInput        = document.getElementById('destination');
            const configSel        = document.getElementById('configurationSelect');

            // Hide all, clear required
            fileGroup.style.display        = 'none';
            configGroup.style.display      = 'none';
            syslogGroup.style.display      = 'none';
            hecOverridesGroup.style.display = 'none';
            destInput.required = false;
            configSel.required = false;

            if (this.value === 'file') {
                fileGroup.style.display = 'block';
                destInput.required = true;
            } else if (this.value === 'configuration') {
                configGroup.style.display      = 'block';
                hecOverridesGroup.style.display = 'block';
                configSel.required = true;
            } else if (this.value === 'syslog') {
                syslogGroup.style.display = 'block';
            }
        });
    });
}

/**
 * Setup log type selection listener
 * Shows/hides appropriate options based on selected type
 */
function setupLogTypeListener() {
    document.getElementById('logType').addEventListener('change', function(e) {
        const description = document.getElementById('logTypeDescription');
        const selectedType = e.target.value;
        const renderFormatGroup = document.getElementById('renderFormatGroup');
        const frequencyGroup = document.getElementById('frequencyGroup');
        const attackOptionsGroup = document.getElementById('attackOptionsGroup');
        const frequencyInput = document.getElementById('frequency');

        // Hide all sourcetype-specific form groups
        const hideAllOptions = () => {
            getAllFormGroupIds().forEach(groupId => {
                const elem = document.getElementById(groupId);
                if (elem) elem.style.display = 'none';
            });
        };

        // Check if it's an attack type
        if (selectedType && state.attackTypes[selectedType]) {
            const attackType = state.attackTypes[selectedType];
            description.textContent = attackType.description;
            description.classList.add('show');

            // Set default values based on log type
            const eventsInput = document.getElementById('attackEventsCount');
            const durationInput = document.getElementById('attackDuration');

            const fieldOverrides = document.getElementById('attackFieldOverrides');
            const userGroup = document.getElementById('attackUserGroup');
            const destGroup = document.getElementById('attackDestGroup');
            const srcIpGroup = document.getElementById('attackSrcIpGroup');
            const destIpGroup = document.getElementById('attackDestIpGroup');
            const destPortGroup = document.getElementById('attackDestPortGroup');

            // Set defaults per log type
            if (attackType.log_type === 'ssh') {
                eventsInput.value = 50;
                durationInput.value = 30;
            } else if (attackType.log_type === 'paloalto') {
                eventsInput.value = 300;
                durationInput.value = 60;
            } else if (attackType.log_type === 'windows') {
                eventsInput.value = 10;
                durationInput.value = 60;
            } else {
                eventsInput.value = 100;
                durationInput.value = 60;
            }

            // Dynamically show override fields for all fixed behaviors
            const fb = attackType.field_behaviors || {};
            userGroup.style.display = fb.user === 'fixed' ? 'block' : 'none';
            destGroup.style.display = fb.dest === 'fixed' ? 'block' : 'none';
            srcIpGroup.style.display = fb.src_ip === 'fixed' ? 'block' : 'none';
            destIpGroup.style.display = fb.dest_ip === 'fixed' ? 'block' : 'none';
            destPortGroup.style.display = fb.dest_port === 'fixed' ? 'block' : 'none';

            // Show field overrides container if any fixed field exists
            const hasFixedFields = Object.values(fb).some(v => v === 'fixed');
            fieldOverrides.style.display = hasFixedFields ? 'block' : 'none';

            hideAllOptions();

            // Show attack options, hide and disable frequency for attacks
            attackOptionsGroup.style.display = 'block';
            frequencyGroup.style.display = 'none';
            frequencyInput.disabled = true;
            document.getElementById('useAssetsIdentitiesGroup').style.display = 'none';
        }
        // Check if it's a sourcetype
        else if (selectedType && state.logTypes[selectedType]) {
            description.textContent = state.logTypes[selectedType].description;
            description.classList.add('show');

            // Hide attack options, show frequency for sourcetypes
            attackOptionsGroup.style.display = 'none';
            frequencyGroup.style.display = 'block';
            frequencyInput.disabled = false;

            // Show Assets & Identities toggle for sourcetypes
            document.getElementById('useAssetsIdentitiesGroup').style.display = 'block';

            // Refresh impact panel if toggle is already on
            if (document.getElementById('useAssetsIdentities').checked) {
                loadAIImpact(selectedType);
            }

            // Show type-specific options using configuration
            hideAllOptions();
            const config = SOURCETYPE_CONFIG[selectedType];
            if (config && config.formGroups) {
                config.formGroups.forEach(groupId => {
                    const elem = document.getElementById(groupId);
                    if (elem) elem.style.display = 'block';
                });
            }
        } else {
            description.classList.remove('show');
            hideAllOptions();

            // Reset to default state
            attackOptionsGroup.style.display = 'none';
            frequencyGroup.style.display = 'none';
            document.getElementById('useAssetsIdentitiesGroup').style.display = 'none';
        }
    });
}

/**
 * Setup tab navigation
 */
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
            } else if (tabName === 'attacks') {
                loadAttackTypesView();
            } else if (tabName === 'simulation') {
                loadSimulations();
            } else if (tabName === 'environment') {
                // handled by environment.js
            }
        });
    });
}

/**
 * Load and render the Environment Impact panel for a given log type.
 * Called when the Environment toggle is checked or the sourcetype changes.
 * Exposed on window so senders.js (another ES module) can call it.
 */
window.loadAIImpact = loadAIImpact;
async function loadAIImpact(logType) {
    const panel = document.getElementById('aiImpactPanel');
    const rows  = document.getElementById('aiImpactRows');
    rows.innerHTML = '<div style="font-size:0.82em;color:#57606a;padding:4px 0;">Loading…</div>';
    panel.style.display = 'block';

    try {
        const res  = await fetch(`/api/environment/impact/${logType}`);
        const data = await res.json();

        if (!data.length) {
            rows.innerHTML = '<div style="font-size:0.82em;color:#57606a;padding:4px 0;">No environment mapping for this sourcetype.</div>';
            return;
        }

        rows.innerHTML = data.map(row => {
            const cls   = row.available ? 'available' : 'fallback';
            const badge = row.available
                ? `<span class="ai-count available">${row.count}</span>`
                : `<span class="ai-count fallback">0</span>`;
            return `<div class="ai-impact-row ${cls}">
                <span class="ai-cim-field">${row.cim_field}</span>
                ${badge}
            </div>`;
        }).join('');
    } catch (err) {
        rows.innerHTML = '<div style="font-size:0.82em;color:#cf222e;">Failed to load impact data.</div>';
    }
}
