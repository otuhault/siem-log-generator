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
        restoreFormToOriginalPosition();
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
}

/**
 * Setup destination type radio button listeners
 */
function setupDestinationTypeListeners() {
    document.querySelectorAll('input[name="destination_type"]').forEach(radio => {
        radio.addEventListener('change', function() {
            const fileGroup = document.getElementById('fileDestinationGroup');
            const configGroup = document.getElementById('configurationDestinationGroup');
            const destinationInput = document.getElementById('destination');

            if (this.value === 'file') {
                fileGroup.style.display = 'block';
                configGroup.style.display = 'none';
                destinationInput.required = true;
                document.getElementById('configurationSelect').required = false;
            } else {
                fileGroup.style.display = 'none';
                configGroup.style.display = 'block';
                destinationInput.required = false;
                document.getElementById('configurationSelect').required = true;
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
        }
        // Check if it's a sourcetype
        else if (selectedType && state.logTypes[selectedType]) {
            description.textContent = state.logTypes[selectedType].description;
            description.classList.add('show');

            // Hide attack options, show frequency for sourcetypes
            attackOptionsGroup.style.display = 'none';
            frequencyGroup.style.display = 'block';
            frequencyInput.disabled = false;

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
            }
        });
    });
}
