/**
 * Log Generator UI - Main Application
 *
 * This is the main entry point that orchestrates all modules.
 * Each feature is separated into its own module for maintainability.
 */

import { state } from './modules/state.js';
import { initNotificationStyles } from './modules/utils.js';
import { loadSenders, handleCreateSender, closeSenderForm } from './modules/senders.js';
import { loadConfigurations, handleCreateConfiguration, closeConfigurationForm, testConnection } from './modules/configurations.js';
import { loadAttackTypesView } from './modules/attacks.js';
import { loadLogTypes, loadSourcetypes } from './modules/sourcetypes.js';

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
        const windowsSourcesGroup = document.getElementById('windowsSourcesGroup');
        const apacheLogTypesGroup = document.getElementById('apacheLogTypesGroup');
        const sshEventCategoriesGroup = document.getElementById('sshEventCategoriesGroup');
        const paloaltoLogTypesGroup = document.getElementById('paloaltoLogTypesGroup');
        const frequencyGroup = document.getElementById('frequencyGroup');
        const attackOptionsGroup = document.getElementById('attackOptionsGroup');
        const frequencyInput = document.getElementById('frequency');

        // Hide all specific options by default
        const hideAllOptions = () => {
            windowsSourcesGroup.style.display = 'none';
            renderFormatGroup.style.display = 'none';
            apacheLogTypesGroup.style.display = 'none';
            sshEventCategoriesGroup.style.display = 'none';
            paloaltoLogTypesGroup.style.display = 'none';
        };

        // Check if it's an attack type
        if (selectedType && state.attackTypes[selectedType]) {
            const attackType = state.attackTypes[selectedType];
            description.textContent = attackType.description;
            description.classList.add('show');

            // Set default values based on log type
            const eventsInput = document.getElementById('attackEventsCount');
            const durationInput = document.getElementById('attackDuration');

            if (attackType.log_type === 'ssh') {
                eventsInput.value = 50;
                durationInput.value = 30;
            } else {
                eventsInput.value = 100;
                durationInput.value = 60;
            }

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

            // Show type-specific options
            if (selectedType === 'windows') {
                windowsSourcesGroup.style.display = 'block';
                renderFormatGroup.style.display = 'block';
                apacheLogTypesGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
                paloaltoLogTypesGroup.style.display = 'none';
            } else if (selectedType === 'apache') {
                apacheLogTypesGroup.style.display = 'block';
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
                paloaltoLogTypesGroup.style.display = 'none';
            } else if (selectedType === 'ssh') {
                sshEventCategoriesGroup.style.display = 'block';
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                apacheLogTypesGroup.style.display = 'none';
                paloaltoLogTypesGroup.style.display = 'none';
            } else if (selectedType === 'paloalto') {
                paloaltoLogTypesGroup.style.display = 'block';
                windowsSourcesGroup.style.display = 'none';
                renderFormatGroup.style.display = 'none';
                apacheLogTypesGroup.style.display = 'none';
                sshEventCategoriesGroup.style.display = 'none';
            } else {
                hideAllOptions();
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
