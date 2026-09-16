/**
 * Log Generator UI - Main Application
 *
 * This is the main entry point that orchestrates all modules.
 * Each feature is separated into its own module for maintainability.
 */

import { state } from './modules/state.js';
import { initNotificationStyles } from './modules/utils.js';
import { loadSenders, initSenderGroups, handleCreateSender, closeSenderForm, openSenderForm } from './modules/senders.js';
import { loadConfigurations, handleCreateConfiguration, closeConfigurationForm, testConnection } from './modules/configurations.js';
import { loadLogTypes } from './modules/sourcetypes.js';
import { SOURCETYPE_CONFIG, getAllFormGroupIds } from './modules/sourcetype-config.js';
import { loadSimulations, initSimulation } from './modules/simulation.js';
import { loadCatalog } from './modules/catalog.js';
import { initAttackConfig, showAttackConfig, hideAttackConfig } from './modules/attack-config.js';
import {
    loadSyslogDestinations,
    showSyslogDestinationForm,
    closeSyslogDestinationForm,
    handleCreateSyslogDestination,
    testSyslogConnection,
} from './modules/syslog-destinations.js';
import {
    loadNetworkPools,
    showPoolForm,
    closePoolForm,
    handleCreateNetworkPool,
} from './modules/network-pools.js';
import { initSenderForm, resetSenderForm } from './modules/sender-form.js';

/**
 * Initialize the application on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize notification styles
    initNotificationStyles();

    // Load initial data
    loadLogTypes();
    initSenderGroups();
    loadSenders();
    loadConfigurations();
    loadSyslogDestinations();   // the senders list names the destination it uses

    // Setup event listeners and tabs
    setupEventListeners();
    setupTabs();
    initSimulation();
    initSenderForm();

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
        openSenderForm();
        loadConfigurations();
        loadSyslogDestinations();   // populate syslog dropdown for the sender form
        resetSenderForm();
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

    // ── Syslog Destinations ──
    const addSyslogBtn = document.getElementById('addSyslogDestinationBtn');
    if (addSyslogBtn) addSyslogBtn.addEventListener('click', () => showSyslogDestinationForm(null));
    const syslogForm = document.getElementById('createSyslogDestinationForm');
    if (syslogForm) syslogForm.addEventListener('submit', handleCreateSyslogDestination);
    const closeSyslogForm  = document.getElementById('closeSyslogDestinationForm');
    if (closeSyslogForm)  closeSyslogForm.addEventListener('click', closeSyslogDestinationForm);
    const cancelSyslogForm = document.getElementById('cancelSyslogDestinationForm');
    if (cancelSyslogForm) cancelSyslogForm.addEventListener('click', closeSyslogDestinationForm);
    const testSyslogBtn = document.getElementById('testSyslogConnectionBtn');
    if (testSyslogBtn) testSyslogBtn.addEventListener('click', testSyslogConnection);

    // ── Network Pools ──
    const addNpBtn = document.getElementById('addNetworkPoolBtn');
    if (addNpBtn) addNpBtn.addEventListener('click', () => showPoolForm(''));
    const npForm = document.getElementById('createNetworkPoolForm');
    if (npForm) npForm.addEventListener('submit', handleCreateNetworkPool);
    const closeNpForm  = document.getElementById('closeNetworkPoolForm');
    if (closeNpForm)  closeNpForm.addEventListener('click', closePoolForm);
    const cancelNpForm = document.getElementById('cancelNetworkPoolForm');
    if (cancelNpForm) cancelNpForm.addEventListener('click', closePoolForm);

    // Destination type radio buttons
    setupDestinationTypeListeners();

    // Log type selection handler
    initAttackConfig();
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
        const trackBg = getComputedStyle(document.documentElement).getPropertyValue('--surface-3').trim() || '#262b34';
        const fillBg  = getComputedStyle(document.documentElement).getPropertyValue('--primary-color').trim() || '#00b7d2';
        this.style.background = `linear-gradient(to right, ${trackBg} 0%, ${trackBg} ${100-pct}%, ${fillBg} ${100-pct}%, ${fillBg} 100%)`;
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
                loadSyslogDestinations();   // refresh the dropdown when user switches to syslog
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

            // An attack that declares its data sources brings its own sourcetype
            // rows, environment, noise and defaults. The others keep these.
            const sourced = showAttackConfig(selectedType, attackType);
            if (sourced) {
                // defaults already applied from the attack's definition
            } else if (attackType.log_type === 'ssh') {
                eventsInput.value = 50;
                durationInput.value = 30;
            } else if (attackType.log_type === 'paloalto') {
                eventsInput.value = 300;
                durationInput.value = 60;
            } else {
                eventsInput.value = 100;
                durationInput.value = 60;
            }

            // Override inputs. A migrated attack pins any of its fields for every
            // event; a legacy one only honours overrides on its fixed fields.
            const fb = attackType.field_behaviors || {};
            const pinnable = (field) => field in fb && (sourced || fb[field] === 'fixed');
            userGroup.style.display = pinnable('user') ? 'block' : 'none';
            destGroup.style.display = pinnable('dest') ? 'block' : 'none';
            srcIpGroup.style.display = pinnable('src_ip') ? 'block' : 'none';
            destIpGroup.style.display = pinnable('dest_ip') ? 'block' : 'none';
            destPortGroup.style.display = pinnable('dest_port') ? 'block' : 'none';
            fieldOverrides.style.display = Object.keys(fb).some(pinnable) ? 'block' : 'none';

            hideAllOptions();

            // Show attack options, hide and disable frequency for attacks
            attackOptionsGroup.style.display = 'block';
            frequencyGroup.style.display = 'none';
            frequencyInput.disabled = true;
            document.getElementById('useAssetsIdentitiesGroup').style.display = 'none';
        }
        // Check if it's a sourcetype
        else if (selectedType && state.logTypes[selectedType]) {
            hideAttackConfig();
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
            hideAttackConfig();
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
 *
 * Two levels:
 *   - Top-level: Senders / Configuration / Simulation (`.tab-btn` + `.tab-content`)
 *   - Configuration sub-tabs: HEC / Syslog / Network / Sourcetypes / Attacks / A&I
 *     (`.config-subtab-btn` + `.config-subtab-content`)
 */
function setupTabs() {
    // Top-level tabs
    document.querySelectorAll('.tab-btn').forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.dataset.tab;

            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

            this.classList.add('active');
            document.getElementById(tabName + 'Tab').classList.add('active');

            if (tabName === 'configuration') {
                // Re-fire the active sub-tab so its loader runs
                const activeSub = document.querySelector('.config-subtab-btn.active');
                if (activeSub) loadConfigSubtab(activeSub.dataset.subtab);
            } else if (tabName === 'simulation') {
                loadSimulations();
            } else if (tabName === 'catalog') {
                loadCatalog();
            }
        });
    });

    // Configuration sub-tabs
    document.querySelectorAll('.config-subtab-btn').forEach(button => {
        button.addEventListener('click', function() {
            const sub = this.dataset.subtab;

            document.querySelectorAll('.config-subtab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.config-subtab-content').forEach(c => c.classList.remove('active'));

            this.classList.add('active');
            const targetId = subtabToContentId(sub);
            const target = document.getElementById(targetId);
            if (target) target.classList.add('active');

            loadConfigSubtab(sub);
        });
    });

    // Catalog sub-tabs. The catalog is one fetch rendered into all three, so
    // switching only swaps which panel shows — there is nothing to reload.
    document.querySelectorAll('.catalog-subtab-btn').forEach(button => {
        button.addEventListener('click', function() {
            document.querySelectorAll('.catalog-subtab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.catalog-subtab-content').forEach(c => c.classList.remove('active'));

            this.classList.add('active');
            const target = document.getElementById(
                'catalog' + this.dataset.subtab.replace(/^./, (c) => c.toUpperCase()) + 'Tab');
            if (target) target.classList.add('active');
        });
    });
}

/** Map sub-tab key → content div id */
function subtabToContentId(sub) {
    return ({
        hec:         'configurationsTab',
        syslog:      'syslogTab',
        network:     'networkTab',
        ai:          'environmentTab',
    })[sub] || sub + 'Tab';
}

/** Trigger the data loader for a Configuration sub-tab */
function loadConfigSubtab(sub) {
    if (sub === 'hec')              loadConfigurations();
    else if (sub === 'syslog')      loadSyslogDestinations();
    else if (sub === 'network')     loadNetworkPools();
    else if (sub === 'ai')          window.loadEnvData?.();
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
    rows.innerHTML = '<div style="font-size:0.82em;color:var(--text-secondary);padding:4px 0;">Loading…</div>';
    panel.style.display = 'block';

    try {
        const res  = await fetch(`/api/environment/impact/${logType}`);
        const data = await res.json();

        if (!data.length) {
            rows.innerHTML = '<div style="font-size:0.82em;color:var(--text-secondary);padding:4px 0;">No environment mapping for this sourcetype.</div>';
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
        rows.innerHTML = '<div style="font-size:0.82em;color:var(--danger-color);">Failed to load impact data.</div>';
    }
}
