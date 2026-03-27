/**
 * Simulation module
 * Handles creating and managing infrastructure volume simulations.
 */

import { SimulationsApi, ConfigurationsApi, LogTypesApi } from './api.js';
import { showNotification } from './utils.js';
import { SOURCETYPE_CONFIG } from './sourcetype-config.js';

let logTypes = {};  // populated from /api/log-types

// ─── Public entry points ────────────────────────────────────────────────────

export async function loadSimulations() {
    try {
        const [simulations, types, configs] = await Promise.all([
            SimulationsApi.getAll(),
            LogTypesApi.getAll(),
            ConfigurationsApi.getAll(),
        ]);
        logTypes = types;
        renderSimulationsList(simulations);
        updateSimulationStats(simulations);
        populateSimSourcetypesGrid(types);
        populateSimHecSelect(configs);
    } catch (e) {
        console.error('Failed to load simulations:', e);
    }
}

export function initSimulation() {
    document.getElementById('addSimulationBtn').addEventListener('click', openSimulationForm);
    document.getElementById('closeSimulationForm').addEventListener('click', closeSimulationForm);
    document.getElementById('cancelSimulationForm').addEventListener('click', closeSimulationForm);
    document.getElementById('createSimulationForm').addEventListener('submit', handleCreateSimulation);

    // Destination type toggle
    document.querySelectorAll('input[name="sim_destination_type"]').forEach(radio => {
        radio.addEventListener('change', () => {
            const val = document.querySelector('input[name="sim_destination_type"]:checked').value;
            document.getElementById('simFileDestGroup').style.display   = val === 'file'          ? 'block' : 'none';
            document.getElementById('simHecDestGroup').style.display    = val === 'configuration' ? 'block' : 'none';
            document.getElementById('simSyslogDestGroup').style.display = val === 'syslog'        ? 'block' : 'none';
        });
    });

    // Live summary update + subcategory toggle when volumes change
    document.getElementById('simSourcetypesGrid').addEventListener('input', e => {
        if (e.target.classList.contains('sim-volume-input')) {
            toggleSubcategories(e.target);
        }
        updateSimSummary();
    });
    document.getElementById('simDurationValue').addEventListener('input', updateSimSummary);
    document.getElementById('simDurationUnit').addEventListener('change', updateSimSummary);
}

// ─── Form ────────────────────────────────────────────────────────────────────

function openSimulationForm() {
    loadSimulations();  // refresh HEC select + grid
    document.getElementById('simulationFormCard').style.display = 'block';
}

function closeSimulationForm() {
    document.getElementById('simulationFormCard').style.display = 'none';
    document.getElementById('createSimulationForm').reset();
    updateSimSummary();
}

function populateSimSourcetypesGrid(types) {
    const grid = document.getElementById('simSourcetypesGrid');
    if (!types || Object.keys(types).length === 0) {
        grid.innerHTML = '<p>No sourcetypes available.</p>';
        return;
    }
    grid.innerHTML = Object.entries(types).map(([key, info]) => {
        const sources = info.sources || [];
        const subcatsHtml = sources.length ? `
            <div class="sim-subcategories" data-log-type="${key}" style="display:none;">
                <div class="sim-subcat-header">
                    <span>Categories:</span>
                    <button type="button" class="sim-subcat-toggle-all" data-log-type="${key}">All / None</button>
                </div>
                <div class="sim-subcat-list">
                    ${sources.map(s => `
                        <label class="sim-subcat-label">
                            <input type="checkbox" class="sim-subcat-checkbox" value="${s.id}" checked>
                            <span>${s.name}</span>
                        </label>
                    `).join('')}
                </div>
            </div>` : '';

        return `
        <div class="sim-sourcetype-block" data-log-type="${key}">
            <div class="sim-sourcetype-row">
                <div class="sim-sourcetype-info">
                    <span class="sim-sourcetype-name">${info.name}</span>
                </div>
                <div class="sim-sourcetype-input">
                    <input type="number" class="sim-volume-input" data-log-type="${key}"
                           min="0" step="0.1" value="0" placeholder="0">
                    <span class="sim-unit">GB</span>
                </div>
            </div>
            ${subcatsHtml}
        </div>`;
    }).join('');

    // All/None toggle buttons
    grid.querySelectorAll('.sim-subcat-toggle-all').forEach(btn => {
        btn.addEventListener('click', () => {
            const block = grid.querySelector(`.sim-subcategories[data-log-type="${btn.dataset.logType}"]`);
            const boxes = block.querySelectorAll('.sim-subcat-checkbox');
            const allChecked = [...boxes].every(cb => cb.checked);
            boxes.forEach(cb => { cb.checked = !allChecked; });
        });
    });
}

function toggleSubcategories(volumeInput) {
    const logType = volumeInput.dataset.logType;
    const gb = parseFloat(volumeInput.value) || 0;
    const subcatDiv = document.querySelector(`.sim-subcategories[data-log-type="${logType}"]`);
    if (subcatDiv) {
        subcatDiv.style.display = gb > 0 ? 'block' : 'none';
    }
}

function populateSimHecSelect(configs) {
    const select = document.getElementById('simConfigurationSelect');
    const current = select.value;
    select.innerHTML = '<option value="">Select a destination...</option>';
    (configs || []).forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = c.name;
        if (c.id === current) opt.selected = true;
        select.appendChild(opt);
    });
}

function updateSimSummary() {
    const durationVal = parseFloat(document.getElementById('simDurationValue').value) || 0;
    const durationUnit = parseFloat(document.getElementById('simDurationUnit').value) || 1;
    const durationHours = durationVal * durationUnit;
    const durationSec = durationHours * 3600;

    let totalGB = 0;
    let totalFreq = 0;

    document.querySelectorAll('.sim-volume-input').forEach(input => {
        const gb = parseFloat(input.value) || 0;
        const logType = input.dataset.logType;
        totalGB += gb;
        if (gb > 0 && durationSec > 0) {
            const avgSize = AVG_LOG_SIZES[logType] || 300;
            const freq = (gb * 1024 ** 3) / (durationSec * avgSize);
            totalFreq += Math.max(1, Math.min(10000, freq));
        }
    });

    const summary = document.getElementById('simSummary');
    if (totalGB > 0) {
        summary.style.display = 'block';
        document.getElementById('simTotalGB').textContent = `${totalGB.toFixed(2)} GB`;
        document.getElementById('simTotalRate').textContent = `~${totalFreq.toFixed(1)} logs/sec`;
    } else {
        summary.style.display = 'none';
    }
}

// Mirror of server-side AVG_LOG_SIZES for the live preview
const AVG_LOG_SIZES = {
    apache: 200, windows: 600, ssh: 150, paloalto: 400,
    active_directory: 900, cisco_ios: 150, cisco_ftd: 250,
};

async function handleCreateSimulation(e) {
    e.preventDefault();

    const name = document.getElementById('simName').value.trim();
    const durationVal = parseFloat(document.getElementById('simDurationValue').value) || 1;
    const durationUnit = parseFloat(document.getElementById('simDurationUnit').value) || 1;
    const durationHours = durationVal * durationUnit;
    const destType       = document.querySelector('input[name="sim_destination_type"]:checked').value;
    const destination    = destType === 'file'          ? document.getElementById('simDestination').value.trim() : null;
    const configId       = destType === 'configuration' ? document.getElementById('simConfigurationSelect').value : null;
    const syslogHost     = destType === 'syslog'        ? document.getElementById('simSyslogHost').value.trim() : null;
    const syslogPort     = destType === 'syslog'        ? parseInt(document.getElementById('simSyslogPort').value) || 514 : null;
    const syslogProtocol = destType === 'syslog'        ? document.getElementById('simSyslogProtocol').value : null;

    const sourcetypes = [];
    document.querySelectorAll('.sim-volume-input').forEach(input => {
        const gb = parseFloat(input.value) || 0;
        if (gb <= 0) return;

        const logType = input.dataset.logType;
        const config = SOURCETYPE_CONFIG[logType];
        let options = {};

        if (config?.optionKey) {
            const block = document.querySelector(`.sim-subcategories[data-log-type="${logType}"]`);
            const selected = block
                ? [...block.querySelectorAll('.sim-subcat-checkbox:checked')].map(cb => cb.value)
                : [];
            if (selected.length) {
                options = { [config.optionKey]: selected };
            }
        }

        sourcetypes.push({ log_type: logType, volume_gb: gb, options });
    });

    if (sourcetypes.length === 0) {
        showNotification('Add at least one sourcetype with volume > 0.', 'error');
        return;
    }
    if (destType === 'file' && !destination) {
        showNotification('Please specify an output file path.', 'error');
        return;
    }
    if (destType === 'configuration' && !configId) {
        showNotification('Please select a HEC destination.', 'error');
        return;
    }
    if (destType === 'syslog' && !syslogHost) {
        showNotification('Please specify a syslog host.', 'error');
        return;
    }

    try {
        const result = await SimulationsApi.create({
            name, duration_hours: durationHours,
            sourcetypes, destination,
            destination_type: destType,
            configuration_id: configId,
            syslog_host: syslogHost,
            syslog_port: syslogPort,
            syslog_protocol: syslogProtocol,
        });

        if (result.success) {
            showNotification('Simulation created!', 'success');
            closeSimulationForm();
            loadSimulations();
        } else {
            showNotification(result.error || 'Failed to create simulation.', 'error');
        }
    } catch (err) {
        showNotification('Error: ' + err.message, 'error');
    }
}

// ─── List rendering ──────────────────────────────────────────────────────────

function renderSimulationsList(simulations) {
    const container = document.getElementById('simulationsContainer');

    if (!simulations || simulations.length === 0) {
        container.innerHTML = '<p class="no-senders">No simulations yet. Click "+ New Simulation" to create one!</p>';
        return;
    }

    container.innerHTML = simulations.map(sim => {
        const isRunning = sim.status === 'running';
        const totalGB = sim.sourcetypes.reduce((s, st) => s + st.volume_gb, 0);
        const totalFreq = sim.sourcetypes.reduce((s, st) => s + st.frequency, 0);
        const durationLabel = formatDuration(sim.duration_hours);

        const sourcetypeBadges = sim.sourcetypes.map(st => {
            const config = SOURCETYPE_CONFIG[st.log_type];
            const optionKey = config?.optionKey;
            const selectedCats = optionKey && st.options?.[optionKey]
                ? ` (${st.options[optionKey].join(', ')})`
                : '';
            return `<span class="sim-badge">${logTypes[st.log_type]?.name || st.log_type}${selectedCats}: ${st.volume_gb} GB @ ${st.frequency} l/s</span>`;
        }).join('');

        return `
        <div class="sender-card ${isRunning ? 'sender-enabled' : ''}">
            <div class="sender-header">
                <div class="sender-info">
                    <h3>${escapeHtml(sim.name)}</h3>
                    <div class="sender-meta">
                        <span>${durationLabel}</span>
                        <span>${totalGB.toFixed(2)} GB total</span>
                        <span>~${totalFreq.toFixed(1)} logs/sec</span>
                        <span class="status-badge ${isRunning ? 'status-running' : 'status-stopped'}">
                            ${isRunning ? 'Running' : 'Stopped'}
                        </span>
                    </div>
                    <div class="sim-badges-row">${sourcetypeBadges}</div>
                </div>
                <div class="sender-actions">
                    <button class="btn ${isRunning ? 'btn-danger' : 'btn-success'} btn-sm"
                            onclick="window._simToggle('${sim.id}', ${isRunning})">
                        ${isRunning ? 'Stop' : 'Start'}
                    </button>
                    <button class="btn btn-danger btn-sm"
                            onclick="window._simDelete('${sim.id}')">
                        Delete
                    </button>
                </div>
            </div>
        </div>`;
    }).join('');

    // Attach global handlers (simple approach)
    window._simToggle = async (id, isRunning) => {
        const result = isRunning ? await SimulationsApi.stop(id) : await SimulationsApi.start(id);
        if (result.success) {
            showNotification(isRunning ? 'Simulation stopped.' : 'Simulation started!', 'success');
            loadSimulations();
        } else {
            showNotification(result.error || 'Action failed.', 'error');
        }
    };

    window._simDelete = async (id) => {
        if (!confirm('Delete this simulation?')) return;
        const result = await SimulationsApi.delete(id);
        if (result.success) {
            showNotification('Simulation deleted.', 'success');
            loadSimulations();
        } else {
            showNotification(result.error || 'Delete failed.', 'error');
        }
    };
}

function updateSimulationStats(simulations) {
    const total = simulations.length;
    const running = simulations.filter(s => s.status === 'running').length;
    document.getElementById('totalSimulations').textContent = total;
    document.getElementById('runningSimulations').textContent = running;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDuration(hours) {
    if (hours >= 168 && hours % 168 === 0) return `${hours / 168} week(s)`;
    if (hours >= 24 && hours % 24 === 0) return `${hours / 24} day(s)`;
    return `${hours} hour(s)`;
}

function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
