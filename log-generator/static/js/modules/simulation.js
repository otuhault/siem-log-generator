/**
 * Simulation module
 * Handles creating and managing infrastructure volume simulations.
 */

import { SimulationsApi, ConfigurationsApi, LogTypesApi } from './api.js';
import { showNotification } from './utils.js';
import { SOURCETYPE_CONFIG } from './sourcetype-config.js';

let logTypes = {};  // populated from /api/log-types
let editingSimId = null;   // set while the form is rewriting an existing simulation

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
    document.getElementById('addSimulationBtn').addEventListener('click', () => openSimulationForm());
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
            refreshIndexRows();
        });
    });

    // A row left untouched follows the HEC index, so the default has to travel.
    document.getElementById('simHecIndex').addEventListener('input', refreshIndexRows);

    // Live summary update + subcategory toggle when volumes change
    document.getElementById('simSourcetypesGrid').addEventListener('input', e => {
        if (e.target.classList.contains('sim-volume-input')) {
            toggleSubcategories(e.target);
        }
        updateSimSummary();
    });
    document.getElementById('simSourcetypesGrid').addEventListener('change', e => {
        if (e.target.classList.contains('sim-volume-unit')) {
            toggleSubcategories(document.querySelector(
                `.sim-volume-input[data-log-type="${e.target.dataset.logType}"]`));
            updateSimSummary();
        }
    });
    document.getElementById('simDurationValue').addEventListener('input', updateSimSummary);
    document.getElementById('simDurationUnit').addEventListener('change', updateSimSummary);
}

// ─── Form ────────────────────────────────────────────────────────────────────

async function openSimulationForm(sim = null) {
    await loadSimulations();          // refresh HEC select + grid before filling
    editingSimId = sim ? sim.id : null;

    document.getElementById('simulationFormTitle').textContent =
        sim ? 'Edit Simulation' : 'Create New Simulation';
    document.getElementById('submitSimulationBtn').textContent =
        sim ? 'Update Simulation' : 'Create Simulation';

    if (sim) fillSimulationForm(sim);
    else refreshIndexRows();          // seed the placeholders on a fresh grid
    document.getElementById('simulationFormCard').style.display = 'block';
}

/** Restore a stored simulation into the form, in the units it reads best in. */
function fillSimulationForm(sim) {
    document.getElementById('simName').value = sim.name || '';

    // Pick the largest unit the duration divides into exactly, so 90 seconds
    // comes back as 90 seconds rather than 0.025 hours.
    const seconds = simSeconds(sim);
    const unit = [604800, 86400, 3600, 60, 1]
        .find(u => seconds >= u && seconds % u === 0) || 1;
    document.getElementById('simDurationUnit').value = String(unit);
    document.getElementById('simDurationValue').value = seconds / unit;

    const destType = sim.destination_type || 'file';
    const radio = document.querySelector(
        `input[name="sim_destination_type"][value="${destType}"]`);
    if (radio) { radio.checked = true; radio.dispatchEvent(new Event('change')); }

    document.getElementById('simDestination').value = sim.destination || '';
    document.getElementById('simConfigurationSelect').value = sim.configuration_id || '';
    document.getElementById('simHecIndex').value = sim.hec_index || '';
    document.getElementById('simSyslogHost').value = sim.syslog_host || '';
    document.getElementById('simSyslogPort').value = sim.syslog_port || 514;
    document.getElementById('simSyslogProtocol').value = sim.syslog_protocol || 'udp';

    for (const entry of sim.sourcetypes || []) {
        const input = document.querySelector(
            `.sim-volume-input[data-log-type="${entry.log_type}"]`);
        if (!input) continue;                     // a source dropped since

        const bytes = entryBytes(entry);
        const scale = [1024 ** 3, 1024 ** 2, 1024]
            .find(u => bytes >= u && bytes % u === 0) || 1024 ** 2;
        const unitField = document.querySelector(
            `.sim-volume-unit[data-log-type="${entry.log_type}"]`);
        if (unitField) unitField.value = String(scale);
        input.value = bytes / scale;
        toggleSubcategories(input);

        const indexField = document.querySelector(
            `.sim-index-input[data-log-type="${entry.log_type}"]`);
        // Only an index the row set itself comes back — one inherited from the
        // simulation stays a placeholder, so it keeps following that field.
        if (indexField) {
            indexField.value = entry.hec_index && entry.hec_index !== sim.hec_index
                ? entry.hec_index : '';
        }

        const optionKey = SOURCETYPE_CONFIG[entry.log_type]?.optionKey;
        const selected = optionKey ? entry.options?.[optionKey] : null;
        if (selected) {
            document.querySelectorAll(
                `.sim-subcategories[data-log-type="${entry.log_type}"] .sim-subcat-checkbox`
            ).forEach(cb => { cb.checked = selected.includes(cb.value); });
        }
    }
    refreshIndexRows();
    updateSimSummary();
}

function closeSimulationForm() {
    editingSimId = null;
    document.getElementById('simulationFormCard').style.display = 'none';
    document.getElementById('createSimulationForm').reset();
    document.getElementById('simulationFormTitle').textContent = 'Create New Simulation';
    document.getElementById('submitSimulationBtn').textContent = 'Create Simulation';
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

        // Shown with the categories, and only over HEC: a syslog collector
        // decides the index itself.
        const indexHtml = `
            <div class="sim-index-row" data-log-type="${key}" style="display:none;">
                <label for="simIndex-${key}">Index:</label>
                <input type="text" class="sim-index-input" id="simIndex-${key}"
                       data-log-type="${key}" placeholder="from the HEC index above">
            </div>`;

        return `
        <div class="sim-sourcetype-block" data-log-type="${key}">
            <div class="sim-sourcetype-row">
                <div class="sim-sourcetype-info">
                    <span class="sim-sourcetype-name">${info.name}</span>
                </div>
                <div class="sim-sourcetype-input">
                    <input type="number" class="sim-volume-input" data-log-type="${key}"
                           min="0" step="0.1" value="0" placeholder="0">
                    <select class="sim-volume-unit" data-log-type="${key}">
                        <option value="1073741824" selected>GB</option>
                        <option value="1048576">MB</option>
                        <option value="1024">KB</option>
                    </select>
                </div>
            </div>
            ${subcatsHtml}
            ${indexHtml}
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
    const hasVolume = rowBytes(volumeInput) > 0;

    const subcatDiv = document.querySelector(`.sim-subcategories[data-log-type="${logType}"]`);
    if (subcatDiv) subcatDiv.style.display = hasVolume ? 'block' : 'none';

    const indexRow = document.querySelector(`.sim-index-row[data-log-type="${logType}"]`);
    if (indexRow) indexRow.style.display = (hasVolume && simIsHec()) ? 'flex' : 'none';
}

/** Is the simulation currently pointed at a HEC destination? */
function simIsHec() {
    const checked = document.querySelector('input[name="sim_destination_type"]:checked');
    return !!checked && checked.value === 'configuration';
}

/**
 * Re-evaluate every row: the destination or the default index just changed.
 *
 * The per-row field carries the default as a placeholder rather than a value,
 * so a row left alone follows the HEC index instead of freezing whatever it
 * happened to say when the row appeared.
 */
function refreshIndexRows() {
    const fallback = document.getElementById('simHecIndex')?.value.trim() || '';
    document.querySelectorAll('.sim-index-input').forEach(input => {
        input.placeholder = fallback || 'from the HEC index above';
    });
    document.querySelectorAll('.sim-volume-input').forEach(toggleSubcategories);
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

/** Seconds the duration field currently expresses. */
function simDurationSeconds() {
    const value = parseFloat(document.getElementById('simDurationValue').value) || 0;
    const unit = parseFloat(document.getElementById('simDurationUnit').value) || 1;
    return value * unit;
}

/** Bytes one sourcetype row currently expresses. */
function rowBytes(input) {
    const value = parseFloat(input.value) || 0;
    const unit = document.querySelector(
        `.sim-volume-unit[data-log-type="${input.dataset.logType}"]`);
    return value * (parseFloat(unit?.value) || 1024 ** 3);
}

/** Human-readable bytes, from KB up. */
function formatBytes(bytes) {
    if (bytes >= 1024 ** 3) return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
    if (bytes >= 1024 ** 2) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
    return `${(bytes / 1024).toFixed(0)} KB`;
}

function updateSimSummary() {
    const durationSec = simDurationSeconds();

    let totalBytes = 0;
    let totalFreq = 0;

    document.querySelectorAll('.sim-volume-input').forEach(input => {
        const bytes = rowBytes(input);
        totalBytes += bytes;
        if (bytes > 0 && durationSec > 0) {
            // Measured on the generator and served with the log type, so the
            // preview cannot drift from what the simulation will actually send.
            const avgSize = logTypes[input.dataset.logType]?.avg_log_size || 300;
            const freq = bytes / (durationSec * avgSize);
            totalFreq += Math.max(1, Math.min(10000, freq));
        }
    });

    const summary = document.getElementById('simSummary');
    if (totalBytes > 0) {
        summary.style.display = 'block';
        document.getElementById('simTotalGB').textContent = formatBytes(totalBytes);
        document.getElementById('simTotalRate').textContent = `~${totalFreq.toFixed(1)} logs/sec`;
    } else {
        summary.style.display = 'none';
    }
}

async function handleCreateSimulation(e) {
    e.preventDefault();

    const name = document.getElementById('simName').value.trim();
    const durationSeconds = simDurationSeconds();
    const destType       = document.querySelector('input[name="sim_destination_type"]:checked').value;
    const destination    = destType === 'file'          ? document.getElementById('simDestination').value.trim() : null;
    const configId       = destType === 'configuration' ? document.getElementById('simConfigurationSelect').value : null;
    // Only over HEC: a syslog collector assigns the index itself.
    const hecIndex       = destType === 'configuration' ? document.getElementById('simHecIndex').value.trim() : null;
    const syslogHost     = destType === 'syslog'        ? document.getElementById('simSyslogHost').value.trim() : null;
    const syslogPort     = destType === 'syslog'        ? parseInt(document.getElementById('simSyslogPort').value) || 514 : null;
    const syslogProtocol = destType === 'syslog'        ? document.getElementById('simSyslogProtocol').value : null;

    const sourcetypes = [];
    document.querySelectorAll('.sim-volume-input').forEach(input => {
        const bytes = rowBytes(input);
        if (bytes <= 0) return;

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

        // Blank means "whatever the HEC index says"; the server fills it in.
        const rowIndex = document.querySelector(
            `.sim-index-input[data-log-type="${logType}"]`)?.value.trim() || null;

        sourcetypes.push({
            log_type: logType, volume_bytes: bytes, options,
            hec_index: destType === 'configuration' ? rowIndex : null,
        });
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
        const payload = {
            name, duration_seconds: durationSeconds,
            sourcetypes, destination,
            destination_type: destType,
            configuration_id: configId,
            hec_index: hecIndex,
            syslog_host: syslogHost,
            syslog_port: syslogPort,
            syslog_protocol: syslogProtocol,
        };
        const result = editingSimId
            ? await SimulationsApi.update(editingSimId, payload)
            : await SimulationsApi.create(payload);

        if (result.success) {
            showNotification(editingSimId ? 'Simulation updated!' : 'Simulation created!',
                             'success');
            closeSimulationForm();
            loadSimulations();
        } else {
            showNotification(result.error || 'Failed to save simulation.', 'error');
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
        const totalBytes = sim.sourcetypes.reduce((s, st) => s + entryBytes(st), 0);
        const totalFreq = sim.sourcetypes.reduce((s, st) => s + st.frequency, 0);
        const durationLabel = formatDuration(simSeconds(sim));

        return `
        <div class="sender-card ${isRunning ? 'sender-enabled' : ''}">
            <div class="sender-header">
                <div class="sender-info">
                    <h3>${escapeHtml(sim.name)}</h3>
                    <div class="sender-meta">
                        <span>${durationLabel}</span>
                        <span>${formatBytes(totalBytes)} total</span>
                        <span>~${totalFreq.toFixed(1)} logs/sec</span>
                        <span class="status-badge ${isRunning ? 'status-running' : 'status-stopped'}"
                              ${isRunning ? `data-sim-countdown="${sim.id}" data-ends-at="${sim.ends_at || ''}"` : ''}>
                            ${isRunning ? formatCountdown(sim.seconds_remaining) : 'Stopped'}
                        </span>
                    </div>
                </div>
                <div class="sender-actions">
                    <button class="btn ${isRunning ? 'btn-danger' : 'btn-success'} btn-sm"
                            onclick="window._simToggle('${sim.id}', ${isRunning})">
                        ${isRunning ? 'Stop' : 'Start'}
                    </button>
                    <button class="btn btn-secondary btn-sm" ${isRunning ? 'disabled' : ''}
                            title="${isRunning ? 'Stop the simulation to edit it' : 'Edit'}"
                            onclick="window._simEdit('${sim.id}')">
                        Edit
                    </button>
                    <button class="btn btn-danger btn-sm"
                            onclick="window._simDelete('${sim.id}')">
                        Delete
                    </button>
                </div>
            </div>
        </div>`;
    }).join('');

    startCountdowns();

    // Attach global handlers (simple approach)
    window._simEdit = (id) => {
        const sim = simulations.find(s => s.id === id);
        if (sim) openSimulationForm(sim);
    };

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

/** Seconds are canonical; records written before that still carry hours. */
function simSeconds(sim) {
    return sim.duration_seconds ?? (sim.duration_hours || 0) * 3600;
}

/** Bytes for one entry, whichever unit it was written with. */
function entryBytes(entry) {
    return entry.volume_bytes ?? (entry.volume_gb || 0) * 1024 ** 3;
}

/** `mm:ss`, or `h:mm:ss` past an hour. Blank input reads as done. */
function formatCountdown(seconds) {
    const left = Math.max(0, Math.round(seconds ?? 0));
    const h = Math.floor(left / 3600);
    const m = Math.floor((left % 3600) / 60);
    const s = left % 60;
    const pad = (n) => String(n).padStart(2, '0');
    return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}

let countdownTimer = null;

/**
 * Tick every running badge once a second.
 *
 * The deadline is absolute and comes from the server, so the tick only reads a
 * clock — it never decides when the simulation ends. When one reaches zero the
 * list is reloaded, and the server confirms the stop it has already performed.
 */
function startCountdowns() {
    clearInterval(countdownTimer);
    const badges = document.querySelectorAll('[data-sim-countdown]');
    if (!badges.length) return;

    countdownTimer = setInterval(() => {
        let anyFinished = false;
        document.querySelectorAll('[data-sim-countdown]').forEach(badge => {
            const endsAt = badge.dataset.endsAt;
            if (!endsAt) return;
            const left = (new Date(endsAt).getTime() - Date.now()) / 1000;
            badge.textContent = formatCountdown(left);
            if (left <= 0) anyFinished = true;
        });
        if (anyFinished) {
            clearInterval(countdownTimer);
            loadSimulations();
        }
    }, 1000);
}

function formatDuration(seconds) {
    const units = [[604800, 'week'], [86400, 'day'], [3600, 'hour'],
                   [60, 'minute'], [1, 'second']];
    for (const [size, label] of units) {
        if (seconds >= size && seconds % size === 0) {
            const n = seconds / size;
            return `${n} ${label}${n > 1 ? 's' : ''}`;
        }
    }
    return `${seconds} seconds`;
}

function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
