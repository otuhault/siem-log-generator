/**
 * Senders management module
 */

import { SendersApi } from './api.js';
import { state } from './state.js';
import { isSourcedAttack, attackOwnsHost, collectAttackOptions, hydrateAttackConfig, hideAttackConfig } from './attack-config.js';
import { formatDateTime, showNotification } from './utils.js';
import { validateSenderForm, clearFormErrors } from './validation.js';
import { SOURCETYPE_CONFIG } from './sourcetype-config.js';
import { getDatamodelSelection, STYPE_TO_GEN_OPTIONS, hydrateFromSender,
         getHecSourcetypeMap, getHecSourceMap } from './sender-form.js';

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

/**
 * The sender whose row we left to open the form, so closing can return to it.
 */
let editingSenderId = null;

/**
 * Open the sender form, and give it the page.
 *
 * The form runs from 650px for a sourcetype sender to 1400px for an attack,
 * against a laptop viewport of roughly 780px: it never fits beside or inside
 * anything. So it takes the page — the two group cards go away while it is
 * open, which is how long create/edit forms work everywhere they are not a
 * two-field dialog. Scrolling then stays inside the task instead of wandering
 * back into the list.
 *
 * The cards are hidden by a class on the tab rather than by touching them
 * directly: `renderGroup()` owns their `hidden` attribute and runs every two
 * seconds, and would undo anything set here on its next pass.
 */
export function openSenderForm(senderId = null) {
    editingSenderId = senderId;
    document.getElementById('sendersTab').classList.add('form-open');
    document.getElementById('senderFormCard').style.display = 'block';
    window.scrollTo({ top: 0, behavior: 'auto' });
}

/**
 * Load all senders and update the UI
 */
/**
 * Sort order of the senders tables, applied to both.
 *
 * Kept at module level because loadSenders() rebuilds the tables every two
 * seconds: an order stored on the DOM would be lost on the next refresh.
 * `null` is the server's own order, which is creation order.
 */
let sendersSort = null;   // null | { key: 'name' | 'mode', dir: 'asc' | 'desc' }

/**
 * How a sender was defined, as the form's Source mode names it.
 *
 * An attack is recognised by its type; a sender created By Datamodel carries
 * `datamodel_group`, which only that mode writes; everything else was created
 * By Sourcetype. Editing a datamodel sender through the form rewrites its
 * options without that key, and it is then listed as what it has become.
 */
export function senderMode(sender) {
    if (sender.log_type && state.attackTypes[sender.log_type]) return 'Attack';
    if (sender.options?.datamodel_group) return 'Datamodel';
    return 'Sourcetype';
}

/** Where a sender sends, in one word. */
export function destinationKind(sender) {
    if (sender.destination_type === 'configuration') return 'HEC';
    if (sender.destination_type === 'syslog') return 'Syslog';
    return 'Local File';
}

/**
 * Which one, for the title attribute — the table says the kind, not the detail.
 *
 * A sender either names a saved syslog destination or carries the host and port
 * itself; reading the inline fields for the first kind used to print
 * `null:514 (UDP)`, the wrong transport on the row that exists to say where the
 * events go.
 */
export function destinationDetail(sender) {
    if (sender.destination_type === 'configuration') {
        const config = state.configurations.find((c) => c.id === sender.configuration_id);
        if (config) return config.name;
        return state.configurationsLoaded ? 'configuration not found' : '';
    }
    if (sender.destination_type === 'syslog') {
        const saved = sender.syslog_destination_id
            ? state.syslogDestinations.find((d) => d.id === sender.syslog_destination_id)
            : null;
        if (sender.syslog_destination_id && !saved) {
            return state.syslogDestinationsLoaded ? 'destination not found' : '';
        }
        const host = saved ? saved.host : sender.syslog_host;
        const port = saved ? saved.port : sender.syslog_port;
        const proto = ((saved ? saved.protocol : sender.syslog_protocol) || 'udp').toUpperCase();
        return saved ? `${saved.name} (${host}:${port}/${proto})` : `${host}:${port} (${proto})`;
    }
    return sender.destination || '';
}

/**
 * The Splunk index an attack's events land in, for the Attacks table.
 *
 * Only HEC carries one: a file is read by whoever reads it, and a syslog
 * collector decides for itself. A sender may override the destination's index.
 */
export function senderIndex(sender) {
    if (sender.destination_type !== 'configuration') return '—';
    const override = sender.options?.hec_index;
    if (override) return override;
    const config = state.configurations.find((c) => c.id === sender.configuration_id);
    if (config?.index) return config.index;
    return state.configurationsLoaded ? 'default' : '—';
}

/**
 * What a row's Mode cell stands for, spelled out for the hover bubble.
 *
 * Sourcetype: the Splunk sourcetypes the selected categories produce — a
 * category whose generator declares none is named by the category instead, so
 * the bubble never invents a sourcetype the add-on would not see. Selecting
 * nothing means the generator's own defaults, which is every category it has,
 * and that is what the sender actually emits.
 *
 * Datamodel: the datamodel the sender was created for, and the one sourcetype
 * feeding it — that mode creates one sender per sourcetype.
 */
export function modeDetail(sender) {
    const options = sender.options || {};
    if (options.datamodel_group) {
        return { heading: options.datamodel_group,
                 items: options.splunk_sourcetype ? [options.splunk_sourcetype] : [] };
    }

    const sources = state.logTypes?.[sender.log_type]?.sources || [];
    const key = SOURCETYPE_CONFIG[sender.log_type]?.optionKey;
    const chosen = key ? options[key] : null;
    const selected = chosen == null ? null
        : (Array.isArray(chosen) ? chosen : [chosen]).map(String);

    const wanted = selected === null ? sources : sources.filter((s) => selected.includes(s.id));
    const items = wanted.map((s) => s.sourcetype || s.name);
    // A selection naming something the type no longer has still has to show.
    const known = new Set(sources.map((s) => s.id));
    (selected || []).filter((id) => !known.has(id)).forEach((id) => items.push(id));
    return { heading: null, items };
}

const DURATION_UNITS = { seconds: 1, minutes: 60, hours: 3600 };

/** The form's number and unit as one count of seconds; 0 means until stopped. */
export function durationSeconds(value, unit) {
    const amount = Math.max(0, parseInt(value, 10) || 0);
    return amount * (DURATION_UNITS[unit] || 1);
}

/** Seconds back as the largest whole unit, so an hour comes back as an hour. */
export function splitDuration(seconds) {
    const total = Math.max(0, parseInt(seconds, 10) || 0);
    if (total && total % 3600 === 0) return { value: total / 3600, unit: 'hours' };
    if (total && total % 60 === 0) return { value: total / 60, unit: 'minutes' };
    return { value: total, unit: 'seconds' };
}

/** How long a sender runs, for the table: a duration, or that it is up to you. */
export function durationLabel(sender) {
    const total = parseInt(sender.duration_seconds, 10) || 0;
    if (!total) return 'Manual';
    const { value, unit } = splitDuration(total);
    return `${value}${{ seconds: 's', minutes: 'm', hours: 'h' }[unit]}`;
}

const SORT_KEYS = {
    name: (sender) => sender.name || '',
    mode: (sender) => senderMode(sender),
    index: (sender) => senderIndex(sender),
};

const compareText = (a, b) => a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true });

/**
 * Running first, then the chosen order.
 *
 * What is sending is what the reader came to look at, so it stays at the top
 * whatever the table is sorted by — the sort decides the order within each half.
 */
function sortSenders(senders) {
    const direction = sendersSort?.dir === 'asc' ? 1 : -1;
    const key = SORT_KEYS[sendersSort?.key] || SORT_KEYS.name;
    return [...senders].sort((a, b) =>
        (b.enabled === true) - (a.enabled === true)
        || (sendersSort ? direction * compareText(key(a), key(b)) : 0)
        || compareText(SORT_KEYS.name(a), SORT_KEYS.name(b)));
}

function toggleSendersSort(key) {
    sendersSort = sendersSort?.key === key && sendersSort.dir === 'asc'
        ? { key, dir: 'desc' }
        : { key, dir: 'asc' };
    loadSenders();
}

/** A sortable header cell for `key`, reflecting the current order. */
function sortableHeader(key, label) {
    const active = sendersSort?.key === key;
    const ariaSort = !active ? 'none' : sendersSort.dir === 'asc' ? 'ascending' : 'descending';
    const arrow = !active ? '↕' : sendersSort.dir === 'asc' ? '▲' : '▼';
    return `<th aria-sort="${ariaSort}">
                <button type="button" class="th-sort" data-sort="${key}" title="Sort by ${label.toLowerCase()}">
                    ${label} <span class="th-sort-arrow" aria-hidden="true">${arrow}</span>
                </button>
            </th>`;
}

//: Each group's own "show only what is running" state, toggled by its title.
const activeOnly = { senders: false, attacks: false };

/**
 * What each group shows, in order. Actions is added to both at the end.
 *
 * A sender is read by what it emits, where it goes and at what rate; an attack
 * by where it landed and how far it got — hence Index first for one, and the
 * counter and the date only for the other.
 */
const GROUPS = {
    senders: { card: 'sendersCard', container: 'sendersContainer', toggle: 'sendersToggle',
               columns: ['name', 'mode', 'destination', 'index', 'frequency', 'duration'] },
    attacks: { card: 'attacksCard', container: 'attacksContainer', toggle: 'attacksToggle',
               columns: ['name', 'index', 'destination', 'frequency', 'lastRun'] },
};

/** One entry per column: its heading, whether it sorts, and the cell it builds. */
const COLUMNS = {
    name: { label: 'Name', sortable: true, build: (sender, isAttack) => {
        const cell = document.createElement('td');
        cell.className = 'sender-name';
        cell.textContent = sender.name;
        // How an attack ended: the toggle says running or stopped, but a
        // finished and a failed attack are both stopped.
        const outcome = isAttack ? attackOutcome(sender.attack_status) : null;
        if (outcome) {
            const badge = document.createElement('span');
            badge.className = `sender-outcome ${outcome.kind}`;
            badge.textContent = outcome.label;
            cell.appendChild(badge);
        }
        return cell;
    } },

    mode: { label: 'Mode', sortable: true, build: (sender) => {
        const cell = document.createElement('td');
        cell.className = 'sender-mode';
        cell.textContent = senderMode(sender);
        attachModeTip(cell, sender);
        return cell;
    } },

    destination: { label: 'Destination', build: (sender) => {
        const cell = document.createElement('td');
        cell.className = 'sender-destination';
        cell.textContent = destinationKind(sender);
        // Which HEC destination, which file, which collector: kept on hover
        // rather than in the column, which only has to say the kind.
        const detail = destinationDetail(sender);
        if (detail) cell.title = detail;
        return cell;
    } },

    index: { label: 'Index', sortable: true, build: (sender) => {
        const cell = document.createElement('td');
        cell.className = 'sender-index';
        cell.textContent = senderIndex(sender);
        return cell;
    } },

    frequency: { label: 'Frequency', build: (sender, isAttack) => {
        const cell = document.createElement('td');
        if (isAttack && sender.options) {
            cell.textContent = `${sender.options.attack_events_count || 0} events`
                + ` / ${sender.options.attack_duration || 0}s`;
        } else {
            cell.textContent = `${sender.frequency} logs/sec`;
        }
        return cell;
    } },

    duration: { label: 'Duration', build: (sender) => {
        const cell = document.createElement('td');
        cell.className = 'sender-duration';
        cell.textContent = durationLabel(sender);
        if (!parseInt(sender.duration_seconds, 10)) cell.classList.add('is-manual');
        return cell;
    } },

    lastRun: { label: 'Last Time Executed', build: (sender) => {
        const cell = document.createElement('td');
        cell.className = 'sender-last-run';
        const when = formatDateTime(sender.last_run_at);
        cell.textContent = when || 'Never';
        if (!when) cell.classList.add('is-never');
        return cell;
    } },
};

export function isAttackSender(sender) {
    return !!(sender.log_type && state.attackTypes[sender.log_type]);
}

// ── the Mode bubble ─────────────────────────────────────────────────────────
//
// Positioned against the viewport rather than the cell: the table sits in a
// horizontal scroller, which would clip anything absolutely placed inside it.

let modeTip = null;

function modeTipElement(doc) {
    if (!modeTip || !doc.body.contains(modeTip)) {
        modeTip = doc.createElement('div');
        modeTip.className = 'mode-tip';
        modeTip.setAttribute('role', 'tooltip');
        modeTip.hidden = true;
        doc.body.appendChild(modeTip);
    }
    return modeTip;
}

export function hideModeTip() {
    if (modeTip) modeTip.hidden = true;
}

/** Whether a bubble is open, and so whether a row is being read right now. */
export function isModeTipOpen() {
    return !!modeTip && !modeTip.hidden && !!modeTip.ownerDocument?.body?.contains(modeTip);
}

/** Show what this row emits while the pointer is over its Mode cell. */
function attachModeTip(cell, sender) {
    // The class is decided now, for the affordance; the content is read again
    // on hover, so a row built before /api/log-types answered still shows the
    // right thing rather than what was knowable at build time.
    if (modeDetail(sender).items.length) cell.classList.add('has-mode-tip');

    cell.addEventListener('mouseenter', () => {
        const detail = modeDetail(sender);
        if (!detail.heading && !detail.items.length) return;
        cell.classList.add('has-mode-tip');
        const doc = cell.ownerDocument;
        const tip = modeTipElement(doc);
        tip.textContent = '';
        if (detail.heading) {
            const heading = doc.createElement('strong');
            heading.textContent = detail.heading;
            tip.appendChild(heading);
        }
        const list = doc.createElement('ul');
        detail.items.forEach((item) => {
            const entry = doc.createElement('li');
            entry.textContent = item;
            list.appendChild(entry);
        });
        if (detail.items.length) tip.appendChild(list);
        tip.hidden = false;

        const at = cell.getBoundingClientRect();
        const width = tip.offsetWidth || 220;
        const view = doc.defaultView;
        const maxLeft = Math.max(8, (view?.innerWidth || 0) - width - 8);
        tip.style.left = `${Math.max(8, Math.min(at.left, maxLeft))}px`;
        tip.style.top = `${at.bottom + 6}px`;
    });
    cell.addEventListener('mouseleave', hideModeTip);
}

/**
 * What the two fields add up to, under them both.
 *
 * The point of putting frequency and duration side by side: neither says much
 * alone, and the volume is what fills an index.
 */
export function refreshVolumeHint() {
    const hint = document.getElementById('senderVolumeHint');
    if (!hint) return;
    const frequency = Math.max(0, parseInt(document.getElementById('frequency')?.value, 10) || 0);
    const seconds = durationSeconds(document.getElementById('senderDuration')?.value,
                                    document.getElementById('senderDurationUnit')?.value);
    if (!seconds) {
        hint.innerHTML = '<strong>Runs until you stop it.</strong> '
            + `${frequency} logs/sec, for as long as you leave it going.`;
        return;
    }
    // Echoed back in the unit that was typed: someone who asked for 60 seconds
    // should not be told about a minute.
    const value = parseInt(document.getElementById('senderDuration')?.value, 10) || 0;
    const unit = document.getElementById('senderDurationUnit')?.value || 'seconds';
    hint.innerHTML = `<strong>≈ ${(frequency * seconds).toLocaleString()} logs</strong> — `
        + `${frequency} logs/sec for ${value} ${value === 1 ? unit.replace(/s$/, '') : unit}. `
        + 'Zero runs until you stop it; either way you can stop it by hand.';
}

/**
 * Wire the two titles; each filters its own table.
 *
 * Called once as the page starts, so it is also where the view begins: showing
 * everything, in the order the server sent it, whatever a previous visit left
 * behind in this module.
 */
export function initSenderGroups() {
    Object.keys(activeOnly).forEach((name) => { activeOnly[name] = false; });
    sendersSort = null;
    ['frequency', 'senderDuration', 'senderDurationUnit'].forEach((id) =>
        document.getElementById(id)?.addEventListener('input', refreshVolumeHint));
    refreshVolumeHint();
    Object.entries(GROUPS).forEach(([name, group]) => {
        document.getElementById(group.toggle)?.addEventListener('click', () => {
            activeOnly[name] = !activeOnly[name];
            loadSenders();
        });
    });
}

export async function loadSenders() {
    try {
        const senders = await SendersApi.getAll();
        const running = senders.filter((s) => s.enabled);

        document.getElementById('totalSenders').textContent = senders.length;
        document.getElementById('enabledSenders').textContent = running.length;
        document.getElementById('disabledSenders').textContent = senders.length - running.length;

        // Skip the rebuild while a Mode bubble is open: its cell would be
        // replaced by an identical one, which fires no mouseenter to bring the
        // bubble back, so it would vanish every two seconds. The live counters
        // still move either way.
        //
        // The edit form used to need the same treatment, because it was moved
        // into the table and a rebuild destroyed it. It now takes the page
        // instead, so the tables can refresh freely behind it.
        if (isModeTipOpen()) {
            senders.forEach((sender) => {
                const cell = document.querySelector(
                    `tr[data-sender-id="${sender.id}"] .sender-logs-count`);
                if (cell) cell.textContent = (sender.logs_generated || 0).toLocaleString();
                const row = document.querySelector(`tr[data-sender-id="${sender.id}"]`);
                if (row) row.classList.toggle('is-running', !!sender.enabled);
            });
            return;
        }

        renderGroup('senders', senders.filter((s) => !isAttackSender(s)));
        renderGroup('attacks', senders.filter(isAttackSender));
    } catch (error) {
        console.error('Error loading senders:', error);
    }
}

/**
 * One group's card: its table, or nothing.
 *
 * With no sender of this kind at all the card goes away — there is nothing to
 * say and nothing to toggle. Filtered down to what is running and finding none,
 * the card stays so the title can be clicked back, but the table goes: an empty
 * table and a line of text both cost more room than they are worth.
 */
function renderGroup(name, all) {
    const group = GROUPS[name];
    const card = document.getElementById(group.card);
    const container = document.getElementById(group.container);
    if (!card || !container) return;

    const filtered = activeOnly[name];
    const shown = sortSenders(filtered ? all.filter((s) => s.enabled) : all);

    card.hidden = all.length === 0;
    const toggle = document.getElementById(group.toggle);
    if (toggle) {
        toggle.setAttribute('aria-pressed', String(filtered));
        toggle.classList.toggle('is-filtering', filtered);
        const chip = toggle.querySelector('.group-filter');
        if (chip) chip.textContent = filtered ? 'running only' : '';
    }

    container.innerHTML = '';
    if (!shown.length) return;
    container.appendChild(buildSendersTable(shown, group.columns));
}

/** The table for one group, from the columns that group names. */
function buildSendersTable(senders, columns) {
    const table = document.createElement('table');
    table.className = 'senders-table';

    const thead = document.createElement('thead');
    thead.innerHTML = `<tr>${columns.map((key) => (COLUMNS[key].sortable
        ? sortableHeader(key, COLUMNS[key].label)
        : `<th>${COLUMNS[key].label}</th>`)).join('')}<th>Actions</th></tr>`;
    thead.querySelectorAll('.th-sort').forEach((button) =>
        button.addEventListener('click', () => toggleSendersSort(button.dataset.sort)));
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    senders.forEach((sender) => tbody.appendChild(createSenderRow(sender, columns)));
    table.appendChild(tbody);

    const scroller = document.createElement('div');
    scroller.className = 'table-scroll';
    scroller.appendChild(table);
    return scroller;
}

/**
 * How an attack ended, or null when there is nothing the row does not already say.
 * The backend writes `Done (<time>)` on completion and a free-text reason on
 * failure; `Running` and `Disabled` are the table and the toggle's business.
 */
function attackOutcome(status) {
    if (!status || status === 'Running' || status === 'Disabled') return null;
    if (status.startsWith('Done')) return { kind: 'done', label: status };
    return { kind: 'error', label: status };
}

/**
 * Create a table row for a sender
 * @param {object} sender - Sender data
 * @returns {HTMLElement} Table row element
 */
function createSenderRow(sender, columns) {
    const row = document.createElement('tr');
    row.dataset.senderId = sender.id;

    const isAttack = isAttackSender(sender);
    if (isAttack) {
        row.classList.add('attack-sender-row');
    }
    // What is sending says so on the row itself, now that the table no longer
    // says it by being the one a sender is listed in.
    if (sender.enabled) {
        row.classList.add('is-running');
    }

    columns.forEach((key) => row.appendChild(COLUMNS[key].build(sender, isAttack)));

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
            document.getElementById('frequency').value = sender.frequency;
            const saved = splitDuration(sender.duration_seconds);
            document.getElementById('senderDuration').value = saved.value;
            document.getElementById('senderDurationUnit').value = saved.unit;
            refreshVolumeHint();

            // Update custom dropdown + fire change event
            if (typeof window.setLogTypeValue === 'function') {
                window.setLogTypeValue(sender.log_type);
            } else {
                document.getElementById('logType').value = sender.log_type;
                document.getElementById('logType').dispatchEvent(new Event('change', { bubbles: true }));
            }

            // Rebuild the source-mode / Technology / Sourcetypes / pool state from
            // THIS sender. Without it the selectors keep the previously edited
            // sender's state and would write it back on save.
            await hydrateFromSender(sender.log_type, sender.options || {});

            // Set destination type
            // Hide all groups first, then show the right one
            document.getElementById('fileDestinationGroup').style.display = 'none';
            document.getElementById('configurationDestinationGroup').style.display = 'none';
            document.getElementById('syslogDestinationGroup').style.display = 'none';
            document.getElementById('destination').required = false;
            document.getElementById('configurationSelect').required = false;

            if (sender.destination_type === 'syslog') {
                document.querySelector('input[name="destination_type"][value="syslog"]').checked = true;
                document.getElementById('syslogDestinationGroup').style.display = 'block';
                // Phase 4b: load destinations then restore selection
                const { loadSyslogDestinations } = await import('./syslog-destinations.js');
                await loadSyslogDestinations();
                const sysSel = document.getElementById('syslogDestinationSelect');
                if (sysSel) sysSel.value = sender.syslog_destination_id || '';
            } else if (sender.destination_type === 'configuration') {
                document.querySelector('input[name="destination_type"][value="configuration"]').checked = true;
                document.getElementById('configurationDestinationGroup').style.display = 'block';
                document.getElementById('hecOverridesGroup').style.display = 'block';
                document.getElementById('configurationSelect').required = true;
            } else {
                document.querySelector('input[name="destination_type"][value="file"]').checked = true;
                document.getElementById('fileDestinationGroup').style.display = 'block';
                document.getElementById('destination').required = true;
                document.getElementById('destination').value = sender.destination || '';
            }

            // Set options based on log type using configuration mapping
            const config = SOURCETYPE_CONFIG[sender.log_type];
            if (config && sender.options) {
                // Restore checkbox selections
                const optionValue = sender.options[config.optionKey];
                if (optionValue) {
                    restoreCheckboxes(config.checkboxGroup, optionValue);
                }

                // Restore Assets & Identities toggle + slider + impact panel
                const useAI = !!sender.options.use_assets_identities;
                document.getElementById('useAssetsIdentities').checked = useAI;
                const ratio = sender.options.assets_identities_ratio ?? 100;
                document.getElementById('aiRatio').value = ratio;
                document.getElementById('aiRatioValue').textContent = ratio + '%';
                document.getElementById('aiRatioGroup').style.display = useAI ? 'block' : 'none';
                if (useAI) {
                    // loadAIImpact is defined in app.js — call via window or dispatch
                    if (typeof window.loadAIImpact === 'function') {
                        window.loadAIImpact(sender.log_type);
                    }
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
                if (sender.options.attack_duration != null) {
                    document.getElementById('attackDuration').value = sender.options.attack_duration;
                }
                hydrateAttackConfig(sender.options);
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

            openSenderForm(senderId);

            // Import and call loadConfigurations to populate dropdown
            const { loadConfigurations } = await import('./configurations.js');
            await loadConfigurations();

            // Set configuration select value AFTER loadConfigurations rebuilds the dropdown
            if (sender.destination_type === 'configuration' && sender.configuration_id) {
                document.getElementById('configurationSelect').value = sender.configuration_id;
                // Restore HEC metadata overrides
                const opts = sender.options || {};
                document.getElementById('hecIndex').value      = opts.hec_index      || '';
                document.getElementById('hecSourcetype').value = opts.hec_sourcetype || '';
                document.getElementById('hecHost').value       = opts.hec_host       || '';
                document.getElementById('hecSource').value     = opts.hec_source     || '';
            }
        }
    } catch (error) {
        showNotification('Error loading sender: ' + error.message, 'error');
    }
}

/**
 * A single free-text HEC override, or undefined when its field is hidden.
 *
 * The per-sourcetype rows replace the single Sourcetype / Source fields and hide
 * them. A hidden field keeps whatever the last edited sender left in it, so
 * reading it unconditionally persisted a value the form was not showing — and
 * which the emitter then ignored, since the per-event value wins.
 */
function visibleHecOverride(fieldId, groupId) {
    const group = document.getElementById(groupId);
    if (!group || group.style.display === 'none') return undefined;
    return document.getElementById(fieldId).value.trim() || undefined;
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

    // Datamodel mode (Phase 4d): fan-out into one sender per checked sourcetype
    const sourceModeRadio = document.querySelector('input[name="source_mode"]:checked');
    if (sourceModeRadio && sourceModeRadio.value === 'datamodel') {
        return submitDatamodelSenders(e.target);
    }

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
        duration_seconds: durationSeconds(formData.get('duration'), formData.get('duration_unit')),
    };
    // Senders are always created stopped; use the ▶ button in the table to run
    // them. On update `enabled` is deliberately absent so the PUT never flips a
    // sender's running state.
    if (!senderId) data.enabled = false;

    // Set destination based on type
    if (destinationType === 'file') {
        data.destination = formData.get('destination').trim();
        data.destination_type = 'file';
    } else if (destinationType === 'syslog') {
        const sysDestId = formData.get('syslog_destination_id');
        if (!sysDestId) {
            showNotification('Please select a syslog destination (Configuration → Syslog Destinations)', 'error');
            return;
        }
        data.syslog_destination_id = sysDestId;
        data.destination_type = 'syslog';
    } else {
        data.configuration_id = formData.get('configuration_id');
        data.destination_type = 'configuration';
        // Collect per-sender HEC metadata overrides (merged into options below)
        const stMap = getHecSourcetypeMap();
        const srcMap = getHecSourceMap();
        data._hecOverrides = {
            hec_index:      document.getElementById('hecIndex').value.trim()      || undefined,
            hec_sourcetype: visibleHecOverride('hecSourcetype', 'hecSourcetypeSingleGroup'),
            hec_host:       document.getElementById('hecHost').value.trim()       || undefined,
            hec_source:     visibleHecOverride('hecSource', 'hecSourceSingleGroup'),
            hec_sourcetype_map: Object.keys(stMap).length ? stMap : undefined,
            hec_source_map: Object.keys(srcMap).length ? srcMap : undefined,
        };
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

        const useAI = document.getElementById('useAssetsIdentities').checked;
        data.options = {
            [config.optionKey]: selectedValues,
            use_assets_identities:    useAI,
            assets_identities_ratio:  useAI ? parseInt(document.getElementById('aiRatio').value) : 100,
        };

        // Delivery format, only when the source actually offers one. The group is
        // hidden for a TA that frames itself or is never collected over syslog,
        // and persisting a value there would promise what the emitter ignores.
        const delivery = visibleHecOverride('deliveryFormat', 'deliveryFormatGroup');
        if (delivery) data.options.delivery_format = delivery;

        // Phase 4c: per-direction pool overrides (only if Use Environment is on)
        if (useAI) {
            ['src', 'dest'].forEach(dir => {
                const checked = document.querySelector(`input[name="${dir}_pool_mode"]:checked`);
                const mode = checked ? checked.value : 'entities';
                if (mode === 'entities') return;   // default — no override needed
                data.options[`${dir}_pool_mode`] = mode;
                if (mode === 'pool' || mode === 'both') {
                    const poolId = document.getElementById(`${dir}PoolSelect`).value;
                    if (poolId) data.options[`${dir}_pool_id`] = poolId;
                }
                if (mode === 'both') {
                    data.options[`${dir}_pool_ai_ratio`] = parseInt(document.getElementById(`${dir}PoolMix`).value);
                }
            });
        }

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

        data.options = isSourcedAttack()
            ? collectAttackOptions()
            : { attack_events_count: eventsCount, attack_duration: duration };

        if (isSourcedAttack() && data._hecOverrides) {
            // Forced by the sourcetype rows; a typed value cannot apply to several.
            ['hec_sourcetype', 'hec_source', 'hec_sourcetype_map', 'hec_source_map']
                .forEach((key) => delete data._hecOverrides[key]);
            // The attack names the machine its events happened on.
            if (attackOwnsHost()) delete data._hecOverrides.hec_host;
        }

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

    // Merge HEC metadata overrides into options (applies to all log types when dest=configuration)
    if (data._hecOverrides) {
        if (!data.options) data.options = {};
        Object.entries(data._hecOverrides).forEach(([k, v]) => {
            if (v !== undefined) data.options[k] = v;
        });
        delete data._hecOverrides;
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
/**
 * Phase 4d — datamodel-mode submit. Creates one sender per checked sourcetype,
 * all sharing the same destination, frequency, A&I settings. The user can
 * later toggle/clone/delete each one independently from the senders table.
 */
async function submitDatamodelSenders(form) {
    const sel = getDatamodelSelection();
    if (!sel.datamodel) { showNotification('Please pick a datamodel.', 'error'); return; }
    if (sel.sources.length === 0) {
        showNotification('No sourcetypes matched (or all unchecked).', 'error'); return;
    }

    const formData = new FormData(form);
    const baseName = formData.get('name').trim() || `[DM:${sel.datamodel}]`;
    const frequency = parseInt(formData.get('frequency')) || 10;
    const duration_seconds = durationSeconds(formData.get('duration'), formData.get('duration_unit'));
    const destinationType = formData.get('destination_type');
    const useAI = document.getElementById('useAssetsIdentities').checked;
    const aiRatio = useAI ? parseInt(document.getElementById('aiRatio').value) : 100;
    const startEnabled = false;   // created stopped, like every other sender

    // Build the shared destination block once
    const sharedDest = {};
    if (destinationType === 'file') {
        sharedDest.destination_type = 'file';
        sharedDest.destination      = formData.get('destination').trim();
        if (!sharedDest.destination) { showNotification('File destination required.', 'error'); return; }
    } else if (destinationType === 'syslog') {
        const id = formData.get('syslog_destination_id');
        if (!id) { showNotification('Please select a syslog destination.', 'error'); return; }
        sharedDest.destination_type      = 'syslog';
        sharedDest.syslog_destination_id = id;
    } else {
        const id = formData.get('configuration_id');
        if (!id) { showNotification('Please select a HEC destination.', 'error'); return; }
        sharedDest.destination_type = 'configuration';
        sharedDest.configuration_id = id;
        sharedDest._hecOverrides = {
            hec_index:      document.getElementById('hecIndex').value.trim()      || undefined,
            hec_sourcetype: visibleHecOverride('hecSourcetype', 'hecSourcetypeSingleGroup'),
            hec_host:       document.getElementById('hecHost').value.trim()       || undefined,
            hec_source:     visibleHecOverride('hecSource', 'hecSourceSingleGroup'),
            hec_sourcetype_map: (() => { const m = getHecSourcetypeMap(); return Object.keys(m).length ? m : undefined; })(),
            hec_source_map:     (() => { const m = getHecSourceMap();     return Object.keys(m).length ? m : undefined; })(),
        };
    }

    let created = 0;
    let failed  = 0;
    for (const src of sel.sources) {
        const genOptions = STYPE_TO_GEN_OPTIONS[src.key];
        if (!genOptions) {
            console.warn(`No generator option mapping for ${src.key} — skipped`);
            failed++;
            continue;
        }

        const payload = {
            name: `${baseName} — ${src.ta}/${src.sourcetype}`,
            log_type: src.ta,
            frequency,
            duration_seconds,
            enabled: startEnabled,
            ...sharedDest,
            options: {
                ...genOptions,
                use_assets_identities:   useAI,
                assets_identities_ratio: aiRatio,
                datamodel_group:         sel.datamodel,
                splunk_sourcetype:       src.sourcetype,
            },
        };

        if (sharedDest._hecOverrides) {
            Object.entries(sharedDest._hecOverrides).forEach(([k, v]) => {
                if (v !== undefined) payload.options[k] = v;
            });
        }

        try {
            const res = await SendersApi.create(payload);
            if (res.success) created++; else failed++;
        } catch (err) {
            console.error('Datamodel sender create failed:', err);
            failed++;
        }
    }

    showNotification(`Created ${created} sender(s) for ${sel.datamodel}${failed ? ` (${failed} failed)` : ''}.`,
                     failed ? 'error' : 'success');
    closeSenderForm();
    await loadSenders();
}


export function closeSenderForm() {
    const form = document.getElementById('createSenderForm');
    document.getElementById('senderFormCard').style.display = 'none';
    document.getElementById('sendersTab').classList.remove('form-open');
    // Back to the row we came from, not to the top of a list the reader then
    // has to search. The row may be gone — deleted, or filtered out of a
    // running-only view — in which case leaving the scroll alone is right.
    const row = editingSenderId
        && document.querySelector(`tr[data-sender-id="${editingSenderId}"]`);
    if (row) row.scrollIntoView({ block: 'center' });
    editingSenderId = null;
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
    document.getElementById('ciscoASAEventCategoriesGroup').style.display = 'none';
    document.getElementById('zscalerLogTypesGroup').style.display = 'none';
    document.getElementById('auditdEventCategoriesGroup').style.display = 'none';
    document.getElementById('fortigateEventCategoriesGroup').style.display = 'none';
    document.getElementById('sysmonEventCategoriesGroup').style.display = 'none';
    document.getElementById('deliveryFormatGroup').style.display = 'none';
    document.getElementById('useAssetsIdentitiesGroup').style.display = 'none';
    document.getElementById('useAssetsIdentities').checked = false;
    document.getElementById('aiRatioGroup').style.display = 'none';
    document.getElementById('aiRatio').value = 100;
    document.getElementById('aiRatioValue').textContent = '100%';
    document.getElementById('aiImpactPanel').style.display = 'none';
    document.getElementById('aiImpactRows').innerHTML = '';

    // Reset attack options and frequency
    hideAttackConfig();
    document.getElementById('attackOptionsGroup').style.display = 'none';
    document.getElementById('attackFieldOverrides').style.display = 'none';
    document.getElementById('attackUserGroup').style.display = 'none';
    document.getElementById('attackDestGroup').style.display = 'none';
    document.getElementById('attackSrcIpGroup').style.display = 'none';
    document.getElementById('attackDestIpGroup').style.display = 'none';
    document.getElementById('attackDestPortGroup').style.display = 'none';
    document.getElementById('frequencyGroup').style.display = 'none';
    document.getElementById('frequency').disabled = false;
    // A new sender runs for a minute unless told otherwise.
    document.getElementById('senderDuration').value = 60;
    document.getElementById('senderDurationUnit').value = 'seconds';
    refreshVolumeHint();
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
    document.getElementById('syslogDestinationGroup').style.display = 'none';
    document.getElementById('hecOverridesGroup').style.display = 'none';
    document.getElementById('hecIndex').value = '';
    document.getElementById('hecSourcetype').value = '';
    document.getElementById('hecHost').value = '';
    document.getElementById('hecSource').value = '';
    document.getElementById('destination').required = true;
    document.getElementById('configurationSelect').required = false;
    // Phase 4b: syslog inline fields removed; reset the destination dropdown if present
    const sysSel = document.getElementById('syslogDestinationSelect');
    if (sysSel) sysSel.value = '';

    // Reset all checkboxes to checked by default
    Object.values(SOURCETYPE_CONFIG).forEach(config => {
        resetCheckboxes(config.checkboxGroup);
    });
}
