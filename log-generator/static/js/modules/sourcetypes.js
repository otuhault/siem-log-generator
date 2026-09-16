/**
 * Sourcetypes display module
 */

import { LogTypesApi, AttacksApi } from './api.js';
import { state, setLogTypes, setAttackTypes } from './state.js';
import { showNotification } from './utils.js';

// value → display name map, used by setLogTypeValue to restore trigger text
const _displayMap = {};

/**
 * Load log types and attacks, build the custom dropdown panel.
 * Also initialises click-outside and keyboard handlers on first call.
 */
/**
 * Filter the unified dropdown to show only options of a given group.
 *   - 'attack'      → hide Sourcetypes group
 *   - 'sourcetype'  → hide Attacks groups
 *   - null|'all'    → show everything
 */
export function filterLogTypeDropdown(group) {
    const panel = document.getElementById('logTypeOptions');
    if (!panel) return;
    panel.querySelectorAll('[data-group]').forEach(el => {
        const show = !group || group === 'all' || el.dataset.group === group;
        el.style.display = show ? '' : 'none';
    });
}

export async function loadLogTypes() {
    try {
        const [logTypesMeta, attackTypes, envCountsRes] = await Promise.all([
            LogTypesApi.getAll(),
            AttacksApi.getTypes(),
            fetch('/api/environment/counts'),
        ]);
        const envCounts = await envCountsRes.json();

        setLogTypes(logTypesMeta);
        setAttackTypes(attackTypes);

        // Build display map and panel HTML
        const optionsEl = document.getElementById('logTypeOptions');
        optionsEl.innerHTML = '';

        // Sourcetypes group — tagged data-group="sourcetype" so we can hide it in Attack mode
        optionsEl.appendChild(_buildGroupLabel('Sourcetypes', 'sourcetype'));
        Object.keys(logTypesMeta).sort().forEach(key => {
            const name = logTypesMeta[key].name;
            _displayMap[key] = name;
            const counts = envCounts[key];
            optionsEl.appendChild(_buildOption(key, name, counts, [], 'sourcetype'));
        });

        // Attack groups — tagged data-group="attack"
        if (Object.keys(attackTypes).length > 0) {
            const categories = {};
            Object.entries(attackTypes).forEach(([key, type]) => {
                const cat = type.category || type.log_type.toUpperCase();
                if (!categories[cat]) categories[cat] = [];
                categories[cat].push({ key, ...type });
            });
            Object.keys(categories).sort().forEach(cat => {
                optionsEl.appendChild(_buildGroupLabel(cat, 'attack'));
                categories[cat].forEach(type => {
                    const label = `${type.name} — ${type.description}`;
                    _displayMap[type.key] = `${type.name} — ${type.description}`;
                    const counts    = envCounts[type.key] ?? envCounts[type.log_type];
                    const srcTypes = type.log_type
                        ? [].concat(type.log_type).map(lt => logTypesMeta[lt]?.name || lt)
                        : [];
                    optionsEl.appendChild(_buildOption(type.key, label, counts, srcTypes, 'attack'));
                });
            });
        }

        _initDropdown();
    } catch (error) {
        console.error('Error loading log types:', error);
    }
}

/** Build an optgroup-style label row */
function _buildGroupLabel(text, group) {
    const div = document.createElement('div');
    div.className = 'csd-group-label';
    div.textContent = text;
    if (group) div.dataset.group = group;
    return div;
}

/** Build a clickable option row with optional sourcetype + env-count badges */
function _buildOption(value, name, counts, srcTypes = [], group) {
    const div = document.createElement('div');
    div.className = 'csd-option';
    div.dataset.value = value;
    if (group) div.dataset.group = group;

    const nameSpan = document.createElement('span');
    nameSpan.className = 'csd-option-name';
    nameSpan.textContent = name;
    div.appendChild(nameSpan);

    const allBadges = [
        ...srcTypes.map(st => {
            const b = document.createElement('span');
            b.className = 'env-badge env-badge-sourcetype';
            b.textContent = st;
            return b;
        }),
        ..._buildBadges(counts),
    ];

    if (allBadges.length) {
        const badgeWrap = document.createElement('span');
        badgeWrap.className = 'env-badges';
        allBadges.forEach(b => badgeWrap.appendChild(b));
        div.appendChild(badgeWrap);
    }

    div.addEventListener('click', () => _selectOption(value));
    return div;
}

/** Return array of env-count badge nodes (entities + accounts), empty if nothing to show */
function _buildBadges(counts) {
    if (!counts) return [];
    const parts = [];
    if (counts.entities > 0) {
        const b = document.createElement('span');
        b.className = 'env-badge env-badge-entity';
        b.textContent = `entities (${counts.entities})`;
        parts.push(b);
    }
    if (counts.accounts > 0) {
        const b = document.createElement('span');
        b.className = 'env-badge env-badge-account';
        b.textContent = `accounts (${counts.accounts})`;
        parts.push(b);
    }
    return parts;
}

/** Select an option: update hidden input, trigger text, close panel, fire change */
function _selectOption(value) {
    const hidden  = document.getElementById('logType');
    const display = document.getElementById('logTypeDisplay');
    hidden.value  = value;
    display.textContent = _displayMap[value] || value;
    document.getElementById('logTypeWrapper').classList.remove('open');
    document.getElementById('logTypePanel').style.display = 'none';
    hidden.dispatchEvent(new Event('change', { bubbles: true }));
}

/** Wire up open/close behaviour — idempotent */
let _dropdownInited = false;
function _initDropdown() {
    if (_dropdownInited) return;
    _dropdownInited = true;

    const wrapper = document.getElementById('logTypeWrapper');
    const trigger = document.getElementById('logTypeTrigger');
    const panel   = document.getElementById('logTypePanel');

    trigger.addEventListener('click', () => {
        const open = wrapper.classList.toggle('open');
        panel.style.display = open ? 'block' : 'none';
    });

    document.addEventListener('click', (e) => {
        if (!wrapper.contains(e.target)) {
            wrapper.classList.remove('open');
            panel.style.display = 'none';
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            wrapper.classList.remove('open');
            panel.style.display = 'none';
        }
    });
}

/**
 * Set the dropdown value programmatically (used by senders.js on edit restore).
 * Updates hidden input, trigger text, and dispatches change.
 */
window.setLogTypeValue = function(value) {
    const hidden  = document.getElementById('logType');
    const display = document.getElementById('logTypeDisplay');
    hidden.value  = value;
    display.textContent = _displayMap[value] || value || 'Select a sourcetype or attack…';
    hidden.dispatchEvent(new Event('change', { bubbles: true }));
};
