/**
 * Sender form orchestrator (Phase 4a).
 *
 * New flow:
 *   1. User picks a "Source mode" radio: sourcetype | datamodel (4d) | attack (legacy)
 *   2. In Sourcetype mode → Technology dropdown (TAs from registry)
 *      → Splunk Sourcetypes multi-check (sourcetypes from registry for that TA)
 *      → Live preview (datamodel + A&I-modifiable fields per sourcetype)
 *   3. The legacy hidden #logType + form-groups + checkboxes still drive the submit
 *      (handled by app.js / senders.js). This module only sets them programmatically.
 *
 * Mapping registry sourcetype → generator source.id:
 *   - When a generator declares METADATA.sources[].sourcetype, we use that exact pairing.
 *   - Otherwise the TA is "umbrella" (one Splunk sourcetype, N generator categories) —
 *     the legacy form-group for categories stays visible and the user picks them there.
 */

import { state } from './state.js';
import { filterLogTypeDropdown } from './sourcetypes.js';
import { SOURCETYPE_CONFIG, getAllFormGroupIds } from './sourcetype-config.js';
import { showNotification } from './utils.js';

const REG_API = '/api/ta-registry';

let _tasIndex = [];        // [{name, full_name, vendor, ...}]
let _activeTA = null;
let _activeST = new Set(); // set of sourcetype strings (e.g. 'pan:traffic')
let _hecSourcetypeMapSeed = {}; // overrides restored from a persisted sender
let _hecDefaultSourcetype = null; // TA-level default ingestion sourcetype (e.g. pan:log)
let _hecDefaultSourcetypeByFormat = null; // same, keyed on render_format (Windows)
let _hecSourceMapSeed = {};     // `source` overrides restored from a persisted sender
let _syslogViable = true;       // does the TA document a syslog collection path?
let _syslogFraming = null;      // framing the TA needs added, when shipped over syslog
let _delivery = null;           // { default, offered: { file, syslog, configuration } } from the API
let _deliveryChosen = false;    // a saved or user-picked value, kept across destination changes

/** Move every per-technology category group under the sourcetype selector.
 *
 * They are scattered through the form for historical reasons and end up about a
 * thousand pixels below the sourcetypes they refine, which reads as an
 * unrelated section. Moving the nodes keeps every existing show/hide rule
 * working — getElementById does not care where they sit — and costs no markup
 * surgery across ten blocks.
 */
function relocateCategoryGroups() {
    const slot = document.getElementById('sourcetypeCategoriesSlot');
    if (!slot) return;
    getAllFormGroupIds().forEach((id) => {
        const group = document.getElementById(id);
        if (group && group.parentElement !== slot) slot.appendChild(group);
    });
}

/** Say which Splunk sourcetype each generator category lands in.
 *
 * For FortiGate the two lists do not line up: eleven categories, four
 * sourcetypes. Ticking `utm_ips` and reading `fortigate_utm` in the list above
 * is the connection, and nothing in the form drew it.
 *
 * Where they all land in the same place — Sysmon's eight events, every
 * single-sourcetype TA — a per-row badge repeats a fifty-character string eight
 * times and says nothing the list above does not. Those groups get one line
 * instead.
 *
 * Both halves come from the registry, so a source added tomorrow is labelled
 * without touching this file. A generator that names the pairing —
 * METADATA.sources[].sourcetype, the same bridge `_sourcetypesUsedBy` reads —
 * is believed; a TA declaring a single sourcetype has nowhere else to put a
 * category, so that one is used even where the generator stays silent. Five TAs
 * are in that second case today (ssh, auditd, cisco_asa, cisco_ios,
 * active_directory) and an earlier version, driven off a hand-written table,
 * labelled neither them nor sysmon.
 *
 * @param {Array} sourcetypes  the registry's sourcetypes for this technology
 */
function labelCategoriesWithSourcetype(technology, sourcetypes = []) {
    const slot = document.getElementById('sourcetypeCategoriesSlot');
    if (!slot) return;

    const meta = state.logTypes ? state.logTypes[technology] : null;
    const declared = new Map(((meta && meta.sources) || [])
        .filter(s => s.sourcetype)
        .map(s => [s.id, s.sourcetype]));
    const only = sourcetypes.length === 1 ? sourcetypes[0].name : null;

    Array.from(slot.children).forEach((group) => {
        const boxes = Array.from(group.querySelectorAll('input[type="checkbox"]'));
        const landing = boxes.map(box => [box, declared.get(box.value) || only]);
        const distinct = new Set(landing.map(([, name]) => name).filter(Boolean));

        // Start from nothing: the previous technology's labels are still here.
        group.querySelectorAll('.sender-cat-stype').forEach(el => el.remove());
        group.querySelector('.sender-cat-lands')?.remove();
        if (!distinct.size) return;

        if (distinct.size === 1) {
            const note = document.createElement('p');
            note.className = 'hint-meta sender-cat-lands';
            note.innerHTML = 'All of these land in ' +
                `<code class="inline-code">${escapeHtml(Array.from(distinct)[0])}</code>`;
            const heading = group.querySelector(':scope > label');
            if (heading) heading.insertAdjacentElement('afterend', note);
            else group.prepend(note);
            return;
        }

        landing.forEach(([box, name]) => {
            const text = box.parentElement.querySelector('.checkbox-text');
            if (!text || !name) return;
            const badge = document.createElement('code');
            badge.className = 'inline-code sender-cat-stype';
            badge.textContent = name;
            text.appendChild(badge);
        });
    });
}

export async function initSenderForm() {
    // Attach listeners FIRST so they bind even if loadTechnologies fails.
    document.querySelectorAll('input[name="source_mode"]').forEach(r =>
        r.addEventListener('change', onModeChange));

    // Defensive click delegate on the segmented wrapper (in case `change` is missed
    // due to label-wrapped radio quirks).
    const segWrap = document.getElementById('sourceModeRadios');
    if (segWrap) {
        segWrap.addEventListener('click', (e) => {
            const radio = e.target.closest('input[type="radio"][name="source_mode"]');
            if (!radio || radio.disabled) return;
            // Defer so the radio's checked state is up-to-date when we read .value
            setTimeout(() => syncModeVisibility(radio.value), 0);
        });
    }

    document.getElementById('techSelect').addEventListener('change', onTechChange);

    // Both warnings are purely informative: they never change the option chosen.
    const renderFormat = document.getElementById('renderFormat');
    if (renderFormat) renderFormat.addEventListener('change', () => {
        // render_format decides both wire values, so the rows must follow it.
        renderHecSourcetypeMap(_hecSourcetypeMapSeed);
        renderHecSourceMap(_hecSourceMapSeed);
        syncRenderFormatWarning();
    });
    document.querySelectorAll('input[name="destination_type"]').forEach(r =>
        r.addEventListener('change', () => {
            syncSyslogViabilityWarning();
            syncDeliveryFormat();
        }));
    const deliveryFormat = document.getElementById('deliveryFormat');
    if (deliveryFormat) deliveryFormat.addEventListener('change', () => {
        _deliveryChosen = true;
        syncDeliveryFormat();
    });

    // Initial visibility (in case the default-checked radio doesn't fire change)
    const initial = document.querySelector('input[name="source_mode"]:checked');
    syncModeVisibility(initial ? initial.value : 'sourcetype');

    relocateCategoryGroups();
    setupPoolSelectorListeners();

    // When the Use Environment toggle flips, recompute pool blocks visibility
    const aiToggle = document.getElementById('useAssetsIdentities');
    if (aiToggle) aiToggle.addEventListener('change', () => refreshPoolSelectors());

    await loadTechnologies();
    await loadNetworkPoolsCache();
}

/** Reset the new selectors (called when opening / closing the form) */
export function resetSenderForm() {
    _activeTA = null;
    _activeST.clear();
    _stByName = {};

    const tech = document.getElementById('techSelect');
    if (tech) tech.value = '';

    const list = document.getElementById('techSourcetypesList');
    if (list) list.innerHTML = '<p class="hint-meta">Select a technology first.</p>';

    const preview = document.getElementById('sourcetypePreview');
    if (preview) preview.innerHTML = '';

    // Default radio = By Sourcetype
    const defaultRadio = document.querySelector('input[name="source_mode"][value="sourcetype"]');
    if (defaultRadio) defaultRadio.checked = true;
    syncModeVisibility('sourcetype');

    // Reset hidden logType (so legacy listeners hide all per-tech form-groups)
    setHiddenLogType('');

    // Reset the per-sourcetype HEC overrides
    const renderFormatSelect = document.getElementById('renderFormat');
    if (renderFormatSelect) renderFormatSelect.value = 'xml';
    const deliverySelect = document.getElementById('deliveryFormat');
    if (deliverySelect) deliverySelect.value = 'uf';
    _delivery = null;
    _deliveryChosen = false;

    _hecSourcetypeMapSeed = {};
    _hecDefaultSourcetype = null;
    _hecDefaultSourcetypeByFormat = null;
    _hecSourceMapSeed = {};
    _syslogViable = true;
    _syslogFraming = null;
    renderHecSourcetypeMap({});
    renderHecSourceMap({});
    syncRenderFormatWarning();
    syncSyslogViabilityWarning();
    syncDeliveryFormat();

    // Reset Phase 4d datamodel selectors
    _activeDatamodel = null;
    _activeDatamodelChecks.clear();
    const dmSel = document.getElementById('datamodelSelect');
    if (dmSel) dmSel.value = '';
    const dmList = document.getElementById('datamodelSourcetypesList');
    if (dmList) dmList.innerHTML = '<p class="hint-meta">Select a datamodel first.</p>';

    // Reset Phase 4c pool selectors
    document.getElementById('aiPoolSelectorsGroup').style.display = 'none';
    ['src', 'dest'].forEach(dir => {
        const radio = document.querySelector(`input[name="${dir}_pool_mode"][value="entities"]`);
        if (radio) radio.checked = true;
        const sel = document.getElementById(`${dir}PoolSelect`);
        if (sel) sel.value = '';
        const mix = document.getElementById(`${dir}PoolMix`);
        if (mix) { mix.value = 50; document.getElementById(`${dir}PoolMixValue`).textContent = '50%'; }
        document.getElementById(`${dir}PoolPicker`).style.display = 'none';
        document.getElementById(`${dir}PoolMixGroup`).style.display = 'none';
    });
}

/**
 * Restore this module's state from a persisted sender (edit flow).
 *
 * Without this, editing a sender leaves `_activeTA` / `_activeST` holding
 * whatever the *previous* sender left behind, and syncLegacyCategoryCheckboxes()
 * then rewrites the generator checkboxes from that stale set — so saving one
 * sender could carry over another's sourcetypes. It also leaves the Technology
 * dropdown blank and the source-mode radio wherever the user last put it
 * (a leftover "By Datamodel" would fan out new senders instead of updating).
 *
 * @param {string} logType  the sender's log_type (== the TA name)
 * @param {object} options  the sender's persisted options blob
 */
export async function hydrateFromSender(logType, options = {}) {
    // An attack sender belongs to the legacy attack picker, not the TA selector.
    const isAttack = !!(logType && state.attackTypes && state.attackTypes[logType]);
    const mode = isAttack ? 'attack' : 'sourcetype';

    const modeRadio = document.querySelector(`input[name="source_mode"][value="${mode}"]`);
    if (modeRadio) modeRadio.checked = true;

    _hecSourcetypeMapSeed = options.hec_sourcetype_map || {};
    _hecSourceMapSeed = options.hec_source_map || {};

    // Adopt render_format here, not in senders.js. It decides both wire values,
    // and senders.js only restores it *after* this call — and only when the key
    // is present — so the rows would otherwise be built from the previously
    // edited sender's format. Absent means the emitter will default to xml.
    const renderFormat = document.getElementById('renderFormat');
    if (renderFormat) renderFormat.value = options.render_format || 'xml';
    const deliveryFormat = document.getElementById('deliveryFormat');
    _deliveryChosen = !!options.delivery_format;
    if (deliveryFormat && options.delivery_format) deliveryFormat.value = options.delivery_format;

    if (isAttack) {
        // syncModeVisibility() would clear #logType, which editSender just set.
        document.getElementById('sourcetypeModeGroup').style.display = 'none';
        document.getElementById('datamodelModeGroup').style.display = 'none';
        document.getElementById('attackModeGroup').style.display = 'block';
        filterLogTypeDropdown('attack');
        _activeTA = null;
        _activeST.clear();
        renderHecSourcetypeMap({});   // attacks keep the single free-text field
        renderHecSourceMap({});
        _syslogViable = true;
        _syslogFraming = null;
        _delivery = null;
        syncRenderFormatWarning();
        syncSyslogViabilityWarning();
        syncDeliveryFormat();
        return;
    }

    // Adopt this sender's TA *before* syncModeVisibility(), which re-publishes
    // _activeTA into the hidden #logType input. Setting it afterwards left the
    // input holding the previously edited sender's TA, so the per-technology
    // form groups (and the submitted log_type) lagged one edit behind.
    _activeTA = logType || null;
    _activeST.clear();
    _stByName = {};

    syncModeVisibility('sourcetype');

    const techSelect = document.getElementById('techSelect');
    const list = document.getElementById('techSourcetypesList');
    const preview = document.getElementById('sourcetypePreview');

    if (!logType) {
        if (techSelect) techSelect.value = '';
        if (list) list.innerHTML = '<p class="hint-meta">Select a technology first.</p>';
        if (preview) preview.innerHTML = '';
        return;
    }

    // The dropdown is filled asynchronously at boot; make sure it is ready.
    if (techSelect && !techSelect.querySelector(`option[value="${CSS.escape(logType)}"]`)) {
        await loadTechnologies();
    }
    if (techSelect) techSelect.value = logType;

    try {
        const detail = await (await fetch(`${REG_API}/${encodeURIComponent(logType)}`)).json();
        const sourcetypes = detail.sourcetypes || [];
        _hecDefaultSourcetype = detail.hec_default_sourcetype || null;
        _hecDefaultSourcetypeByFormat = detail.hec_default_sourcetype_by_render_format || null;
        _syslogViable = detail.syslog_viable !== false;
        _syslogFraming = detail.syslog_framing || null;
        _delivery = detail.delivery || null;
        _stByName = Object.fromEntries(sourcetypes.map(s => [s.name, s]));
        syncDeliveryFormat();
        renderSourcetypeChecks(sourcetypes, _sourcetypesUsedBy(logType, options));
        labelCategoriesWithSourcetype(logType, sourcetypes);
    } catch (err) {
        console.error('hydrateFromSender failed:', err);
        if (list) list.innerHTML = '<p class="hint-meta">Failed to load sourcetypes.</p>';
        return;
    }

    _restorePoolSelectors(options);
    refreshPoolSelectors();
}

/**
 * Which registry sourcetypes does a persisted sender actually cover?
 *
 * The sender stores generator source ids (e.g. log_types: ['traffic']); the
 * bridge back to Splunk sourcetypes is METADATA.sources[].sourcetype. TAs
 * without that bridge are "umbrella" (one sourcetype, N generator categories),
 * so everything the registry declares applies.
 *
 * @returns {Set<string>|null} null means "no restriction, check them all"
 */
function _sourcetypesUsedBy(logType, options) {
    const meta = state.logTypes ? state.logTypes[logType] : null;
    const sources = (meta && meta.sources) || [];
    if (!sources.length || !sources.every(s => s.sourcetype)) return null;

    const optionKey = (SOURCETYPE_CONFIG[logType] || {}).optionKey;
    const selectedIds = optionKey ? options[optionKey] : null;
    if (!Array.isArray(selectedIds) || !selectedIds.length) return null;

    const names = selectedIds
        .map(id => (sources.find(s => s.id === id) || {}).sourcetype)
        .filter(Boolean);
    return names.length ? new Set(names) : null;
}

/** Put the Phase 4c per-direction pool controls back the way the sender saved them. */
function _restorePoolSelectors(options) {
    ['src', 'dest'].forEach(dir => {
        const mode = options[`${dir}_pool_mode`] || 'entities';
        const radio = document.querySelector(`input[name="${dir}_pool_mode"][value="${mode}"]`);
        if (radio) radio.checked = true;

        const select = document.getElementById(`${dir}PoolSelect`);
        if (select) select.value = options[`${dir}_pool_id`] || '';

        const mix = document.getElementById(`${dir}PoolMix`);
        const mixLabel = document.getElementById(`${dir}PoolMixValue`);
        const ratio = options[`${dir}_pool_ai_ratio`];
        if (mix) mix.value = (ratio === undefined || ratio === null) ? 50 : ratio;
        if (mixLabel && mix) mixLabel.textContent = `${mix.value}%`;

        onPoolModeChange(dir);
    });
}

let _stByName = {};        // sourcetype name → registry detail (cached for current TA)
let _networkPools = [];    // [{category, name, range, type, ip_count}]
let _fullRegistry = [];    // [{ta_name, ta_label, sourcetypes:[…]}] — populated lazily for datamodel mode
let _activeDatamodel = null;
let _activeDatamodelChecks = new Set();   // set of `${ta}::${sourcetype}` strings

/**
 * Mapping (TA, registry-sourcetype) → generator option overrides needed to
 * constrain the generator to that sourcetype. Used by senders.js when submitting
 * a datamodel-mode sender. For sourcetypes where the underlying generator only
 * produces one shape of event, no overrides are needed (empty object).
 */
export const STYPE_TO_GEN_OPTIONS = {
    'paloalto::pan:traffic':   { log_types: ['traffic'] },
    'paloalto::pan:threat':    { log_types: ['threat']  },
    'paloalto::pan:system':    { log_types: ['system']  },
    'windows::WinEventLog:Security':    { sources: ['Security'] },
    'windows::WinEventLog:System':      { sources: ['System'] },
    'windows::WinEventLog:Application': { sources: ['Application'] },
    'apache::apache:access:kv':       { log_types: ['access'] },
    'apache::apache:access:combined': { log_types: ['combined'] },
    'apache::apache:error':           { log_types: ['error'] },
    // Single-sourcetype TAs: no override needed
    'ssh::linux_secure':                 {},
    'active_directory::WinEventLog:Security': {},
    'cisco_asa::cisco:asa':              {},
    'cisco_ios::cisco:ios':              {},
    'zscaler::zscalernss-web':           { log_types: ['web'] },
    'zscaler::zscalernss-tunnel':        { log_types: ['tunnel'] },
    'auditd::auditd':                    {},
    // One FortiGate sourcetype covers several categories: the add-on splits on
    // `type=`, which is coarser than the subtypes the generator produces.
    'fortigate::fortigate_traffic': { event_categories: ['traffic'] },
    'fortigate::fortigate_utm':     { event_categories: ['utm_webfilter', 'utm_ips',
                                                         'utm_virus', 'utm_appctrl'] },
    'fortigate::fortigate_event':   { event_categories: ['event_auth', 'event_admin',
                                                         'event_vpn', 'event_config',
                                                         'event_perf'] },
    'fortigate::fortigate_anomaly': { event_categories: ['anomaly'] },
};

/**
 * Render one "Splunk sourcetype" input per selected sourcetype.
 *
 * Each row defaults to the sourcetype's own name; the user may override it to
 * collapse several sourcetypes under a single name and let Splunk split them at
 * index time. Attacks have no registry sourcetype, so they keep the single
 * free-text field instead.
 *
 * @param {object} saved  previously stored map (edit flow), keyed by sourcetype
 */
export function renderHecSourcetypeMap(saved = {}) {
    const group = document.getElementById('hecSourcetypeMapGroup');
    const rows = document.getElementById('hecSourcetypeMapRows');
    const singleGroup = document.getElementById('hecSourcetypeSingleGroup');
    if (!group || !rows) return;

    const selected = Array.from(_activeST).sort();

    if (!selected.length) {
        // Attack mode or nothing picked yet: fall back to the single field.
        group.style.display = 'none';
        rows.innerHTML = '';
        if (singleGroup) singleGroup.style.display = '';
        return;
    }

    if (singleGroup) singleGroup.style.display = 'none';
    group.style.display = 'block';
    rows.innerHTML = selected.map(name => {
        // saved override > the default the emitter would resolve on its own
        const fallback = defaultSourcetypeFor(name);
        const value = saved[name] || fallback;
        return `
        <div class="hec-st-row">
            <code class="inline-code field-cim">${escapeHtml(name)}</code>
            <span class="hec-st-arrow" aria-hidden="true">→</span>
            <input type="text" class="hec-st-input"
                   data-sourcetype="${escapeHtml(name)}"
                   data-default-sourcetype="${escapeHtml(fallback)}"
                   value="${escapeHtml(value)}"
                   placeholder="${escapeHtml(fallback)}">
        </div>`;
    }).join('');
}

/**
 * Read the per-sourcetype overrides back.
 *
 * Only rows the user actually changed are returned. Comparing against the row's
 * own default rather than the sourcetype name matters: as soon as a TA declares a
 * default, every row differs from its own name, so the old comparison froze that
 * default into the sender as if the user had typed it — and a later registry fix
 * could no longer reach the sender. Every value here comes from the API.
 */
export function getHecSourcetypeMap() {
    const rows = document.getElementById('hecSourcetypeMapRows');
    if (!rows) return {};
    const map = {};
    rows.querySelectorAll('input.hec-st-input').forEach(input => {
        const key = input.dataset.sourcetype;
        const value = input.value.trim();
        if (value && value !== input.dataset.defaultSourcetype) map[key] = value;
    });
    return map;
}

/**
 * Which render_format the sender will emit, as the backend reads it.
 *
 * `options.render_format` is only sent for TAs that expose the select; the
 * backend defaults an absent value to 'xml', so mirror that here or the row
 * would advertise a value the emitter is not going to use.
 */
function currentRenderFormat() {
    const select = document.getElementById('renderFormat');
    const group = document.getElementById('renderFormatGroup');
    const exposed = !!select && !!group && group.style.display !== 'none';
    return (exposed && select.value) || 'xml';
}

/** The `source` the registry documents for a sourcetype, or '' when it documents none. */
function registrySourceFor(name) {
    const info = _stByName[name];
    if (!info) return '';
    // Windows keys it on render_format: the TA reads `source` off the event body,
    // and render_format is what decides the body's shape.
    const byFormat = info.hec_source_by_render_format;
    if (byFormat) return byFormat[currentRenderFormat()] || '';
    return info.hec_source || '';
}

/** The sourcetype the sender will put on the wire for `name`, absent an override. */
function defaultSourcetypeFor(name) {
    if (_hecDefaultSourcetypeByFormat) {
        const value = _hecDefaultSourcetypeByFormat[currentRenderFormat()];
        if (value) return value;
    }
    return _hecDefaultSourcetype || name;
}

/**
 * Render one `source` input per selected sourcetype, prefilled from the registry.
 *
 * Unlike the sourcetype map there is no fallback: a TA that documents no `source`
 * gets no row and no value. Absence is information — the Windows add-on needs a
 * per-channel `source` to classify, Palo Alto needs none, and inventing a value
 * for the latter would silently change how Splunk indexes it. Every value shown
 * here comes from the registry over the API; none is written in this file.
 *
 * @param {object} saved  previously stored map (edit flow), keyed by sourcetype
 */
export function renderHecSourceMap(saved = {}) {
    const group = document.getElementById('hecSourceMapGroup');
    const rows = document.getElementById('hecSourceMapRows');
    const singleGroup = document.getElementById('hecSourceSingleGroup');
    if (!group || !rows) return;

    const selected = Array.from(_activeST).sort();
    const documented = selected.filter(name => registrySourceFor(name));

    if (!documented.length) {
        // Nothing documented for this TA: keep the single free-text field, emit nothing.
        group.style.display = 'none';
        rows.innerHTML = '';
        if (singleGroup) singleGroup.style.display = '';
        return;
    }

    if (singleGroup) singleGroup.style.display = 'none';
    group.style.display = 'block';
    rows.innerHTML = documented.map(name => {
        const fallback = registrySourceFor(name);
        const value = saved[name] || fallback;
        return `
        <div class="hec-st-row">
            <code class="inline-code field-cim">${escapeHtml(name)}</code>
            <span class="hec-st-arrow" aria-hidden="true">→</span>
            <input type="text" class="hec-source-input"
                   data-sourcetype="${escapeHtml(name)}"
                   data-registry-source="${escapeHtml(fallback)}"
                   value="${escapeHtml(value)}"
                   placeholder="${escapeHtml(fallback)}">
        </div>`;
    }).join('');
}

/**
 * Read the per-sourcetype `source` overrides back.
 * Only values the user actually changed are returned, so an untouched form
 * stores nothing and the backend keeps resolving from the registry.
 */
export function getHecSourceMap() {
    const rows = document.getElementById('hecSourceMapRows');
    if (!rows) return {};
    const map = {};
    rows.querySelectorAll('input.hec-source-input').forEach(input => {
        const key = input.dataset.sourcetype;
        const value = input.value.trim();
        if (value && value !== input.dataset.registrySource) map[key] = value;
    });
    return map;
}

/**
 * Warn that `render_format=classic` produces output no add-on parses.
 *
 * The generator emits the Event Viewer layout (`Log Name:      Security`) while
 * Splunk_TA_windows keys its classic extractions on `^LogName=`. Both the option
 * and the generator are left as they are — this only says what will happen.
 */
function syncRenderFormatWarning() {
    const warn = document.getElementById('renderFormatWarning');
    const select = document.getElementById('renderFormat');
    if (!warn) return;
    const group = document.getElementById('renderFormatGroup');
    const visible = !!select && select.value === 'classic' &&
                    !!group && group.style.display !== 'none';
    warn.style.display = visible ? 'block' : 'none';
}

/**
 * Offer the delivery format wherever the destination leaves a real choice.
 *
 * The API says, per destination, which formats a source offers
 * (`detail.delivery.offered`) and which shape it has by default. A Local File can
 * hold either shape for any source collected over syslog; HEC always receives
 * the event itself; a syslog destination offers the choice only where there is
 * one. Two entries or more means a choice; anything less hides the selector.
 *
 * The default follows the source until a value is saved or picked, so switching
 * technology does not carry one source's shape over to another.
 */
function syncDeliveryFormat() {
    const group = document.getElementById('deliveryFormatGroup');
    const select = document.getElementById('deliveryFormat');
    if (!group) return;

    const destination = document.querySelector('input[name="destination_type"]:checked');
    const offered = (_delivery?.offered?.[destination ? destination.value : 'file']) || [];
    const choice = offered.length > 1;
    group.style.display = choice ? 'block' : 'none';
    if (!choice || !select) return;

    [...select.options].forEach((option) => { option.hidden = !offered.includes(option.value); });
    if (!_deliveryChosen && _delivery?.default) select.value = _delivery.default;
    if (!offered.includes(select.value)) select.value = offered[0];
}

/** Warn when a syslog destination is picked for a TA the registry marks non-viable. */
function syncSyslogViabilityWarning() {
    const warn = document.getElementById('syslogViabilityWarning');
    if (!warn) return;
    const radio = document.querySelector('input[name="destination_type"]:checked');
    const isSyslog = !!radio && radio.value === 'syslog';
    warn.style.display = (isSyslog && !_syslogViable) ? 'block' : 'none';
}

/** Selected datamodel + matching sourcetypes (read by senders.js at submit time). */
export function getDatamodelSelection() {
    return {
        datamodel: _activeDatamodel,
        sources: Array.from(_activeDatamodelChecks).map(key => {
            const [ta, sourcetype] = key.split('::');
            return { ta, sourcetype, key };
        }),
    };
}

// ── Mode switching ──────────────────────────────────────────────────────────

function onModeChange(e) {
    const mode = e.target.value;
    syncModeVisibility(mode);
}

/**
 * Show/hide the right form blocks based on the current mode.
 *  - sourcetype: Tech+Sourcetypes panel + (re-applied) #logType so per-tech form-groups appear
 *  - attack:    only the legacy attack dropdown — everything else is wiped clean
 *  - datamodel: nothing visible yet (Phase 4d)
 */
function syncModeVisibility(mode) {
    const stGroup  = document.getElementById('sourcetypeModeGroup');
    const dmGroup  = document.getElementById('datamodelModeGroup');
    const atGroup  = document.getElementById('attackModeGroup');
    if (stGroup) stGroup.style.display = (mode === 'sourcetype') ? 'block' : 'none';
    if (dmGroup) dmGroup.style.display = (mode === 'datamodel')  ? 'block' : 'none';
    if (atGroup) atGroup.style.display = (mode === 'attack')     ? 'block' : 'none';

    if (mode === 'sourcetype') {
        if (_activeTA) setHiddenLogType(_activeTA);
        else           setHiddenLogType('');
        filterLogTypeDropdown('all');
    } else if (mode === 'datamodel') {
        // For datamodel mode we set logType to a pseudo-value so the legacy
        // per-tech form-groups stay hidden but A&I + frequency still appear.
        setHiddenLogType('');                   // hide per-tech form-groups
        document.getElementById('frequencyGroup').style.display = 'block';
        document.getElementById('useAssetsIdentitiesGroup').style.display = 'block';
        loadDatamodelOptions();
    } else {
        setHiddenLogType('');
        if (mode === 'attack') {
            filterLogTypeDropdown('attack');
            const display = document.getElementById('logTypeDisplay');
            if (display) display.textContent = 'Select an attack…';
        } else {
            filterLogTypeDropdown('all');
        }
    }
}

/** Build the datamodel dropdown from the union of datamodels declared in the registry. */
async function loadDatamodelOptions() {
    const select = document.getElementById('datamodelSelect');
    if (!select) return;
    // If already populated, skip
    if (select.options.length > 1) return;

    await ensureFullRegistry();

    const seen = new Set();
    _fullRegistry.forEach(ta => (ta.sourcetypes || []).forEach(st => {
        (st.datamodels || []).forEach(d => seen.add(d));
        (st.datamodel_conditions || []).forEach(c =>
            (c.datamodels || []).forEach(d => seen.add(d)));
    }));

    const ordered = Array.from(seen).sort();
    select.innerHTML = '<option value="">Select a datamodel…</option>' +
        ordered.map(d => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('');

    if (!select._wired) {
        select.addEventListener('change', onDatamodelChange);
        select._wired = true;
    }
}

/** Fetch every TA + its sourcetypes (one shot, cached in _fullRegistry). */
async function ensureFullRegistry() {
    if (_fullRegistry.length) return;
    try {
        const list = await (await fetch(REG_API)).json();
        const tas = (list.tas || []);
        const details = await Promise.all(tas.map(t =>
            fetch(`${REG_API}/${encodeURIComponent(t.name)}`).then(r => r.json())));
        _fullRegistry = tas.map((t, i) => ({
            ta_name:  t.name,
            ta_label: t.display_name || t.full_name,
            sourcetypes: details[i].sourcetypes || [],
        }));
    } catch (err) { console.error('ensureFullRegistry failed:', err); }
}

function onDatamodelChange(e) {
    _activeDatamodel = e.target.value || null;
    _activeDatamodelChecks.clear();
    renderDatamodelSourcetypeList();
}

/** Walk the cached registry and list every sourcetype that includes the active datamodel. */
function renderDatamodelSourcetypeList() {
    const container = document.getElementById('datamodelSourcetypesList');
    if (!container) return;
    if (!_activeDatamodel) {
        container.innerHTML = '<p class="hint-meta">Select a datamodel first.</p>';
        return;
    }

    const groups = [];
    _fullRegistry.forEach(ta => {
        const matches = (ta.sourcetypes || []).filter(st => {
            if ((st.datamodels || []).includes(_activeDatamodel)) return true;
            return (st.datamodel_conditions || []).some(c =>
                (c.datamodels || []).includes(_activeDatamodel));
        });
        if (matches.length) groups.push({ ta, matches });
    });

    if (!groups.length) {
        container.innerHTML = '<p class="hint-meta">No sourcetypes in the registry map to this datamodel.</p>';
        return;
    }

    container.innerHTML = groups.map(({ ta, matches }) => `
        <div class="sender-dm-ta-block">
            <div class="sender-dm-ta-label">${escapeHtml(ta.ta_label)}</div>
            ${matches.map(st => {
                const key = `${ta.ta_name}::${st.name}`;
                const conditional = (st.datamodel_conditions || []).some(c =>
                    (c.datamodels || []).includes(_activeDatamodel) && c.when !== 'always');
                _activeDatamodelChecks.add(key);
                return `
                    <label class="checkbox-label sender-st-check">
                        <input type="checkbox" name="dm_sources" value="${escapeHtml(key)}" checked>
                        <span class="checkbox-text">
                            <strong><code class="inline-code">${escapeHtml(st.name)}</code></strong>
                            ${conditional ? '<small class="hint-meta">(conditional — only a subset of events match)</small>' : ''}
                        </span>
                    </label>`;
            }).join('')}
        </div>
    `).join('');

    container.querySelectorAll('input[name="dm_sources"]').forEach(cb => {
        cb.addEventListener('change', () => {
            if (cb.checked) _activeDatamodelChecks.add(cb.value);
            else            _activeDatamodelChecks.delete(cb.value);
        });
    });
}

// ── Technology / Sourcetype loading ────────────────────────────────────────

async function loadTechnologies() {
    try {
        const res = await fetch(REG_API);
        const data = await res.json();
        const labelOf = t => t.display_name || t.full_name;
        _tasIndex = (data.tas || []).slice().sort((a, b) => labelOf(a).localeCompare(labelOf(b)));

        const sel = document.getElementById('techSelect');
        sel.innerHTML = '<option value="">Select a technology…</option>' +
            _tasIndex.map(t => `<option value="${t.name}">${escapeHtml(labelOf(t))}</option>`).join('');
    } catch (err) {
        console.error('loadTechnologies failed:', err);
    }
}

async function onTechChange(e) {
    const taName = e.target.value;
    _activeTA = taName || null;
    _activeST.clear();

    const list = document.getElementById('techSourcetypesList');
    const preview = document.getElementById('sourcetypePreview');

    if (!taName) {
        list.innerHTML = '<p class="hint-meta">Select a technology first.</p>';
        preview.innerHTML = '';
        setHiddenLogType('');
        return;
    }

    setHiddenLogType(taName);  // triggers legacy form-group display via app.js listener

    list.innerHTML = '<p class="hint-meta">Loading sourcetypes…</p>';
    try {
        const detail = await (await fetch(`${REG_API}/${encodeURIComponent(taName)}`)).json();
        const sts = detail.sourcetypes || [];
        _hecDefaultSourcetype = detail.hec_default_sourcetype || null;
        _hecDefaultSourcetypeByFormat = detail.hec_default_sourcetype_by_render_format || null;
        _syslogViable = detail.syslog_viable !== false;
        _syslogFraming = detail.syslog_framing || null;
        _delivery = detail.delivery || null;
        _stByName = Object.fromEntries(sts.map(s => [s.name, s]));
        _deliveryChosen = false;        // another source, another default shape
        syncDeliveryFormat();
        renderSourcetypeChecks(sts);
        labelCategoriesWithSourcetype(taName, sts);
        refreshPoolSelectors();
    } catch (err) {
        list.innerHTML = '<p class="hint-meta">Failed to load sourcetypes.</p>';
    }
}

async function loadNetworkPoolsCache() {
    try {
        const res = await fetch('/api/network-pools');
        const data = await res.json();
        _networkPools = [];
        Object.entries(data.categories || {}).forEach(([cat, pools]) => {
            (pools || []).forEach(p => _networkPools.push({ category: cat, ...p }));
        });
        ['src', 'dest'].forEach(dir => {
            const sel = document.getElementById(`${dir}PoolSelect`);
            if (!sel) return;
            sel.innerHTML = '<option value="">— Select a pool —</option>' +
                _networkPools.map(p => `
                    <option value="${escapeHtml(p.category)}/${escapeHtml(p.name)}">
                        ${escapeHtml(p.category)} / ${escapeHtml(p.name)} (${escapeHtml(p.range)}, ${p.ip_count} IPs)
                    </option>`).join('');
        });
    } catch (err) { console.error('loadNetworkPoolsCache failed:', err); }
}

/** Walk the active sourcetypes' fields[] to detect which directions need pool selectors. */
function refreshPoolSelectors() {
    const useAI = document.getElementById('useAssetsIdentities').checked;
    const group = document.getElementById('aiPoolSelectorsGroup');
    if (!useAI || _activeST.size === 0) { group.style.display = 'none'; return; }

    const checked = Array.from(_activeST).map(n => _stByName[n]).filter(Boolean);
    const fieldsHavingPool = (dir) => {
        const list = [];
        checked.forEach(st => (st.fields || []).forEach(f => {
            if (f.direction !== dir) return;
            const src = f.ai_source || {};
            const opts = src.type === 'either' ? (src.options || []) : [src];
            if (opts.some(o => (o || {}).type === 'network_pool')) {
                list.push(`${st.name}.${f.raw_field}`);
            }
        }));
        return list;
    };

    const srcFields  = fieldsHavingPool('src');
    const destFields = fieldsHavingPool('dest');

    const srcBlock  = document.getElementById('srcPoolBlock');
    const destBlock = document.getElementById('destPoolBlock');

    if (srcFields.length || destFields.length) group.style.display = 'block';
    else                                       { group.style.display = 'none'; return; }

    if (srcFields.length) {
        srcBlock.style.display = 'block';
        document.getElementById('srcPoolFieldsHint').textContent = `(${srcFields.join(', ')})`;
    } else {
        srcBlock.style.display = 'none';
    }
    if (destFields.length) {
        destBlock.style.display = 'block';
        document.getElementById('destPoolFieldsHint').textContent = `(${destFields.join(', ')})`;
    } else {
        destBlock.style.display = 'none';
    }
}

function setupPoolSelectorListeners() {
    ['src', 'dest'].forEach(dir => {
        document.querySelectorAll(`input[name="${dir}_pool_mode"]`).forEach(r =>
            r.addEventListener('change', () => onPoolModeChange(dir)));
        const mix = document.getElementById(`${dir}PoolMix`);
        if (mix) mix.addEventListener('input', e =>
            document.getElementById(`${dir}PoolMixValue`).textContent = e.target.value + '%');
    });
}

function onPoolModeChange(dir) {
    const checked = document.querySelector(`input[name="${dir}_pool_mode"]:checked`);
    const mode = checked ? checked.value : 'entities';
    document.getElementById(`${dir}PoolPicker`).style.display   = (mode === 'pool' || mode === 'both') ? 'block' : 'none';
    document.getElementById(`${dir}PoolMixGroup`).style.display = (mode === 'both') ? 'block' : 'none';
}

function renderSourcetypeChecks(sourcetypes, preselected = null) {
    const list = document.getElementById('techSourcetypesList');
    if (!sourcetypes.length) {
        list.innerHTML = '<p class="hint-meta">No sourcetypes declared in the registry.</p>';
        _activeST = new Set();
        return;
    }

    // Creating a sender: everything checked. Editing one: only what it uses.
    const checkedNames = preselected && preselected.size
        ? new Set(preselected)
        : new Set(sourcetypes.map(s => s.name));

    list.innerHTML = sourcetypes.map((st, i) => `
        <label class="checkbox-label sender-st-check">
            <input type="checkbox" name="splunk_sourcetypes" value="${escapeHtml(st.name)}"
                   ${checkedNames.has(st.name) ? 'checked' : ''}
                   data-st-index="${i}">
            <span class="checkbox-text">
                <strong><code class="inline-code">${escapeHtml(st.name)}</code></strong>
                <small>${escapeHtml(st.description || '')}</small>
            </span>
            <span class="env-badges">
                ${(st.datamodels || []).map(dm => `<span class="env-badge env-badge-entity">${escapeHtml(dm)}</span>`).join('')}
            </span>
        </label>
    `).join('');

    _activeST = new Set(sourcetypes.filter(s => checkedNames.has(s.name)).map(s => s.name));

    list.querySelectorAll('input[name="splunk_sourcetypes"]').forEach(cb => {
        cb.addEventListener('change', () => {
            // A sender with no sourcetype has nothing to send. Refusing the last
            // one here says so at the moment of the click, where a validation
            // message on submit would leave the form looking merely empty.
            if (!cb.checked && _activeST.size === 1 && _activeST.has(cb.value)) {
                cb.checked = true;
                showNotification(
                    'Keep at least one sourcetype — a sender with none sends nothing',
                    'error');
                return;
            }
            if (cb.checked) _activeST.add(cb.value);
            else            _activeST.delete(cb.value);
            syncLegacyCategoryCheckboxes(sourcetypes);
            renderPreview(sourcetypes);
            refreshPoolSelectors();
            renderHecSourcetypeMap(_hecSourcetypeMapSeed);
            renderHecSourceMap(_hecSourceMapSeed);
        });
    });

    syncLegacyCategoryCheckboxes(sourcetypes);
    renderPreview(sourcetypes);
    renderHecSourcetypeMap(_hecSourcetypeMapSeed);
    renderHecSourceMap(_hecSourceMapSeed);
    syncRenderFormatWarning();
    syncSyslogViabilityWarning();
    syncDeliveryFormat();
}

/**
 * If the generator declares per-source `sourcetype` (e.g. Palo Alto: traffic→pan:traffic),
 * sync the legacy category checkboxes (paloalto_log_types) to mirror the active set.
 * If the TA is umbrella (no per-source sourcetype mapping), do nothing — the user picks
 * categories from the legacy form-group as before.
 */
function syncLegacyCategoryCheckboxes(sourcetypes) {
    const meta = state.logTypes[_activeTA];
    if (!meta || !meta.sources || !meta.sources.length) return;

    // The sourcetype selector can only stand in for the category group when the
    // two say the same thing — one sourcetype per category. Several categories
    // sharing one sourcetype is an umbrella TA: Sysmon puts five event IDs on
    // XmlWinEventLog:Microsoft-Windows-Sysmon/Operational, FortiGate eleven
    // subtypes on four sourcetypes. Ticking the sourcetype cannot express which
    // of them you want, so the category group stays and stays visible. Testing
    // only that each source declares *a* sourcetype hid it anyway, and every
    // category came back checked — a Sysmon sender emitted all five event IDs
    // with no way to narrow it.
    const names = meta.sources.map(s => s.sourcetype);
    const onePerCategory = names.every(Boolean) && new Set(names).size === names.length;
    if (!onePerCategory) return;

    // Find the legacy checkbox group for this generator (e.g. paloalto_log_types)
    const firstId = meta.sources[0].id;
    const firstCb = document.querySelector(`input[type="checkbox"][value="${CSS.escape(firstId)}"]`);
    if (!firstCb) return;
    const groupName = firstCb.name;

    document.querySelectorAll(`input[name="${groupName}"]`).forEach(cb => {
        const src = meta.sources.find(s => s.id === cb.value);
        if (!src) return;
        cb.checked = _activeST.has(src.sourcetype);
    });

    // Hide the legacy form-group (it would duplicate the new sourcetype selector).
    // The legacy listener in app.js shows it on logType change — we hide it right after.
    const legacyGroup = firstCb.closest('.form-group');
    if (legacyGroup) legacyGroup.style.display = 'none';
}

// ── Preview panel (datamodel + fields) ─────────────────────────────────────

async function renderPreview(sourcetypes) {
    const preview = document.getElementById('sourcetypePreview');
    const checked = sourcetypes.filter(s => _activeST.has(s.name));
    if (!checked.length) { preview.innerHTML = ''; return; }

    preview.innerHTML = checked.map(st => renderPreviewCard(st)).join('');
    wireFieldsToggles(preview);
}

function renderPreviewCard(st) {
    const hasFields = (st.fields || []).length > 0;
    const conditions = st.datamodel_conditions || [];

    const dmRow = (st.datamodels || []).length
        ? (st.datamodels || []).map(d => `<span class="category-badge">${escapeHtml(d)}</span>`).join(' ')
        : '<span class="hint-meta">no primary datamodel</span>';

    const conditionalNote = conditions.length > 1
        ? `<span class="hint-meta">(${conditions.length} conditional rules — final datamodel depends on the event subtype)</span>`
        : '';

    const fieldsTable = hasFields ? `
        <table class="data-table sender-st-fields-table">
            <thead><tr><th>Raw</th><th>CIM</th><th>Source</th><th>Datamodel(s)</th></tr></thead>
            <tbody>
                ${st.fields.map(f => `
                    <tr>
                        <td><code class="inline-code field-raw">${escapeHtml(f.raw_field)}</code></td>
                        <td><code class="inline-code field-cim">${escapeHtml(f.cim_field)}</code></td>
                        <td>${renderAiSource(f.ai_source)}</td>
                        <td>${(f.datamodels || []).length
                            ? (f.datamodels || []).map(d => `<span class="category-badge">${escapeHtml(d)}</span>`).join(' ')
                            : '<span class="hint-meta">—</span>'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    ` : '<p class="hint-meta">No Phase 3 mapping yet — fields will fall back to the generator defaults.</p>';

    const fieldCount = hasFields ? st.fields.length : 0;

    return `
        <div class="sender-st-preview-card collapsed">
            <div class="sender-st-preview-head">
                <code class="inline-code field-cim">${escapeHtml(st.name)}</code>
                <span>${dmRow}</span>
                ${conditionalNote}
            </div>
            <button type="button" class="sender-st-fields-toggle"
                    aria-expanded="false">
                <span class="sender-st-fields-caret" aria-hidden="true">▸</span>
                Fields${fieldCount ? ` <span class="badge">${fieldCount}</span>` : ''}
            </button>
            <div class="sender-st-fields-body">
                ${fieldsTable}
            </div>
        </div>
    `;
}

/** Wire the per-card "Fields" toggle (collapsed by default). */
function wireFieldsToggles(container) {
    container.querySelectorAll('.sender-st-fields-toggle').forEach(button => {
        button.addEventListener('click', () => {
            const card = button.closest('.sender-st-preview-card');
            const collapsed = card.classList.toggle('collapsed');
            button.setAttribute('aria-expanded', String(!collapsed));
            const caret = button.querySelector('.sender-st-fields-caret');
            if (caret) caret.textContent = collapsed ? '▸' : '▾';
        });
    });
}

function renderAiSource(src) {
    if (!src || !src.type || src.type === 'random') return '<span class="hint-meta">random</span>';
    if (src.type === 'static') return '<span class="badge">static</span>';
    if (src.type === 'entity')
        return `<span class="ai-src ai-src-entity">entity</span><code class="inline-code">${escapeHtml(src.entity_type)}.${escapeHtml(src.entity_field)}</code>`;
    if (src.type === 'account')
        return `<span class="ai-src ai-src-account">account</span><code class="inline-code">${escapeHtml(src.account_type)}.${escapeHtml(src.account_field)}</code>`;
    if (src.type === 'network_pool')
        return `<span class="ai-src ai-src-pool">network</span><code class="inline-code">${escapeHtml(src.role)}</code>`;
    if (src.type === 'either')
        return (src.options || []).map(o => renderAiSource(o)).join('<span class="hint-meta" style="margin:0 4px;">or</span>');
    return '<span class="hint-meta">' + escapeHtml(src.type) + '</span>';
}

// ── Helpers ────────────────────────────────────────────────────────────────

function setHiddenLogType(value) {
    const hidden = document.getElementById('logType');
    if (!hidden) return;
    hidden.value = value;
    hidden.dispatchEvent(new Event('change'));
}

function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
