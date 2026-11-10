/**
 * Attack Configuration for attacks that declare their data sources.
 *
 * Such an attack says which sourcetypes it lands in (`data_sources`), in which
 * formats, what its detection returns, and its own defaults. This module renders
 * that — sourcetype rows, the environment, noise — and collects it back into the
 * sender's options. Attacks not yet migrated keep the legacy fields and none of
 * this is shown for them.
 *
 * The sourcetype and source are forced from the selection: a single typed
 * override cannot be right for several sourcetypes, and the Windows add-on
 * classifies on `source`. So the HEC Sourcetype and Source inputs are hidden
 * while such an attack is selected, and stripped from what is submitted.
 */

import { escapeHtml } from './utils.js';

const FORM_CLASS = 'attack-sourced';
const DESTINATION_LABELS = { file: 'Local File', configuration: 'HEC', syslog: 'Syslog' };
let current = null;          // { key, definition } of the selected migrated attack

const $ = (id) => document.getElementById(id);

/** True while the selected attack uses the data-source configuration. */
export function isSourcedAttack() {
    return !!current;
}

/**
 * True while the selected attack names the machine its events happened on.
 *
 * It stamps the HEC host itself, so the form's Host override is hidden and
 * dropped rather than silently losing to the attack's own value.
 */
export function attackOwnsHost() {
    return !!(current?.definition.identity_fields || []).some((f) => f.field === 'host');
}

/**
 * Show the configuration for `attackKey`. Returns false, and hides it, for an
 * attack that has not been migrated — the caller then keeps the legacy fields.
 */
export function showAttackConfig(attackKey, definition) {
    const sources = definition?.data_sources || [];
    if (!sources.length) {
        hideAttackConfig();
        return false;
    }
    current = { key: attackKey, definition };
    $('createSenderForm')?.classList.add(FORM_CLASS);

    renderSources(sources);
    $('attackSourcesGroup').hidden = false;
    $('attackEnvironmentGroup').hidden = false;
    $('attackNoiseGroup').hidden = !definition.noise;
    $('attackEventsHint').hidden = false;
    $('attackEventsLabel').textContent = `${definition.count_label || 'Number of Events'}:`;
    $('attackEventsHint').textContent = definition.count_hint || 'Events the detection matches.';

    const defaults = definition.defaults || {};
    $('attackEventsCount').value = defaults.events ?? 5;
    $('attackNoiseCount').value = defaults.noise_events ?? 20;
    $('attackDuration').value = defaults.duration ?? 1;
    $('attackDuration').min = '0';
    $('attackDurationHint').textContent = '0 sends every event at once.';

    renderWarning(definition.warning);

    renderExtraCounts(definition.extra_counts);
    resetPickerCache();
    renderIdentity(definition.identity_fields);
    $('createSenderForm')?.classList.toggle('attack-owns-host', attackOwnsHost());
    setEnvironment(false, 100);
    setNoise(false);
    restrictDestinations(definition.destinations);
    refreshRate();
    return true;
}

export function hideAttackConfig() {
    current = null;
    $('createSenderForm')?.classList.remove(FORM_CLASS);
    $('createSenderForm')?.classList.remove('attack-owns-host');
    ['attackSourcesGroup', 'attackEnvironmentGroup', 'attackNoiseGroup', 'attackEventsHint',
     'attackIdentityRows', 'attackExtraCounts', 'attackRate', 'attackWarning']
        .forEach((id) => { if ($(id)) $(id).hidden = true; });
    if ($('attackSourcesRows')) $('attackSourcesRows').innerHTML = '';
    if ($('attackIdentityRows')) $('attackIdentityRows').innerHTML = '';
    if ($('attackExtraCounts')) $('attackExtraCounts').innerHTML = '';
    if ($('attackWarning')) $('attackWarning').textContent = '';
    if ($('attackUseEnvironmentLabel')) $('attackUseEnvironmentLabel').hidden = false;
    if ($('attackEventsLabel')) $('attackEventsLabel').textContent = 'Number of Events:';
    if ($('attackDuration')) {
        $('attackDuration').min = '1';
        $('attackDurationHint').textContent = 'Generate the specified number of events over the given duration';
    }
    restrictDestinations(null);
}

// ── the warning some attacks carry ──────────────────────────────────────────

/**
 * What the reader has to do before the attack can fire, above everything else.
 *
 * `{ text, code }`: the sentence, then a value to copy — the SID this attack
 * plants, which their Enterprise Security has to hold as a privileged identity.
 * Built as elements rather than markup: the code block must be selectable, and
 * nothing here is worth an innerHTML.
 */
function renderWarning(warning) {
    const box = $('attackWarning');
    if (!box) return;
    box.textContent = '';
    box.hidden = !warning;
    if (!warning) return;

    const lead = document.createElement('strong');
    lead.textContent = 'Before you run this — ';
    box.append(lead, document.createTextNode(warning.text || warning));
    if (warning.code) {
        const code = document.createElement('code');
        code.className = 'attack-warning-code';
        code.textContent = warning.code;
        box.append(code);
    }
}

// ── destinations ────────────────────────────────────────────────────────────

/**
 * Leave only the destination types the attack can be sent to. An attack over
 * several sourcetypes is not sent over syslog, where one stream would be
 * classified as one sourcetype; a file receives the events as HEC sends them.
 * `null` restores every type.
 */
function restrictDestinations(allowed) {
    const radios = [...document.querySelectorAll('input[name="destination_type"]')];
    const open = allowed && allowed.length ? allowed : radios.map((r) => r.value);
    radios.forEach((radio) => { radio.disabled = !open.includes(radio.value); });

    const note = $('attackDestinationNote');
    const restricted = open.length < radios.length;
    if (note) {
        note.hidden = !restricted;
        // The reason belongs to the attack — several sourcetypes, or a source
        // syslog does not collect — so it comes from the API with the list.
        note.textContent = restricted
            ? (current?.definition.destinations_note
               || `This attack is sent to ${open.map((v) => DESTINATION_LABELS[v] || v).join(' or ')} only.`)
            : '';
    }
    const checked = radios.find((r) => r.checked);
    if (restricted && (!checked || checked.disabled)) {
        const first = radios.find((r) => !r.disabled);
        if (first) {
            first.checked = true;
            first.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }
}

// ── sourcetypes ─────────────────────────────────────────────────────────────

function renderSources(sources) {
    const several = sources.length > 1;
    $('attackSourcesRows').innerHTML = sources.map((source, index) => {
        const formats = source.formats;
        const picker = formats.length > 1
            ? `<select class="attack-source-format" aria-label="Format for ${escapeHtml(source.label)}">
                   ${formats.map((f) => `<option value="${escapeHtml(f.value)}">${escapeHtml(f.sourcetype)}</option>`).join('')}
               </select>`
            : `<code class="attack-source-sourcetype">${escapeHtml(formats[0].sourcetype)}</code>`;
        // Delivery format, for a source collected over syslog. Shown or hidden by
        // syncDelivery() as the destination changes.
        const offersChoice = Object.values(source.delivery?.offered || {}).some((o) => o.length > 1);
        const delivery = offersChoice
            ? `<select class="attack-source-delivery" aria-label="Delivery format for ${escapeHtml(source.label)}" hidden>
                   <option value="uf">UF — raw event</option>
                   <option value="syslog">Syslog — framed</option>
               </select>`
            : '';
        return `
        <div class="attack-source-row" data-index="${index}">
            ${several ? `<input type="checkbox" class="attack-source-check" checked
                               aria-label="Send as ${escapeHtml(source.label)}">` : ''}
            ${picker}
            ${delivery}
            <span class="attack-source-label">${escapeHtml(source.label)}</span>
            ${formats.some((f) => f.source)
                ? `<span class="attack-source-wire">source <code>${escapeHtml(formats[0].source || '—')}</code></span>`
                : ''}
        </div>`;
    }).join('');

    $('attackSourcesRows').querySelectorAll('.attack-source-row').forEach((row) => {
        const select = row.querySelector('.attack-source-format');
        if (select) select.addEventListener('change', () => refreshWire(row));
        const check = row.querySelector('.attack-source-check');
        if (check) check.addEventListener('change', () => { keepOneSelected(); refreshRate(); });
        const delivery = row.querySelector('.attack-source-delivery');
        if (delivery) delivery.value = sourceFor(row).delivery.default;
    });
    keepOneSelected();
    syncDelivery();
}

/** Show each row's delivery selector where the current destination offers a choice. */
export function syncDelivery() {
    if (!current) return;
    const radio = document.querySelector('input[name="destination_type"]:checked');
    const destination = radio ? radio.value : 'file';
    $('attackSourcesRows').querySelectorAll('.attack-source-row').forEach((row) => {
        const select = row.querySelector('.attack-source-delivery');
        if (!select) return;
        const offered = sourceFor(row).delivery?.offered?.[destination] || [];
        select.hidden = offered.length < 2;
    });
}

function sourceFor(row) {
    return current.definition.data_sources[Number(row.dataset.index)];
}

function refreshWire(row) {
    const select = row.querySelector('.attack-source-format');
    const format = sourceFor(row).formats.find((f) => f.value === select.value);
    const wire = row.querySelector('.attack-source-wire code');
    if (wire) wire.textContent = format?.source || '—';
}

/** At least one sourcetype must stay selected: the last one cannot be unticked. */
function keepOneSelected() {
    const checks = [...$('attackSourcesRows').querySelectorAll('.attack-source-check')];
    const checked = checks.filter((c) => c.checked);
    checks.forEach((c) => {
        c.disabled = c.checked && checked.length === 1;
        c.closest('.attack-source-row').classList.toggle('is-off', !c.checked);
    });
}

// ── environment ─────────────────────────────────────────────────────────────

function setEnvironment(on, ratio) {
    $('attackUseEnvironment').checked = on;
    $('attackAiRatio').value = ratio;
    $('attackAiRatioValue').textContent = `${ratio}%`;
    // An attack that sets its fields one by one has no share to slide.
    const byField = hasIdentityFields();
    $('attackUseEnvironmentLabel').hidden = byField;
    $('attackAiRatioGroup').hidden = byField || !on;
    refreshEnvironmentFields(byField ? identityUsesEnvironment() : on);
}

function refreshEnvironmentFields(show) {
    const wasHidden = $('attackAiFields').hidden;
    $('attackAiFields').hidden = !show;
    if (show && wasHidden) loadEnvironmentFields();
}

// ── extra threshold inputs (e.g. privileged ports) ──────────────────────────

function renderExtraCounts(counts) {
    const box = $('attackExtraCounts');
    if (!box) return;
    if (!counts || !counts.length) {
        box.innerHTML = '';
        box.hidden = true;
        return;
    }
    box.hidden = false;
    box.innerHTML = counts.map((c) => `
        <label class="attack-input-label" for="attackExtra_${escapeHtml(c.key)}">${escapeHtml(c.label)}:</label>
        <input type="number" id="attackExtra_${escapeHtml(c.key)}" class="attack-extra-count"
               data-key="${escapeHtml(c.key)}" min="0" max="65535" value="${Number(c.default) || 0}">
        ${c.hint ? `<small>${escapeHtml(c.hint)}</small>` : ''}`).join('');
    box.querySelectorAll('.attack-extra-count').forEach((input) =>
        input.addEventListener('input', refreshRate));
}

function collectExtraCounts() {
    const out = {};
    $('attackExtraCounts').querySelectorAll('.attack-extra-count').forEach((input) => {
        out[input.dataset.key] = parseInt(input.value, 10);
    });
    return out;
}

// ── per-field identity: one source, many destinations ───────────────────────

function hasIdentityFields() {
    return !!(current && current.definition.identity_fields);
}

//: The A&I rows behind each picker source — fetched once each, then reused.
//: `label` names the row in the dropdown, `value` is the attribute the attack
//: needs, so the form hands the backend a resolved value and never an id.
const PICKERS = {
    assets:     { url: '/api/entities', label: (r) => r.name, empty: 'asset' },
    identities: { url: '/api/accounts', label: (r) => r.username, empty: 'identity' },
};
let pickerRows = {};

/** Forget the fetched rows, so an asset added since the last look shows up. */
function resetPickerCache() {
    pickerRows = {};
}

function loadPickerRows(source) {
    const picker = PICKERS[source];
    if (!picker) return Promise.resolve([]);
    if (!pickerRows[source]) {
        pickerRows[source] = fetch(picker.url)
            .then((res) => res.json())
            .then((rows) => (Array.isArray(rows) ? rows : []))
            .catch(() => []);
    }
    return pickerRows[source];
}

/** Fill a field's A&I dropdown with the rows that carry the attribute it needs. */
async function fillAssetPicker(row) {
    const picker = row.querySelector('.attack-identity-asset');
    if (!picker || picker.dataset.filled) return;
    const source = picker.dataset.source || 'assets';
    const attribute = picker.dataset.value || 'ip';
    const spec = PICKERS[source] || PICKERS.assets;
    const rows = (await loadPickerRows(source)).filter((r) => r[attribute]);
    picker.dataset.filled = '1';
    picker.innerHTML = rows.length
        ? rows.map((r) => {
            const label = spec.label(r) || r[attribute];
            const shown = label === r[attribute] ? label : `${label} — ${r[attribute]}`;
            return `<option value="${escapeHtml(r[attribute])}">${escapeHtml(shown)}</option>`;
        }).join('')
        : `<option value="">No ${spec.empty} has a ${attribute.replace('_', ' ')}</option>`;
    const wanted = picker.dataset.wanted;
    if (wanted && rows.some((r) => r[attribute] === wanted)) picker.value = wanted;
}

//: A random stand-in per kind of field, used as the Custom placeholder and as
//: its value when the reader leaves it empty.
const PLACEHOLDERS = {
    ip: () => randomPrivateIp(),
    hostname: () => `DC0${1 + Math.floor(Math.random() * 3)}`,
    username: () => ['jsmith', 'adm_dupont', 'svc_adsync'][Math.floor(Math.random() * 3)],
};
const PATTERNS = { ip: '^(\\d{1,3}\\.){3}\\d{1,3}$' };
const TITLES = {
    ip: 'An IPv4 address, e.g. 10.0.1.50',
    hostname: 'A host name, e.g. DC01',
    username: 'An account name, e.g. jsmith',
};

/** A random RFC 1918 host address, the placeholder of a typed source. */
export function randomPrivateIp(rng = Math.random) {
    const byte = (low, high) => low + Math.floor(rng() * (high - low + 1));
    const pick = byte(0, 2);
    if (pick === 0) return `10.${byte(0, 255)}.${byte(0, 255)}.${byte(1, 254)}`;
    if (pick === 1) return `172.${byte(16, 31)}.${byte(0, 255)}.${byte(1, 254)}`;
    return `192.168.${byte(0, 255)}.${byte(1, 254)}`;
}

function renderIdentity(fields) {
    const rows = $('attackIdentityRows');
    if (!fields) {
        rows.innerHTML = '';
        rows.hidden = true;
        return;
    }
    rows.hidden = false;
    rows.innerHTML = fields.map((spec) => {
        const { field } = spec;
        const id = `attackIdentity_${field}`;
        if (spec.mode === 'single' || spec.mode === 'asset') {
            // 'single' offers Environment (any value from the pool); 'asset'
            // offers A&I, a row picked from the assets or the identities. A
            // field with no A&I source behind it (`picker: none`) offers neither.
            const source = spec.picker === undefined ? 'assets' : spec.picker;
            const kind = spec.kind || 'ip';
            const aiOption = spec.mode === 'single'
                ? '<option value="environment">Environment</option>'
                : '<option value="ai">A&amp;I</option>';
            const assetPicker = spec.mode === 'asset'
                ? `<select class="attack-identity-asset" hidden data-source="${escapeHtml(source)}"
                           data-value="${escapeHtml(spec.picker_value || 'ip')}"
                           aria-label="${escapeHtml(spec.label)} from Assets and Identities"></select>`
                : '';
            const pattern = PATTERNS[kind] ? ` pattern="${PATTERNS[kind]}"` : '';
            return `
            <div class="attack-identity-row" data-field="${escapeHtml(field)}" data-mode="${spec.mode}"
                 data-kind="${escapeHtml(kind)}">
                <label class="attack-input-label" for="${id}">${escapeHtml(spec.label)}:</label>
                <select id="${id}" class="attack-identity-mode">
                    <option value="random">Random</option>
                    ${aiOption}
                    <option value="custom">Custom</option>
                </select>
                ${assetPicker}
                <input type="text" class="attack-identity-value" hidden
                       placeholder="${escapeHtml((PLACEHOLDERS[kind] || PLACEHOLDERS.ip)())}"
                       aria-label="${escapeHtml(spec.label)}"${pattern}
                       title="${escapeHtml(TITLES[kind] || TITLES.ip)}">
                <small>${escapeHtml(spec.hint
                    || 'The same value for the whole attack. Custom without a value uses the placeholder.')}</small>
            </div>`;
        }
        if (spec.mode === 'text') {
            return `
            <div class="attack-identity-row" data-field="${escapeHtml(field)}" data-mode="text"
                 data-kind="${escapeHtml(spec.kind || 'text')}">
                <label class="attack-input-label" for="${id}">${escapeHtml(spec.label)}:</label>
                <input type="text" id="${id}" class="attack-identity-value"
                       value="${escapeHtml(spec.default || '')}" aria-label="${escapeHtml(spec.label)}">
                ${spec.hint ? `<small>${escapeHtml(spec.hint)}</small>` : ''}
            </div>`;
        }
        return `
            <div class="attack-identity-row" data-field="${escapeHtml(field)}" data-mode="distinct">
                <label class="checkbox-label">
                    <input type="checkbox" id="${id}" class="attack-identity-environment">
                    <span class="checkbox-text">
                        <strong>${escapeHtml(spec.label)} — Use Environment</strong>
                        <small>Hosts from your Assets &amp; Identities first, completed with random addresses up to the number below</small>
                    </span>
                </label>
            </div>`;
    }).join('');

    rows.querySelectorAll('.attack-identity-mode').forEach((select) =>
        select.addEventListener('change', () => onModeChange(select.closest('.attack-identity-row'))));
    rows.querySelectorAll('.attack-identity-environment').forEach((check) =>
        check.addEventListener('change', () => refreshEnvironmentFields(identityUsesEnvironment())));
}

function onModeChange(row) {
    const mode = row.querySelector('.attack-identity-mode').value;
    row.querySelector('.attack-identity-value').hidden = mode !== 'custom';
    const picker = row.querySelector('.attack-identity-asset');
    if (picker) {
        picker.hidden = mode !== 'ai';
        if (mode === 'ai') fillAssetPicker(row);
    }
    refreshEnvironmentFields(identityUsesEnvironment());
}

function identityUsesEnvironment() {
    const choice = collectIdentity();
    return Object.values(choice).some((c) => c.mode === 'environment' || c.mode === 'ai' || c.environment);
}


function collectIdentity() {
    const out = {};
    $('attackIdentityRows').querySelectorAll('.attack-identity-row').forEach((row) => {
        const field = row.dataset.field;
        if (row.dataset.mode === 'distinct') {
            out[field] = { environment: row.querySelector('.attack-identity-environment').checked };
            return;
        }
        if (row.dataset.mode === 'text') {
            out[field] = { value: row.querySelector('.attack-identity-value').value.trim() };
            return;
        }
        const mode = row.querySelector('.attack-identity-mode').value;
        const input = row.querySelector('.attack-identity-value');
        if (mode === 'custom') {
            out[field] = { mode, value: input.value.trim() || input.placeholder };
        } else if (mode === 'ai') {
            // The chosen asset's IP, resolved here so the backend needs no lookup.
            out[field] = { mode, value: row.querySelector('.attack-identity-asset')?.value || '' };
        } else {
            out[field] = { mode };
        }
    });
    return out;
}

function hydrateIdentity(saved = {}) {
    $('attackIdentityRows').querySelectorAll('.attack-identity-row').forEach((row) => {
        const choice = saved[row.dataset.field] || {};
        if (row.dataset.mode === 'distinct') {
            row.querySelector('.attack-identity-environment').checked = !!choice.environment;
            return;
        }
        if (row.dataset.mode === 'text') {
            // An older sender may carry no value; the field keeps its default.
            if (choice.value) row.querySelector('.attack-identity-value').value = choice.value;
            return;
        }
        const select = row.querySelector('.attack-identity-mode');
        select.value = choice.mode || 'random';
        const input = row.querySelector('.attack-identity-value');
        input.value = choice.mode === 'custom' ? (choice.value || '') : '';
        const picker = row.querySelector('.attack-identity-asset');
        if (picker && choice.mode === 'ai' && choice.value) {
            picker.dataset.wanted = choice.value;   // selected once the options are loaded
        }
        onModeChange(row);
    });
}

// ── rate ────────────────────────────────────────────────────────────────────

/** Events per second the attack sends: (events + noise) / duration.
 *
 * The count is the total, not a count per sourcetype: several sourcetypes share
 * the events between them rather than each replaying the whole attack.
 */
function refreshRate() {
    const rate = $('attackRate');
    if (!current || !rate) return;
    const events = Math.max(0, parseInt($('attackEventsCount').value, 10) || 0);
    const noise = current.definition.noise && $('attackNoise').checked
        ? Math.max(0, parseInt($('attackNoiseCount').value, 10) || 0) : 0;
    const sources = [...$('attackSourcesRows').querySelectorAll('.attack-source-row')]
        .filter((row) => row.querySelector('.attack-source-check')?.checked ?? true).length;
    const duration = Math.max(0, parseInt($('attackDuration').value, 10) || 0);
    const total = events + noise;

    const split = sources > 1 ? `, split over ${sources} sourcetypes` : '';
    const formula = `${events}${noise ? ` + ${noise}` : ''}`;
    rate.textContent = duration
        ? `≈ ${formatRate(total / duration)} events/s — ${formula} / ${duration} s${split}`
        : `${total} events at once — ${formula}${split}`;
    rate.hidden = false;
}

function formatRate(value) {
    return value >= 100 ? String(Math.round(value)) : value.toFixed(value >= 10 ? 1 : 2);
}

async function loadEnvironmentFields() {
    const rows = $('attackAiFieldRows');
    if (!current) return;
    rows.innerHTML = '<div class="attack-ai-empty">Loading…</div>';
    try {
        const res = await fetch(`/api/environment/attack-impact/${encodeURIComponent(current.key)}`);
        const data = await res.json();
        if (!Array.isArray(data) || !data.length) {
            rows.innerHTML = '<div class="attack-ai-empty">No field of this detection comes from the environment.</div>';
            return;
        }
        rows.innerHTML = data.map((row) => `
            <div class="ai-impact-row ${row.available ? 'available' : 'fallback'}">
                <span class="ai-cim-field">${escapeHtml(row.field)}</span>
                <span class="attack-ai-source">${escapeHtml(row.sources.join(' / '))}</span>
                <span class="ai-count ${row.available ? 'available' : 'fallback'}">${row.count}</span>
            </div>`).join('');
    } catch (err) {
        rows.innerHTML = '<div class="attack-ai-empty is-error">Failed to load environment fields.</div>';
    }
}

// ── noise ───────────────────────────────────────────────────────────────────

function setNoise(on) {
    $('attackNoise').checked = on;
    $('attackNoiseCountGroup').hidden = !on;
}

// ── wiring, collection, restoration ─────────────────────────────────────────

export function initAttackConfig() {
    $('attackUseEnvironment')?.addEventListener('change', (e) =>
        setEnvironment(e.target.checked, Number($('attackAiRatio').value)));
    $('attackAiRatio')?.addEventListener('input', (e) => {
        $('attackAiRatioValue').textContent = `${e.target.value}%`;
    });
    $('attackNoise')?.addEventListener('change', (e) => { setNoise(e.target.checked); refreshRate(); });
    ['attackEventsCount', 'attackNoiseCount', 'attackDuration'].forEach((id) =>
        $(id)?.addEventListener('input', refreshRate));
    document.querySelectorAll('input[name="destination_type"]').forEach((radio) =>
        radio.addEventListener('change', syncDelivery));
}

/** The options this configuration contributes to the sender. */
export function collectAttackOptions() {
    const rows = [...$('attackSourcesRows').querySelectorAll('.attack-source-row')];
    const attack_sources = rows
        .filter((row) => row.querySelector('.attack-source-check')?.checked ?? true)
        .map((row) => {
            const source = sourceFor(row);
            const select = row.querySelector('.attack-source-format');
            const delivery = row.querySelector('.attack-source-delivery');
            return { log_type: source.log_type, sourcetype: source.sourcetype,
                     render_format: select ? select.value : source.formats[0].value,
                     ...(delivery && !delivery.hidden ? { delivery_format: delivery.value } : {}) };
        });

    const noise = !current.definition.noise ? false : $('attackNoise').checked;
    const identity = hasIdentityFields() ? { attack_identity: collectIdentity() } : {};
    const useEnvironment = hasIdentityFields() ? identityUsesEnvironment() : $('attackUseEnvironment').checked;
    return {
        attack_sources,
        ...identity,
        ...collectExtraCounts(),
        attack_events_count: parseInt($('attackEventsCount').value, 10),
        attack_duration: parseInt($('attackDuration').value, 10),
        attack_noise: noise,
        ...(noise ? { attack_noise_count: parseInt($('attackNoiseCount').value, 10) } : {}),
        use_assets_identities: useEnvironment,
        assets_identities_ratio: useEnvironment && !hasIdentityFields() ? parseInt($('attackAiRatio').value, 10) : 100,
    };
}

/** Put a saved attack sender's options back into the form. */
export function hydrateAttackConfig(options = {}) {
    if (!current) return;
    const rows = [...$('attackSourcesRows').querySelectorAll('.attack-source-row')];
    const saved = options.attack_sources || [];
    if (saved.length) {
        rows.forEach((row) => {
            const source = sourceFor(row);
            const match = saved.find((s) => s.log_type === source.log_type && s.sourcetype === source.sourcetype);
            const check = row.querySelector('.attack-source-check');
            if (check) check.checked = !!match;
            const select = row.querySelector('.attack-source-format');
            if (select && match?.render_format) {
                select.value = match.render_format;
                refreshWire(row);
            }
            const delivery = row.querySelector('.attack-source-delivery');
            if (delivery && match?.delivery_format) delivery.value = match.delivery_format;
        });
        keepOneSelected();
        syncDelivery();
    }
    if (options.attack_events_count != null) $('attackEventsCount').value = options.attack_events_count;
    if (options.attack_duration != null) $('attackDuration').value = options.attack_duration;
    if (options.attack_noise_count != null) $('attackNoiseCount').value = options.attack_noise_count;
    $('attackExtraCounts').querySelectorAll('.attack-extra-count').forEach((input) => {
        if (options[input.dataset.key] != null) input.value = options[input.dataset.key];
    });
    setNoise(!!options.attack_noise);
    if (hasIdentityFields()) hydrateIdentity(options.attack_identity || legacyIdentity(options));
    setEnvironment(!!options.use_assets_identities, options.assets_identities_ratio ?? 100);
    refreshRate();
}

/** A sender saved before the attack set its fields one by one: a typed source IP. */
function legacyIdentity(options) {
    return options.target_src_ip ? { src_ip: { mode: 'custom', value: options.target_src_ip } } : {};
}
