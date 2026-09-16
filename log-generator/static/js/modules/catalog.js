/**
 * Catalog tab — what the generator can produce.
 *
 * A renderer only. Every value comes from /api/catalog, which assembles it from
 * the generators, ta_registry.py and the attack registry: nothing about a source
 * is written here, so the catalog cannot say something a sender would not do.
 */

import { escapeHtml } from './utils.js';

/**
 * The catalog payload, fetched once.
 *
 * What is cached is the data, not the fact of having rendered: the registries
 * do not change while the app runs, but the panels can be emptied and asked for
 * again, and a "rendered already" flag would leave them blank.
 */
let payload = null;

/** Forget it, so the next visit fetches again. */
export function resetCatalogCache() {
    payload = null;
}

/** escapeHtml leaves quotes alone, which is fine in text but not inside an attribute. */
function escapeAttr(text) {
    return escapeHtml(String(text ?? '')).replace(/"/g, '&quot;');
}

export async function loadCatalog() {
    const sourcesEl = document.getElementById('catalogSources');
    const datamodelsEl = document.getElementById('catalogDatamodels');
    const attacksEl = document.getElementById('catalogAttacks');
    try {
        const catalog = payload || (payload = await (await fetch('/api/catalog')).json());
        sourcesEl.innerHTML = catalog.sources.map(renderSource).join('');
        datamodelsEl.innerHTML = catalog.datamodels.map(renderDatamodel).join('')
            || '<p class="no-senders">No datamodel is reached by any source.</p>';
        attacksEl.innerHTML = renderAttacks(catalog.attacks);

        const sourcetypes = catalog.sources.reduce((n, s) => n + s.sourcetypes.length, 0);
        document.getElementById('catalogSourceCount').textContent = catalog.sources.length;
        document.getElementById('catalogSourcetypeCount').textContent = sourcetypes;
        document.getElementById('catalogDatamodelCount').textContent = catalog.datamodels.length;
        document.getElementById('catalogAttackCount').textContent = catalog.attacks.length;

        wireDisclosure(sourcesEl);
    } catch (err) {
        console.error('Failed to load catalog:', err);
        payload = null;   // a failed fetch must not be remembered as the catalog
        sourcesEl.innerHTML = '<p class="no-senders">Failed to load the catalog.</p>';
    }
}

/**
 * A sourcetype row opens onto how it reaches CIM.
 *
 * The row is the control rather than a separate caret: the whole point of
 * clicking it is the detail underneath, and a 24px target beside a table cell
 * would be the only hard thing to hit on the page.
 */
function wireDisclosure(root) {
    root.querySelectorAll('.catalog-st-row').forEach((row) => {
        const detail = root.querySelector(`#${row.getAttribute('aria-controls')}`);
        if (!detail) return;
        const toggle = () => {
            const open = row.getAttribute('aria-expanded') === 'true';
            row.setAttribute('aria-expanded', String(!open));
            detail.hidden = open;
        };
        row.addEventListener('click', toggle);
        row.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
        });
    });
}

function chips(values, emptyLabel) {
    if (!values.length) return `<span class="catalog-chip muted">${emptyLabel}</span>`;
    return values.map(v => `<span class="catalog-chip">${escapeHtml(v)}</span>`).join('');
}

function renderSource(source) {
    const sourcetypes = source.sourcetypes.map((st, i) => {
        const id = `st-${source.key}-${i}`;
        const detail = renderMapping(st);
        return `
        <tr class="catalog-st-row" tabindex="0" role="button"
            aria-expanded="false" aria-controls="${id}">
            <td>
                <span class="catalog-st-caret" aria-hidden="true">▸</span>
                <code>${escapeHtml(st.name)}</code>${st.wire !== st.name
                ? `<div class="catalog-wire">sent as <code>${escapeHtml(st.wire)}</code></div>` : ''}
                ${st.description ? `<div class="catalog-desc">${escapeHtml(st.description)}</div>` : ''}
            </td>
            <td>${chips(st.datamodels, 'no datamodel')}</td>
        </tr>
        <tr class="catalog-st-detail" id="${id}" hidden>
            <td colspan="2">${detail}</td>
        </tr>`;
    }).join('');

    const categories = source.categories
        .map(c => `<li title="${escapeAttr(c.description)}">${escapeHtml(c.name)}</li>`).join('');

    return `
    <article class="catalog-source">
        <div class="catalog-source-head">
            <div>
                <h3>${escapeHtml(source.name)}</h3>
                <div class="catalog-vendor">${escapeHtml(source.vendor)} · ${source.add_on_url
                    ? `<a href="${escapeAttr(source.add_on_url)}" target="_blank" rel="noopener"
                          class="catalog-addon">${escapeHtml(source.add_on)} ↗</a>`
                    : escapeHtml(source.add_on)}${source.add_on_version
                    ? `<span class="catalog-addon-version" title="The add-on version this source was modelled against">v${escapeHtml(source.add_on_version)}</span>`
                    : ''}</div>
            </div>
            ${source.sc4s_url
                ? `<a class="catalog-sc4s" href="${escapeAttr(source.sc4s_url)}" target="_blank" rel="noopener"
                      title="Splunk Connect for Syslog parses this source and assigns its sourcetype">SC4S compatible ↗</a>`
                : ''}
        </div>
        <p class="catalog-desc">${escapeHtml(source.description)}</p>

        <div class="table-scroll">
            <table class="catalog-table">
                <thead><tr><th>Sourcetype</th><th>Datamodels</th></tr></thead>
                <tbody>${sourcetypes}</tbody>
            </table>
        </div>

        <details class="catalog-details">
            <summary>${source.categories.length} event categories${source.attacks.length
                ? ` · ${source.attacks.length} attack${source.attacks.length > 1 ? 's' : ''}` : ''}</summary>
            <ul class="catalog-categories">${categories}</ul>
        </details>
    </article>`;
}

/**
 * How one sourcetype reaches CIM: the rules that map it, then its fields.
 *
 * This is what Configuration → Sourcetype Mapping used to show in its own tab.
 * It read the same registry as the catalog did and said the same things twice,
 * so it lives here, under the sourcetype it describes, and nowhere else.
 */
function renderMapping(st) {
    const blocks = [renderRules(st), renderFields(st), renderAccepted(st)].filter(Boolean);
    if (!blocks.length) {
        return '<p class="catalog-empty">No field mapping recorded for this sourcetype yet.</p>';
    }
    return blocks.join('');
}

function renderRules(st) {
    if (!st.datamodel_conditions.length) return '';
    const rows = st.datamodel_conditions.map(c => `
        <tr>
            <td>${escapeHtml(c.when)}</td>
            <td><code>${escapeHtml(c.eventtype)}</code></td>
            <td>${c.tags.map(t => `<code>${escapeHtml(t)}</code>`).join(' ')
                 || '<span class="catalog-chip muted">none</span>'}</td>
            <td>${chips(c.datamodels, 'none')}</td>
        </tr>`).join('');
    return `
    <div class="catalog-block">
        <h4>Datamodel matching rules</h4>
        <div class="table-scroll">
            <table class="catalog-table">
                <thead><tr><th>When</th><th>Eventtype</th><th>Tags</th><th>Datamodels</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    </div>`;
}

function renderFields(st) {
    if (!st.fields.length) return '';
    const rows = st.fields.map(f => {
        const origin = f.csv_position != null
            ? `<div class="catalog-wire">CSV #${f.csv_position}</div>`
            : (f.extracted_from ? `<div class="catalog-wire">via ${escapeHtml(f.extracted_from)}</div>` : '');
        return `
        <tr>
            <td><code>${escapeHtml(f.raw_field)}</code>${origin}</td>
            <td><code>${escapeHtml(f.cim_field)}</code></td>
            <td>${renderAiSource(f.ai_source)}</td>
            <td>${chips(f.datamodels, '—')}</td>
            <td>${escapeHtml(f.description)}</td>
        </tr>`;
    }).join('');
    return `
    <div class="catalog-block">
        <h4>Fields <span class="catalog-chip">${st.fields.length}</span></h4>
        <div class="table-scroll">
            <table class="catalog-table">
                <thead><tr>
                    <th>Raw field</th><th>CIM field</th><th>Filled from</th>
                    <th>Datamodels</th><th>Notes</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    </div>`;
}

/** Where a field's value comes from: the environment, a pool, or chance. */
function renderAiSource(src) {
    if (!src || !src.type || src.type === 'random') return '<span class="catalog-chip muted">random</span>';
    if (src.type === 'static') return '<span class="catalog-chip">static</span>';
    if (src.type === 'entity') {
        return `<span class="catalog-chip">asset</span>
                <code>${escapeHtml(src.entity_type)}.${escapeHtml(src.entity_field)}</code>`;
    }
    if (src.type === 'account') {
        return `<span class="catalog-chip">identity</span>
                <code>${escapeHtml(src.account_type)}.${escapeHtml(src.account_field)}</code>`;
    }
    if (src.type === 'network_pool') {
        return `<span class="catalog-chip">network pool</span> <code>${escapeHtml(src.role)}</code>`;
    }
    if (src.type === 'either') {
        return (src.options || []).map(renderAiSource).join('<span class="catalog-or">or</span>');
    }
    return `<span class="catalog-chip muted">${escapeHtml(src.type)}</span>`;
}

function renderAccepted(st) {
    if (!st.entity_types.length && !st.account_types.length) return '';
    return `
    <div class="catalog-block catalog-accepted">
        ${st.entity_types.length
            ? `<div><strong>Assets used:</strong> ${chips(st.entity_types, '')}</div>` : ''}
        ${st.account_types.length
            ? `<div><strong>Identities used:</strong> ${chips(st.account_types, '')}</div>` : ''}
    </div>`;
}

/** One CIM datamodel, and the sourcetypes that actually reach it. */
function renderDatamodel(dm) {
    const rows = dm.sourcetypes.map(st => `
        <tr>
            <td><code>${escapeHtml(st.name)}</code></td>
            <td>${escapeHtml(st.source)}</td>
        </tr>`).join('');

    return `
    <article class="catalog-source">
        <div class="catalog-source-head">
            <div>
                <h3><code>${escapeHtml(dm.name)}</code></h3>
                <div class="catalog-vendor">
                    ${dm.sourcetypes.length} sourcetype${dm.sourcetypes.length > 1 ? 's' : ''}
                    from ${dm.sources.length} source${dm.sources.length > 1 ? 's' : ''}
                </div>
            </div>
        </div>

        <div class="table-scroll">
            <table class="catalog-table">
                <thead><tr><th>Sourcetype</th><th>Source</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>

        ${dm.attacks.length ? `
        <div class="catalog-block">
            <h4>Attacks detected through it</h4>
            <ul class="catalog-categories">
                ${dm.attacks.map(a => `<li>${escapeHtml(a)}</li>`).join('')}
            </ul>
        </div>` : ''}
    </article>`;
}

function renderAttacks(attacks) {
    if (!attacks.length) return '<p class="no-senders">No attacks available.</p>';

    const rows = attacks.map(a => {
        const link = a.research_url
            ? `<a href="${escapeAttr(a.research_url)}" target="_blank" rel="noopener">Splunk research ↗</a>`
            : '';
        return `
        <tr>
            <td>
                <strong>${escapeHtml(a.name)}</strong>
                <div class="catalog-desc">${escapeHtml(a.description)}</div>
                ${a.sample ? `<details class="catalog-details">
                    <summary>Sample event</summary>
                    <code class="catalog-sample">${escapeHtml(a.sample)}</code>
                </details>` : ''}
            </td>
            <td>${escapeHtml(a.category)}</td>
            <td>${escapeHtml(a.source_name)}</td>
            <td>${chips(a.datamodel ? [a.datamodel] : [], '—')}</td>
            <td>${link}</td>
        </tr>`;
    }).join('');

    return `
    <div class="table-scroll">
        <table class="catalog-table catalog-attacks">
            <thead><tr>
                <th>Attack</th><th>Category</th><th>Source</th>
                <th>Datamodel</th><th></th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>
    </div>`;
}
