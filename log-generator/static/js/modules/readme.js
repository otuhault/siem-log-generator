/**
 * Read Me tab — the data sources and the Splunk add-ons they need.
 *
 * The rest of the tab is prose, written once. These two tables are not: they
 * come from /api/catalog, so the tab lists exactly what this build generates,
 * and the add-on grouping is the server's (catalog.add_ons), the same list the
 * repository README is rendered from by tools/readme_sources.py.
 */

import { fetchCatalog } from './catalog.js';
import { escapeHtml } from './utils.js';

function escapeAttr(text) {
    return escapeHtml(String(text ?? '')).replace(/"/g, '&quot;');
}

function sourceRow(source) {
    const sourcetypes = source.sourcetypes
        .map((st) => `<code>${escapeHtml(st.name)}</code>`).join(', ');
    return `<tr>
        <td>${escapeHtml(source.name)}</td>
        <td>${sourcetypes}</td>
        <td>${escapeHtml(source.add_on)}</td>
    </tr>`;
}

function addOnRow(addOn) {
    return `<tr>
        <td><a href="${escapeAttr(addOn.url)}" target="_blank" rel="noopener">${escapeHtml(addOn.name)}</a></td>
        <td><code>${escapeHtml(addOn.package)}</code></td>
        <td>${escapeHtml(addOn.version)}</td>
        <td>${addOn.used_by.map(escapeHtml).join(', ')}</td>
    </tr>`;
}

export async function loadReadmeSources() {
    const sourcesEl = document.getElementById('readmeSourcesRows');
    const addOnsEl = document.getElementById('readmeAddOnsRows');
    if (!sourcesEl || !addOnsEl) return;
    try {
        const catalog = await fetchCatalog();
        sourcesEl.innerHTML = catalog.sources.map(sourceRow).join('');
        addOnsEl.innerHTML = catalog.add_ons.map(addOnRow).join('');
    } catch (error) {
        // Said in the table rather than left empty: an empty table reads as
        // "this build ships nothing", which is the one wrong thing to imply.
        const failed = '<tr><td colspan="4">Could not load the list — the '
            + 'Catalog tab shows the same data.</td></tr>';
        sourcesEl.innerHTML = failed;
        addOnsEl.innerHTML = failed;
    }
}
