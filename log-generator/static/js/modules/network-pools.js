/**
 * Network Pools UI module — manage IP pools (CIDR / range / static).
 * Backend already exists in network_pools.py.
 */

import { showNotification } from './utils.js';

const API = '/api/network-pools';

let _categories = {};   // category -> [{name, range, type, ip_count}]

export async function loadNetworkPools() {
    try {
        const res  = await fetch(API);
        const data = await res.json();
        _categories = data.categories || {};
        renderNetworkPools();
    } catch (err) {
        console.error('Error loading network pools:', err);
    }
}

function renderNetworkPools() {
    const container = document.getElementById('networkPoolsContainer');
    if (!container) return;

    const cats = Object.keys(_categories).sort();
    const totalPools = cats.reduce((acc, c) => acc + _categories[c].length, 0);
    const totalEl = document.getElementById('totalNetworkPools');
    if (totalEl) totalEl.textContent = totalPools;

    if (cats.length === 0) {
        container.innerHTML = '<p class="no-senders">No network pools yet. Create one to get started.</p>';
        return;
    }

    container.innerHTML = cats.map(category => {
        const pools = _categories[category];
        const rows = pools.map(p => `
            <tr data-category="${escapeHtml(category)}" data-name="${escapeHtml(p.name)}">
                <td><span class="sender-name">${escapeHtml(p.name)}</span></td>
                <td><code style="font-family:'SF Mono',Menlo,monospace;font-size:0.88em;">${escapeHtml(p.range)}</code></td>
                <td><span class="badge">${escapeHtml(p.type)}</span></td>
                <td>${p.ip_count}</td>
                <td class="sender-actions">
                    <button class="btn btn-small" data-action="edit" title="Edit">✏️</button>
                    <button class="btn btn-small btn-delete" data-action="delete" title="Delete">🗑️</button>
                </td>
            </tr>
        `).join('');

        return `
            <div class="card" style="margin-bottom:16px;">
                <div class="card-header">
                    <h2 style="text-transform:capitalize;">${escapeHtml(category)} <span class="badge" style="font-size:0.7em;">${pools.length}</span></h2>
                    <button class="btn btn-small" data-add-pool="${escapeHtml(category)}">+ Add Pool</button>
                </div>
                <table class="senders-table">
                    <thead><tr><th>Name</th><th>Range</th><th>Type</th><th>IP Count</th><th>Actions</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }).join('');

    container.querySelectorAll('button[data-add-pool]').forEach(btn => {
        btn.addEventListener('click', () => showPoolForm(btn.dataset.addPool));
    });
    container.querySelectorAll('button[data-action]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const tr = e.target.closest('tr');
            const category = tr.dataset.category;
            const name = tr.dataset.name;
            if (btn.dataset.action === 'edit')   editPool(category, name);
            if (btn.dataset.action === 'delete') deletePool(category, name);
        });
    });
}

export function showPoolForm(category = '', pool = null) {
    const card  = document.getElementById('networkPoolFormCard');
    const title = document.getElementById('networkPoolFormTitle');
    const form  = document.getElementById('createNetworkPoolForm');
    form.reset();
    document.getElementById('npOriginalCategory').value = '';
    document.getElementById('npOriginalName').value     = '';

    const catInput = document.getElementById('npCategory');
    catInput.value = category || '';

    if (pool) {
        title.textContent = `Edit Pool — ${pool.name}`;
        document.getElementById('npOriginalCategory').value = category;
        document.getElementById('npOriginalName').value     = pool.name;
        document.getElementById('npName').value             = pool.name;
        document.getElementById('npRange').value            = pool.range;
        document.getElementById('npType').value             = pool.type;
        // Lock category in edit mode (backend update is keyed on category+name)
        catInput.readOnly = true;
        document.getElementById('npName').readOnly = true;
    } else {
        title.textContent = 'Create New Pool';
        catInput.readOnly = false;
        document.getElementById('npName').readOnly = false;
    }
    card.style.display = 'block';
}

export function closePoolForm() {
    document.getElementById('networkPoolFormCard').style.display = 'none';
    document.getElementById('createNetworkPoolForm').reset();
}

export async function handleCreateNetworkPool(event) {
    event.preventDefault();

    const isEdit       = !!document.getElementById('npOriginalName').value;
    const editCategory = document.getElementById('npOriginalCategory').value;
    const editName     = document.getElementById('npOriginalName').value;

    const category = document.getElementById('npCategory').value.trim().toLowerCase();
    const body = {
        name:  document.getElementById('npName').value.trim(),
        range: document.getElementById('npRange').value.trim(),
        type:  document.getElementById('npType').value,
    };

    if (!category) { showNotification('Category required', 'error'); return; }
    if (!body.name || !body.range) { showNotification('Name and range required', 'error'); return; }

    try {
        let url, method;
        if (isEdit) {
            url    = `${API}/${encodeURIComponent(editCategory)}/${encodeURIComponent(editName)}`;
            method = 'PUT';
        } else {
            url    = `${API}/${encodeURIComponent(category)}`;
            method = 'POST';
        }
        const res  = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.success !== false && !data.error) {
            showNotification(isEdit ? 'Pool updated' : 'Pool created', 'success');
            closePoolForm();
            loadNetworkPools();
        } else {
            showNotification('Error: ' + (data.error || 'unknown'), 'error');
        }
    } catch (err) {
        showNotification('Error: ' + err.message, 'error');
    }
}

function editPool(category, name) {
    const pool = (_categories[category] || []).find(p => p.name === name);
    if (pool) showPoolForm(category, pool);
}

async function deletePool(category, name) {
    if (!confirm(`Delete pool "${name}" from "${category}"?`)) return;
    try {
        const res  = await fetch(`${API}/${encodeURIComponent(category)}/${encodeURIComponent(name)}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            showNotification('Pool deleted', 'success');
            loadNetworkPools();
        } else {
            showNotification('Error: ' + (data.error || 'unknown'), 'error');
        }
    } catch (err) {
        showNotification('Error: ' + err.message, 'error');
    }
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
