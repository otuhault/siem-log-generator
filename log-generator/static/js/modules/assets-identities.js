/**
 * Assets & Identities Tab — UI module
 *
 * Manages the Assets & Identities tab: CRUD for assets and identities,
 * sub-tab switching, and table rendering.
 */

// ── State ──────────────────────────────────────────────────────────────────

const aiState = {
    assets:                   [],
    identities:               [],
    assetCategories:          [],
    assetCategoryLabels:      {},
    identityCategories:       [],
    identityCategoryLabels:   {},
    priorities:               [],
    currentSubTab:            'assets',
    editingAssetId:           null,
    editingIdentityId:        null,
};

// ── Bootstrap ──────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    setupSubTabs();
    setupAssetForm();
    setupIdentityForm();
    setupAddButtons();

    // Load when tab is clicked
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.dataset.tab === 'assets-identities') {
                loadAIData();
            }
        });
    });
});

// ── Sub-tab switching ──────────────────────────────────────────────────────

function setupSubTabs() {
    document.querySelectorAll('.ai-sub-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.subtab;
            aiState.currentSubTab = target;

            document.querySelectorAll('.ai-sub-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.ai-subtab-content').forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`${target}SubTab`).classList.add('active');

            // Toggle add buttons
            document.getElementById('addAssetBtn').style.display     = target === 'assets'     ? 'inline-block' : 'none';
            document.getElementById('addIdentityBtn').style.display  = target === 'identities' ? 'inline-block' : 'none';

            // Close any open forms
            closeAssetForm();
            closeIdentityForm();
        });
    });
}

// ── Data loading ────────────────────────────────────────────────────────────

async function loadAIData() {
    try {
        const [metaRes, assetsRes, identitiesRes] = await Promise.all([
            fetch('/api/assets-identities/meta'),
            fetch('/api/assets'),
            fetch('/api/identities'),
        ]);
        const meta       = await metaRes.json();
        aiState.assets                 = await assetsRes.json();
        aiState.identities             = await identitiesRes.json();
        aiState.assetCategories        = meta.asset_categories || [];
        aiState.assetCategoryLabels    = meta.asset_category_labels || {};
        aiState.identityCategories     = meta.identity_categories || [];
        aiState.identityCategoryLabels = meta.identity_category_labels || {};
        aiState.priorities             = meta.priorities || [];

        renderAssets();
        renderIdentities();
        updateStats();
        buildCategoryCheckboxes();
    } catch (err) {
        console.error('Failed to load assets/identities:', err);
    }
}

function updateStats() {
    document.getElementById('totalAssets').textContent     = aiState.assets.length;
    document.getElementById('totalIdentities').textContent = aiState.identities.length;
}

// ── Category checkbox builders ─────────────────────────────────────────────

function buildCategoryCheckboxes() {
    buildCheckboxGroup('assetCategoryGroup',    aiState.assetCategories,    aiState.assetCategoryLabels);
    buildCheckboxGroup('identityCategoryGroup', aiState.identityCategories, aiState.identityCategoryLabels);
}

function buildCheckboxGroup(containerId, categories, labels = {}) {
    const container = document.getElementById(containerId);
    if (!container || container.dataset.built) return;
    container.innerHTML = '';
    categories.forEach(cat => {
        const label = document.createElement('label');
        const input = document.createElement('input');
        input.type  = 'checkbox';
        input.name  = 'category';
        input.value = cat;
        label.appendChild(input);
        label.appendChild(document.createTextNode(' ' + (labels[cat] || cat)));
        container.appendChild(label);
    });
    container.dataset.built = '1';
}

function getCheckedCategories(containerId) {
    return Array.from(
        document.querySelectorAll(`#${containerId} input[type=checkbox]:checked`)
    ).map(cb => cb.value);
}

function setCheckedCategories(containerId, values) {
    document.querySelectorAll(`#${containerId} input[type=checkbox]`).forEach(cb => {
        cb.checked = values.includes(cb.value);
    });
}

// ── Rendering ──────────────────────────────────────────────────────────────

function renderAssets() {
    const tbody   = document.getElementById('assetsTableBody');
    const empty   = document.getElementById('assetsEmptyState');
    const table   = document.getElementById('assetsTableContainer');

    tbody.innerHTML = '';

    if (!aiState.assets.length) {
        empty.style.display = 'block';
        table.style.display = 'none';
        return;
    }
    empty.style.display = 'none';
    table.style.display = 'block';

    aiState.assets.forEach(asset => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escHtml(asset.ip)}</strong></td>
            <td>${escHtml(asset.nt_host)}</td>
            <td>${escHtml(asset.dns)}</td>
            <td>${renderCategories(asset.category, aiState.assetCategoryLabels)}</td>
            <td>${escHtml(asset.os)}</td>
            <td>${escHtml(asset.bunit)}</td>
            <td>${renderPriority(asset.priority)}</td>
            <td>
                <button class="btn btn-small btn-secondary" onclick="editAsset('${asset.id}')">Edit</button>
                <button class="btn btn-small btn-delete" onclick="deleteAsset('${asset.id}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function renderIdentities() {
    const tbody = document.getElementById('identitiesTableBody');
    const empty = document.getElementById('identitiesEmptyState');
    const table = document.getElementById('identitiesTableContainer');

    tbody.innerHTML = '';

    if (!aiState.identities.length) {
        empty.style.display = 'block';
        table.style.display = 'none';
        return;
    }
    empty.style.display = 'none';
    table.style.display = 'block';

    aiState.identities.forEach(ident => {
        const fullName = [ident.first, ident.last].filter(Boolean).join(' ');
        const watchlistBadge = ident.watchlist
            ? '<span class="watchlist-badge">Watchlist</span>'
            : '';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escHtml(ident.identity)}</strong></td>
            <td>${escHtml(ident.email)}</td>
            <td>${escHtml(fullName)}</td>
            <td>${renderCategories(ident.category, aiState.identityCategoryLabels)}</td>
            <td>${escHtml(ident.bunit)}</td>
            <td>${renderPriority(ident.priority)}</td>
            <td>${watchlistBadge}</td>
            <td>
                <button class="btn btn-small btn-secondary" onclick="editIdentity('${ident.id}')">Edit</button>
                <button class="btn btn-small btn-delete" onclick="deleteIdentity('${ident.id}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function renderCategories(cats, labels = {}) {
    if (!Array.isArray(cats) || !cats.length) return '';
    return cats.map(c => `<span class="category-badge">${escHtml(labels[c] || c)}</span>`).join('');
}

function renderPriority(p) {
    const label = p || 'unknown';
    return `<span class="priority-badge ${label}">${label}</span>`;
}

function escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ── Add buttons ────────────────────────────────────────────────────────────

function setupAddButtons() {
    document.getElementById('addAssetBtn').addEventListener('click', () => {
        aiState.editingAssetId = null;
        document.getElementById('assetFormTitle').textContent = 'Add Asset';
        document.getElementById('submitAssetBtn').textContent = 'Add Asset';
        document.getElementById('assetForm').reset();
        setCheckedCategories('assetCategoryGroup', []);
        document.getElementById('assetId').value = '';
        document.getElementById('assetFormCard').style.display = 'block';
    });

    document.getElementById('addIdentityBtn').addEventListener('click', () => {
        aiState.editingIdentityId = null;
        document.getElementById('identityFormTitle').textContent = 'Add Identity';
        document.getElementById('submitIdentityBtn').textContent = 'Add Identity';
        document.getElementById('identityForm').reset();
        setCheckedCategories('identityCategoryGroup', []);
        document.getElementById('identityId').value = '';
        document.getElementById('identityFormCard').style.display = 'block';
    });

    document.getElementById('closeAssetForm').addEventListener('click', closeAssetForm);
    document.getElementById('cancelAssetBtn').addEventListener('click', closeAssetForm);
    document.getElementById('closeIdentityForm').addEventListener('click', closeIdentityForm);
    document.getElementById('cancelIdentityBtn').addEventListener('click', closeIdentityForm);
}

function closeAssetForm() {
    document.getElementById('assetFormCard').style.display = 'none';
    document.getElementById('assetForm').reset();
    aiState.editingAssetId = null;
}

function closeIdentityForm() {
    document.getElementById('identityFormCard').style.display = 'none';
    document.getElementById('identityForm').reset();
    aiState.editingIdentityId = null;
}

// ── Asset form ─────────────────────────────────────────────────────────────

function setupAssetForm() {
    document.getElementById('assetForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);

        const payload = {
            ip:       formData.get('ip').trim(),
            nt_host:  formData.get('nt_host').trim(),
            dns:      formData.get('dns').trim(),
            mac:      formData.get('mac').trim(),
            os:       formData.get('os').trim(),
            bunit:    formData.get('bunit').trim(),
            owner:    formData.get('owner').trim(),
            priority: formData.get('priority'),
            category: getCheckedCategories('assetCategoryGroup'),
        };

        if (!payload.ip) {
            alert('IP Address is required');
            return;
        }

        const id  = aiState.editingAssetId;
        const url = id ? `/api/assets/${id}` : '/api/assets';
        const method = id ? 'PUT' : 'POST';

        try {
            const res  = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (data.success === false) throw new Error(data.error);
            closeAssetForm();
            await loadAIData();
        } catch (err) {
            alert('Error: ' + err.message);
        }
    });
}

// ── Identity form ──────────────────────────────────────────────────────────

function setupIdentityForm() {
    document.getElementById('identityForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);

        const payload = {
            identity:  formData.get('identity').trim(),
            email:     formData.get('email').trim(),
            first:     formData.get('first').trim(),
            last:      formData.get('last').trim(),
            bunit:     formData.get('bunit').trim(),
            priority:  formData.get('priority'),
            watchlist: document.getElementById('identityWatchlist').checked,
            category:  getCheckedCategories('identityCategoryGroup'),
        };

        if (!payload.identity) {
            alert('Username is required');
            return;
        }

        const id  = aiState.editingIdentityId;
        const url = id ? `/api/identities/${id}` : '/api/identities';
        const method = id ? 'PUT' : 'POST';

        try {
            const res  = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (data.success === false) throw new Error(data.error);
            closeIdentityForm();
            await loadAIData();
        } catch (err) {
            alert('Error: ' + err.message);
        }
    });
}

// ── Edit / Delete (global functions for inline onclick) ────────────────────

window.editAsset = function(id) {
    const asset = aiState.assets.find(a => a.id === id);
    if (!asset) return;

    aiState.editingAssetId = id;
    document.getElementById('assetFormTitle').textContent = 'Edit Asset';
    document.getElementById('submitAssetBtn').textContent = 'Update Asset';
    document.getElementById('assetId').value    = id;
    document.getElementById('assetIp').value     = asset.ip || '';
    document.getElementById('assetHostname').value = asset.nt_host || '';
    document.getElementById('assetDns').value    = asset.dns || '';
    document.getElementById('assetMac').value    = asset.mac || '';
    document.getElementById('assetOs').value     = asset.os || '';
    document.getElementById('assetBunit').value  = asset.bunit || '';
    document.getElementById('assetOwner').value  = asset.owner || '';
    document.getElementById('assetPriority').value = asset.priority || 'unknown';
    setCheckedCategories('assetCategoryGroup', asset.category || []);
    document.getElementById('assetFormCard').style.display = 'block';
    document.getElementById('assetFormCard').scrollIntoView({ behavior: 'smooth' });
};

window.deleteAsset = async function(id) {
    if (!confirm('Delete this asset?')) return;
    try {
        const res  = await fetch(`/api/assets/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success === false) throw new Error(data.error);
        await loadAIData();
    } catch (err) {
        alert('Error: ' + err.message);
    }
};

window.editIdentity = function(id) {
    const ident = aiState.identities.find(i => i.id === id);
    if (!ident) return;

    aiState.editingIdentityId = id;
    document.getElementById('identityFormTitle').textContent  = 'Edit Identity';
    document.getElementById('submitIdentityBtn').textContent  = 'Update Identity';
    document.getElementById('identityId').value       = id;
    document.getElementById('identityUsername').value = ident.identity || '';
    document.getElementById('identityEmail').value    = ident.email || '';
    document.getElementById('identityFirst').value    = ident.first || '';
    document.getElementById('identityLast').value     = ident.last || '';
    document.getElementById('identityBunit').value    = ident.bunit || '';
    document.getElementById('identityPriority').value = ident.priority || 'unknown';
    document.getElementById('identityWatchlist').checked = !!ident.watchlist;
    setCheckedCategories('identityCategoryGroup', ident.category || []);
    document.getElementById('identityFormCard').style.display = 'block';
    document.getElementById('identityFormCard').scrollIntoView({ behavior: 'smooth' });
};

window.deleteIdentity = async function(id) {
    if (!confirm('Delete this identity?')) return;
    try {
        const res  = await fetch(`/api/identities/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success === false) throw new Error(data.error);
        await loadAIData();
    } catch (err) {
        alert('Error: ' + err.message);
    }
};
