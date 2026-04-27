import { escapeHtml as escHtml } from './utils.js';
import { loadLogTypes } from './sourcetypes.js';

/**
 * Environment Tab — UI module
 *
 * Manages the Environment tab: CRUD for entities and accounts,
 * sub-tab switching, and table rendering.
 */

// ── State ──────────────────────────────────────────────────────────────────

const envState = {
    entities:          [],
    accounts:          [],
    entityTypeLabels:  {},
    accountTypeLabels: {},

    currentSubTab:     'entities',
    editingEntityId:   null,
    editingAccountId:  null,
};

// ── Bootstrap ──────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    setupSubTabs();
    setupEntityForm();
    setupAccountForm();
    setupAddButtons();

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.dataset.tab === 'environment') {
                loadEnvData();
            }
        });
    });
});

// ── Sub-tab switching ──────────────────────────────────────────────────────

function setupSubTabs() {
    document.querySelectorAll('.env-sub-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.dataset.subtab;
            envState.currentSubTab = target;

            document.querySelectorAll('.env-sub-tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.ai-subtab-content').forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`${target}SubTab`).classList.add('active');

            document.getElementById('addEntityBtn').style.display  = target === 'entities'  ? 'inline-block' : 'none';
            document.getElementById('addAccountBtn').style.display = target === 'accounts'  ? 'inline-block' : 'none';

            closeEntityForm();
            closeAccountForm();
        });
    });
}

// ── Data loading ────────────────────────────────────────────────────────────

async function loadEnvData() {
    try {
        const [metaRes, entitiesRes, accountsRes] = await Promise.all([
            fetch('/api/environment/meta'),
            fetch('/api/entities'),
            fetch('/api/accounts'),
        ]);
        const meta              = await metaRes.json();
        envState.entities       = await entitiesRes.json();
        envState.accounts       = await accountsRes.json();
        envState.entityTypeLabels  = meta.entity_type_labels  || {};
        envState.accountTypeLabels = meta.account_type_labels || {};

        renderEntities();
        renderAccounts();
        updateStats();
        populateLinkedEntityDropdown();
        loadLogTypes(); // refresh dropdown counts
    } catch (err) {
        console.error('Failed to load environment data:', err);
    }
}

function updateStats() {
    document.getElementById('totalEntities').textContent = envState.entities.length;
    document.getElementById('totalAccounts').textContent = envState.accounts.length;
}

// ── Rendering ──────────────────────────────────────────────────────────────

function renderEntities() {
    const tbody = document.getElementById('entitiesTableBody');
    const empty = document.getElementById('entitiesEmptyState');
    const table = document.getElementById('entitiesTableContainer');

    tbody.innerHTML = '';

    if (!envState.entities.length) {
        empty.style.display = 'block';
        table.style.display = 'none';
        return;
    }
    empty.style.display = 'none';
    table.style.display = 'block';

    envState.entities.forEach(entity => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escHtml(entity.name)}</strong></td>
            <td><span class="category-badge">${escHtml(envState.entityTypeLabels[entity.type] || entity.type)}</span></td>
            <td>${escHtml(entity.ip)}</td>
            <td>${escHtml(entity.nt_host)}</td>
            <td>${escHtml(entity.fqdn)}</td>
            <td>${escHtml(entity.os)}</td>
            <td>
                <button class="btn btn-small btn-secondary" onclick="editEntity('${entity.id}')">Edit</button>
                <button class="btn btn-small btn-delete" onclick="deleteEntity('${entity.id}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function renderAccounts() {
    const tbody = document.getElementById('accountsTableBody');
    const empty = document.getElementById('accountsEmptyState');
    const table = document.getElementById('accountsTableContainer');

    tbody.innerHTML = '';

    if (!envState.accounts.length) {
        empty.style.display = 'block';
        table.style.display = 'none';
        return;
    }
    empty.style.display = 'none';
    table.style.display = 'block';

    envState.accounts.forEach(acc => {
        const linkedName = acc.linked_entity
            ? (envState.entities.find(e => e.id === acc.linked_entity)?.name || acc.linked_entity)
            : '';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${escHtml(acc.username)}</strong></td>
            <td>${escHtml(acc.email)}</td>
            <td><span class="category-badge">${escHtml(envState.accountTypeLabels[acc.type] || acc.type)}</span></td>
            <td>${escHtml(linkedName)}</td>
            <td>
                <button class="btn btn-small btn-secondary" onclick="editAccount('${acc.id}')">Edit</button>
                <button class="btn btn-small btn-delete" onclick="deleteAccount('${acc.id}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function populateLinkedEntityDropdown(selectedId = null) {
    const sel = document.getElementById('accountLinkedEntity');
    // Keep first "None" option, rebuild the rest
    while (sel.options.length > 1) sel.remove(1);
    envState.entities.forEach(e => {
        const opt = document.createElement('option');
        opt.value = e.id;
        opt.textContent = `${e.name} (${envState.entityTypeLabels[e.type] || e.type})`;
        if (e.id === selectedId) opt.selected = true;
        sel.appendChild(opt);
    });
}

// ── Add buttons ────────────────────────────────────────────────────────────

function setupAddButtons() {
    document.getElementById('addEntityBtn').addEventListener('click', () => {
        envState.editingEntityId = null;
        document.getElementById('entityFormTitle').textContent = 'Add Entity';
        document.getElementById('submitEntityBtn').textContent = 'Add Entity';
        document.getElementById('entityForm').reset();
        document.getElementById('entityId').value = '';
        document.getElementById('entityFormCard').style.display = 'block';
    });

    document.getElementById('addAccountBtn').addEventListener('click', () => {
        envState.editingAccountId = null;
        document.getElementById('accountFormTitle').textContent = 'Add Account';
        document.getElementById('submitAccountBtn').textContent = 'Add Account';
        document.getElementById('accountForm').reset();
        document.getElementById('accountId').value = '';
        populateLinkedEntityDropdown();
        document.getElementById('accountFormCard').style.display = 'block';
    });

    document.getElementById('closeEntityForm').addEventListener('click', closeEntityForm);
    document.getElementById('cancelEntityBtn').addEventListener('click', closeEntityForm);
    document.getElementById('closeAccountForm').addEventListener('click', closeAccountForm);
    document.getElementById('cancelAccountBtn').addEventListener('click', closeAccountForm);
}

function closeEntityForm() {
    document.getElementById('entityFormCard').style.display = 'none';
    document.getElementById('entityForm').reset();
    envState.editingEntityId = null;
}

function closeAccountForm() {
    document.getElementById('accountFormCard').style.display = 'none';
    document.getElementById('accountForm').reset();
    envState.editingAccountId = null;
}

// ── Entity form ─────────────────────────────────────────────────────────────

function setupEntityForm() {
    document.getElementById('entityForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);

        const payload = {
            name:    formData.get('name').trim(),
            type:    formData.get('type'),
            ip:      formData.get('ip').trim(),
            nt_host: formData.get('nt_host').trim(),
            mac:     formData.get('mac').trim(),
            fqdn:    formData.get('fqdn').trim(),
            os:      formData.get('os').trim(),
        };

        if (!payload.name) { alert('Name is required'); return; }
        if (!payload.type) { alert('Type is required'); return; }

        const id     = envState.editingEntityId;
        const url    = id ? `/api/entities/${id}` : '/api/entities';
        const method = id ? 'PUT' : 'POST';

        try {
            const res  = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (data.success === false) throw new Error(data.error);
            closeEntityForm();
            await loadEnvData();
        } catch (err) {
            alert('Error: ' + err.message);
        }
    });
}

// ── Account form ─────────────────────────────────────────────────────────────

function setupAccountForm() {
    document.getElementById('accountForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);

        const linkedVal = formData.get('linked_entity');
        const payload = {
            username:       formData.get('username').trim(),
            email:          formData.get('email').trim(),
            type:           formData.get('type'),
            linked_entity:  linkedVal || null,
        };

        if (!payload.username) { alert('Username is required'); return; }

        const id     = envState.editingAccountId;
        const url    = id ? `/api/accounts/${id}` : '/api/accounts';
        const method = id ? 'PUT' : 'POST';

        try {
            const res  = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await res.json();
            if (data.success === false) throw new Error(data.error);
            closeAccountForm();
            await loadEnvData();
        } catch (err) {
            alert('Error: ' + err.message);
        }
    });
}

// ── Edit / Delete (global functions for inline onclick) ────────────────────

window.editEntity = function(id) {
    const entity = envState.entities.find(e => e.id === id);
    if (!entity) return;

    envState.editingEntityId = id;
    document.getElementById('entityFormTitle').textContent  = 'Edit Entity';
    document.getElementById('submitEntityBtn').textContent  = 'Update Entity';
    document.getElementById('entityId').value       = id;
    document.getElementById('entityName').value     = entity.name    || '';
    document.getElementById('entityType').value     = entity.type    || '';
    document.getElementById('entityIp').value       = entity.ip      || '';
    document.getElementById('entityHostname').value = entity.nt_host || '';
    document.getElementById('entityMac').value      = entity.mac     || '';
    document.getElementById('entityFqdn').value     = entity.fqdn    || '';
    document.getElementById('entityOs').value       = entity.os      || '';
    document.getElementById('entityFormCard').style.display = 'block';
    document.getElementById('entityFormCard').scrollIntoView({ behavior: 'smooth' });
};

window.deleteEntity = async function(id) {
    if (!confirm('Delete this entity?')) return;
    try {
        const res  = await fetch(`/api/entities/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success === false) throw new Error(data.error);
        await loadEnvData();
    } catch (err) {
        alert('Error: ' + err.message);
    }
};

window.editAccount = function(id) {
    const acc = envState.accounts.find(a => a.id === id);
    if (!acc) return;

    envState.editingAccountId = id;
    document.getElementById('accountFormTitle').textContent  = 'Edit Account';
    document.getElementById('submitAccountBtn').textContent  = 'Update Account';
    document.getElementById('accountId').value       = id;
    document.getElementById('accountUsername').value = acc.username || '';
    document.getElementById('accountEmail').value    = acc.email    || '';
    document.getElementById('accountType').value     = acc.type     || 'standard';
    populateLinkedEntityDropdown(acc.linked_entity);
    document.getElementById('accountFormCard').style.display = 'block';
    document.getElementById('accountFormCard').scrollIntoView({ behavior: 'smooth' });
};

window.deleteAccount = async function(id) {
    if (!confirm('Delete this account?')) return;
    try {
        const res  = await fetch(`/api/accounts/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success === false) throw new Error(data.error);
        await loadEnvData();
    } catch (err) {
        alert('Error: ' + err.message);
    }
};
