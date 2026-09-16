/**
 * Syslog Destinations management module — symmetric to configurations.js (HEC).
 */

import { setSyslogDestinations } from './state.js';
import { showNotification, formatDate } from './utils.js';

const API = '/api/syslog-destinations';

let _cache = [];

/** GET all + render table + populate sender dropdown */
export async function loadSyslogDestinations() {
    try {
        const res  = await fetch(API);
        const dests = await res.json();
        _cache = dests;
        setSyslogDestinations(dests);

        const totalEl = document.getElementById('totalSyslogDestinations');
        if (totalEl) totalEl.textContent = dests.length;

        // Populate dropdown in sender form (added later in Phase 4)
        const select = document.getElementById('syslogDestinationSelect');
        if (select) {
            select.innerHTML = '<option value="">Select a syslog destination…</option>';
            dests.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.id;
                opt.textContent = `${d.name} (${d.host}:${d.port}/${d.protocol.toUpperCase()})`;
                select.appendChild(opt);
            });
        }

        const container = document.getElementById('syslogDestinationsContainer');
        if (!container) return;

        if (dests.length === 0) {
            container.innerHTML = '<p class="no-senders">No syslog destinations yet. Click "Add Syslog Destination" to create one.</p>';
            return;
        }

        const rows = dests.map(d => `
            <tr data-id="${d.id}">
                <td><span class="sender-name">${escapeHtml(d.name)}</span></td>
                <td><span class="sender-destination">${escapeHtml(d.host)}</span></td>
                <td>${d.port}</td>
                <td><span class="badge">${d.protocol.toUpperCase()}</span></td>
                <td><span class="sender-created">${formatDate(d.created_at)}</span></td>
                <td class="sender-actions">
                    <button class="btn btn-small" data-action="edit"   title="Edit">✏️</button>
                    <button class="btn btn-small" data-action="clone"  title="Clone">📋</button>
                    <button class="btn btn-small btn-delete" data-action="delete" title="Delete">🗑️</button>
                </td>
            </tr>
        `).join('');

        container.innerHTML = `
            <table class="senders-table">
                <thead>
                    <tr><th>Name</th><th>Host</th><th>Port</th><th>Protocol</th><th>Created</th><th>Actions</th></tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;

        container.querySelectorAll('button[data-action]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tr = e.target.closest('tr');
                const id = tr.dataset.id;
                const action = btn.dataset.action;
                if (action === 'edit')   editDestination(id);
                if (action === 'clone')  cloneDestination(id);
                if (action === 'delete') deleteDestination(id);
            });
        });
    } catch (err) {
        console.error('Error loading syslog destinations:', err);
    }
}

export function showSyslogDestinationForm(dest = null) {
    const card = document.getElementById('syslogDestinationFormCard');
    const title = document.getElementById('syslogDestinationFormTitle');
    const form = document.getElementById('createSyslogDestinationForm');
    form.reset();
    document.getElementById('syslogDestinationId').value = '';

    if (dest) {
        title.textContent = 'Edit Syslog Destination';
        document.getElementById('syslogDestinationId').value     = dest.id;
        document.getElementById('syslogDestinationName').value   = dest.name;
        document.getElementById('syslogDestinationHost').value   = dest.host;
        document.getElementById('syslogDestinationPort').value   = dest.port;
        document.getElementById('syslogDestinationProtocol').value = dest.protocol || 'udp';
    } else {
        title.textContent = 'Create New Syslog Destination';
    }
    card.style.display = 'block';
}

export function closeSyslogDestinationForm() {
    document.getElementById('syslogDestinationFormCard').style.display = 'none';
    document.getElementById('createSyslogDestinationForm').reset();
    document.getElementById('syslogDestinationId').value = '';
}

export async function handleCreateSyslogDestination(event) {
    event.preventDefault();
    const id   = document.getElementById('syslogDestinationId').value;
    const body = {
        name:     document.getElementById('syslogDestinationName').value.trim(),
        host:     document.getElementById('syslogDestinationHost').value.trim(),
        port:     parseInt(document.getElementById('syslogDestinationPort').value, 10),
        protocol: document.getElementById('syslogDestinationProtocol').value,
    };
    try {
        const url    = id ? `${API}/${id}` : API;
        const method = id ? 'PUT' : 'POST';
        const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        if (data.success) {
            showNotification(id ? 'Syslog destination updated' : 'Syslog destination created', 'success');
            closeSyslogDestinationForm();
            loadSyslogDestinations();
        } else {
            showNotification('Error: ' + (data.error || 'unknown'), 'error');
        }
    } catch (err) {
        showNotification('Error: ' + err.message, 'error');
    }
}

export async function testSyslogConnection() {
    const body = {
        host:     document.getElementById('syslogDestinationHost').value.trim(),
        port:     parseInt(document.getElementById('syslogDestinationPort').value, 10),
        protocol: document.getElementById('syslogDestinationProtocol').value,
    };
    if (!body.host || !body.port) {
        showNotification('Host and port required', 'error');
        return;
    }
    try {
        const res = await fetch(`${API}/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        const data = await res.json();
        showNotification(data.success ? data.message : ('Error: ' + data.error),
                         data.success ? 'success' : 'error');
    } catch (err) {
        showNotification('Error: ' + err.message, 'error');
    }
}

async function editDestination(id) {
    const dest = _cache.find(d => d.id === id);
    if (dest) showSyslogDestinationForm(dest);
}

async function cloneDestination(id) {
    try {
        const res = await fetch(`${API}/${id}/clone`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showNotification('Cloned', 'success');
            loadSyslogDestinations();
        }
    } catch (err) { showNotification('Error: ' + err.message, 'error'); }
}

async function deleteDestination(id) {
    if (!confirm('Delete this syslog destination?')) return;
    try {
        const res = await fetch(`${API}/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            showNotification('Deleted', 'success');
            loadSyslogDestinations();
        }
    } catch (err) { showNotification('Error: ' + err.message, 'error'); }
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
