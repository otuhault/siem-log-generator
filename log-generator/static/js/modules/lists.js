/**
 * Lists management module
 */

import { ListsApi } from './api.js';
import { state, setLists } from './state.js';
import { formatDate, showNotification } from './utils.js';

/**
 * List type labels for display
 */
const LIST_TYPE_LABELS = {
    'user': 'Username',
    'ip': 'IP Address',
    'port': 'Port',
    'hostname': 'Hostname',
    'url': 'URL'
};

/**
 * Load all lists and update the UI
 */
export async function loadLists() {
    try {
        const lists = await ListsApi.getAll();
        setLists(lists);

        const container = document.getElementById('listsContainer');
        const totalLists = document.getElementById('totalLists');

        if (totalLists) {
            totalLists.textContent = lists.length;
        }

        if (!container) return;

        if (lists.length === 0) {
            container.innerHTML = '<p class="no-senders">No lists created yet. Click "Add List" to create one!</p>';
            return;
        }

        // Create table
        const table = document.createElement('table');
        table.className = 'senders-table';

        const thead = document.createElement('thead');
        thead.innerHTML = `
            <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Values</th>
                <th>Preview</th>
                <th>Created</th>
                <th>Actions</th>
            </tr>
        `;
        table.appendChild(thead);

        const tbody = document.createElement('tbody');
        lists.forEach(list => {
            tbody.appendChild(createListRow(list));
        });
        table.appendChild(tbody);

        container.innerHTML = '';
        container.appendChild(table);

    } catch (error) {
        console.error('Error loading lists:', error);
    }
}

/**
 * Create a table row for a list
 */
function createListRow(list) {
    const row = document.createElement('tr');
    row.dataset.listId = list.id;

    // Name
    const nameCell = document.createElement('td');
    nameCell.textContent = list.name;
    nameCell.className = 'sender-name';
    row.appendChild(nameCell);

    // Type
    const typeCell = document.createElement('td');
    const typeBadge = document.createElement('span');
    typeBadge.className = `list-type-badge list-type-${list.type}`;
    typeBadge.textContent = LIST_TYPE_LABELS[list.type] || list.type;
    typeCell.appendChild(typeBadge);
    row.appendChild(typeCell);

    // Values count
    const countCell = document.createElement('td');
    countCell.textContent = `${list.values.length} value${list.values.length !== 1 ? 's' : ''}`;
    row.appendChild(countCell);

    // Preview (first 3 values)
    const previewCell = document.createElement('td');
    const preview = list.values.slice(0, 3).join(', ');
    previewCell.textContent = list.values.length > 3 ? preview + '...' : preview;
    previewCell.style.maxWidth = '250px';
    previewCell.style.overflow = 'hidden';
    previewCell.style.textOverflow = 'ellipsis';
    previewCell.style.whiteSpace = 'nowrap';
    previewCell.style.fontFamily = "'Courier New', monospace";
    previewCell.style.fontSize = '0.85em';
    row.appendChild(previewCell);

    // Created
    const createdCell = document.createElement('td');
    createdCell.textContent = formatDate(list.created_at);
    createdCell.className = 'sender-created';
    row.appendChild(createdCell);

    // Actions
    const actionsCell = document.createElement('td');
    actionsCell.className = 'sender-actions';

    const editBtn = document.createElement('button');
    editBtn.className = 'btn btn-small btn-secondary';
    editBtn.title = 'Edit';
    editBtn.textContent = '\u270E';
    editBtn.addEventListener('click', () => editList(list.id));

    const cloneBtn = document.createElement('button');
    cloneBtn.className = 'btn btn-small btn-clone';
    cloneBtn.title = 'Clone';
    cloneBtn.textContent = '\u2398';
    cloneBtn.addEventListener('click', () => cloneList(list.id));

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn btn-small btn-delete';
    deleteBtn.title = 'Delete';
    deleteBtn.textContent = '\u00D7';
    deleteBtn.addEventListener('click', () => deleteList(list.id));

    actionsCell.appendChild(editBtn);
    actionsCell.appendChild(cloneBtn);
    actionsCell.appendChild(deleteBtn);
    row.appendChild(actionsCell);

    return row;
}

/**
 * Handle list form submission
 */
export async function handleCreateList(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const listId = formData.get('id');

    const name = formData.get('name')?.trim();
    const type = formData.get('type');
    const valuesRaw = formData.get('values')?.trim();

    if (!name) {
        showNotification('Please enter a list name', 'error');
        return;
    }
    if (!type) {
        showNotification('Please select a list type', 'error');
        return;
    }
    if (!valuesRaw) {
        showNotification('Please enter at least one value', 'error');
        return;
    }

    // Parse values (one per line, filter empty)
    const values = valuesRaw.split('\n')
        .map(v => v.trim())
        .filter(v => v.length > 0);

    if (values.length === 0) {
        showNotification('Please enter at least one value', 'error');
        return;
    }

    const data = { name, type, values };

    try {
        let result;
        let successMessage;

        if (listId) {
            result = await ListsApi.update(listId, data);
            successMessage = 'List updated successfully!';
        } else {
            result = await ListsApi.create(data);
            successMessage = 'List created successfully!';
        }

        if (result.success) {
            closeListForm();
            await loadLists();
            showNotification(successMessage, 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error saving list: ' + error.message, 'error');
    }
}

/**
 * Edit a list
 */
export async function editList(listId) {
    try {
        const list = await ListsApi.get(listId);

        if (list) {
            document.getElementById('listId').value = list.id;
            document.getElementById('listName').value = list.name;
            document.getElementById('listType').value = list.type;
            document.getElementById('listValues').value = list.values.join('\n');

            document.getElementById('listFormTitle').textContent = 'Edit List';
            document.getElementById('submitListBtn').textContent = 'Update List';

            document.getElementById('listFormCard').style.display = 'block';
        }
    } catch (error) {
        showNotification('Error loading list: ' + error.message, 'error');
    }
}

/**
 * Clone a list
 */
export async function cloneList(listId) {
    try {
        const result = await ListsApi.clone(listId);

        if (result.success) {
            await loadLists();
            showNotification('List cloned successfully!', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error cloning list: ' + error.message, 'error');
    }
}

/**
 * Delete a list
 */
export async function deleteList(listId) {
    if (!confirm('Are you sure you want to delete this list?')) {
        return;
    }

    try {
        const result = await ListsApi.delete(listId);

        if (result.success) {
            await loadLists();
            showNotification('List deleted', 'success');
        } else {
            showNotification('Error: ' + result.error, 'error');
        }
    } catch (error) {
        showNotification('Error deleting list: ' + error.message, 'error');
    }
}

/**
 * Close and reset the list form
 */
export function closeListForm() {
    const form = document.getElementById('createListForm');
    document.getElementById('listFormCard').style.display = 'none';
    form.reset();
    document.getElementById('listId').value = '';
    document.getElementById('listFormTitle').textContent = 'Create New List';
    document.getElementById('submitListBtn').textContent = 'Create List';
}
