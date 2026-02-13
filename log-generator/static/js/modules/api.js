/**
 * API wrapper functions for the Log Generator
 * Centralizes all API calls for easier maintenance
 */

const API_BASE = '/api';

/**
 * Generic fetch wrapper with error handling
 * @param {string} endpoint - API endpoint
 * @param {object} options - Fetch options
 * @returns {Promise<any>} Response data
 */
async function fetchApi(endpoint, options = {}) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...options.headers
        }
    });
    return response.json();
}

// ============== Senders API ==============

export const SendersApi = {
    getAll: () => fetchApi('/senders'),

    get: (id) => fetchApi(`/senders/${id}`),

    create: (data) => fetchApi('/senders', {
        method: 'POST',
        body: JSON.stringify(data)
    }),

    update: (id, data) => fetchApi(`/senders/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data)
    }),

    delete: (id) => fetchApi(`/senders/${id}`, {
        method: 'DELETE'
    }),

    toggle: (id) => fetchApi(`/senders/${id}/toggle`, {
        method: 'POST'
    }),

    clone: (id) => fetchApi(`/senders/${id}/clone`, {
        method: 'POST'
    })
};

// ============== Configurations API ==============

export const ConfigurationsApi = {
    getAll: () => fetchApi('/configurations'),

    get: (id) => fetchApi(`/configurations/${id}`),

    create: (data) => fetchApi('/configurations', {
        method: 'POST',
        body: JSON.stringify(data)
    }),

    update: (id, data) => fetchApi(`/configurations/${id}`, {
        method: 'PUT',
        body: JSON.stringify(data)
    }),

    delete: (id) => fetchApi(`/configurations/${id}`, {
        method: 'DELETE'
    }),

    clone: (id) => fetchApi(`/configurations/${id}/clone`, {
        method: 'POST'
    }),

    test: (data) => fetchApi('/configurations/test', {
        method: 'POST',
        body: JSON.stringify(data)
    })
};

// ============== Attacks API ==============

export const AttacksApi = {
    getTypes: () => fetchApi('/attack-types')
};

// ============== Log Types API ==============

export const LogTypesApi = {
    getAll: () => fetchApi('/log-types')
};
