/* API client for OWASP Scanner backend */
const BASE = '/api';

async function request(path, options = {}) {
    const { method = 'GET', body, headers = {} } = options;
    const config = {
        method,
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            ...headers,
        },
    };
    if (body) config.body = JSON.stringify(body);

    const res = await fetch(`${BASE}${path}`, config);

    if (res.status === 401) {
        // Session expired — throw error, let React Router handle redirect
        if (!path.includes('/auth/login') && !path.includes('/auth/me')) {
            // Force re-check auth state by reloading only for non-auth calls
            window.dispatchEvent(new Event('auth-expired'));
        }
        throw new Error('Not authenticated');
    }

    if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || `Request failed (${res.status})`);
    }

    // Handle file downloads
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('text/csv') || res.headers.get('content-disposition')) {
        return res;
    }

    return res.json();
}

const api = {
    // Auth
    login: (username, password) => request('/auth/login', { method: 'POST', body: { username, password } }),
    logout: () => request('/auth/logout', { method: 'POST' }),
    me: () => request('/auth/me'),

    // Dashboard
    dashboard: () => request('/dashboard'),

    // Scan
    submitScan: (target_url, scan_note) => request('/scan', { method: 'POST', body: { target_url, scan_note } }),
    listScans: (page = 1, status = '') => request(`/scan?page=${page}${status ? `&status=${status}` : ''}`),
    getScan: (id) => request(`/scan/${id}`),
    stopScan: (id) => request(`/scan/${id}/stop`, { method: 'POST' }),
    getFindings: (jobId, page = 1, severity = '', owasp = '') =>
        request(`/scan/${jobId}/findings?page=${page}${severity ? `&severity=${severity}` : ''}${owasp ? `&owasp=${owasp}` : ''}`),
    exportFindings: (jobId, format = 'json') => request(`/scan/${jobId}/export?format=${format}`),

    // Findings
    markFinding: (id, status) => request(`/findings/${id}/mark`, { method: 'POST', body: { status } }),

    // Admin
    adminDashboard: () => request('/admin/dashboard'),
    listUsers: (page = 1, search = '') => request(`/admin/users?page=${page}&search=${search}`),
    createUser: (data) => request('/admin/users', { method: 'POST', body: data }),
    updateUser: (id, data) => request(`/admin/users/${id}`, { method: 'PUT', body: data }),
    deleteUser: (id) => request(`/admin/users/${id}`, { method: 'DELETE' }),
    listLogs: (page = 1, action = '') => request(`/admin/logs?page=${page}${action ? `&action=${action}` : ''}`),
    listAllJobs: (page = 1, status = '') => request(`/admin/jobs?page=${page}${status ? `&status=${status}` : ''}`),
};

export default api;
