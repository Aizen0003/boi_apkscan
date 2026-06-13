/**
 * APKScan API Client
 * Handles authentication, API calls, file upload, and job polling.
 * All methods attach JWT Bearer token from sessionStorage.
 */

const API = (() => {
    const TOKEN_KEY = 'apkscan_token';
    const ROLE_KEY = 'apkscan_role';
    const USER_KEY = 'apkscan_user';

    // --- Auth ---
    function getToken() {
        return sessionStorage.getItem(TOKEN_KEY);
    }

    function isLoggedIn() {
        return !!getToken();
    }

    function getRole() {
        return sessionStorage.getItem(ROLE_KEY) || '';
    }

    function getUser() {
        return sessionStorage.getItem(USER_KEY) || '';
    }

    function logout() {
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.removeItem(ROLE_KEY);
        sessionStorage.removeItem(USER_KEY);
        window.location.href = '/login';
    }

    function requireAuth() {
        return true;
    }

    function _headers(extra = {}) {
        const token = getToken();
        const h = { ...extra };
        if (token) {
            h['Authorization'] = 'Bearer ' + token;
        }
        return h;
    }

    async function _fetch(url, options = {}) {
        const resp = await fetch(url, {
            ...options,
            headers: { ..._headers(), ...(options.headers || {}) },
        });
        return resp;
    }

    // --- Login ---
    async function login(username, password) {
        const resp = await fetch('/auth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || 'Login failed');
        }
        const data = await resp.json();
        sessionStorage.setItem(TOKEN_KEY, data.access_token);
        sessionStorage.setItem(ROLE_KEY, data.role);
        sessionStorage.setItem(USER_KEY, username);
        return data;
    }

    // --- Samples / Reports ---
    async function fetchSamples({ verdict, limit } = {}) {
        const params = new URLSearchParams();
        if (verdict) params.set('verdict', verdict);
        if (limit) params.set('limit', String(limit));
        const resp = await _fetch('/api/v1/samples?' + params.toString());
        if (!resp.ok) throw new Error('Failed to fetch samples');
        return resp.json();
    }

    async function fetchReport(reportId) {
        const resp = await _fetch('/api/v1/reports/' + reportId);
        if (!resp.ok) throw new Error('Failed to fetch report');
        return resp.json();
    }

    async function fetchJobStatus(jobId) {
        const resp = await _fetch('/api/v1/jobs/' + jobId);
        if (!resp.ok) throw new Error('Failed to fetch job status');
        return resp.json();
    }

    // --- Upload ---
    async function uploadSample(file, priority = 'default') {
        const fd = new FormData();
        fd.append('file', file);
        fd.append('priority', priority);
        const resp = await fetch('/api/v1/samples', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + getToken() },
            body: fd,
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || 'Upload failed');
        }
        return resp.json();
    }

    // --- Job Polling ---
    async function pollJob(jobId, onProgress, maxAttempts = 120) {
        for (let i = 0; i < maxAttempts; i++) {
            const data = await fetchJobStatus(jobId);
            if (onProgress) onProgress(data);

            if (data.status === 'completed' && data.report_id) {
                return data;
            }
            if (data.status === 'failed') {
                throw new Error(data.error || 'Analysis failed');
            }
            await new Promise(r => setTimeout(r, 1000));
        }
        throw new Error('Analysis timed out');
    }

    // --- PDF Download ---
    async function downloadPdf(reportId) {
        const resp = await _fetch('/api/v1/reports/' + reportId + '/pdf');
        if (!resp.ok) throw new Error('PDF not available');
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'apkscan_report_' + reportId + '.pdf';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 150);
    }

    // --- STIX Export ---
    async function exportStix(reportId) {
        const resp = await _fetch('/api/v1/reports/' + reportId + '/export');
        if (!resp.ok) throw new Error('Export failed');
        const data = await resp.json();
        const blob = new Blob([JSON.stringify(data.stix_bundle, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'apkscan_stix_' + reportId + '.json';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 150);
    }

    // --- Sign Off ---
    async function signOff(reportId, decision, note = '') {
        const resp = await _fetch('/api/v1/reports/' + reportId + '/signoff', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision, note }),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || 'Sign-off failed');
        }
        return resp.json();
    }

    // --- Health ---
    async function health() {
        const resp = await fetch('/health');
        return resp.json();
    }

    return {
        getToken, isLoggedIn, getRole, getUser, logout, requireAuth,
        login, fetchSamples, fetchReport, fetchJobStatus,
        uploadSample, pollJob, downloadPdf, exportStix, signOff, health,
    };
})();
