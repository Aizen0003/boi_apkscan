/**
 * APKScan Dashboard Logic
 * Handles file upload, job polling, stats display, and analyses list.
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!API.requireAuth()) return;

    // Show current user
    const navUser = document.getElementById('nav-user');
    if (navUser) {
        navUser.textContent = API.getUser() + ' (' + API.getRole() + ')';
        navUser.style.display = 'inline';
    }

    initUpload();
    loadAnalyses();

    // Filter change
    document.getElementById('filter-verdict')?.addEventListener('change', () => loadAnalyses());
});

// --- Upload ---
function initUpload() {
    const dropzone = document.getElementById('upload-dropzone');
    const fileInput = document.getElementById('file-input');
    if (!dropzone || !fileInput) return;

    // Click to browse
    dropzone.addEventListener('click', (e) => {
        if (e.target === fileInput) return;
        fileInput.click();
    });

    // Drag events
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file) startUpload(file);
    });

    // File selected
    fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) startUpload(fileInput.files[0]);
    });
}

async function startUpload(file) {
    if (!file.name.toLowerCase().endsWith('.apk')) {
        showToast('Please select an APK file', 'error');
        return;
    }

    const priority = document.querySelector('input[name="priority"]:checked')?.value || 'default';
    const statusDiv = document.getElementById('upload-status');
    const statusText = document.getElementById('upload-status-text');
    const progressBar = document.getElementById('upload-progress');
    const detailText = document.getElementById('upload-detail');
    const dropzone = document.getElementById('upload-dropzone');

    statusDiv.classList.remove('hidden');
    dropzone.style.display = 'none';

    try {
        // Upload phase
        statusText.textContent = 'Uploading ' + file.name + '...';
        progressBar.style.width = '20%';
        detailText.textContent = 'Size: ' + formatSize(file.size) + ' · Priority: ' + priority;

        const result = await API.uploadSample(file, priority);
        progressBar.style.width = '40%';

        if (result.deduped) {
            detailText.textContent = 'Duplicate detected — reusing existing analysis.';
        }

        // Polling phase
        statusText.textContent = 'Analyzing...';
        const jobResult = await API.pollJob(result.job_id, (data) => {
            const statusMap = {
                'queued': 40,
                'running': 60,
                'static_analysis': 70,
                'genai': 80,
                'scoring': 85,
                'reporting': 90,
            };
            const pct = statusMap[data.status] || 50;
            progressBar.style.width = pct + '%';
            statusText.textContent = 'Analyzing — ' + data.status + '...';
        });

        progressBar.style.width = '100%';
        statusText.textContent = 'Analysis complete! Redirecting...';
        document.getElementById('upload-spinner').style.display = 'none';

        // Redirect to report
        setTimeout(() => {
            window.location.href = '/report?id=' + jobResult.report_id;
        }, 500);

    } catch (err) {
        statusText.textContent = 'Error: ' + err.message;
        statusText.style.color = 'var(--color-error)';
        document.getElementById('upload-spinner').style.borderTopColor = 'var(--color-error)';
        progressBar.className = 'progress-bar-fill error';
        progressBar.style.width = '100%';
    }
}

// --- Analyses List ---
async function loadAnalyses() {
    const listDiv = document.getElementById('analyses-list');
    const emptyDiv = document.getElementById('analyses-empty');
    const loadingDiv = document.getElementById('analyses-loading');
    const filter = document.getElementById('filter-verdict')?.value;

    loadingDiv?.classList.remove('hidden');
    emptyDiv?.classList.add('hidden');

    try {
        const samples = await API.fetchSamples({ verdict: filter || undefined, limit: 50 });
        loadingDiv?.classList.add('hidden');

        if (!samples.length) {
            listDiv.innerHTML = '';
            emptyDiv?.classList.remove('hidden');
            // Hide stats if no samples
            document.getElementById('stats-grid').style.display = 'none';
            return;
        }

        // Show stats from the most recent report
        updateStats(samples[0]);

        listDiv.innerHTML = samples.map(s => renderAnalysisItem(s)).join('');
    } catch (err) {
        loadingDiv?.classList.add('hidden');
        listDiv.innerHTML = '<div class="glass-card p-6 text-center text-error">Failed to load analyses: ' + err.message + '</div>';
    }
}

function renderAnalysisItem(sample) {
    const verdictClass = (sample.verdict || '').toLowerCase();
    const verdictColors = {
        benign: 'var(--verdict-benign)',
        suspicious: 'var(--verdict-suspicious)',
        malicious: 'var(--verdict-malicious)',
    };
    const color = verdictColors[verdictClass] || 'var(--color-outline)';
    const riskPct = Math.min(100, Math.round(sample.risk_score));

    return `
        <a href="/report?id=${sample.report_id}" class="glass-card analysis-item ${verdictClass}" style="text-decoration:none; color: inherit;">
            <div style="width:48px; height:48px; border-radius: var(--radius-lg); background: var(--color-surface-variant); display:flex; align-items:center; justify-content:center;">
                <span class="material-symbols-outlined" style="color: ${color};">android</span>
            </div>
            <div style="flex: 1; min-width: 0;">
                <div class="flex items-center gap-2 mb-2">
                    <h4 class="truncate" style="font-weight: 700;">${escapeHtml(sample.sample_sha256.slice(0, 16))}...</h4>
                    <span class="verdict-badge ${verdictClass}" style="font-size: 10px; padding: 2px 8px;">${escapeHtml(sample.verdict)}</span>
                    ${sample.requires_signoff ? '<span class="material-symbols-outlined" style="color: var(--verdict-suspicious); font-size: 16px;" title="Sign-off required">pending</span>' : ''}
                </div>
                <div class="flex items-center gap-4 text-code-sm text-muted">
                    <span>Risk: ${sample.risk_score.toFixed(1)}</span>
                    <span>Confidence: ${(sample.confidence * 100).toFixed(0)}%</span>
                    <span>Severity: ${escapeHtml(sample.severity)}</span>
                </div>
            </div>
            <div style="display: none;">
                <span class="text-code-sm text-muted">Risk: ${sample.risk_score.toFixed(1)}</span>
                <div class="progress-bar" style="width: 96px; height: 6px;">
                    <div class="progress-bar-fill" style="width: ${riskPct}%; background: ${color};"></div>
                </div>
            </div>
            <span class="material-symbols-outlined text-muted" style="flex-shrink: 0;">chevron_right</span>
        </a>
    `;
}

function updateStats(sample) {
    const statsGrid = document.getElementById('stats-grid');
    statsGrid.style.display = '';

    const verdictClass = (sample.verdict || '').toLowerCase();
    const verdictColors = {
        benign: 'var(--verdict-benign)',
        suspicious: 'var(--verdict-suspicious)',
        malicious: 'var(--verdict-malicious)',
    };
    const color = verdictColors[verdictClass] || 'var(--color-primary)';

    // Risk score ring
    const score = sample.risk_score;
    const circumference = 2 * Math.PI * 36; // r=36
    const offset = circumference - (score / 100) * circumference;
    const ring = document.getElementById('risk-ring');
    ring.style.stroke = color;
    ring.setAttribute('stroke-dashoffset', String(offset));
    document.getElementById('risk-score-text').textContent = score.toFixed(1);
    document.getElementById('risk-score-text').style.color = color;

    // Glow class
    const statCards = document.querySelectorAll('.stat-card');
    statCards.forEach(c => {
        c.classList.remove('verdict-glow-benign', 'verdict-glow-suspicious', 'verdict-glow-malicious');
        c.classList.add('verdict-glow-' + verdictClass);
    });

    // Verdict badge
    const badge = document.getElementById('verdict-badge');
    badge.className = 'verdict-badge ' + verdictClass;
    document.getElementById('verdict-text').textContent = sample.verdict.toUpperCase();
    const icons = { benign: 'check_circle', suspicious: 'warning', malicious: 'dangerous' };
    badge.querySelector('.material-symbols-outlined').textContent = icons[verdictClass] || 'help';

    // Confidence
    const conf = Math.round(sample.confidence * 100);
    document.getElementById('confidence-text').textContent = conf + '%';
    document.getElementById('confidence-bar').style.width = conf + '%';

    // Severity
    const sevText = document.getElementById('severity-text');
    sevText.textContent = sample.severity.toUpperCase();
    sevText.style.color = color;
    const sevMap = { low: 1, medium: 2, high: 3, critical: 4 };
    const sevLevel = sevMap[(sample.severity || '').toLowerCase()] || 0;
    const dots = document.querySelectorAll('#severity-dots .severity-dot');
    dots.forEach((dot, i) => {
        dot.classList.toggle('active', i < sevLevel);
        dot.classList.remove('suspicious', 'malicious');
        if (i < sevLevel) dot.classList.add(verdictClass);
    });
}

// --- Utilities ---
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.style.borderColor = type === 'error' ? 'var(--color-error)' : 'rgba(78,222,163,0.3)';
    toast.classList.add('visible');
    setTimeout(() => toast.classList.remove('visible'), 3000);
}
