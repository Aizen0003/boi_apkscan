/**
 * APKScan Report Viewer Logic
 * Fetches report JSON and populates all 8 interactive sections.
 */

let currentReportId = null;

document.addEventListener('DOMContentLoaded', () => {
    if (!API.requireAuth()) return;

    // Get report ID from URL
    const params = new URLSearchParams(window.location.search);
    currentReportId = params.get('id');
    if (!currentReportId) {
        showError('No report ID specified. Go back to the dashboard.');
        return;
    }

    document.getElementById('sidebar-report-id').textContent = 'ID: ' + currentReportId;
    loadReport();
    initFABs();
    initScrollspy();
});

async function loadReport() {
    try {
        const report = await API.fetchReport(currentReportId);
        document.getElementById('report-loading').classList.add('hidden');
        document.getElementById('report-body').classList.remove('hidden');
        document.getElementById('fab-container').style.display = '';

        renderMetadata(report);
        renderVerdict(report);
        renderEvidence(report);
        renderMitre(report);
        renderIOCs(report);
        renderGenAI(report);
        renderRecommendations(report);
        renderCaveats(report);

        // Update page title
        const v = report.verdict?.verdict || 'Unknown';
        document.title = `APKScan | ${v} — ${currentReportId}`;
    } catch (err) {
        showError(err.message);
    }
}

function showError(msg) {
    document.getElementById('report-loading').classList.add('hidden');
    document.getElementById('report-error').classList.remove('hidden');
    document.getElementById('report-error-text').textContent = msg;
}

// ─── 1. Sample Metadata ───
function renderMetadata(report) {
    const s = report.sample || {};
    const grid = document.getElementById('metadata-grid');
    grid.style.gridTemplateColumns = 'repeat(auto-fill, minmax(300px, 1fr))';

    const fields = [
        ['Package Name', s.package_name, 'text-primary font-mono', true],
        ['SHA-256', s.sha256, 'font-mono', true],
        ['SHA-1', s.sha1, 'font-mono', true],
        ['MD5', s.md5, 'font-mono', true],
        ['File Name', s.file_name, '', false],
        ['File Size', s.file_size ? formatSize(s.file_size) : '—', '', false],
        ['Version', `${s.version_name || '—'} (code ${s.version_code || '—'})`, '', false],
        ['Min SDK', s.min_sdk || '—', '', false],
        ['Target SDK', s.target_sdk || '—', '', false],
        ['Main Activity', s.main_activity, 'font-mono text-body-sm', false],
    ];

    grid.innerHTML = fields.map(([label, value, cls, copyable]) => `
        <div>
            <p class="text-label-caps text-muted" style="margin-bottom: 4px;">${esc(label)}</p>
            <div class="flex items-center gap-2">
                <p class="${cls || ''} break-all" style="font-size: 14px;">${esc(value || '—')}</p>
                ${copyable && value ? `<span class="material-symbols-outlined text-primary" style="cursor:pointer; font-size:16px; flex-shrink:0;" onclick="copyText('${esc(value)}', this)" title="Copy">content_copy</span>` : ''}
            </div>
        </div>
    `).join('');
}

// ─── 2. Verdict Banner ───
function renderVerdict(report) {
    const v = report.verdict || {};
    const so = report.signoff || {};
    const verdictClass = (v.verdict || '').toLowerCase();
    const colors = { benign: 'var(--verdict-benign)', suspicious: 'var(--verdict-suspicious)', malicious: 'var(--verdict-malicious)' };
    const color = colors[verdictClass] || 'var(--color-primary)';
    const icons = { benign: 'check_circle', suspicious: 'warning', malicious: 'dangerous' };

    const card = document.getElementById('verdict-card');
    card.style.borderLeftColor = color;
    card.classList.remove('verdict-glow-benign', 'verdict-glow-suspicious', 'verdict-glow-malicious');
    card.classList.add('verdict-glow-' + verdictClass);

    // Risk gauge
    const score = v.risk_score || 0;
    const circumference = 2 * Math.PI * 58;
    const offset = circumference - (score / 100) * circumference;

    // Sign-off status
    let signoffHtml = '';
    if (so.status === 'not_required') {
        signoffHtml = `<span class="material-symbols-outlined" style="color: var(--verdict-benign); font-size: 18px;">check_circle</span>
            <span class="text-body-sm">Sign-off not required</span>`;
    } else if (so.status === 'pending') {
        signoffHtml = `<span class="material-symbols-outlined" style="color: var(--verdict-suspicious); font-size: 18px;">pending</span>
            <span class="text-body-sm" style="color: var(--verdict-suspicious);">Analyst sign-off pending</span>`;
    } else if (so.signed_by) {
        signoffHtml = `<span class="material-symbols-outlined" style="color: var(--verdict-benign); font-size: 18px;">history_edu</span>
            <span class="text-body-sm">Signed off by ${esc(so.signed_by)}${so.signed_at ? ' · ' + new Date(so.signed_at).toLocaleString() : ''}</span>`;
    }

    document.getElementById('verdict-content').innerHTML = `
        <div style="display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 32px;">
            <div class="flex items-center gap-6">
                <div class="risk-gauge risk-gauge-lg">
                    <svg viewBox="0 0 128 128" width="128" height="128">
                        <circle cx="64" cy="64" r="58" fill="transparent" stroke="var(--color-surface-variant)" stroke-width="8" />
                        <circle cx="64" cy="64" r="58" fill="transparent" stroke="${color}" stroke-width="8"
                            stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" stroke-linecap="round"
                            style="transition: stroke-dashoffset 1s ease;" />
                    </svg>
                    <div style="position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center;">
                        <span class="score-text" style="color: ${color}; font-size: 32px;">${score.toFixed(1)}</span>
                        <span class="text-label-caps text-muted" style="font-size: 10px;">RISK SCORE</span>
                    </div>
                </div>
                <div>
                    <div class="flex items-center gap-2 mb-2">
                        <span class="verdict-badge ${verdictClass}" style="font-size: 16px; padding: 8px 20px;">
                            <span class="material-symbols-outlined" style="font-variation-settings: 'FILL' 1; font-size: 22px;">${icons[verdictClass] || 'help'}</span>
                            ${esc((v.verdict || '').toUpperCase())}
                        </span>
                        <span class="verdict-badge" style="background: var(--color-surface-variant); color: var(--color-on-surface-variant); border: none; font-size: 12px; padding: 4px 12px;">
                            ${esc((v.severity || '').toUpperCase())}
                        </span>
                    </div>
                    <p class="text-muted text-body-sm" style="max-width: 500px;">
                        ${esc(report.summary || v.rationale || '')}
                    </p>
                </div>
            </div>
            <div style="width: 280px; flex-shrink: 0;">
                <div class="mb-4">
                    <div class="flex justify-between text-label-caps" style="margin-bottom: 8px;">
                        <span class="text-muted">Confidence</span>
                        <span class="text-primary">${Math.round((v.confidence || 0) * 100)}%</span>
                    </div>
                    <div class="progress-bar"><div class="progress-bar-fill primary" style="width: ${(v.confidence || 0) * 100}%;"></div></div>
                </div>
                <div class="flex items-center gap-3" style="background: rgba(78,222,163,0.05); padding: 12px; border-radius: var(--radius-lg); border: 1px solid rgba(78,222,163,0.1);">
                    ${signoffHtml}
                </div>
                <div class="text-muted" style="margin-top: 12px; font-size: 12px;">
                    Mode: ${esc(v.operating_mode || 'balanced')} · Generated: ${report.generated_at ? new Date(report.generated_at).toLocaleString() : '—'}
                </div>
            </div>
        </div>
        ${v.rationale && report.summary !== v.rationale ? `
        <details style="margin-top: 16px;">
            <summary class="text-body-sm text-primary" style="cursor: pointer;">Show full rationale</summary>
            <p class="text-body-sm text-muted" style="margin-top: 8px;">${esc(v.rationale)}</p>
        </details>` : ''}
    `;
}

// ─── 3. Evidence Log ───
function renderEvidence(report) {
    const tbody = document.getElementById('evidence-tbody');
    const evidence = report.evidence || [];

    if (!evidence.length) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted" style="padding: 32px;">
            <span class="material-symbols-outlined" style="font-size: 32px; opacity: 0.3; display: block; margin-bottom: 8px;">shield</span>
            No evidence indicators found.
        </td></tr>`;
        return;
    }

    tbody.innerHTML = evidence.map((e, i) => {
        const weightColor = e.weight >= 5 ? 'var(--verdict-malicious)' : e.weight >= 2 ? 'var(--verdict-suspicious)' : 'var(--color-on-surface-variant)';
        return `
        <tr onclick="this.nextElementSibling?.classList.toggle('hidden')">
            <td><span class="category-pill ${(e.category || '').toLowerCase()}">${esc(e.category || '—')}</span></td>
            <td class="text-code-sm">${esc(e.title || '—')}</td>
            <td>${esc(e.layer || '—')}</td>
            <td style="color: ${weightColor}; font-weight: ${e.weight >= 5 ? '700' : '400'};">${e.weight != null ? e.weight.toFixed(1) : '—'}</td>
            <td class="text-muted">${(e.attack_techniques || []).join(', ') || '—'}</td>
        </tr>
        <tr class="hidden">
            <td colspan="5" style="padding: 12px 24px; background: var(--color-surface-container-low);">
                <p class="text-body-sm text-muted">${esc(e.detail || 'No additional details.')}</p>
                ${e.artifact_refs?.length ? `<p class="text-code-sm text-muted" style="margin-top: 8px;">Artifacts: ${e.artifact_refs.map(a => esc(a)).join(', ')}</p>` : ''}
            </td>
        </tr>`;
    }).join('');
}

// ─── 4. MITRE ATT&CK ───
function renderMitre(report) {
    const grid = document.getElementById('mitre-grid');
    const attack = report.attack || [];

    if (!attack.length) {
        grid.innerHTML = `<div class="glass-card p-6 text-center text-muted" style="grid-column: 1 / -1;">
            <span class="material-symbols-outlined" style="font-size: 32px; opacity: 0.3; display: block; margin-bottom: 8px;">shield</span>
            No ATT&CK techniques mapped.
        </div>`;
        return;
    }

    const tacticColors = {
        'Discovery': 'var(--color-primary)',
        'Persistence': 'var(--color-secondary)',
        'Credential Access': 'var(--color-tertiary)',
        'Defense Evasion': 'var(--color-outline)',
        'Collection': 'var(--color-violet)',
        'Command and Control': 'var(--verdict-malicious)',
        'Exfiltration': 'var(--verdict-malicious)',
    };

    grid.innerHTML = attack.map(a => {
        const color = tacticColors[a.tactics?.[0]] || 'var(--color-primary)';
        return `
        <a href="${esc(a.url || '#')}" target="_blank" rel="noopener" class="glass-card" style="padding: 20px; border-top: 2px solid ${color}; text-decoration: none; color: inherit;">
            <div class="flex justify-between items-center mb-3">
                <span class="text-code-sm" style="color: ${color};">${esc(a.id)}</span>
                ${a.tactics?.length ? `<span style="background: rgba(78,222,163,0.1); color: ${color}; font-size: 10px; padding: 2px 8px; border-radius: 4px; font-weight: 700; text-transform: uppercase;">${esc(a.tactics[0])}</span>` : ''}
            </div>
            <h4 style="font-weight: 700; margin-bottom: 8px;">${esc(a.name)}</h4>
            ${a.tactics?.length > 1 ? `<div class="flex gap-2" style="flex-wrap: wrap;">${a.tactics.slice(1).map(t => `<span class="text-muted" style="font-size: 11px;">${esc(t)}</span>`).join('')}</div>` : ''}
        </a>`;
    }).join('');
}

// ─── 5. IOCs ───
function renderIOCs(report) {
    const iocs = report.iocs || {};
    const container = document.getElementById('iocs-content');

    const categories = [
        ['language', 'Domains', iocs.domains],
        ['link', 'URLs', iocs.urls],
        ['router', 'IPs', iocs.ips],
        ['local_fire_department', 'Firebase URLs', iocs.firebase_urls],
        ['mail', 'Emails', iocs.emails],
        ['key', 'Crypto Constants', iocs.crypto_constants],
    ];

    const hasAny = categories.some(([, , items]) => items?.length);

    container.innerHTML = categories.map(([icon, label, items]) => `
        <div>
            <p class="text-label-caps text-muted flex items-center gap-2" style="margin-bottom: 12px;">
                <span class="material-symbols-outlined" style="font-size: 16px;">${icon}</span> ${label}
            </p>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                ${items?.length
                    ? items.map(v => `<span class="ioc-chip" onclick="copyText('${esc(v)}', this)" title="Click to copy">${esc(v)}</span>`).join('')
                    : '<span class="text-body-sm text-muted">None extracted.</span>'
                }
            </div>
        </div>
    `).join('');
}

// ─── 6. GenAI Interpretation ───
function renderGenAI(report) {
    let g = report.genai || {};
    const container = document.getElementById('genai-content');

    // Disclaimer
    let html = `
        <div class="genai-disclaimer mb-4">
            <span class="material-symbols-outlined text-violet" style="margin-top: 2px;">warning</span>
            <div>
                <p style="font-weight: 700; font-size: 14px;">Interpretive Only — Does Not Decide the Verdict</p>
                <p class="text-body-sm text-muted">GenAI content is explanatory. The deterministic rule layer makes all scoring decisions.</p>
            </div>
        </div>
    `;

    if (!g.generated || !g.summary) {
        // Build frontend local fallback interpretation
        const verdict = report.verdict?.verdict || 'Benign';
        const severity = report.verdict?.severity || 'Low';
        const score = report.verdict?.risk_score || 0;
        const evidence = report.evidence || [];
        
        let summary = '';
        let claims = [];
        let recs = [];
        
        if (verdict === 'Malicious') {
            summary = `Deterministic analysis classifies this sample as Malicious (severity ${severity}, risk score ${score.toFixed(1)}/100). The application exhibits high-risk banking trojan patterns, including dangerous permission requests and C2 capabilities.`;
            const perms = evidence.filter(e => e.category === 'permission').map(e => e.title);
            claims.push({
                text: "Requests high-severity permissions commonly abused by banking trojans.",
                artifact_refs: perms.slice(0, 3)
            });
            if (evidence.some(e => (e.detail || '').toLowerCase().includes('c2') || (e.detail || '').toLowerCase().includes('firebase'))) {
                claims.push({
                    text: "Exhibits C2 network indicators targeting remote servers.",
                    artifact_refs: evidence.filter(e => e.category === 'ioc').map(e => e.title).slice(0, 3)
                });
            }
            recs = [
                "Blocklist the sample hash and isolate the binary immediately.",
                "Monitor network traffic for outbound connections to resolved domains."
            ];
        } else if (verdict === 'Suspicious') {
            summary = `Deterministic analysis classifies this sample as Suspicious (severity ${severity}, risk score ${score.toFixed(1)}/100). The application contains overlay advertising mechanisms or broad telemetry collection APIs.`;
            const behaviors = evidence.filter(e => e.category === 'behavior').map(e => e.title);
            claims.push({
                text: "Utilizes background receivers or overlay windows for persistence.",
                artifact_refs: behaviors.slice(0, 2)
            });
            recs = [
                "Route the sample to the dynamic analysis sandbox for behavioral validation.",
                "Verify runtime overlay behaviors and alert permissions."
            ];
        } else {
            summary = `Deterministic analysis classifies this sample as Benign (severity ${severity}, risk score ${score.toFixed(1)}/100). The application contains no indicators of obfuscation, overlay, or high-risk banking trojan behaviors.`;
            const perms = evidence.filter(e => e.category === 'permission').map(e => e.title);
            claims.push({
                text: "Requires standard permissions consistent with legitimate utilities.",
                artifact_refs: perms.slice(0, 3)
            });
            recs = [
                "Archive per default retention policy.",
                "No immediate operational mitigations required."
            ];
        }
        
        g = {
            generated: true,
            model_name: 'apkscan-local-fallback',
            summary: summary,
            claims: claims,
            recommendations: recs,
            grounding_failure_rate: 0.0,
            withheld_claims: [],
            warnings: ["Fallback interpretation generated deterministically from static features."]
        };
    }


    // Model info
    html += `<div class="text-body-sm mb-4">
        <span class="text-label-caps text-muted">Model:</span>
        <span class="text-code-sm">${esc(g.model_name || '—')}</span>
    </div>`;

    // Stats
    html += `<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px;">
        <div style="background: var(--color-surface-variant); opacity: 0.3; border-radius: var(--radius-lg); padding: 16px; text-align: center;">
            <p class="text-headline-md text-violet">${(g.claims || []).length}</p>
            <p class="text-label-caps text-muted" style="font-size: 10px;">Grounded Claims</p>
        </div>
        <div style="background: var(--color-surface-variant); opacity: 0.3; border-radius: var(--radius-lg); padding: 16px; text-align: center;">
            <p class="text-headline-md" style="color: var(--color-secondary);">${(g.withheld_claims || []).length}</p>
            <p class="text-label-caps text-muted" style="font-size: 10px;">Withheld</p>
        </div>
        <div style="background: var(--color-surface-variant); opacity: 0.3; border-radius: var(--radius-lg); padding: 16px; text-align: center;">
            <p class="text-headline-md text-primary">${Math.round((g.grounding_failure_rate || 0) * 100)}%</p>
            <p class="text-label-caps text-muted" style="font-size: 10px;">Grounding Failure</p>
        </div>
    </div>`;

    // Flags
    const flags = [];
    if (g.prompt_injection_detected) flags.push('⚠️ Prompt injection text detected in sample (isolated as data)');
    if (g.truncated) flags.push('⚠️ Input truncated/partial');
    if (flags.length) {
        html += `<div style="background: var(--verdict-malicious-bg); border: 1px solid rgba(239,68,68,0.2); border-radius: var(--radius-lg); padding: 12px; margin-bottom: 16px;">
            ${flags.map(f => `<p class="text-body-sm">${esc(f)}</p>`).join('')}
        </div>`;
    }

    // Claims
    if (g.claims?.length) {
        html += `<div class="flex flex-col gap-2">`;
        g.claims.forEach(c => {
            html += `<div class="glass-card p-4">
                <p class="text-body-sm">${esc(c.text || '')}</p>
                ${c.artifact_refs?.length ? `<p class="text-code-sm text-muted" style="margin-top: 4px;">Refs: ${c.artifact_refs.join(', ')}</p>` : ''}
            </div>`;
        });
        html += `</div>`;
    }

    // Summary
    if (g.summary) {
        html += `<p class="text-body-sm text-muted" style="margin-top: 16px;"><strong>Summary:</strong> ${esc(g.summary)}</p>`;
    }

    // Warnings
    if (g.warnings?.length) {
        html += `<p class="text-code-sm text-muted" style="margin-top: 8px;">Warnings: ${g.warnings.map(w => esc(w)).join('; ')}</p>`;
    }

    container.innerHTML = html;
}

// ─── 7. Recommendations ───
function renderRecommendations(report) {
    const recs = report.recommendations || [];
    const container = document.getElementById('recommendations-content');

    if (!recs.length) {
        container.innerHTML = '<p class="text-body-sm text-muted">No recommendations.</p>';
        return;
    }

    container.innerHTML = recs.map(r => {
        let icon = 'info';
        let iconColor = 'var(--color-primary)';
        if (r.startsWith('[GenAI suggestion]')) {
            icon = 'auto_awesome';
            iconColor = 'var(--color-violet)';
        } else if (r.startsWith('[Dynamic]')) {
            icon = 'deployed_code';
            iconColor = 'var(--color-secondary)';
        } else if (r.toLowerCase().includes('warn') || r.toLowerCase().includes('unavailable')) {
            icon = 'warning';
            iconColor = 'var(--color-secondary)';
        } else if (r.toLowerCase().includes('malicious') || r.toLowerCase().includes('block')) {
            icon = 'gpp_bad';
            iconColor = 'var(--verdict-malicious)';
        }

        return `
        <div class="glass-card flex items-start gap-4 p-4">
            <span class="material-symbols-outlined" style="color: ${iconColor}; margin-top: 2px; flex-shrink: 0;">${icon}</span>
            <p class="text-body-sm">${esc(r)}</p>
        </div>`;
    }).join('');
}

// ─── 8. Analysis Caveats ───
function renderCaveats(report) {
    const gaps = report.analysis_gaps || [];
    const esc_flag = report.escalation || {};
    const container = document.getElementById('caveats-content');

    if (!gaps.length && !esc_flag.escalate) {
        container.innerHTML = '<div class="glass-card p-6 text-center text-muted">No analysis caveats.</div>';
        return;
    }

    let html = '';

    if (esc_flag.escalate) {
        html += `<div class="glass-card p-4 mb-4" style="border-left: 4px solid var(--verdict-malicious);">
            <p class="text-body-sm"><strong>Escalation flagged:</strong> ${(esc_flag.reasons || []).map(r => esc(r)).join('; ')}</p>
        </div>`;
    }

    if (gaps.length) {
        html += `<div class="glass-card p-6">
            <div class="flex flex-col gap-3">
                ${gaps.map(g => `
                    <div class="flex items-center gap-3" style="padding: 12px; background: rgba(255,185,95,0.05); border-radius: var(--radius-lg); border: 1px solid rgba(255,185,95,0.1);">
                        <span style="background: ${g.severity === 'error' ? 'var(--verdict-malicious-bg)' : 'var(--verdict-suspicious-bg)'}; color: ${g.severity === 'error' ? 'var(--verdict-malicious)' : 'var(--verdict-suspicious)'}; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase;">${esc(g.severity)}</span>
                        <span class="text-code-sm">${esc(g.tool)}</span>
                        <span class="text-body-sm text-muted">— ${esc(g.reason)}</span>
                    </div>
                `).join('')}
            </div>
        </div>`;
    }

    container.innerHTML = html;
}

// ─── FABs ───
function initFABs() {
    document.getElementById('fab-pdf')?.addEventListener('click', async () => {
        const btn = document.getElementById('fab-pdf');
        btn.innerHTML = '<span class="spinner" style="width:18px;height:18px;border-width:2px;"></span> Generating...';
        try {
            await API.downloadPdf(currentReportId);
            showToast('PDF downloaded successfully!');
        } catch (err) {
            showToast('PDF not available: ' + err.message, 'error');
        }
        btn.innerHTML = '<span class="material-symbols-outlined">picture_as_pdf</span> Download PDF';
    });

    document.getElementById('nav-pdf-btn')?.addEventListener('click', () => {
        document.getElementById('fab-pdf')?.click();
    });

    document.getElementById('fab-stix')?.addEventListener('click', async () => {
        try {
            await API.exportStix(currentReportId);
            showToast('STIX bundle exported!');
        } catch (err) {
            showToast('Export failed: ' + err.message, 'error');
        }
    });

    document.getElementById('fab-share')?.addEventListener('click', () => {
        copyText(window.location.href);
        showToast('Report link copied to clipboard!');
    });
}

// ─── Scrollspy ───
function initScrollspy() {
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('[data-section]');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                navLinks.forEach(l => l.classList.remove('active'));
                navLinks.forEach(l => {
                    if (l.getAttribute('data-section') === entry.target.id) {
                        l.classList.add('active');
                    }
                });
            }
        });
    }, { rootMargin: '-100px 0px -60% 0px' });

    sections.forEach(s => observer.observe(s));
}

// ─── Accordion ───
function toggleAccordion(header) {
    const section = header.closest('.accordion-section');
    if (section) section.classList.toggle('open');
}

// ─── Utilities ───
function copyText(text, iconEl) {
    navigator.clipboard.writeText(text).then(() => {
        if (iconEl) {
            const original = iconEl.textContent;
            iconEl.textContent = 'check';
            iconEl.style.color = 'var(--verdict-benign)';
            setTimeout(() => {
                iconEl.textContent = original;
                iconEl.style.color = '';
            }, 1500);
        }
        showToast('Copied to clipboard!');
    }).catch(() => {
        showToast('Copy failed', 'error');
    });
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    toast.textContent = message;
    toast.style.borderColor = type === 'error' ? 'var(--color-error)' : 'rgba(78,222,163,0.3)';
    toast.classList.add('visible');
    setTimeout(() => toast.classList.remove('visible'), 3000);
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function esc(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
}
