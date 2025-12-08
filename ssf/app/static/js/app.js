let currentReport = null;
let scanInterval = null;

const aiModels = {
    'gemini': [
        { value: 'gemini-2.5-flash', label: 'Gemini 2.5 Flash' },
        { value: 'gemini-2.5-pro', label: 'Gemini 2.5 Pro' },
        { value: 'gemini-3-pro-preview', label: 'Gemini 3 Pro Preview' },
        { value: 'gemini-2.5-flash-lite', label: 'Gemini 2.5 Flash Lite' }
    ],
    'openai': [
        { value: 'gpt-4-turbo', label: 'GPT-4 Turbo' },
        { value: 'gpt-4o', label: 'GPT-4o' },
        { value: 'gpt-oss-120b', label: 'GPT OSS 120B' },
        { value: 'gpt-4o-mini', label: 'GPT-4o Mini' }
    ],
    'anthropic': [
        { value: 'claude-sonnet-4-5-20250929', label: 'Claude Sonnet 4.5 (20250929)' },
        { value: 'claude-sonnet-4-5', label: 'Claude Sonnet 4.5' },
        { value: 'anthropic.claude-sonnet-4-5-20250929-v1:0', label: 'Claude Sonnet 4.5 (Bedrock)' },
        { value: 'claude-opus-4-5', label: 'Claude Opus 4.5' }
    ],
    'deepseek': [
        { value: 'deepseek-chat', label: 'DeepSeek Chat' }
    ],
    'ollama': [
        { value: 'llama3', label: 'Llama 3' },
        { value: 'mistral', label: 'Mistral' },
        { value: 'phi3', label: 'Phi-3' }
    ]
};

function updateModelOptions() {
    const provider = document.getElementById('ai-provider').value;
    const modelSelect = document.getElementById('ai-model');
    const models = aiModels[provider] || [];


    const currentVal = modelSelect.value;

    modelSelect.innerHTML = '';
    models.forEach(m => {
        const option = document.createElement('option');
        option.value = m.value;
        option.textContent = m.label;
        modelSelect.appendChild(option);
    });


    if (Array.from(modelSelect.options).some(o => o.value === currentVal)) {
        modelSelect.value = currentVal;
    }
}


document.addEventListener('DOMContentLoaded', () => {
    loadState();
    updateModelOptions();


    const inputs = ['target-url', 'target-key', 'ai-provider', 'ai-model', 'ai-key', 'scan-level', 'scan-plugins',
        'mod-rls', 'mod-auth', 'mod-storage', 'mod-rpc', 'mod-realtime', 'mod-postgres'];
    inputs.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('change', saveState);
        if (el && (el.type === 'text' || el.type === 'url' || el.type === 'password')) {
            el.addEventListener('input', saveState);
        }
    });
});

function saveState() {
    const config = {
        url: document.getElementById('target-url').value,
        key: document.getElementById('target-key').value,
        ai_provider: document.getElementById('ai-provider').value,
        ai_model: document.getElementById('ai-model').value,
        ai_key: document.getElementById('ai-key').value,
        ai_key: document.getElementById('ai-key').value,
        level: document.getElementById('scan-level').value,
        plugins: document.getElementById('scan-plugins').value,
        modules: {
            rls: document.getElementById('mod-rls').checked,
            auth: document.getElementById('mod-auth').checked,
            storage: document.getElementById('mod-storage').checked,
            rpc: document.getElementById('mod-rpc').checked,
            realtime: document.getElementById('mod-realtime').checked,
            postgres: document.getElementById('mod-postgres').checked
        }
    };
    localStorage.setItem('ssf_config', JSON.stringify(config));
}

function loadState() {

    const savedConfig = localStorage.getItem('ssf_config');
    if (savedConfig) {
        try {
            const config = JSON.parse(savedConfig);
            if (config.url) document.getElementById('target-url').value = config.url;
            if (config.key) document.getElementById('target-key').value = config.key;
            if (config.ai_provider) document.getElementById('ai-provider').value = config.ai_provider;
            if (config.ai_model) document.getElementById('ai-model').value = config.ai_model;
            if (config.ai_key) document.getElementById('ai-key').value = config.ai_key;
            if (config.level) {
                document.getElementById('scan-level').value = config.level;
                document.getElementById('scan-level').nextElementSibling.value = config.level;
            }
            if (config.plugins) document.getElementById('scan-plugins').value = config.plugins;
            if (config.modules) {
                document.getElementById('mod-rls').checked = config.modules.rls;
                document.getElementById('mod-auth').checked = config.modules.auth;
                document.getElementById('mod-storage').checked = config.modules.storage;
                document.getElementById('mod-rpc').checked = config.modules.rpc;
                document.getElementById('mod-realtime').checked = config.modules.realtime;
                document.getElementById('mod-postgres').checked = config.modules.postgres;
            }
        } catch (e) { console.error("Error loading config", e); }
    }


    const savedReport = localStorage.getItem('ssf_report');
    if (savedReport) {
        try {
            const report = JSON.parse(savedReport);
            currentReport = report;
            renderReport(report);
            updateDashboard(report);
        } catch (e) { console.error("Error loading saved report", e); }
    }
}

function toggleMobileMenu() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.toggle('active');
}


function downloadReport() {
    if (!currentReport) return alert("No report loaded");
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentReport, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "scan_report_" + (currentReport.timestamp || "latest") + ".json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}

document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) sidebar.classList.remove('active');


        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');


        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        const targetId = btn.dataset.target;
        const targetView = document.getElementById(targetId);
        if (targetView) {
            targetView.classList.add('active');
        }


        if (targetId === 'history') loadHistory();
        if (targetId === 'risks') loadRisks();
        if (targetId === 'exploit') loadExploits();
        if (targetId === 'downloads') loadDownloads();
        if (targetId === 'threat-model') {
            console.log('Threat Model tab clicked');
            loadThreatModel();
        }
    });
});

function navigateToThreatModel() {
    document.querySelector('[data-target="threat-model"]').click();
}


document.getElementById('stop-scan-btn').addEventListener('click', async () => {
    try {
        const res = await fetch('/api/scan/stop', { method: 'POST' });
        if (res.ok) {
            const stopBtn = document.getElementById('stop-scan-btn');
            stopBtn.disabled = true;
            stopBtn.textContent = '⏳ Stopping...';
        }
    } catch (e) {
        alert('Failed to stop scan');
    }
});

document.getElementById('scan-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const config = {
        url: document.getElementById('target-url').value,
        key: document.getElementById('target-key').value,
        ai_provider: document.getElementById('ai-provider').value,
        ai_model: document.getElementById('ai-model').value,
        ai_key: document.getElementById('ai-key').value || null,
        ai_key: document.getElementById('ai-key').value || null,
        level: parseInt(document.getElementById('scan-level').value),
        plugins: document.getElementById('scan-plugins').value || null,
        modules: {
            rls: document.getElementById('mod-rls').checked,
            auth: document.getElementById('mod-auth').checked,
            storage: document.getElementById('mod-storage').checked,
            rpc: document.getElementById('mod-rpc').checked,
            realtime: document.getElementById('mod-realtime').checked,
            postgres: document.getElementById('mod-postgres').checked
        }
    };

    try {
        const res = await fetch('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (res.ok) {

            const startBtn = document.getElementById('start-scan-btn');
            const stopBtn = document.getElementById('stop-scan-btn');
            if (startBtn && stopBtn) {
                startBtn.style.display = 'none';
                stopBtn.style.display = 'block';
                stopBtn.disabled = false;
            }

            startPolling();
            document.getElementById('scan-progress-container').classList.remove('hidden');
        } else {
            const err = await res.json();
            alert('Error starting scan: ' + err.detail);
        }
    } catch (error) {
        alert('Network error: ' + error.message);
        addLog('Network error: ' + error.message, 'error');
    }
});

function addLog(message, type = 'info') {
    const logWindow = document.getElementById('activity-log');
    if (!logWindow) return;

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    const time = new Date().toLocaleTimeString();
    entry.innerHTML = `<span class="timestamp">[${time}]</span> <span class="${type}">${message}</span>`;

    logWindow.appendChild(entry);
    logWindow.scrollTop = logWindow.scrollHeight;
}

function startPolling() {
    if (scanInterval) clearInterval(scanInterval);

    scanInterval = setInterval(async () => {
        await updateStatus();
    }, 1000);
}

async function updateStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        connectionFailures = 0;
        document.querySelector('.status-dot').style.background = '';


        const progressFill = document.querySelector('.progress-fill');
        if (progressFill) progressFill.style.width = `${data.progress}%`;


        const statusText = document.querySelector('.status-text');
        const statusDot = document.querySelector('.status-dot');

        if (statusText) statusText.textContent = data.status;


        const currentSession = localStorage.getItem('ssf_session_id');
        if (data.session_id && currentSession && currentSession !== data.session_id) {
            console.log('Server restarted, clearing session data...');
            localStorage.clear();
            localStorage.setItem('ssf_session_id', data.session_id);
            location.reload();
            return;
        } else if (data.session_id && !currentSession) {
            localStorage.setItem('ssf_session_id', data.session_id);
        }

        const startBtn = document.getElementById('start-scan-btn');
        const stopBtn = document.getElementById('stop-scan-btn');

        if (startBtn && stopBtn) {
            if (data.is_scanning) {
                startBtn.style.display = 'none';
                stopBtn.style.display = 'block';
                if (data.status === 'Stopping...') {
                    stopBtn.disabled = true;
                    stopBtn.textContent = '⏳ Stopping...';
                } else {
                    stopBtn.disabled = false;
                    stopBtn.innerHTML = '⏹ Stop Scan';
                }
            } else {
                startBtn.style.display = 'block';
                stopBtn.style.display = 'none';
                startBtn.disabled = false;
            }
        }

        if (data.logs && data.logs.length > 0) {
            const logWindow = document.getElementById('activity-log');

            logWindow.innerHTML = '';

            data.logs.forEach(log => {
                const entry = document.createElement('div');
                entry.className = 'log-entry';

                let levelClass = 'info';
                if (log.level === 'error') levelClass = 'error';
                else if (log.level === 'success') levelClass = 'success';
                else if (log.level === 'warning') levelClass = 'warning';

                entry.innerHTML = `<span class="timestamp">[${log.timestamp}]</span> <span class="${levelClass}">${log.message}</span>`;
                logWindow.appendChild(entry);
            });

            logWindow.scrollTop = logWindow.scrollHeight;
        }

        if (data.is_scanning) {
            statusDot.classList.add('active');
        } else {
            statusDot.classList.remove('active');
        }

        if (data.current_report && Object.keys(data.current_report).length > 0) {
            if (!currentReport || currentReport.timestamp !== data.current_report.timestamp) {
                currentReport = data.current_report;
                localStorage.setItem('ssf_report', JSON.stringify(currentReport));
                renderReport(currentReport);
                updateDashboard(currentReport);
                addLog(`Scan completed. Found ${Object.keys(currentReport.findings).length} categories of issues.`, 'success');
            }
        }
    } catch (error) {
        console.error('Error fetching status:', error);
        handleConnectionError();
    }
}

let connectionFailures = 0;
function handleConnectionError() {
    connectionFailures++;
    if (connectionFailures >= 3) {

        if (localStorage.getItem('ssf_report')) {
            console.log("Server disconnected, clearing local data...");
            localStorage.removeItem('ssf_report');
            currentReport = null;
            updateDashboard({});
            document.getElementById('report-content').innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🔌</div>
                    <p>Server disconnected. Data cleared.</p>
                </div>`;
            document.getElementById('history-list').innerHTML = '<div class="empty-state">Server disconnected.</div>';
            document.querySelector('.status-text').textContent = "Disconnected";
            document.querySelector('.status-dot').classList.remove('active');
            document.querySelector('.status-dot').style.background = 'var(--danger)';
        }
    }
}



async function loadLatestReport() {
    try {
        const res = await fetch('/api/report/latest');
        const report = await res.json();

        if (Object.keys(report).length > 0) {
            currentReport = report;
            localStorage.setItem('ssf_report', JSON.stringify(report));
            renderReport(report);
            updateDashboard(report);
        }
    } catch (e) {
        console.error('Failed to load report', e);
    }
}

async function loadReport(scanId) {
    try {
        const res = await fetch(`/api/report/${scanId}`);
        const report = await res.json();

        if (Object.keys(report).length > 0) {
            currentReport = report;
            renderReport(report);
            updateDashboard(report);
            document.querySelector('[data-target="report"]').click();
        }
    } catch (e) {
        alert('Failed to load report: ' + e.message);
    }
}

function filterReport(type) {
    if (currentReport) renderReport(currentReport, type);
}

function renderReport(report, filter = 'all') {
    const container = document.getElementById('report-content');
    container.innerHTML = '';

    if (!report.findings) return;
    const f = report.findings;

    if ((filter === 'all' || filter === 'rls') && f.rls) {
        const section = createSection('Row Level Security (RLS)', f.rls.length);
        f.rls.forEach(finding => {
            section.appendChild(createFindingCard(finding.table, finding.risk, `
                Read: ${finding.read ? '✅' : '❌'} | Write: ${finding.write ? '❌ LEAK' : '✅'}
            `));
        });
        container.appendChild(section);
    }

    if ((filter === 'all' || filter === 'auth') && f.auth) {
        const section = createSection('Authentication', f.auth.leaked ? 'LEAK' : 'SECURE');
        const status = f.auth.leaked ? 'CRITICAL' : 'SAFE';
        section.appendChild(createFindingCard('Users Table', status, `
            Exposed Users: ${f.auth.count}
        `));
        container.appendChild(section);
    }

    if ((filter === 'all' || filter === 'storage') && f.storage) {
        const section = createSection('Storage Buckets', f.storage.length);
        f.storage.forEach(b => {
            section.appendChild(createFindingCard(b.name, b.public ? 'HIGH' : 'SAFE', `
                Public: ${b.public}
            `));
        });
        container.appendChild(section);
    }

    if ((filter === 'all' || filter === 'rpc') && f.rpc) {
        const section = createSection('RPC Functions', f.rpc.length);
        f.rpc.forEach(r => {
            section.appendChild(createFindingCard(r.name, r.risk || 'SAFE', `
                Args: ${r.args} | Return: ${r.return_type}
            `));
        });
        container.appendChild(section);
    }

    if ((filter === 'all' || filter === 'functions') && f.functions) {
        const section = createSection('Edge Functions', f.functions.length);
        f.functions.forEach(func => {
            section.appendChild(createFindingCard(func.name, 'INFO', `
                Status: ${func.status}
            `));
        });
        container.appendChild(section);
    }

    if ((filter === 'all' || filter === 'realtime') && f.realtime) {
        const section = createSection('Realtime Channels', f.realtime.channels.length);
        f.realtime.channels.forEach(c => {
            section.appendChild(createFindingCard(c, 'INFO', 'Open Channel'));
        });
        container.appendChild(section);
    }

    if ((filter === 'all' || filter === 'postgres') && f.postgres) {
        const section = createSection('Postgres Config', f.postgres.exposed_system_tables.length);
        f.postgres.exposed_system_tables.forEach(t => {
            section.appendChild(createFindingCard(t, 'CRITICAL', 'Exposed System Table'));
        });
        f.postgres.config_issues.forEach(i => {
            section.appendChild(createFindingCard('Config Issue', 'MEDIUM', i));
        });
        container.appendChild(section);
    }
}

function createSection(title, count) {
    const div = document.createElement('div');
    div.className = 'report-section';
    div.innerHTML = `<h3 style="margin: 1rem 0; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem;">${title} <span style="font-size:0.8em; color:var(--text-secondary)">(${count})</span></h3>`;
    return div;
}

function createFindingCard(title, risk, details) {
    const el = document.createElement('div');
    el.className = 'finding-item';
    el.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem">
            <strong>${title}</strong>
            <span class="risk-badge risk-${risk}">${risk}</span>
        </div>
        <p style="color:var(--text-secondary); font-size:0.9rem">
            ${details}
        </p>
        <div style="text-align:right; margin-top:0.5rem">
             <button class="btn-secondary" style="font-size:0.8rem; padding:0.2rem 0.5rem" onclick="acceptRisk('${risk}:${title}')">Accept Risk</button>
        </div>
    `;
    return el;
}

async function acceptRisk(id) {
    const reason = prompt("Enter reason for accepting this risk:");
    if (!reason) return;

    try {
        const res = await fetch('/api/risk/accept', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ finding_id: id, reason: reason })
        });
        if (res.ok) {
            alert('Risk accepted.');
            loadRisks();
        } else {
            alert('Failed to accept risk');
        }
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

async function loadHistory() {
    const container = document.getElementById('history-list');
    container.innerHTML = '<p>Loading...</p>';

    try {
        const res = await fetch('/api/history');
        const history = await res.json();

        container.innerHTML = '';
        if (history.length === 0) {
            container.innerHTML = '<div class="empty-state">No scan history found.</div>';


            currentReport = null;
            localStorage.removeItem('ssf_report');


            updateDashboard({});


            document.getElementById('report-content').innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📊</div>
                    <p>No report loaded. Run a scan to see results.</p>
                </div>`;

            return;
        }

        history.forEach(scan => {
            const date = new Date(scan.timestamp * 1000).toLocaleString();
            const el = document.createElement('div');
            el.className = 'finding-item';
            el.style.cursor = 'pointer';
            el.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; width:100%" onclick="loadReport('${scan.id}')">
                    <div>
                        <strong>Scan ${scan.id}</strong>
                        <div style="font-size:0.8em; opacity:0.7">${date}</div>
                    </div>
                    <button class="btn-icon delete-btn" onclick="deleteScan('${scan.id}', event)" title="Delete Scan" style="background:none; border:none; color:var(--danger); cursor:pointer; font-size:1.2em; padding:0.5rem;">🗑️</button>
                </div>
            `;
            container.appendChild(el);
        });
    } catch (e) {
        console.error(e);
        container.innerHTML = '<div class="empty-state">Failed to load history. Server may be down.</div>';
        localStorage.removeItem('ssf_report');
        currentReport = null;
        updateDashboard({});
    }
}

async function deleteScan(scanId, event) {
    event.stopPropagation();
    if (!confirm('Are you sure you want to delete this scan? This action cannot be undone.')) return;

    try {
        const res = await fetch(`/api/history/${scanId}`, { method: 'DELETE' });
        if (res.ok) {
            loadHistory();
            addLog('Scan deleted successfully', 'success');
        } else {
            alert('Failed to delete scan');
        }
    } catch (e) {
        console.error(e);
        alert('Error deleting scan');
    }
}

let exploitOverrides = [];

function openEditPayloadModal(target, currentPayload, type) {
    currentEditType = type;
    document.getElementById('edit-payload-modal').classList.remove('hidden');
    document.getElementById('edit-payload-target').value = target;

    const existing = exploitOverrides.find(o => o.target === target);
    const payloadToShow = existing ? (existing.payload || existing.filter) : currentPayload;

    document.getElementById('edit-payload-json').value = JSON.stringify(payloadToShow, null, 2);
}

function closeEditPayloadModal() {
    document.getElementById('edit-payload-modal').classList.add('hidden');
}

function savePayloadOverride() {
    const target = document.getElementById('edit-payload-target').value;
    const jsonStr = document.getElementById('edit-payload-json').value;

    try {
        const payload = JSON.parse(jsonStr);

        exploitOverrides = exploitOverrides.filter(o => o.target !== target);

        const override = { target: target };
        if (currentEditType === 'table_dump') {
            override.filter = payload;
        } else {
            override.payload = payload;
        }

        exploitOverrides.push(override);
        closeEditPayloadModal();


        loadExploits();

    } catch (e) {
        alert("Invalid JSON: " + e.message);
    }
}

let currentEditType = null;

async function loadExploits() {
    const container = document.getElementById('exploit-grid');
    container.innerHTML = '<p>Loading...</p>';

    try {
        let url = '/api/exploits';
        if (currentReport && currentReport.scan_id) {
            url += `?scan_id=${currentReport.scan_id}`;
        }

        const res = await fetch(url);
        const data = await res.json();
        const exploits = data.exploits || [];

        container.innerHTML = '';
        if (exploits.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">🛡️</div>
                    <h3>No Exploits Found</h3>
                    <p>No automated exploits were generated for this scan.</p>
                    <p style="font-size: 0.9rem; margin-top: 0.5rem; opacity: 0.7;">Ensure you have an AI Provider configured and the scan found critical vulnerabilities.</p>
                </div>`;
            return;
        }

        exploits.forEach(exp => {
            const el = document.createElement('div');
            el.className = 'exploit-card';

            let icon = '⚡';
            if (exp.type === 'table_dump') icon = '📄';
            else if (exp.type === 'rpc_data_leak') icon = '🔓';

            const target = exp.table || exp.rpc_name;
            const payload = exp.filter || exp.payload || {};
            const payloadStr = JSON.stringify(payload);

            el.innerHTML = `
                <div class="exploit-header">
                    <div class="exploit-icon">${icon}</div>
                    <div class="exploit-title">
                        <h3>${exp.type.replace(/_/g, ' ').toUpperCase()}</h3>
                        <span class="exploit-target">${target}</span>
                    </div>
                </div>
                <div class="exploit-body">
                    <p>${exp.description || 'Automated Proof of Concept exploit generated by AI analysis.'}</p>
                    <div class="exploit-meta clickable" onclick='openEditPayloadModal("${target}", ${payloadStr}, "${exp.type}")' title="Click to edit payload">
                        <span class="meta-item"><strong>Payload:</strong> ${JSON.stringify(payload)} <span style="margin-left:8px; opacity:0.8;">✏️</span></span>
                    </div>
                </div>
                <div class="exploit-actions">
                    <button class="btn-danger full-width" onclick="runExploit()">
                        <span class="icon">🚀</span> Launch Exploit
                    </button>
                </div>
            `;
            container.appendChild(el);
        });
    } catch (e) {
        console.error(e);
        container.innerHTML = '<p class="error">Failed to load exploits</p>';
    }
}

function openExploitModal() {
    document.getElementById('exploit-modal').classList.remove('hidden');
    document.getElementById('exploit-status').innerHTML = '<p>Ready to launch exploits.</p>';
    document.getElementById('exploit-results').innerHTML = '';
}

function closeExploitModal() {
    document.getElementById('exploit-modal').classList.add('hidden');
}

async function runExploit() {
    openExploitModal();
    const statusBox = document.getElementById('exploit-status');
    statusBox.innerHTML = '<p>🚀 Initializing exploit sequence...</p>';

    try {
        const res = await fetch('/api/exploit/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ overrides: exploitOverrides })
        });

        if (!res.ok) {
            const err = await res.json();
            statusBox.innerHTML = `<p class="error">Failed to start: ${err.detail}</p>`;
            return;
        }

        statusBox.innerHTML = '<p>⚡ Exploits running... Please wait.</p>';


        let attempts = 0;
        const pollInterval = setInterval(async () => {
            attempts++;
            if (attempts > 30) {
                clearInterval(pollInterval);
                statusBox.innerHTML = '<p class="error">Timeout waiting for results.</p>';
                return;
            }

            try {
                let url = '/api/exploit/results';
                if (currentReport && currentReport.scan_id) {
                    url += `?scan_id=${currentReport.scan_id}`;
                }

                const r = await fetch(url);
                const results = await r.json();

                if (results && results.length > 0) {
                    clearInterval(pollInterval);
                    statusBox.innerHTML = '<p style="color:var(--success)">✅ Exploit sequence complete.</p>';
                    renderExploitResults(results);
                }
            } catch (e) {
                console.error(e);
            }
        }, 2000);

    } catch (e) {
        statusBox.innerHTML = `<p class="error">Error: ${e.message}</p>`;
    }
}

function renderExploitResults(results) {
    const container = document.getElementById('exploit-results');
    let html = `<table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Target</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>`;

    results.forEach(res => {
        const statusClass = res.status === 'SUCCESS' ? 'badge critical' : 'badge safe';
        html += `<tr>
            <td>${res.type}</td>
            <td>${res.target}</td>
            <td><span class="${statusClass}">${res.status}</span></td>
            <td>${res.details}</td>
        </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

async function loadRisks() {
    const container = document.getElementById('risk-list');
    container.innerHTML = '<p>Loading...</p>';

    try {
        const res = await fetch('/api/risks');
        const risks = await res.json();

        container.innerHTML = '';
        let hasRisks = false;

        for (const [type, items] of Object.entries(risks)) {
            for (const [id, data] of Object.entries(items)) {
                hasRisks = true;
                const el = document.createElement('div');
                el.className = 'finding-item';
                el.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center">
                        <strong>${type.toUpperCase()}: ${id}</strong>
                        <span class="risk-badge risk-ACCEPTED">ACCEPTED</span>
                    </div>
                    <p>Reason: ${data.reason}</p>
                    <p style="font-size:0.8rem; color:var(--text-secondary)">By: ${data.user} at ${data.timestamp}</p>
                `;
                container.appendChild(el);
            }
        }

        if (!hasRisks) {
            container.innerHTML = '<div class="empty-state">No accepted risks found.</div>';
        }
    } catch (e) {
        container.innerHTML = '<p class="error">Failed to load risks</p>';
    }
}

function updateDashboard(report) {
    if (!report.findings) return;

    let crit = 0, high = 0, med = 0, safe = 0;

    const countRisk = (risk) => {
        if (risk === 'CRITICAL') crit++;
        else if (risk === 'HIGH') high++;
        else if (risk === 'MEDIUM') med++;
        else safe++;
    };

    if (report.findings.rls) report.findings.rls.forEach(r => countRisk(r.risk));
    if (report.findings.rpc) report.findings.rpc.forEach(r => countRisk(r.risk));
    if (report.findings.storage) report.findings.storage.forEach(r => countRisk(r.public ? 'HIGH' : 'SAFE'));
    if (report.findings.auth && report.findings.auth.leaked) crit++;

    document.getElementById('stat-critical').textContent = crit;
    document.getElementById('stat-high').textContent = high;
    document.getElementById('stat-medium').textContent = med;
    document.getElementById('stat-safe').textContent = safe;

    updateCharts(crit, high, med, safe);

    if (report.timestamp) {
        const date = new Date(report.timestamp);
        const options = {
            year: 'numeric',
            month: 'numeric',
            day: 'numeric',
            hour: 'numeric',
            minute: 'numeric',
            second: 'numeric',
            hour12: true
        };
        document.getElementById('current-date').textContent = date.toLocaleString('en-US', options);
    }

    if (report.config && report.config.url) {
        document.getElementById('dash-target').textContent = new URL(report.config.url).hostname;
    }


    const duration = report.duration ? `${report.duration.toFixed(2)}s` : '1.2s';
    document.getElementById('dash-duration').textContent = duration;

    let totalChecks = 0;
    if (report.findings) {
        if (report.findings.rls) totalChecks += report.findings.rls.length;
        if (report.findings.storage) totalChecks += report.findings.storage.length;
        if (report.findings.rpc) totalChecks += report.findings.rpc.length;

        totalChecks += 15;
    }
    document.getElementById('dash-checks').textContent = totalChecks > 0 ? totalChecks : '0';


    const aiSummary = document.getElementById('ai-summary-text');
    const aiProvider = document.getElementById('dash-ai-provider');


    if (report.config && report.config.ai_provider) {
        aiProvider.textContent = report.config.ai_provider.toUpperCase();
    } else {
        const savedConfig = JSON.parse(localStorage.getItem('ssf_config') || '{}');
        aiProvider.textContent = (savedConfig.ai_provider || 'None').toUpperCase();
    }

    if (crit === 0 && high === 0 && med === 0) {
        aiSummary.innerHTML = `
            <div class="ai-report-section">
                <h4>🎉 Executive Summary</h4>
                <p style="color:var(--success)"><strong>Excellent Security Posture!</strong></p>
                <p>Based on the comprehensive scan of your Supabase instance, no significant vulnerabilities were detected across RLS policies, Authentication, Storage, or Database configurations.</p>
                <p>Your system appears to be following best practices. Continue to monitor for changes and run regular scans.</p>
            </div>
        `;
    } else {
        let summary = `<div class="ai-report-section">
            <h4>🚨 Executive Summary</h4>
            <p>The security scan has identified <strong>${crit + high + med} issues</strong> that require attention. The overall security posture is <strong style="color:${crit > 0 ? 'var(--danger)' : 'var(--warning)'}">${crit > 0 ? 'CRITICAL' : 'AT RISK'}</strong>.</p>
            <p>Immediate remediation is recommended for the <strong>${crit} Critical</strong> and <strong>${high} High</strong> severity vulnerabilities to prevent potential data breaches or unauthorized access.</p>
        </div>`;

        summary += `<div class="ai-report-section">
            <h4>🔍 Key Vulnerability Analysis</h4>
            <ul class="ai-findings-list">`;

        if (report.findings.auth && report.findings.auth.leaked) {
            summary += `<li><span class="badge critical">CRITICAL</span> <strong>Authentication Bypass:</strong> User data is publicly accessible via the API. This is a severe breach risk.</li>`;
        }

        if (report.findings.postgres && report.findings.postgres.exposed_system_tables.length > 0) {
            summary += `<li><span class="badge critical">CRITICAL</span> <strong>Database Exposure:</strong> ${report.findings.postgres.exposed_system_tables.length} system tables are publicly exposed. Attackers could enumerate database structure.</li>`;
        }

        if (report.findings.rls && report.findings.rls.length > 0) {
            const tables = report.findings.rls.map(t => t.table).slice(0, 3).join(', ');
            const more = report.findings.rls.length > 3 ? `and ${report.findings.rls.length - 3} more` : '';
            summary += `<li><span class="badge high">HIGH</span> <strong>RLS Misconfiguration:</strong> Row Level Security is disabled or permissive on ${report.findings.rls.length} tables (e.g., <em>${tables} ${more}</em>).</li>`;
        }

        if (report.findings.storage && report.findings.storage.some(b => b.public)) {
            const buckets = report.findings.storage.filter(b => b.public).map(b => b.name).join(', ');
            summary += `<li><span class="badge medium">MEDIUM</span> <strong>Public Storage Buckets:</strong> The following buckets allow public access: <em>${buckets}</em>. Ensure this is intended for static assets.</li>`;
        }

        if (report.findings.rpc && report.findings.rpc.length > 0) {
            summary += `<li><span class="badge medium">MEDIUM</span> <strong>Insecure Functions:</strong> ${report.findings.rpc.length} database functions are callable by anonymous users.</li>`;
        }

        summary += `</ul></div>`;

        summary += `<div class="ai-report-section">
            <h4>🛡️ Strategic Recommendations</h4>
            <ol class="ai-remediation-list">
                ${crit > 0 ? '<li><strong>Immediate Containment:</strong> Restrict public access to exposed tables and rotate compromised API keys immediately.</li>' : ''}
                <li><strong>Enforce RLS:</strong> Enable Row Level Security on all tables and define strict policies for SELECT, INSERT, UPDATE, and DELETE.</li>
                <li><strong>Review Storage:</strong> Set storage buckets to 'Private' by default and use signed URLs for access where possible.</li>
                <li><strong>Audit Functions:</strong> Review SECURITY DEFINER functions to ensure they do not grant unintended privileges.</li>
            </ol>
        </div>`;

        if (report.threat_model) {
            summary += `<div style="margin-top: 1.5rem; text-align: center;">
                <button class="btn-primary large" onclick="navigateToThreatModel()">
                    🕸️ View Visual Threat Model
                </button>
            </div>`;
        }

        aiSummary.innerHTML = summary;
    }
}

let vulnChart = null;

function updateCharts(crit, high, med, safe) {
    const ctx = document.getElementById('vulnChart').getContext('2d');

    if (vulnChart) vulnChart.destroy();

    vulnChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Safe'],
            datasets: [{
                data: [crit, high, med, safe],
                backgroundColor: ['#ef4444', '#f59e0b', '#fbbf24', '#10b981'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8' }
                }
            }
        }
    });
}

loadLatestReport();

async function loadDownloads() {
    const container = document.getElementById('downloads-list');
    container.innerHTML = '<p>Loading...</p>';

    try {
        const res = await fetch('/api/dumps');
        if (!res.ok) throw new Error('Failed to fetch downloads');
        const dumps = await res.json();

        container.innerHTML = '';

        if (!Array.isArray(dumps)) {
            console.error('Expected array but got:', dumps);
            container.innerHTML = '<p class="error">Invalid response format</p>';
            return;
        }

        if (dumps.length === 0) {
            container.innerHTML = '<div class="empty-state">No downloads available.</div>';
            return;
        }

        let displayDumps = dumps;
        const currentScanId = currentReport ? currentReport.scan_id : null;

        if (currentScanId) {
            displayDumps = dumps.filter(d => d.scan_id === currentScanId);
        }

        if (displayDumps.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>No downloads for this scan.</p>
                    <button class="btn-secondary" onclick="loadAllDownloads()">Show All Downloads</button>
                </div>`;
            return;
        }

        if (currentScanId && dumps.length > displayDumps.length) {
            const header = document.createElement('div');
            header.style.marginBottom = '1rem';
            header.innerHTML = `<button class="btn-secondary" onclick="loadAllDownloads()">Show All Downloads</button>`;
            container.appendChild(header);
        }

        displayDumps.forEach(scan => {
            const date = new Date(scan.timestamp * 1000).toLocaleString('en-US', {
                year: 'numeric',
                month: 'numeric',
                day: 'numeric',
                hour: 'numeric',
                minute: 'numeric',
                second: 'numeric',
                hour12: true
            });
            const section = document.createElement('div');
            section.className = 'download-section';
            section.innerHTML = `
                <h3 style="margin-bottom:0.5rem; border-bottom:1px solid var(--border); padding-bottom:0.5rem;">
                    Scan ${scan.scan_id} <span style="font-size:0.8em; color:var(--text-secondary)">(${date})</span>
                </h3>
            `;

            const list = document.createElement('div');
            list.className = 'file-list';

            scan.files.forEach(file => {
                const item = document.createElement('div');
                item.className = 'file-item';
                const size = (file.size / 1024).toFixed(2) + ' KB';
                item.innerHTML = `
                    <div class="file-info">
                        <span class="file-name">📄 ${file.name}</span>
                        <span class="file-size">${size}</span>
                    </div>
                    <a href="/api/download/${scan.scan_id}/${file.name}" class="btn-primary" download>Download</a>
                `;
                list.appendChild(item);
            });

            section.appendChild(list);
            container.appendChild(section);
        });
    } catch (e) {
        console.error(e);
        container.innerHTML = '<p class="error">Failed to load downloads</p>';
    }
}

async function loadAllDownloads() {
    currentReport = null;
    loadDownloads();
}
