const urlInput = document.getElementById('url-input');
const runBtn = document.getElementById('run-btn');
const statusLine = document.getElementById('status-line');
const resultsEl = document.getElementById('results');
const summaryCards = document.getElementById('summary-cards');
const tabSecurity = document.getElementById('tab-security');
const tabFunctionality = document.getElementById('tab-functionality');
const tabScreenshots = document.getElementById('tab-screenshots');
const downloadBtn = document.getElementById('download-report');
const historyList = document.getElementById('history-list');
const authToggle = document.getElementById('auth-toggle');
const authPanel = document.getElementById('auth-panel');
const authMethod = document.getElementById('auth-method');
const authFields = document.getElementById('auth-fields');

let pollTimer = null;

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
  });
});

runBtn.addEventListener('click', startScan);
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') startScan(); });

// Auth panel toggle and field rendering
authToggle.addEventListener('click', () => {
  authPanel.classList.toggle('hidden');
  authToggle.classList.toggle('active');
});

const AUTH_FIELDS = {
  none: '',
  form: `
    <div class="field-row">
      <input type="text" id="auth-login-url" placeholder="Login URL (e.g. /login)" />
    </div>
    <div class="field-row">
      <input type="text" id="auth-username" placeholder="Username" />
      <input type="password" id="auth-password" placeholder="Password" />
    </div>
    <div class="field-row">
      <input type="text" id="auth-user-field" placeholder="Username field name (default: username)" />
      <input type="text" id="auth-pass-field" placeholder="Password field name (default: password)" />
    </div>`,
  bearer: `<input type="text" id="auth-token" placeholder="Bearer token" />`,
  cookie: `<input type="text" id="auth-cookies" placeholder="cookie_name=value; another=value2" />`,
  basic: `
    <div class="field-row">
      <input type="text" id="auth-username" placeholder="Username" />
      <input type="password" id="auth-password" placeholder="Password" />
    </div>`,
};

authMethod.addEventListener('change', () => {
  authFields.innerHTML = AUTH_FIELDS[authMethod.value] || '';
});

function getAuthConfig() {
  const method = authMethod.value;
  if (method === 'none') return null;

  if (method === 'form') {
    return {
      method: 'form',
      login_url: document.getElementById('auth-login-url')?.value || '',
      username: document.getElementById('auth-username')?.value || '',
      password: document.getElementById('auth-password')?.value || '',
      username_field: document.getElementById('auth-user-field')?.value || 'username',
      password_field: document.getElementById('auth-pass-field')?.value || 'password',
    };
  }
  if (method === 'bearer') {
    return { method: 'bearer', token: document.getElementById('auth-token')?.value || '' };
  }
  if (method === 'cookie') {
    const raw = document.getElementById('auth-cookies')?.value || '';
    const cookies = {};
    raw.split(';').forEach(pair => {
      const [k, ...v] = pair.split('=');
      if (k?.trim()) cookies[k.trim()] = v.join('=').trim();
    });
    return { method: 'cookie', cookies };
  }
  if (method === 'basic') {
    return {
      method: 'basic',
      username: document.getElementById('auth-username')?.value || '',
      password: document.getElementById('auth-password')?.value || '',
    };
  }
  return null;
}

async function startScan() {
  const url = urlInput.value.trim();
  if (!url) return;

  runBtn.disabled = true;
  statusLine.classList.remove('error');
  statusLine.textContent = 'Starting scan\u2026';
  resultsEl.classList.add('hidden');

  const body = { url };
  const auth = getAuthConfig();
  if (auth) body.auth = auth;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      statusLine.classList.add('error');
      statusLine.textContent = data.error || 'Could not start scan.';
      runBtn.disabled = false;
      return;
    }
    pollScan(data.scan_id);
    loadHistory();
  } catch (err) {
    statusLine.classList.add('error');
    statusLine.textContent = 'Network error starting scan.';
    runBtn.disabled = false;
  }
}

function pollScan(scanId) {
  clearInterval(pollTimer);
  let dots = 0;
  pollTimer = setInterval(async () => {
    dots = (dots + 1) % 4;
    try {
      const res = await fetch(`/api/scan/${scanId}`);
      const data = await res.json();

      if (data.status === 'running') {
        statusLine.textContent = 'Scanning ' + data.url + ' \u2014 crawling & checking' + '.'.repeat(dots);
      } else if (data.status === 'done') {
        clearInterval(pollTimer);
        statusLine.textContent = 'Done \u2014 ' + data.url;
        runBtn.disabled = false;
        renderResults(data);
        loadHistory();
      } else if (data.status === 'error') {
        clearInterval(pollTimer);
        statusLine.classList.add('error');
        statusLine.textContent = 'Scan failed: ' + (data.error || 'unknown error');
        runBtn.disabled = false;
      }
    } catch (err) {
      clearInterval(pollTimer);
      statusLine.classList.add('error');
      statusLine.textContent = 'Lost connection while polling scan status.';
      runBtn.disabled = false;
    }
  }, 1500);
}

function severityCounts(findings) {
  const c = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1; });
  return c;
}

function renderFindings(container, findings) {
  container.innerHTML = '';
  if (!findings.length) {
    container.innerHTML = '<div class="empty-state">No findings for this check.</div>';
    return;
  }
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  sorted.forEach(f => {
    const div = document.createElement('div');
    div.className = 'finding';
    let detailHtml = '';
    if (f.detail) {
      const detailText = typeof f.detail === 'string' ? f.detail : JSON.stringify(f.detail, null, 2);
      if (detailText) detailHtml = `<div class="detail">${escapeHtml(detailText)}</div>`;
    }
    div.innerHTML = `
      <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
      <div class="finding-body">
        <div class="check">${escapeHtml(f.check)}</div>
        <div class="message">${escapeHtml(f.message)}</div>
        ${detailHtml}
      </div>`;
    container.appendChild(div);
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function renderResults(data) {
  const result = data.result;
  const secCounts = severityCounts(result.security_findings);

  summaryCards.innerHTML = `
    <div class="s-card high"><div class="num">${secCounts.high}</div><div class="label">High</div></div>
    <div class="s-card medium"><div class="num">${secCounts.medium}</div><div class="label">Medium</div></div>
    <div class="s-card"><div class="num">${result.functionality_summary.pages_crawled}</div><div class="label">Pages crawled</div></div>
    <div class="s-card"><div class="num">${result.functionality_summary.forms_found}</div><div class="label">Forms found</div></div>
    ${result.authenticated ? '<div class="s-card"><div class="num">\ud83d\udd10</div><div class="label">Authenticated</div></div>' : ''}
    ${result.screenshots && result.screenshots.length ? `<div class="s-card"><div class="num">${result.screenshots.length}</div><div class="label">Screenshots</div></div>` : ''}
  `;

  renderFindings(tabSecurity, result.security_findings);
  renderFindings(tabFunctionality, result.functionality_findings);
  renderScreenshots(data.scan_id, result.screenshots || []);

  downloadBtn.href = `/api/scan/${data.scan_id}/report`;
  resultsEl.classList.remove('hidden');
}

function renderScreenshots(scanId, screenshots) {
  if (!screenshots.length) {
    tabScreenshots.innerHTML = '<div class="empty-state">No error screenshots captured (that\'s a good sign).</div>';
    return;
  }
  let html = '<div class="screenshot-grid">';
  screenshots.forEach(s => {
    if (!s.screenshot_path) return;
    const filename = s.screenshot_path.split(/[\/\\]/).pop();
    const imgUrl = `/api/scan/${scanId}/screenshots/${filename}`;
    const jsErrors = (s.js_errors || []).slice(0, 3).map(e => escapeHtml(e)).join('\n');
    html += `
      <div class="screenshot-card">
        <img src="${imgUrl}" alt="Screenshot of ${escapeHtml(s.url)}" onclick="window.open('${imgUrl}', '_blank')" />
        <div class="meta">
          <div class="url">${escapeHtml(s.url)}</div>
          <div class="reason">${escapeHtml(s.reason || '')}</div>
          ${jsErrors ? `<div class="js-errors">JS errors:\n${jsErrors}</div>` : ''}
        </div>
      </div>`;
  });
  html += '</div>';
  tabScreenshots.innerHTML = html;
}

async function loadHistory() {
  const res = await fetch('/api/scans');
  const scans = await res.json();
  historyList.innerHTML = '';
  scans.forEach(s => {
    const li = document.createElement('li');
    li.innerHTML = `<span class="h-status ${s.status}">\u25cf</span>${s.url}`;
    li.title = s.url;
    li.addEventListener('click', () => {
      statusLine.textContent = '';
      if (s.status === 'running') {
        pollScan(s.id);
      } else if (s.status === 'done') {
        fetch(`/api/scan/${s.id}`).then(r => r.json()).then(renderResults);
      }
    });
    historyList.appendChild(li);
  });
}

loadHistory();
