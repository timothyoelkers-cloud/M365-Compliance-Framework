/* ═══════════════════════════════════════════
   TENANT SCAN PAGE — dedicated tab for tenant analysis.

   Layers:
     1. Provenance bar       — tenant ID, signed-in user, scan time, error count
     2. Coverage Dashboard   — score 0-100, severity strip, per-workload progress
     3. Recommended Actions  — top-10 prioritised remediations
     4. Findings             — severity-grouped, exportable
     5. Inventory            — per-source items, exportable
═══════════════════════════════════════════ */
const TenantScanPage = (() => {

  // Workload labels / colours used by the per-workload progress section.
  // Maps Findings analyzer workload slug → display label + accent colour.
  const WORKLOAD_META = {
    'conditional-access': { label: 'Conditional Access',     colour: 'var(--blue)' },
    'intune':             { label: 'Intune / Devices',        colour: '#00b894' },
    'entra':              { label: 'Entra ID',                colour: '#0984e3' },
    'sharepoint':         { label: 'SharePoint / OneDrive',   colour: 'var(--teal)' },
    'defender-endpoint':  { label: 'Defender for Endpoint',   colour: '#e84393' },
    'purview':            { label: 'Purview / Data Protection', colour: '#6c5ce7' },
    '_scan':              { label: 'Scan diagnostics',        colour: 'var(--ink3)' },
  };

  function init() { render(); }

  function render() {
    const root = document.getElementById('tenant-scan-content');
    if (!root) return;

    const isConnected = (typeof TenantAuth !== 'undefined') && TenantAuth.isAuthenticated();
    const scanData = (typeof TenantScanner !== 'undefined') ? TenantScanner.getScanResults() : null;
    const scanProgress = AppState.get('scanProgress');

    if (!isConnected) {
      root.innerHTML = renderEmptyState('Sign in first', 'Click <strong>Connect Tenant</strong> at the top right to authorise the framework against an M365 tenant. Then come back here and run a scan.');
      return;
    }

    if (scanProgress && scanProgress.completed < scanProgress.total) {
      root.innerHTML = renderProgress(scanProgress);
      return;
    }

    if (!scanData) {
      root.innerHTML = renderNoScanYet();
      return;
    }

    // We have a scan — render all the layers.
    const analysis = (typeof Findings !== 'undefined') ? Findings.analyzeAll(scanData) : null;

    let html = '';
    html += renderProvenance(scanData);
    html += renderDashboard(scanData, analysis);
    html += renderTrendSection();
    html += renderDriftSection();          // 🆕
    html += renderRecommendedActions(analysis);
    html += renderFrameworkAlignmentSection();
    html += renderCAFlowCardsSection(scanData);
    html += renderFindingsSection(analysis);
    html += renderInventorySection(scanData);

    root.innerHTML = html;

    // Persist this scan into history for the trend chart (idempotent — same
    // tenantId + same timestamp won't add a duplicate).
    if (typeof ScanHistory !== 'undefined' && ScanHistory.saveScan && analysis) {
      try {
        ScanHistory.saveScan(scanData, AppState.get('tenantScanResults') || {}, analysis.counts || {}, analysis.score);
      } catch (e) { /* non-fatal */ }
    }

    // Async-populate trend chart + drift card from IndexedDB (non-blocking).
    setTimeout(() => _loadTrendChart().catch(e => console.warn('[Scan] trend load failed:', e)), 50);
    setTimeout(() => _loadDriftCard().catch(e => console.warn('[Scan] drift load failed:', e)), 75);
  }

  // ── Framework Alignment layer ────────────────────────────────────────

  function renderFrameworkAlignmentSection() {
    if (typeof FrameworkAlignment === 'undefined') return '';
    const alignment = FrameworkAlignment.computeAlignment();
    if (!alignment) return '';

    let html = '<div class="card" style="padding:16px 20px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">Framework Alignment</strong>';
    html += '<span style="font-size:.66rem;color:var(--ink3)">' +
      alignment.overall.configured + ' of ' + alignment.overall.total + ' CIS controls configured · overall ' + alignment.overall.score + '%</span>';
    html += '</div>';
    html += '<p style="font-size:.66rem;color:var(--ink3);margin:0 0 14px;line-height:1.6">A CIS control is "configured" when at least one policy mapped to it has been detected as configured in the scan. Frameworks are sorted by alignment score.</p>';

    for (const f of alignment.byFramework) {
      const colour = f.score >= 80 ? 'var(--green)' : f.score >= 50 ? 'var(--amber)' : 'var(--red)';
      html += '<details style="margin-bottom:6px">';
      html += '<summary style="cursor:pointer;display:flex;align-items:center;gap:10px;padding:6px 0">';
      html += '<span style="width:200px;color:var(--ink2);font-size:.7rem;flex-shrink:0">' + escHtml(f.framework) + '</span>';
      html += '<div style="flex:1;height:8px;background:var(--surface2);border-radius:4px;overflow:hidden;display:flex">';
      html += '<div style="background:var(--green);width:' + (f.configured / f.total * 100) + '%" title="' + f.configured + ' configured"></div>';
      html += '<div style="background:var(--amber);width:' + (f.manual    / f.total * 100) + '%" title="' + f.manual    + ' manual check"></div>';
      html += '<div style="background:var(--red);width:'   + (f.missing   / f.total * 100) + '%" title="' + f.missing   + ' missing"></div>';
      html += '</div>';
      html += '<span style="width:60px;text-align:right;color:' + colour + ';font-weight:600;font-size:.7rem">' + f.score + '%</span>';
      html += '<span style="width:90px;text-align:right;color:var(--ink4);font-size:.6rem">' + f.configured + ' / ' + f.total + '</span>';
      html += '</summary>';
      // Collapsed-detail: list controls grouped by status
      const groups = { missing: [], manual: [], configured: [] };
      for (const c of f.controls) {
        if (groups[c.status]) groups[c.status].push(c);
      }
      html += '<div style="padding:8px 12px;background:var(--surface2);border-radius:4px;margin-top:4px">';
      ['missing', 'manual', 'configured'].forEach(g => {
        if (!groups[g].length) return;
        html += '<div style="font-size:.62rem;font-weight:600;color:var(--ink3);text-transform:uppercase;margin:6px 0 2px">' + g + ' (' + groups[g].length + ')</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:4px">';
        for (const c of groups[g].slice(0, 50)) {
          html += '<span class="badge badge-dark" style="font-size:.58rem" title="' + escHtml(c.name) + '">' + escHtml(c.id) + '</span>';
        }
        if (groups[g].length > 50) html += '<span style="font-size:.58rem;color:var(--ink4);align-self:center">+' + (groups[g].length - 50) + ' more</span>';
        html += '</div>';
      });
      html += '</div></details>';
    }

    html += '</div>';
    return html;
  }

  // ── CA Flow Cards layer ──────────────────────────────────────────────
  // Per-policy visual breakdown: Users → Conditions → Apps → Controls.

  function renderCAFlowCardsSection(scanData) {
    const policies = scanData && scanData.data && scanData.data.conditionalAccess;
    if (!Array.isArray(policies) || policies.length === 0) return '';

    let html = '<div class="card" style="padding:16px 20px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">Conditional Access — flow cards</strong>';
    html += '<span style="font-size:.66rem;color:var(--ink3)">' + policies.length + ' policies</span>';
    html += '</div>';

    const sorted = policies.slice().sort((a, b) => {
      const order = { enabled: 0, enabledForReportingButNotEnforced: 1, disabled: 2 };
      return (order[a.state] || 99) - (order[b.state] || 99);
    });

    for (const p of sorted) html += renderCACard(p);
    html += '</div>';
    return html;
  }

  function renderCACard(p) {
    const grant = (p.grantControls && p.grantControls.builtInControls) || [];
    const session = p.sessionControls || {};
    const isBlock = grant.indexOf('block') !== -1;
    const stateColour = p.state === 'enabled'
      ? (isBlock ? 'var(--red)' : 'var(--green)')
      : p.state === 'enabledForReportingButNotEnforced' ? 'var(--amber)'
      : 'var(--ink4)';
    const stateLabel = p.state === 'enabledForReportingButNotEnforced' ? 'Report-only' :
                       p.state === 'enabled' ? 'Enabled' : 'Disabled';

    const conds = p.conditions || {};
    const usersC = conds.users || {};
    const appsC = conds.applications || {};

    function fmtIds(arr, max) {
      if (!Array.isArray(arr) || arr.length === 0) return '—';
      if (max && arr.length > max) return arr.slice(0, max).join(', ') + ' (+' + (arr.length - max) + ' more)';
      return arr.join(', ');
    }
    function userTargetText() {
      const inc = usersC.includeUsers || [];
      const incRoles = usersC.includeRoles || [];
      const incGroups = usersC.includeGroups || [];
      const parts = [];
      if (inc.indexOf('All') !== -1) parts.push('All users');
      else if (inc.length) parts.push(inc.length + ' user' + (inc.length > 1 ? 's' : ''));
      if (incRoles.length) parts.push(incRoles.length + ' role' + (incRoles.length > 1 ? 's' : ''));
      if (incGroups.length) parts.push(incGroups.length + ' group' + (incGroups.length > 1 ? 's' : ''));
      return parts.length ? parts.join(' + ') : '(none)';
    }
    function appTargetText() {
      const inc = appsC.includeApplications || [];
      const actions = appsC.includeUserActions || [];
      if (inc.indexOf('All') !== -1) return 'All apps';
      if (actions.length) return 'User action: ' + actions.join(', ');
      if (inc.length) return inc.length + ' app(s)';
      return '(none)';
    }
    function controlsText() {
      const out = [];
      if (isBlock) out.push('Block');
      if (grant.indexOf('mfa') !== -1) out.push('MFA');
      if (grant.indexOf('compliantDevice') !== -1) out.push('Compliant device');
      if (grant.indexOf('domainJoinedDevice') !== -1) out.push('Hybrid join');
      if (grant.indexOf('approvedApplication') !== -1) out.push('Approved app');
      if (grant.indexOf('compliantApplication') !== -1) out.push('App protection');
      if (grant.indexOf('passwordChange') !== -1) out.push('Password change');
      if (p.grantControls && p.grantControls.authenticationStrength) out.push('Auth strength: ' + p.grantControls.authenticationStrength.displayName);
      if (session.signInFrequency) out.push('Sign-in frequency');
      if (session.persistentBrowser) out.push('Persistent browser');
      if (session.cloudAppSecurity) out.push('Defender for Cloud Apps');
      return out.length ? out.join(' · ') : '(none)';
    }
    function condText() {
      const out = [];
      const cat = (conds.clientAppTypes || []).filter(x => x !== 'all');
      if (cat.length) out.push('Client: ' + cat.join(','));
      const sr = conds.signInRiskLevels || [];
      if (sr.length) out.push('Sign-in risk: ' + sr.join(','));
      const ur = conds.userRiskLevels || [];
      if (ur.length) out.push('User risk: ' + ur.join(','));
      const plat = conds.platforms;
      if (plat && (plat.includePlatforms || []).length) out.push('Platforms: ' + plat.includePlatforms.join(','));
      const loc = conds.locations;
      if (loc && (loc.includeLocations || []).length) out.push('Locations: ' + (loc.includeLocations.length === 1 && loc.includeLocations[0] === 'All' ? 'All' : loc.includeLocations.length + ' named'));
      return out.length ? out.join(' · ') : '(no extra conditions)';
    }

    const exclusionCount = (usersC.excludeUsers || []).length + (usersC.excludeGroups || []).length + (usersC.excludeRoles || []).length;

    let html = '<div style="background:var(--surface2);border-left:3px solid ' + stateColour + ';border-radius:6px;padding:10px 14px;margin-bottom:8px">';
    html += '<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:6px;flex-wrap:wrap">';
    html += '<strong style="font-size:.74rem;color:var(--ink);flex:1;min-width:0">' + escHtml(p.displayName || '(unnamed)') + '</strong>';
    html += '<span style="background:' + stateColour + '22;color:' + stateColour + ';padding:1px 7px;border-radius:8px;font-size:.56rem;font-weight:600;text-transform:uppercase">' + stateLabel + '</span>';
    if (isBlock) html += '<span style="background:var(--red)22;color:var(--red);padding:1px 7px;border-radius:8px;font-size:.56rem;font-weight:600;text-transform:uppercase">Block</span>';
    if (exclusionCount > 0) html += '<span style="background:var(--ink4)22;color:var(--ink3);padding:1px 7px;border-radius:8px;font-size:.56rem">' + exclusionCount + ' exclusion' + (exclusionCount > 1 ? 's' : '') + '</span>';
    else if (isBlock) html += '<span style="background:var(--red)22;color:var(--red);padding:1px 7px;border-radius:8px;font-size:.56rem;font-weight:600">No exclusions ⚠</span>';
    html += '</div>';

    // Flow row: Users → Conditions → Apps → Controls
    html += '<div style="display:flex;gap:8px;align-items:stretch;flex-wrap:wrap;font-size:.62rem">';
    function box(label, value, colour) {
      return '<div style="flex:1;min-width:140px;background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:6px 8px">' +
        '<div style="font-size:.54rem;color:' + (colour || 'var(--ink4)') + ';text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px">' + label + '</div>' +
        '<div style="color:var(--ink2);line-height:1.5">' + escHtml(value) + '</div>' +
        '</div>';
    }
    html += box('Who', userTargetText(), 'var(--blue)');
    html += '<div style="align-self:center;color:var(--ink4)">→</div>';
    html += box('When (conditions)', condText());
    html += '<div style="align-self:center;color:var(--ink4)">→</div>';
    html += box('Where (apps)', appTargetText());
    html += '<div style="align-self:center;color:var(--ink4)">→</div>';
    html += box('Result', controlsText(), isBlock ? 'var(--red)' : 'var(--green)');
    html += '</div>';
    html += '</div>';
    return html;
  }

  // ── Drift section ────────────────────────────────────────────────────
  // Compares the current scan against the previous scan stored in IndexedDB.
  // Renders a placeholder card; populated async by _loadDriftCard().
  function renderDriftSection() {
    return '<div class="card" id="scan-drift-card" style="padding:16px 20px;margin-bottom:14px;display:none"></div>';
  }

  async function _loadDriftCard() {
    const card = document.getElementById('scan-drift-card');
    if (!card) return;
    if (typeof ScanHistory === 'undefined' || !ScanHistory.getScans) return;
    const acct = TenantAuth.getAccount();
    if (!acct) return;
    const scans = await ScanHistory.getScans(acct.tenantId, 2);
    if (!scans || scans.length < 2) return;  // no previous scan to diff against

    const current = scans[0];
    const previous = scans[1];

    // Compare per-source counts (CA policies, compliance, etc.)
    const sources = ['conditionalAccess', 'compliancePolicies', 'deviceConfigurations', 'configurationPolicies', 'sensitivityLabels', 'retentionLabels', 'dlpPolicies', 'namedLocations'];
    const counts = [];
    for (const s of sources) {
      const cur = Array.isArray(current.data && current.data[s]) ? current.data[s].length : null;
      const prev = Array.isArray(previous.data && previous.data[s]) ? previous.data[s].length : null;
      if (cur === null || prev === null) continue;
      if (cur !== prev) counts.push({ source: s, prev, cur, delta: cur - prev });
    }

    // Compare CA policies specifically — show added / removed by name
    const prevCANames = new Set((previous.data && previous.data.conditionalAccess || []).map(p => p.id));
    const curCANames = new Set((current.data && current.data.conditionalAccess || []).map(p => p.id));
    const addedCA   = (current.data && current.data.conditionalAccess || []).filter(p => !prevCANames.has(p.id));
    const removedCA = (previous.data && previous.data.conditionalAccess || []).filter(p => !curCANames.has(p.id));

    // Score delta + finding-count delta
    const scoreDelta = (current.score || 0) - (previous.score || 0);
    const prevSummary = previous.summary || {};
    const curSummary = current.summary || {};
    const critDelta = (curSummary.critical || 0) - (prevSummary.critical || 0);
    const highDelta = (curSummary.high || 0) - (prevSummary.high || 0);

    if (counts.length === 0 && addedCA.length === 0 && removedCA.length === 0 && scoreDelta === 0 && critDelta === 0 && highDelta === 0) {
      // Nothing changed — show a quiet "no drift" line
      card.innerHTML = '<div style="display:flex;align-items:center;gap:10px;font-size:.7rem;color:var(--ink3)">' +
        '<strong style="color:var(--ink2)">No drift detected</strong> · since last scan ' + escHtml(new Date(previous.timestamp).toLocaleString()) + '</div>';
      card.style.display = 'block';
      return;
    }

    let html = '<div style="display:flex;align-items:center;gap:14px;margin-bottom:10px;flex-wrap:wrap">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">What changed since last scan</strong>';
    html += '<span style="font-size:.62rem;color:var(--ink4)">previous: ' + escHtml(new Date(previous.timestamp).toLocaleString()) + '</span>';
    if (scoreDelta !== 0) {
      const colour = scoreDelta > 0 ? 'var(--green)' : 'var(--red)';
      html += '<span style="font-size:.66rem;color:' + colour + ';font-weight:600">Score: ' + (scoreDelta > 0 ? '+' : '') + scoreDelta + '</span>';
    }
    if (critDelta !== 0) {
      const colour = critDelta < 0 ? 'var(--green)' : 'var(--red)';
      html += '<span style="font-size:.66rem;color:' + colour + ';font-weight:600">Critical findings: ' + (critDelta > 0 ? '+' : '') + critDelta + '</span>';
    }
    if (highDelta !== 0) {
      const colour = highDelta < 0 ? 'var(--green)' : '#e84393';
      html += '<span style="font-size:.66rem;color:' + colour + ';font-weight:600">High findings: ' + (highDelta > 0 ? '+' : '') + highDelta + '</span>';
    }
    html += '</div>';

    if (addedCA.length > 0) {
      html += '<div style="margin-bottom:10px"><strong style="font-size:.66rem;color:var(--green);text-transform:uppercase;letter-spacing:.5px">+ Added CA policies</strong>';
      html += '<ul style="margin:6px 0 0;padding-left:20px;font-size:.66rem;color:var(--ink2);line-height:1.6">';
      addedCA.forEach(p => { html += '<li>' + escHtml(p.displayName || p.id) + ' <span style="color:var(--ink4)">— ' + escHtml(p.state || 'unknown') + '</span></li>'; });
      html += '</ul></div>';
    }
    if (removedCA.length > 0) {
      html += '<div style="margin-bottom:10px"><strong style="font-size:.66rem;color:var(--red);text-transform:uppercase;letter-spacing:.5px">− Removed CA policies</strong>';
      html += '<ul style="margin:6px 0 0;padding-left:20px;font-size:.66rem;color:var(--ink2);line-height:1.6">';
      removedCA.forEach(p => { html += '<li>' + escHtml(p.displayName || p.id) + '</li>'; });
      html += '</ul></div>';
    }
    if (counts.length > 0) {
      html += '<div><strong style="font-size:.66rem;color:var(--ink2);text-transform:uppercase;letter-spacing:.5px">Per-source counts</strong>';
      html += '<table style="margin-top:6px;font-size:.66rem;border-collapse:collapse"><tbody>';
      counts.forEach(c => {
        const colour = c.delta > 0 ? 'var(--green)' : 'var(--red)';
        html += '<tr><td style="padding:2px 12px 2px 0;color:var(--ink3)">' + escHtml(c.source) + '</td>' +
                '<td style="padding:2px 12px;color:var(--ink4)">' + c.prev + ' → ' + c.cur + '</td>' +
                '<td style="padding:2px 0;color:' + colour + ';font-weight:600">' + (c.delta > 0 ? '+' : '') + c.delta + '</td></tr>';
      });
      html += '</tbody></table></div>';
    }
    card.innerHTML = html;
    card.style.display = 'block';
  }

  // ── Trend chart layer ────────────────────────────────────────────────

  function renderTrendSection() {
    // Render placeholder; populate async (IndexedDB read)
    return '<div class="card" id="scan-trend-card" style="padding:16px 20px;margin-bottom:14px;display:none"></div>';
  }

  async function _loadTrendChart() {
    const card = document.getElementById('scan-trend-card');
    if (!card) return;
    if (typeof ScanHistory === 'undefined' || !ScanHistory.getScans) return;
    const acct = TenantAuth.getAccount();
    if (!acct) return;
    const scans = await ScanHistory.getScans(acct.tenantId, 30);
    if (!scans || scans.length < 2) return;  // need at least 2 points for a trend

    // Build score-over-time data (oldest first)
    const points = scans.slice().reverse().map(s => ({ ts: s.timestamp, score: s.score || 0 }));
    const minScore = Math.min(...points.map(p => p.score), 0);
    const maxScore = Math.max(...points.map(p => p.score), 100);
    const range = Math.max(maxScore - minScore, 1);

    const w = 600, h = 80, pad = 4;
    const stepX = (w - pad * 2) / Math.max(points.length - 1, 1);
    const path = points.map((p, i) => {
      const x = pad + i * stepX;
      const y = h - pad - ((p.score - minScore) / range) * (h - pad * 2);
      return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1);
    }).join(' ');

    const last = points[points.length - 1];
    const prev = points[points.length - 2];
    const delta = last.score - prev.score;
    const deltaText = delta > 0 ? '+' + delta : String(delta);
    const deltaColour = delta > 0 ? 'var(--green)' : delta < 0 ? 'var(--red)' : 'var(--ink3)';

    let html = '<div style="display:flex;align-items:center;gap:14px;margin-bottom:8px;flex-wrap:wrap">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">Coverage trend</strong>';
    html += '<span style="font-size:.66rem;color:var(--ink3)">' + scans.length + ' historical scans</span>';
    html += '<span style="font-size:.66rem;color:' + deltaColour + ';font-weight:600">' + deltaText + ' since previous</span>';
    html += '</div>';
    html += '<svg viewBox="0 0 ' + w + ' ' + h + '" style="width:100%;height:80px;display:block">';
    html += '<path d="' + path + '" stroke="var(--blue)" stroke-width="2" fill="none" />';
    points.forEach((p, i) => {
      const x = pad + i * stepX;
      const y = h - pad - ((p.score - minScore) / range) * (h - pad * 2);
      html += '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="3" fill="var(--blue)"><title>' + new Date(p.ts).toLocaleString() + ': ' + p.score + '/100</title></circle>';
    });
    html += '</svg>';
    html += '<div style="display:flex;justify-content:space-between;font-size:.58rem;color:var(--ink4);margin-top:4px">' +
      '<span>' + new Date(points[0].ts).toLocaleDateString() + '</span>' +
      '<span>' + new Date(last.ts).toLocaleDateString() + '</span>' +
      '</div>';

    card.innerHTML = html;
    card.style.display = 'block';
  }

  // ── Provenance bar ────────────────────────────────────────────────

  function renderProvenance(scanData) {
    const acct = TenantAuth.getAccount();
    const tenantId = scanData.tenantId || (acct && acct.tenantId);
    const scannedBy = scanData.scannedBy || (acct && acct.email);
    const time = scanData.timestamp ? new Date(scanData.timestamp).toLocaleString() : '';
    const errs = Array.isArray(scanData.errors) ? scanData.errors.length : 0;
    const isScanning = TenantScanner.isScanning();

    let html = '<div class="card" style="padding:14px 18px;margin-bottom:14px;display:flex;align-items:center;gap:18px;flex-wrap:wrap">';
    if (tenantId)   html += '<div><div style="font-size:.58rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.5px">Tenant</div><code style="font-size:.7rem;color:var(--ink)">' + escHtml(tenantId) + '</code></div>';
    if (scannedBy)  html += '<div><div style="font-size:.58rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.5px">Signed in as</div><span style="font-size:.7rem;color:var(--ink2)">' + escHtml(scannedBy) + '</span></div>';
    if (time)       html += '<div><div style="font-size:.58rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.5px">Last scanned</div><span style="font-size:.7rem;color:var(--ink2)">' + escHtml(time) + '</span></div>';
    if (errs > 0)   html += '<div><div style="font-size:.58rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.5px">Endpoint errors</div><span style="font-size:.7rem;color:var(--red)"><strong>' + errs + '</strong> failed</span></div>';
    html += '<div style="flex:1"></div>';
    html += '<button class="btn btn-sm" onclick="TenantScanPage.generateReport()" title="Open a printable customer report in a new tab">Generate Report</button>';
    html += '<button class="btn btn-sm btn-primary" onclick="TenantScanPage.scan()" ' + (isScanning ? 'disabled' : '') + '>' + (isScanning ? 'Scanning…' : 'Re-scan') + '</button>';
    html += '</div>';
    return html;
  }

  // ── Dashboard layer ─────────────────────────────────────────────────

  function renderDashboard(scanData, analysis) {
    if (!analysis) return '';
    const score = analysis.score;
    const counts = analysis.counts;
    const findings = analysis.findings || [];

    // Per-workload breakdown
    const byWorkload = {};
    for (const f of findings) {
      const wl = f.workload || 'other';
      if (!byWorkload[wl]) byWorkload[wl] = { critical:0, high:0, medium:0, low:0, info:0, label: f.workloadLabel };
      byWorkload[wl][f.severity || 'info']++;
    }

    const sColour = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--amber)' : 'var(--red)';
    let html = '<div class="card" style="padding:18px 20px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:flex-start;gap:24px;flex-wrap:wrap">';

    // Score donut (CSS-only)
    html += '<div style="text-align:center;min-width:140px">';
    html += '<div style="position:relative;width:120px;height:120px;margin:0 auto;border-radius:50%;background:conic-gradient(' + sColour + ' ' + (score * 3.6) + 'deg, var(--surface2) 0deg);display:flex;align-items:center;justify-content:center">';
    html += '<div style="background:var(--surface);width:90px;height:90px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center">';
    html += '<div style="font-size:1.6rem;font-weight:700;color:' + sColour + ';line-height:1">' + score + '</div>';
    html += '<div style="font-size:.55rem;color:var(--ink3);text-transform:uppercase;letter-spacing:.5px">/ 100</div>';
    html += '</div></div>';
    html += '<div style="font-size:.66rem;color:var(--ink3);margin-top:8px">Coverage Score</div>';
    html += '</div>';

    // Severity strip + per-workload bars
    html += '<div style="flex:1;min-width:280px">';
    html += '<div style="font-size:.62rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">Findings by severity</div>';
    html += '<div style="display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap">';
    ['critical', 'high', 'medium', 'low', 'info'].forEach(sev => {
      const def = Findings.SEVERITY[sev];
      const c = counts[sev] || 0;
      if (c === 0) return;
      html += '<span style="background:' + def.colour + '22;color:' + def.colour + ';padding:4px 10px;border-radius:12px;font-weight:600;font-size:.66rem">' + def.label + ': ' + c + '</span>';
    });
    if (findings.length === 0) html += '<span style="color:var(--green);font-size:.7rem;font-weight:600">No findings — every analyzer ran clean.</span>';
    html += '</div>';

    html += '<div style="font-size:.62rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px">By workload</div>';
    const workloadKeys = Object.keys(byWorkload).sort((a, b) => {
      const pa = (byWorkload[a].critical * 4) + (byWorkload[a].high * 3) + (byWorkload[a].medium * 2) + byWorkload[a].low;
      const pb = (byWorkload[b].critical * 4) + (byWorkload[b].high * 3) + (byWorkload[b].medium * 2) + byWorkload[b].low;
      return pb - pa;
    });
    if (workloadKeys.length === 0) {
      html += '<div style="font-size:.7rem;color:var(--ink3)">All workloads clean.</div>';
    } else {
      for (const wl of workloadKeys) {
        const meta = WORKLOAD_META[wl] || { label: byWorkload[wl].label, colour: 'var(--ink3)' };
        const c = byWorkload[wl];
        const total = c.critical + c.high + c.medium + c.low + c.info;
        if (total === 0) continue;
        html += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;font-size:.66rem">';
        html += '<span style="width:160px;color:var(--ink2);flex-shrink:0">' + escHtml(meta.label) + '</span>';
        html += '<div style="flex:1;height:8px;background:var(--surface2);border-radius:4px;overflow:hidden;display:flex">';
        if (c.critical) html += '<div style="background:var(--red);width:' + (c.critical / total * 100) + '%" title="' + c.critical + ' critical"></div>';
        if (c.high)     html += '<div style="background:#e84393;width:' + (c.high / total * 100) + '%" title="' + c.high + ' high"></div>';
        if (c.medium)   html += '<div style="background:var(--amber);width:' + (c.medium / total * 100) + '%" title="' + c.medium + ' medium"></div>';
        if (c.low)      html += '<div style="background:var(--blue);width:' + (c.low / total * 100) + '%" title="' + c.low + ' low"></div>';
        if (c.info)     html += '<div style="background:var(--ink4);width:' + (c.info / total * 100) + '%" title="' + c.info + ' info"></div>';
        html += '</div>';
        html += '<span style="width:30px;text-align:right;color:var(--ink3)">' + total + '</span>';
        html += '</div>';
      }
    }
    html += '</div></div></div>';
    return html;
  }

  // ── Recommended Actions layer ───────────────────────────────────────

  function renderRecommendedActions(analysis) {
    if (!analysis || !analysis.findings) return '';
    // Take the top-N by severity, drop info-level + duplicates.
    const seen = new Set();
    const top = analysis.findings.filter(f => {
      if (f.severity === 'info') return false;
      const key = f.workload + '|' + (f.title || '');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }).slice(0, 10);
    if (top.length === 0) return '';

    let html = '<div class="card" style="padding:16px 20px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">Recommended Actions</strong>';
    html += '<span style="font-size:.62rem;color:var(--ink4)">Top ' + top.length + ' highest-impact remediations</span>';
    html += '</div>';
    html += '<ol style="margin:0;padding-left:24px">';
    for (const f of top) {
      const sevDef = Findings.SEVERITY[f.severity];
      html += '<li style="margin-bottom:8px;padding-left:4px">';
      html += '<span style="background:' + sevDef.colour + '22;color:' + sevDef.colour + ';padding:1px 6px;border-radius:8px;font-size:.56rem;font-weight:600;text-transform:uppercase;margin-right:6px">' + sevDef.label + '</span>';
      html += '<strong style="font-size:.7rem;color:var(--ink)">' + escHtml(f.title) + '</strong>';
      if (f.remediation) html += '<div style="font-size:.64rem;color:var(--ink3);margin-top:2px;line-height:1.5">' + escHtml(f.remediation) + '</div>';
      html += '</li>';
    }
    html += '</ol></div>';
    return html;
  }

  // ── Findings layer ───────────────────────────────────────────────────

  function renderFindingsSection(analysis) {
    if (!analysis) return '';
    const findings = analysis.findings || [];
    if (findings.length === 0) {
      return '<div class="card" style="padding:14px 18px;margin-bottom:14px;font-size:.74rem;color:var(--green)">✓ No findings — every analyzer ran clean.</div>';
    }
    const filterWorkload = AppState.get('scanFilterWorkload') || '';

    let html = '<div class="card" style="padding:16px 20px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">All findings</strong>';
    html += '<span style="font-size:.66rem;color:var(--ink3)">' + findings.length + ' total</span>';
    html += '<div style="flex:1"></div>';
    html += '<button class="btn btn-sm" onclick="TenantScanPage.exportFindingsJson()">Export JSON</button>';
    html += '<button class="btn btn-sm" onclick="TenantScanPage.exportFindingsCsv()">Export CSV</button>';
    html += '</div>';

    // Workload filter pills
    const workloads = Array.from(new Set(findings.map(f => f.workload)));
    html += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;font-size:.62rem">';
    html += '<button class="btn btn-sm ' + (!filterWorkload ? 'btn-primary' : '') + '" onclick="TenantScanPage.filterWorkload(\'\')">All</button>';
    for (const wl of workloads) {
      const meta = WORKLOAD_META[wl] || { label: wl };
      const count = findings.filter(f => f.workload === wl).length;
      html += '<button class="btn btn-sm ' + (filterWorkload === wl ? 'btn-primary' : '') + '" onclick="TenantScanPage.filterWorkload(\'' + escHtml(wl) + '\')">' + escHtml(meta.label) + ' <span style="opacity:.7">' + count + '</span></button>';
    }
    html += '</div>';

    const filtered = filterWorkload ? findings.filter(f => f.workload === filterWorkload) : findings;
    const byWorkload = {};
    for (const f of filtered) (byWorkload[f.workloadLabel] = byWorkload[f.workloadLabel] || []).push(f);

    for (const wl of Object.keys(byWorkload)) {
      const list = byWorkload[wl];
      html += '<div style="font-size:.62rem;font-weight:600;color:var(--ink2);margin:14px 0 6px;letter-spacing:.5px;text-transform:uppercase">' + escHtml(wl) + ' (' + list.length + ')</div>';
      for (const f of list) {
        const sevDef = Findings.SEVERITY[f.severity] || Findings.SEVERITY.info;
        html += '<details style="margin:0 0 6px;background:var(--surface2);border-left:3px solid ' + sevDef.colour + ';border-radius:6px;padding:8px 10px">';
        html += '<summary style="cursor:pointer;font-size:.7rem;color:var(--ink)">';
        html += '<span style="background:' + sevDef.colour + '22;color:' + sevDef.colour + ';padding:1px 6px;border-radius:8px;font-size:.56rem;font-weight:600;margin-right:8px;text-transform:uppercase">' + sevDef.label + '</span>';
        html += '<strong>' + escHtml(f.title) + '</strong>';
        html += '</summary>';
        if (f.description) html += '<p style="margin:6px 0;font-size:.64rem;color:var(--ink2);line-height:1.6">' + escHtml(f.description) + '</p>';
        if (f.remediation) html += '<p style="margin:6px 0;font-size:.64rem;color:var(--ink3);line-height:1.6"><strong>Remediation:</strong> ' + escHtml(f.remediation) + '</p>';
        if (f.refs && f.refs.length) html += '<div style="font-size:.6rem;color:var(--ink4);margin-top:6px">Related: ' + f.refs.map(r => '<code>' + escHtml(r) + '</code>').join(', ') + '</div>';

        // ── One-click remediation ──
        // For each ref that matches one of our 143 deployable policy IDs,
        // surface a Deploy button that hands off to DeployEngine.
        const deployableRefs = _findDeployableRefs(f.refs);
        if (deployableRefs.length > 0) {
          html += '<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">';
          for (const polId of deployableRefs) {
            html += '<button class="btn btn-sm btn-deploy" onclick="TenantScanPage.deployFix(\'' + escHtml(polId) + '\')">Deploy ' + escHtml(polId) + ' to fix</button>';
          }
          html += '</div>';
        }

        html += '</details>';
      }
    }
    html += '</div>';
    return html;
  }

  // Filter a finding's refs to only those that match one of our 143
  // deployable policy IDs. Strings that look like CIS check numbers (1.2.3)
  // or arbitrary text are dropped.
  function _findDeployableRefs(refs) {
    if (!Array.isArray(refs) || typeof AppState === 'undefined') return [];
    const policies = AppState.get('policies') || [];
    const policyIds = new Set(policies.map(p => p.id));
    return refs.filter(r => policyIds.has(r));
  }

  async function deployFix(policyId) {
    if (typeof Policies === 'undefined' || !Policies.deploy) {
      // Fallback: navigate to policies page if Deploy module not loaded
      Router.navigate('policies');
      showToast('Open the Policies page and find ' + policyId + ' to deploy.');
      return;
    }
    showToast('Deploying ' + policyId + '…');
    await Policies.deploy(policyId);
    // After deploy, re-render so the user sees updated state.
    render();
  }

  // ── Inventory layer ──────────────────────────────────────────────────

  function renderInventorySection(scanData) {
    if (typeof TenantInventory === 'undefined') return '';
    const inv = TenantInventory.build(scanData, TenantScanner.SCAN_ENDPOINTS || {});
    if (!inv) return '';

    let html = '<div class="card" style="padding:16px 20px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">Tenant Inventory</strong>';
    html += '<span style="font-size:.66rem;color:var(--ink3)">' + inv.totals.items + ' items across ' + Object.keys(inv.totals.byCategory).length + ' categories</span>';
    html += '<div style="flex:1"></div>';
    html += '<button class="btn btn-sm" onclick="TenantScanPage.exportInventoryJson()">Export JSON</button>';
    html += '<button class="btn btn-sm" onclick="TenantScanPage.exportInventoryCsv()">Export CSV</button>';
    html += '</div>';

    const cats = Object.entries(inv.totals.byCategory).sort((a, b) => a[0].localeCompare(b[0]));
    html += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">';
    for (const [cat, count] of cats) html += '<span class="badge badge-dark" style="font-size:.6rem">' + escHtml(cat) + ': ' + count + '</span>';
    html += '</div>';

    const byCat = {};
    for (const g of inv.groups) (byCat[g.category] = byCat[g.category] || []).push(g);
    for (const cat of Object.keys(byCat).sort()) {
      html += '<div style="font-size:.62rem;font-weight:600;color:var(--ink2);margin:12px 0 6px;letter-spacing:.5px;text-transform:uppercase">' + escHtml(cat) + '</div>';
      for (const group of byCat[cat]) {
        const dot = group.error ? 'var(--red)' : (!group.available ? 'var(--ink4)' : group.count > 0 ? 'var(--green)' : 'var(--ink3)');
        const status = group.error ? 'error: ' + escHtml(group.error.substring(0, 80)) :
                       (!group.available ? '(not available in this tenant)' :
                        group.count === 0 ? '(none configured)' :
                        group.count + ' item' + (group.count > 1 ? 's' : ''));
        const expandable = group.count > 0;
        html += '<details ' + (group.count <= 5 && expandable ? 'open' : '') + ' style="margin:0 0 6px;background:var(--surface2);border-radius:6px;padding:8px 10px">';
        html += '<summary style="cursor:' + (expandable ? 'pointer' : 'default') + ';font-size:.66rem;color:var(--ink2)">';
        html += '<span style="display:inline-block;width:8px;height:8px;background:' + dot + ';border-radius:50%;margin-right:8px;vertical-align:middle"></span>';
        html += '<strong>' + escHtml(group.label) + '</strong> · <span style="color:var(--ink3)">' + status + '</span>';
        html += '</summary>';
        if (expandable) {
          html += '<table style="width:100%;margin-top:8px;border-collapse:collapse;font-size:.62rem">';
          html += '<thead><tr style="text-align:left;color:var(--ink3);border-bottom:1px solid var(--border)">' +
                  '<th style="padding:4px 6px">Name</th><th style="padding:4px 6px">Kind</th><th style="padding:4px 6px">State</th><th style="padding:4px 6px">Summary</th>' +
                  '</tr></thead><tbody>';
          for (const item of group.items) {
            const stateColour = item.state === 'enabled' ? 'var(--green)' :
                                item.state === 'reportOnly' ? 'var(--amber)' :
                                item.state === 'disabled' ? 'var(--ink4)' : 'var(--ink3)';
            html += '<tr style="border-bottom:1px solid var(--border)">' +
                    '<td style="padding:4px 6px;color:var(--ink)">' + escHtml(item.name) + '</td>' +
                    '<td style="padding:4px 6px;color:var(--ink3)">' + escHtml(item.kind) + '</td>' +
                    '<td style="padding:4px 6px;color:' + stateColour + '">' + escHtml(item.state || '') + '</td>' +
                    '<td style="padding:4px 6px;color:var(--ink3)">' + escHtml(item.summary || '') + '</td>' +
                    '</tr>';
          }
          html += '</tbody></table>';
        }
        html += '</details>';
      }
    }
    html += '</div>';
    return html;
  }

  // ── Empty / progress states ──────────────────────────────────────────

  function renderEmptyState(title, body) {
    return '<div class="card" style="padding:40px;text-align:center"><h3>' + escHtml(title) + '</h3><p style="color:var(--ink3);margin-top:8px;font-size:.78rem;line-height:1.6">' + body + '</p></div>';
  }

  function renderNoScanYet() {
    return '<div class="card" style="padding:40px;text-align:center">' +
      '<h3>No scan run yet</h3>' +
      '<p style="color:var(--ink3);margin:12px 0;font-size:.78rem;line-height:1.6">Click below to read 15+ Microsoft Graph endpoints and build a tenant inventory + findings report.</p>' +
      '<button class="btn btn-primary" onclick="TenantScanPage.scan()">Scan Tenant</button>' +
      '</div>';
  }

  function renderProgress(progress) {
    const pct = Math.round((progress.completed / progress.total) * 100);
    return '<div class="card" style="padding:30px;text-align:center">' +
      '<h3 style="margin-bottom:14px">Scanning tenant…</h3>' +
      '<div style="background:var(--surface2);height:10px;border-radius:5px;overflow:hidden;max-width:400px;margin:0 auto">' +
      '<div style="background:var(--green);width:' + pct + '%;height:100%;transition:width .3s"></div>' +
      '</div>' +
      '<p style="margin-top:12px;font-size:.7rem;color:var(--ink3)">' + progress.completed + ' / ' + progress.total + ' — ' + escHtml(progress.current || '') + '</p>' +
      '</div>';
  }

  // ── Public actions ───────────────────────────────────────────────────

  async function scan() {
    if (TenantScanner.isScanning()) return;
    render();
    const result = await TenantScanner.scanTenant();
    if (result.success && typeof PolicyMatcher !== 'undefined') {
      PolicyMatcher.matchAll(AppState.get('policies'));
    }
    render();
  }

  function filterWorkload(slug) {
    AppState.set('scanFilterWorkload', slug);
    render();
  }

  function exportFindingsJson() {
    const a = Findings.analyzeAll(TenantScanner.getScanResults());
    if (!a || !a.findings.length) { showToast('No findings to export'); return; }
    _download(JSON.stringify(a, null, 2), 'findings-' + Date.now() + '.json', 'application/json');
  }
  function exportFindingsCsv() {
    const a = Findings.analyzeAll(TenantScanner.getScanResults());
    if (!a || !a.findings.length) { showToast('No findings to export'); return; }
    const headers = ['Severity', 'Workload', 'Title', 'Description', 'Remediation', 'Refs', 'RuleId'];
    const rows = [headers.join(',')];
    for (const f of a.findings) {
      rows.push([f.severity, f.workloadLabel, f.title, f.description || '', f.remediation || '', (f.refs || []).join('; '), f.id || ''].map(_csv).join(','));
    }
    _download(rows.join('\n'), 'findings-' + Date.now() + '.csv', 'text/csv');
  }
  function exportInventoryJson() {
    const inv = TenantInventory.build(TenantScanner.getScanResults(), TenantScanner.SCAN_ENDPOINTS || {});
    if (!inv) { showToast('No scan to export'); return; }
    _download(TenantInventory.toJson(inv), 'tenant-inventory-' + Date.now() + '.json', 'application/json');
  }
  function exportInventoryCsv() {
    const inv = TenantInventory.build(TenantScanner.getScanResults(), TenantScanner.SCAN_ENDPOINTS || {});
    if (!inv) { showToast('No scan to export'); return; }
    _download(TenantInventory.toCsv(inv), 'tenant-inventory-' + Date.now() + '.csv', 'text/csv');
  }
  function _csv(v) { var s = String(v == null ? '' : v); if (s.indexOf(',') > -1 || s.indexOf('"') > -1 || s.indexOf('\n') > -1) s = '"' + s.replace(/"/g, '""') + '"'; return s; }
  function _download(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    showToast(filename + ' downloaded');
  }

  function generateReport() {
    if (typeof ScanReport === 'undefined' || !ScanReport.generate) {
      showToast('Report module not loaded');
      return;
    }
    ScanReport.generate();
  }

  return { init, render, scan, filterWorkload, exportFindingsJson, exportFindingsCsv, exportInventoryJson, exportInventoryCsv, deployFix, generateReport };
})();
