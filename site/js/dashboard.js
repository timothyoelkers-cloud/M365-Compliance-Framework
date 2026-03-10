/* ═══════════════════════════════════════════
   DASHBOARD — Compliance status overview
═══════════════════════════════════════════ */
const Dashboard = (() => {
  let remediationLoaded = false;
  let executiveMode = false;

  function init() {
    render();
    // Re-render when scan results change
    AppState.on('tenantScanResults', function () {
      if (AppState.get('currentPage') === 'dashboard') {
        remediationLoaded = false;
        render();
      }
    });
  }

  function toggleExecutiveMode() {
    executiveMode = !executiveMode;
    render();
  }

  function render() {
    const container = document.getElementById('dashboard-content');
    if (!container) return;

    const sel = AppState.get('selectedFrameworks');
    if (sel.size === 0) {
      container.innerHTML = `<div class="card" style="text-align:center;padding:48px">
        <h3 style="color:var(--ink3);margin-bottom:8px">No Assessment Data</h3>
        <p style="color:var(--ink4);font-size:.78rem;margin-bottom:16px">Start an assessment to see your compliance dashboard.</p>
        <button class="btn btn-amber btn-lg" onclick="Router.navigate('assessment')">Start Assessment &rarr;</button>
      </div>`;
      return;
    }

    const stats = AppState.getScoreStats();
    const fwCoverage = AppState.getFrameworkCoverage();
    const gaps = AppState.getGaps().slice(0, 25);

    // View toggle + action buttons
    let html = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">';
    html += '<div style="display:flex;gap:6px">';
    html += '<button class="btn btn-sm' + (executiveMode ? '' : ' btn-primary') + '" onclick="Dashboard.toggleExecutiveMode()" style="font-size:.62rem">' + (executiveMode ? 'Detailed View' : 'Executive View') + '</button>';
    if (typeof ScanScheduler !== 'undefined') {
      html += ScanScheduler.renderSettingsUI();
    }
    html += '</div>';
    html += '<div style="display:flex;gap:6px">';
    if (typeof PSDeploy !== 'undefined') {
      html += '<button class="btn btn-sm" onclick="PSDeploy.showDeployModal()" style="font-size:.62rem">Deploy Scripts</button>';
    }
    if (typeof EvidenceCollector !== 'undefined') {
      html += EvidenceCollector.renderExportButton();
    }
    if (typeof WebhookNotifier !== 'undefined') {
      html += '<button class="btn btn-sm" onclick="WebhookNotifier.renderSettingsModal()" style="font-size:.62rem" title="Webhook Settings">&#128276;</button>';
    }
    html += '</div></div>';

    // Executive mode — simplified board-level view
    if (executiveMode) {
      html += renderExecutiveSummary(stats, fwCoverage);
      container.innerHTML = html;
      return;
    }

    // KPI Row
    html += `<div class="kpi-row">
      <div class="kpi">
        <div class="kpi-num" style="color:${stats.score >= 80 ? 'var(--green)' : stats.score >= 50 ? 'var(--amber2)' : 'var(--red)'}">${stats.score}%</div>
        <div class="kpi-label">Compliance Score</div>
      </div>
      <div class="kpi">
        <div class="kpi-num" style="color:var(--green)">${stats.done}</div>
        <div class="kpi-label">Controls Implemented</div>
      </div>
      <div class="kpi">
        <div class="kpi-num" style="color:var(--red)">${stats.gap}</div>
        <div class="kpi-label">Gaps Identified</div>
      </div>
      <div class="kpi">
        <div class="kpi-num" style="color:var(--blue)">${sel.size}</div>
        <div class="kpi-label">Frameworks Assessed</div>
      </div>
    </div>`;

    // ── Tenant Policy Compliance (from scan results) ──
    html += renderTenantComplianceSection();

    // Score Breakdown + Donut
    html += `<div class="section-hdr">Score Breakdown</div>
    <div style="display:grid;grid-template-columns:200px 1fr;gap:24px;align-items:center;margin-bottom:28px">
      <div class="donut-wrap">${buildDonut(stats, 90)}</div>
      <div class="donut-legend">
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--green)"></div>
          Implemented
          <span class="legend-val" style="color:var(--green)">${stats.done} (${stats.total > 0 ? Math.round(stats.done/stats.total*100) : 0}%)</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--red)"></div>
          Gaps
          <span class="legend-val" style="color:var(--red)">${stats.gap} (${stats.total > 0 ? Math.round(stats.gap/stats.total*100) : 0}%)</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--border2)"></div>
          Not Reviewed
          <span class="legend-val" style="color:var(--ink4)">${stats.unrev} (${stats.total > 0 ? Math.round(stats.unrev/stats.total*100) : 0}%)</span>
        </div>
        <div class="legend-item">
          <div class="legend-dot" style="background:var(--bg2)"></div>
          Total Checks
          <span class="legend-val">${stats.total}</span>
        </div>
      </div>
    </div>`;

    // Framework Coverage
    if (fwCoverage.length > 0) {
      html += `<div class="section-hdr">Framework Coverage</div>`;
      const fwMeta = AppState.get('frameworkMeta') || {};
      for (const bar of fwCoverage) {
        const clr = bar.pct > 80 ? 'var(--green)' : bar.pct > 50 ? 'var(--amber2)' : 'var(--red)';
        const meta = fwMeta[bar.fw];
        const verBadge = meta && meta.version ? ` <span class="fw-version-badge">${meta.version}</span>` : '';
        html += `<div class="fw-bar">
          <div class="fw-bar-name" title="${bar.fw}">${bar.fw.length > 24 ? bar.fw.slice(0, 22) + '...' : bar.fw}${verBadge}</div>
          <div class="progress-track"><div class="progress-fill" style="width:${bar.pct}%;background:${clr}"></div></div>
          <div class="fw-bar-pct">${bar.pct}%</div>
        </div>`;
      }
    }

    // Gap Register
    if (gaps.length > 0) {
      html += `<div class="section-hdr" style="margin-top:28px">Gap Register (Top ${gaps.length})</div>
      <table class="data-table">
        <thead><tr>
          <th style="width:70px">Check ID</th>
          <th>Control</th>
          <th style="width:100px">Category</th>
          <th style="width:50px">Level</th>
          <th style="width:80px">Priority</th>
          <th style="width:70px">Impact</th>
        </tr></thead>
        <tbody>`;
      for (const g of gaps) {
        const tierBadge = g.tier === 'critical' ? 'badge-red' : g.tier === 'high' ? 'badge-amber' : 'badge-blue';
        html += `<tr>
          <td class="text-mono" style="font-size:.67rem;color:var(--blue);font-weight:600">${g.id}</td>
          <td style="font-size:.74rem;max-width:300px">${g.name}</td>
          <td><span class="badge badge-blue">${g.cat}</span></td>
          <td><span class="text-mono" style="font-weight:600;color:${g.level === 'L1' ? 'var(--green)' : 'var(--amber)'}">${g.level}</span></td>
          <td><span class="badge ${tierBadge}">${g.tier}</span></td>
          <td class="text-mono" style="font-size:.67rem">${g.impact} fw</td>
        </tr>`;
      }
      html += `</tbody></table>`;
    } else if (stats.gap === 0 && stats.done > 0) {
      html += `<div class="section-hdr">Gap Register</div>
        <div class="card" style="border-color:var(--green);background:var(--green-lt);padding:20px">
          <strong style="color:var(--green)">No Gaps Recorded</strong>
          <p style="font-size:.74rem;color:var(--ink2);margin-top:4px">All reviewed controls have been marked as implemented.</p>
        </div>`;
    }

    // Scan History Timeline
    html += '<div id="dashboard-scan-history"></div>';

    // RBAC Summary
    if (typeof RBACCheck !== 'undefined' && RBACCheck.hasFetched()) {
      html += RBACCheck.renderPermissionSummary();
    }

    // Remediation Priorities placeholder
    html += '<div id="dashboard-remediation"></div>';

    container.innerHTML = html;

    // Lazy-load remediation data
    if (!remediationLoaded) {
      loadRemediationPriorities();
    }

    // Render scan history timeline
    if (typeof ScanHistory !== 'undefined') {
      ScanHistory.renderTimeline('dashboard-scan-history').catch(function () {});
    }
  }

  // ── Executive Summary ──
  function renderExecutiveSummary(stats, fwCoverage) {
    var html = '<div class="exec-summary">';

    // Large donut
    html += '<div style="display:flex;justify-content:center;align-items:center;gap:40px;margin-bottom:32px;flex-wrap:wrap">';
    html += '<div class="donut-wrap" style="width:200px;height:200px">' + buildDonut(stats, 100) + '</div>';
    html += '<div class="exec-kpi-row">';
    html += '<div class="exec-kpi"><div class="exec-kpi-num" style="color:' + (stats.score >= 80 ? 'var(--green)' : stats.score >= 50 ? 'var(--amber2)' : 'var(--red)') + '">' + stats.score + '%</div><div class="exec-kpi-label">Compliance Score</div></div>';
    html += '<div class="exec-kpi"><div class="exec-kpi-num" style="color:var(--green)">' + stats.done + '</div><div class="exec-kpi-label">Implemented</div></div>';
    html += '<div class="exec-kpi"><div class="exec-kpi-num" style="color:var(--red)">' + stats.gap + '</div><div class="exec-kpi-label">Gaps</div></div>';
    html += '<div class="exec-kpi"><div class="exec-kpi-num" style="color:var(--blue)">' + AppState.get('selectedFrameworks').size + '</div><div class="exec-kpi-label">Frameworks</div></div>';
    html += '</div></div>';

    // Last scan indicator
    var scanResults = AppState.get('tenantScanResults');
    if (scanResults && Object.keys(scanResults).length > 0 && typeof TenantScanner !== 'undefined') {
      var scanCache = TenantScanner.getScanResults ? TenantScanner.getScanResults() : null;
      if (scanCache && scanCache.timestamp) {
        var ago = Date.now() - scanCache.timestamp;
        var agoStr = ago < 60000 ? 'just now' : ago < 3600000 ? Math.round(ago / 60000) + 'm ago' : Math.round(ago / 3600000) + 'h ago';
        html += '<div style="text-align:center;font-size:.72rem;color:var(--ink4);margin-bottom:20px">Last scanned: ' + agoStr + '</div>';
      }
    }

    // Traffic-light framework grid
    if (fwCoverage.length > 0) {
      html += '<div class="section-hdr">Framework Status</div>';
      html += '<div class="exec-fw-grid">';
      for (var i = 0; i < fwCoverage.length; i++) {
        var fw = fwCoverage[i];
        var cls = fw.pct >= 80 ? 'exec-green' : fw.pct >= 50 ? 'exec-amber' : 'exec-red';
        html += '<div class="exec-fw-card ' + cls + '">';
        html += '<div class="exec-fw-pct">' + fw.pct + '%</div>';
        html += '<div class="exec-fw-name">' + escHtml(fw.fw.length > 30 ? fw.fw.slice(0, 28) + '...' : fw.fw) + '</div>';
        html += '<div class="exec-fw-detail">' + fw.done + '/' + fw.total + ' controls</div>';
        html += '</div>';
      }
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  // ── Tenant Policy Compliance ──
  function renderTenantComplianceSection() {
    var scanResults = AppState.get('tenantScanResults');
    if (!scanResults || Object.keys(scanResults).length === 0) return '';

    var summary = (typeof PolicyMatcher !== 'undefined') ? PolicyMatcher.getSummary() : null;
    if (!summary) return '';

    var policies = AppState.get('policies') || [];
    var policyTypes = AppState.get('policyTypes') || {};

    // Group by category
    var byCategory = {};
    for (var i = 0; i < policies.length; i++) {
      var pol = policies[i];
      var cat = pol.type;
      if (!byCategory[cat]) byCategory[cat] = { configured: 0, missing: 0, manual: 0, total: 0 };
      byCategory[cat].total++;
      var result = scanResults[pol.id];
      if (!result) continue;
      if (result.status === 'configured') byCategory[cat].configured++;
      else if (result.status === 'missing') byCategory[cat].missing++;
      else if (result.status === 'manual') byCategory[cat].manual++;
    }

    var html = '<div class="section-hdr">Tenant Policy Compliance</div>';

    // Secure Score widget
    var scanData = (typeof TenantScanner !== 'undefined') ? TenantScanner.getScanResults() : null;
    if (scanData && scanData.data && scanData.data.secureScores && scanData.data.secureScores.length > 0) {
      var ss = scanData.data.secureScores[0];
      var ssScore = ss.currentScore || 0;
      var ssMax = ss.maxScore || 1;
      var ssPct = Math.round(ssScore / ssMax * 100);
      var ssClr = ssPct >= 80 ? 'var(--green)' : ssPct >= 50 ? 'var(--amber2)' : 'var(--red)';
      html += `<div class="card score-widget" style="display:flex;align-items:center;gap:16px;padding:14px;margin-bottom:16px;border-left:3px solid ${ssClr}">
        <div style="text-align:center">
          <div class="text-mono" style="font-size:1.2rem;font-weight:700;color:${ssClr}">${ssScore}/${ssMax}</div>
          <div style="font-size:.58rem;color:var(--ink4);text-transform:uppercase">Secure Score</div>
        </div>
        <div style="flex:1">
          <div class="progress-track"><div class="progress-fill" style="width:${ssPct}%;background:${ssClr}"></div></div>
        </div>
        <div class="text-mono" style="font-size:.78rem;color:${ssClr};font-weight:600">${ssPct}%</div>
      </div>`;
    }

    // Scan KPI row
    html += `<div class="kpi-row">
      <div class="kpi">
        <div class="kpi-num" style="color:var(--green)">${summary.configured}</div>
        <div class="kpi-label">Policies Configured</div>
      </div>
      <div class="kpi">
        <div class="kpi-num" style="color:var(--red)">${summary.missing}</div>
        <div class="kpi-label">Policies Missing</div>
      </div>
      <div class="kpi">
        <div class="kpi-num" style="color:var(--blue)">${summary.manual}</div>
        <div class="kpi-label">Manual Verification</div>
      </div>
      <div class="kpi">
        <div class="kpi-num" style="color:var(--ink4)">${summary.total}</div>
        <div class="kpi-label">Total Policies</div>
      </div>
    </div>`;

    // Per-category progress bars
    var cats = Object.keys(byCategory).sort();
    for (var c = 0; c < cats.length; c++) {
      var type = cats[c];
      var counts = byCategory[type];
      var label = (policyTypes[type] && policyTypes[type].label) || type;
      var pct = counts.total > 0 ? Math.round(counts.configured / counts.total * 100) : 0;
      var clr = pct >= 80 ? 'var(--green)' : pct >= 50 ? 'var(--amber2)' : 'var(--red)';
      html += `<div class="fw-bar">
        <div class="fw-bar-name">${escHtml(label)}</div>
        <div class="progress-track"><div class="progress-fill" style="width:${pct}%;background:${clr}"></div></div>
        <div class="fw-bar-pct">${counts.configured}/${counts.total}</div>
      </div>`;
    }

    // PS Verify buttons
    if (summary.manual > 0 && typeof PSVerify !== 'undefined') {
      html += `<div style="display:flex;gap:8px;margin-top:12px;margin-bottom:8px">
        <button class="btn btn-sm" onclick="PSVerify.showGenerateModal()">Generate PS Verification Script</button>
        <button class="btn btn-sm" onclick="PSVerify.showImportModal()">Import PS Results</button>
      </div>`;
    }

    return html;
  }

  // ── Remediation Priorities ──
  function loadRemediationPriorities() {
    var el = document.getElementById('dashboard-remediation');
    if (!el) return;

    var scanResults = AppState.get('tenantScanResults') || {};
    var missingCount = Object.keys(scanResults).filter(function (id) {
      return scanResults[id].status === 'missing';
    }).length;

    if (missingCount === 0 || typeof Remediation === 'undefined') {
      el.innerHTML = '';
      return;
    }

    el.innerHTML = '<div class="section-hdr" style="margin-top:28px">Remediation Priorities</div>' +
      '<div style="font-size:.68rem;color:var(--ink4)">Loading remediation data...</div>';

    Remediation.getRemediationsForGaps(15).then(function (rems) {
      remediationLoaded = true;
      var remEl = document.getElementById('dashboard-remediation');
      if (!remEl) return;

      var html = '<div class="section-hdr" style="margin-top:28px">Remediation Priorities (' + missingCount + ' missing policies)</div>';

      if (rems.length === 0) {
        html += '<div style="font-size:.68rem;color:var(--ink4)">No remediation data available.</div>';
      } else {
        for (var i = 0; i < rems.length; i++) {
          html += Remediation.renderCard(rems[i]);
        }
        if (missingCount > rems.length) {
          html += '<div style="font-size:.68rem;color:var(--ink4);margin-top:8px">' +
            (missingCount - rems.length) + ' more missing policies not shown. ' +
            '<a href="#" onclick="event.preventDefault();Router.navigate(\'policies\')" style="color:var(--accent)">View all policies &rarr;</a></div>';
        }
      }

      remEl.innerHTML = html;
    });
  }

  function buildDonut(stats, size) {
    const r = size * 0.38;
    const c = size;
    const circ = 2 * Math.PI * r;
    const perimDone = (stats.done / Math.max(stats.total, 1)) * circ;
    const perimGap = (stats.gap / Math.max(stats.total, 1)) * circ;
    const perimUnrev = circ - perimDone - perimGap;
    const scoreColor = stats.score >= 80 ? 'var(--green)' : stats.score >= 50 ? 'var(--amber2)' : 'var(--red)';

    return `<svg width="${c*2}" height="${c*2}" viewBox="0 0 ${c*2} ${c*2}" style="transform:rotate(-90deg)">
      <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="var(--bg2)" stroke-width="16"/>
      <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="var(--green)" stroke-width="16"
        stroke-dasharray="${perimDone} ${circ - perimDone}" stroke-dashoffset="0"/>
      <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="var(--red)" stroke-width="16"
        stroke-dasharray="${perimGap} ${circ - perimGap}" stroke-dashoffset="${-perimDone}"/>
      <circle cx="${c}" cy="${c}" r="${r}" fill="none" stroke="var(--border2)" stroke-width="16"
        stroke-dasharray="${perimUnrev} ${circ - perimUnrev}" stroke-dashoffset="${-(perimDone + perimGap)}"/>
    </svg>
    <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%) rotate(0deg);text-align:center">
      <div class="text-mono" style="font-weight:600;font-size:1.4rem;color:${scoreColor}">${stats.score}%</div>
      <div style="font-size:.58rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.05em">Score</div>
    </div>`;
  }

  return { init: init, render: render, toggleExecutiveMode: toggleExecutiveMode };
})();
