/* ═══════════════════════════════════════════
   REPORTS — Compliance report generator
═══════════════════════════════════════════ */
const Reports = (() => {
  let logoDataUrl = null;  // base64 logo

  function init() {
    render();
  }

  function render() {
    const container = document.getElementById('reports-content');
    if (!container) return;

    const sel = AppState.get('selectedFrameworks');
    const hasData = sel.size > 0;

    let html = `<div style="display:grid;grid-template-columns:340px 1fr;gap:24px;align-items:start">`;

    // Config panel
    html += `<div class="card" style="position:sticky;top:80px">
      <div class="section-hdr" style="margin-top:0">Report Configuration</div>
      <div class="rpt-form" style="grid-template-columns:1fr">
        <div class="rpt-field">
          <label>Organisation Name</label>
          <input type="text" id="rpt-org-name" placeholder="Your Organisation" oninput="Reports.preview()">
        </div>
        <div class="rpt-field">
          <label>Report Title</label>
          <input type="text" id="rpt-title" value="M365 Compliance Assessment Report" oninput="Reports.preview()">
        </div>
        <div class="rpt-field">
          <label>Subtitle</label>
          <input type="text" id="rpt-subtitle" placeholder="CIS Microsoft 365 Benchmark v3" oninput="Reports.preview()">
        </div>
        <div class="rpt-field">
          <label>Author</label>
          <input type="text" id="rpt-author" placeholder="Author name" oninput="Reports.preview()">
        </div>
        <div class="rpt-field">
          <label>Logo (max 500KB)</label>
          <input type="file" id="rpt-logo" accept="image/*" onchange="Reports.handleLogo(this)" style="font-size:.68rem">
          <div id="rpt-logo-preview" style="margin-top:4px"></div>
        </div>
        <div class="rpt-field" style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          <div>
            <label>Primary Colour</label>
            <input type="color" id="rpt-color-primary" value="#1d4ed8" onchange="Reports.preview()">
          </div>
          <div>
            <label>Accent Colour</label>
            <input type="color" id="rpt-color-accent" value="#d97706" onchange="Reports.preview()">
          </div>
        </div>
      </div>

      <div class="section-hdr">Sections</div>
      <div style="display:flex;flex-direction:column;gap:2px">
        <label class="rpt-toggle"><input type="checkbox" id="sec-exec" checked onchange="Reports.preview()"> Executive Summary</label>
        <label class="rpt-toggle"><input type="checkbox" id="sec-kpi" checked onchange="Reports.preview()"> KPI Overview</label>
        <label class="rpt-toggle"><input type="checkbox" id="sec-score" checked onchange="Reports.preview()"> Score Breakdown</label>
        <label class="rpt-toggle"><input type="checkbox" id="sec-fwcov" checked onchange="Reports.preview()"> Framework Coverage</label>
        <label class="rpt-toggle"><input type="checkbox" id="sec-gaps" checked onchange="Reports.preview()"> Gap Register</label>
        <label class="rpt-toggle"><input type="checkbox" id="sec-roadmap" checked onchange="Reports.preview()"> Remediation Roadmap</label>
        <label class="rpt-toggle"><input type="checkbox" id="sec-fwdetails" onchange="Reports.preview()"> Framework Details</label>
        <label class="rpt-toggle"><input type="checkbox" id="sec-deploystatus" onchange="Reports.preview()"> Deployment Status</label>
        <label class="rpt-toggle"><input type="checkbox" id="sec-method" onchange="Reports.preview()"> Methodology</label>
      </div>

      <div class="section-hdr">Additional Content</div>
      <div class="rpt-field">
        <label>Executive Summary</label>
        <textarea id="rpt-exec-summary" rows="3" placeholder="Enter executive summary..." oninput="Reports.preview()"></textarea>
      </div>
      <div class="rpt-field">
        <label>Recommendations</label>
        <textarea id="rpt-recommendations" rows="3" placeholder="Enter recommendations..." oninput="Reports.preview()"></textarea>
      </div>
      <div class="rpt-field">
        <label>Methodology</label>
        <textarea id="rpt-methodology" rows="3" placeholder="Describe methodology and scope..." oninput="Reports.preview()"></textarea>
      </div>
      <div class="rpt-field">
        <label>Disclaimer</label>
        <textarea id="rpt-disclaimer" rows="2" placeholder="Footer disclaimer text..." oninput="Reports.preview()"></textarea>
      </div>

      <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
        <button class="btn btn-primary" onclick="Reports.exportPDF()">Export PDF</button>
        <button class="btn btn-amber" onclick="Reports.exportHTML()">Export HTML</button>
        <button class="btn" onclick="Reports.exportExcel()">Export Excel</button>
      </div>
      <div style="display:flex;gap:8px;margin-top:8px">
        ${typeof EvidenceCollector !== 'undefined' ? EvidenceCollector.renderExportButton() : ''}
      </div>
    </div>`;

    // Preview canvas
    html += `<div>
      ${!hasData ? `<div class="card" style="text-align:center;padding:40px;margin-bottom:16px">
        <p style="color:var(--ink3);font-size:.78rem">Complete an assessment first to populate the report with real data.</p>
        <button class="btn btn-amber btn-sm" onclick="Router.navigate('assessment')" style="margin-top:8px">Go to Assessment</button>
      </div>` : ''}
      <div id="report-canvas" style="background:white"></div>
    </div>`;

    html += `</div>`;
    container.innerHTML = html;

    // Initial preview
    preview();
  }

  function handleLogo(input) {
    var file = input.files && input.files[0];
    var previewEl = document.getElementById('rpt-logo-preview');
    if (!file) { logoDataUrl = null; if (previewEl) previewEl.innerHTML = ''; preview(); return; }
    if (file.size > 500 * 1024) {
      showToast('Logo must be under 500KB');
      input.value = '';
      return;
    }
    var reader = new FileReader();
    reader.onload = function (e) {
      logoDataUrl = e.target.result;
      if (previewEl) previewEl.innerHTML = '<img src="' + logoDataUrl + '" style="max-height:40px;max-width:120px;margin-top:4px">';
      preview();
    };
    reader.readAsDataURL(file);
  }

  function val(id) { return document.getElementById(id)?.value || ''; }
  function checked(id) { return document.getElementById(id)?.checked ?? false; }

  function preview() {
    const canvas = document.getElementById('report-canvas');
    if (!canvas) return;

    const orgName = val('rpt-org-name') || 'Organisation';
    const title = val('rpt-title') || 'M365 Compliance Assessment Report';
    const subtitle = val('rpt-subtitle');
    const author = val('rpt-author');
    const primary = val('rpt-color-primary') || '#1d4ed8';
    const accent = val('rpt-color-accent') || '#d97706';
    const execSummary = val('rpt-exec-summary');
    const recommendations = val('rpt-recommendations');
    const methodology = val('rpt-methodology');
    const disclaimer = val('rpt-disclaimer');
    const today = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

    const secExec = checked('sec-exec');
    const secKpi = checked('sec-kpi');
    const secScore = checked('sec-score');
    const secFwcov = checked('sec-fwcov');
    const secGaps = checked('sec-gaps');
    const secRoadmap = checked('sec-roadmap');
    const secFwDetails = checked('sec-fwdetails');
    const secDeployStatus = checked('sec-deploystatus');
    const secMethod = checked('sec-method');

    const stats = AppState.getScoreStats();
    const fwBars = AppState.getFrameworkCoverage();
    const gaps = AppState.getGaps().slice(0, 25);
    const sel = AppState.get('selectedFrameworks');

    // Build donut SVG
    const donutC = 80, donutR = donutC * 0.38;
    const circ = 2 * Math.PI * donutR;
    const perimDone = (stats.done / Math.max(stats.total, 1)) * circ;
    const perimGap = (stats.gap / Math.max(stats.total, 1)) * circ;
    const perimUnrev = circ - perimDone - perimGap;
    const donutSvg = `<svg width="${donutC*2}" height="${donutC*2}" viewBox="0 0 ${donutC*2} ${donutC*2}" style="transform:rotate(-90deg)">
      <circle cx="${donutC}" cy="${donutC}" r="${donutR}" fill="none" stroke="#eef0f4" stroke-width="14"/>
      <circle cx="${donutC}" cy="${donutC}" r="${donutR}" fill="none" stroke="${primary}" stroke-width="14"
        stroke-dasharray="${perimDone} ${circ - perimDone}" stroke-dashoffset="0"/>
      <circle cx="${donutC}" cy="${donutC}" r="${donutR}" fill="none" stroke="#dc2626" stroke-width="14"
        stroke-dasharray="${perimGap} ${circ - perimGap}" stroke-dashoffset="${-perimDone}"/>
      <circle cx="${donutC}" cy="${donutC}" r="${donutR}" fill="none" stroke="#d1d5db" stroke-width="14"
        stroke-dasharray="${perimUnrev} ${circ - perimUnrev}" stroke-dashoffset="${-(perimDone + perimGap)}"/>
    </svg>`;

    canvas.innerHTML = `
    <div style="--rpt-primary:${primary};--rpt-accent:${accent}">
      <div class="rpt-cover" style="background:linear-gradient(135deg, ${primary} 0%, ${shadeColour(primary,-40)} 100%);page-break-after:always">
        ${logoDataUrl ? `<img src="${logoDataUrl}" style="max-height:48px;max-width:160px;margin-bottom:16px">` : ''}
        <div style="font-family:'IBM Plex Mono',monospace;font-size:.7rem;opacity:.5;margin-bottom:20px">${escHtml(orgName)}</div>
        <div class="rpt-cover-title">${escHtml(title)}</div>
        ${subtitle ? `<div class="rpt-cover-subtitle">${escHtml(subtitle)}</div>` : ''}
        <div class="rpt-cover-meta">
          <span>${today}</span>
          ${author ? `<span>${escHtml(author)}</span>` : ''}
          <span>CIS M365 v3 Benchmark</span>
        </div>
      </div>
      <div class="rpt-body" style="padding:24px 32px">

        ${secExec && execSummary ? `
          <div class="rpt-section-head" style="color:${primary};border-bottom:2px solid ${primary}">Executive Summary</div>
          <div style="background:#f4f6f9;border-left:3px solid ${accent};padding:12px 16px;font-size:.78rem;color:#374151;line-height:1.6;white-space:pre-wrap;margin-bottom:16px">${escHtml(execSummary)}</div>
        ` : ''}

        ${secKpi ? `
          <div class="rpt-section-head" style="color:${primary};border-bottom:2px solid ${primary}">Assessment Overview</div>
          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px">
            ${kpiBox('Compliance Score', stats.score + '%', primary)}
            ${kpiBox('Controls Implemented', stats.done, '#16a34a')}
            ${kpiBox('Gaps Identified', stats.gap, '#dc2626')}
            ${kpiBox('Frameworks Assessed', sel.size, primary)}
          </div>
        ` : ''}

        ${secScore ? `
          <div class="rpt-section-head" style="color:${primary};border-bottom:2px solid ${primary}">Score Breakdown</div>
          <div style="display:grid;grid-template-columns:160px 1fr;gap:20px;align-items:center;margin-bottom:20px">
            <div style="position:relative;display:inline-block">
              ${donutSvg}
              <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center">
                <div style="font-family:'IBM Plex Mono',monospace;font-weight:600;font-size:1.2rem;color:${primary}">${stats.score}%</div>
              </div>
            </div>
            <div style="display:flex;flex-direction:column;gap:6px;font-size:.73rem">
              <div style="display:flex;align-items:center;gap:8px"><div style="width:10px;height:10px;background:${primary}"></div>Implemented <span style="margin-left:auto;font-family:'IBM Plex Mono',monospace;font-weight:600;color:${primary}">${stats.done}</span></div>
              <div style="display:flex;align-items:center;gap:8px"><div style="width:10px;height:10px;background:#dc2626"></div>Gaps <span style="margin-left:auto;font-family:'IBM Plex Mono',monospace;font-weight:600;color:#dc2626">${stats.gap}</span></div>
              <div style="display:flex;align-items:center;gap:8px"><div style="width:10px;height:10px;background:#d1d5db"></div>Not Reviewed <span style="margin-left:auto;font-family:'IBM Plex Mono',monospace;font-weight:600;color:#9ca3af">${stats.unrev}</span></div>
            </div>
          </div>
        ` : ''}

        ${secFwcov && fwBars.length > 0 ? `
          <div class="rpt-section-head" style="color:${primary};border-bottom:2px solid ${primary}">Framework Coverage</div>
          ${fwBars.map(b => `
            <div style="display:grid;grid-template-columns:160px 1fr 50px;align-items:center;gap:8px;margin-bottom:5px">
              <div style="font-size:.72rem;color:#374151;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${b.fw}">${b.fw}</div>
              <div style="height:6px;background:#eef0f4;overflow:hidden"><div style="height:100%;width:${b.pct}%;background:${b.pct>80?'#16a34a':b.pct>50?primary:'#dc2626'}"></div></div>
              <div style="font-family:'IBM Plex Mono',monospace;font-size:.68rem;color:#9ca3af;text-align:right">${b.pct}%</div>
            </div>
          `).join('')}
        ` : ''}

        ${secGaps && gaps.length > 0 ? `
          <div class="rpt-section-head" style="color:${primary};border-bottom:2px solid ${primary}">Gap Register (Top ${gaps.length})</div>
          <table style="width:100%;border-collapse:collapse;font-size:.72rem;margin-bottom:20px">
            <thead><tr>
              <th style="background:${primary};color:white;padding:6px 10px;text-align:left;font-size:.6rem;text-transform:uppercase;letter-spacing:.05em">ID</th>
              <th style="background:${primary};color:white;padding:6px 10px;text-align:left;font-size:.6rem;text-transform:uppercase;letter-spacing:.05em">Control</th>
              <th style="background:${primary};color:white;padding:6px 10px;text-align:left;font-size:.6rem;text-transform:uppercase;letter-spacing:.05em">Cat</th>
              <th style="background:${primary};color:white;padding:6px 10px;text-align:left;font-size:.6rem;text-transform:uppercase;letter-spacing:.05em">Level</th>
              <th style="background:${primary};color:white;padding:6px 10px;text-align:left;font-size:.6rem;text-transform:uppercase;letter-spacing:.05em">Priority</th>
              <th style="background:${primary};color:white;padding:6px 10px;text-align:left;font-size:.6rem;text-transform:uppercase;letter-spacing:.05em">Impact</th>
            </tr></thead>
            <tbody>
              ${gaps.map((g, i) => `<tr>
                <td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-family:'IBM Plex Mono',monospace;font-size:.66rem;color:${primary};font-weight:600;${i%2?'background:#f8f9fc;':''}">${g.id}</td>
                <td style="padding:5px 10px;border-bottom:1px solid #d8dce6;max-width:260px;${i%2?'background:#f8f9fc;':''}">${g.name}</td>
                <td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-family:'IBM Plex Mono',monospace;font-size:.62rem;${i%2?'background:#f8f9fc;':''}">${g.cat}</td>
                <td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-family:'IBM Plex Mono',monospace;font-weight:600;color:${g.level==='L1'?'#16a34a':'#d97706'};${i%2?'background:#f8f9fc;':''}">${g.level}</td>
                <td style="padding:5px 10px;border-bottom:1px solid #d8dce6;${i%2?'background:#f8f9fc;':''}"><span style="font-family:'IBM Plex Mono',monospace;font-size:.6rem;padding:2px 6px;font-weight:600;${g.tier==='critical'?'background:#fef2f2;color:#dc2626;border:1px solid #fee2e2':g.tier==='high'?'background:#fefce8;color:#ca8a04;border:1px solid #fef08a':'background:#eff6ff;color:#1d4ed8;border:1px solid #dbeafe'}">${g.tier}</span></td>
                <td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-family:'IBM Plex Mono',monospace;font-size:.66rem;${i%2?'background:#f8f9fc;':''}">${g.impact} fw</td>
              </tr>`).join('')}
            </tbody>
          </table>
        ` : ''}

        ${secRoadmap && gaps.length > 0 ? `
          <div class="rpt-section-head" style="color:${primary};border-bottom:2px solid ${primary}">Remediation Roadmap</div>
          ${roadmapSection(gaps.filter(g=>g.tier==='critical'), 'Critical Priority', '#dc2626', primary)}
          ${roadmapSection(gaps.filter(g=>g.tier==='high'), 'High Priority', '#d97706', primary)}
        ` : ''}

        ${secFwDetails ? renderFrameworkDetailsSection(primary, sel) : ''}

        ${secDeployStatus ? renderDeployStatusSection(primary) : ''}

        ${recommendations ? `
          <div class="rpt-section-head" style="color:${primary};border-bottom:2px solid ${primary}">Recommendations</div>
          <div style="background:#f4f6f9;border-left:3px solid ${accent};padding:12px 16px;font-size:.78rem;color:#374151;line-height:1.6;white-space:pre-wrap">${escHtml(recommendations)}</div>
        ` : ''}

        ${secMethod && methodology ? `
          <div class="rpt-section-head" style="color:${primary};border-bottom:2px solid ${primary}">Methodology & Scope</div>
          <div style="font-size:.76rem;color:#374151;line-height:1.6;white-space:pre-wrap">${escHtml(methodology)}</div>
        ` : ''}

      </div>
      <div style="background:#f4f6f9;border-top:1px solid #d8dce6;padding:12px 32px;display:flex;justify-content:space-between;font-size:.64rem;color:#9ca3af">
        <span>${disclaimer ? escHtml(disclaimer) : `Confidential - ${escHtml(orgName)}`}</span>
        <span>${today} &middot; M365 Compliance Framework &middot; CIS M365 v3</span>
      </div>
    </div>`;
  }

  function kpiBox(label, value, color) {
    return `<div style="border:1px solid #d8dce6;padding:12px;position:relative;overflow:hidden">
      <div style="position:absolute;top:0;left:0;right:0;height:3px;background:${color}"></div>
      <div style="font-family:'IBM Plex Mono',monospace;font-weight:600;font-size:1.6rem;color:${color};line-height:1">${value}</div>
      <div style="font-size:.62rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#9ca3af;margin-top:2px">${label}</div>
    </div>`;
  }

  function roadmapSection(items, title, titleColor, primary) {
    if (items.length === 0) return '';
    return `<div style="margin-bottom:12px">
      <div style="font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:${titleColor};margin-bottom:6px">${title}</div>
      ${items.slice(0, 10).map(g => `
        <div style="display:flex;align-items:flex-start;gap:10px;padding:5px 0;border-bottom:1px solid #d8dce6;font-size:.72rem">
          <span style="font-family:'IBM Plex Mono',monospace;font-size:.66rem;color:${primary};min-width:48px;font-weight:600">${g.id}</span>
          <span style="color:#374151;flex:1">${g.name}</span>
          <span style="font-family:'IBM Plex Mono',monospace;font-size:.6rem;color:#9ca3af">${g.impact}fw</span>
        </div>
      `).join('')}
    </div>`;
  }

  function renderFrameworkDetailsSection(primary, selFws) {
    var meta = AppState.get('frameworkMeta') || {};
    var fwList = [...selFws].filter(function (fw) { return meta[fw]; });
    if (fwList.length === 0) return '';

    var html = '<div class="rpt-section-head" style="color:' + primary + ';border-bottom:2px solid ' + primary + '">Framework Details</div>';
    html += '<table style="width:100%;border-collapse:collapse;font-size:.72rem;margin-bottom:20px;page-break-inside:avoid">';
    html += '<thead><tr>';
    ['Framework', 'Type', 'Version', 'Publisher', 'Jurisdiction'].forEach(function (h) {
      html += '<th style="background:' + primary + ';color:white;padding:6px 10px;text-align:left;font-size:.6rem;text-transform:uppercase;letter-spacing:.05em">' + h + '</th>';
    });
    html += '</tr></thead><tbody>';

    fwList.forEach(function (fw, i) {
      var m = meta[fw];
      var bg = i % 2 ? 'background:#f8f9fc;' : '';
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-weight:600;color:' + primary + ';' + bg + '">' + escHtml(fw) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;' + bg + '">' + escHtml(m.type || '-') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-family:\'IBM Plex Mono\',monospace;font-size:.66rem;' + bg + '">' + escHtml(m.version || '-') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;' + bg + '">' + escHtml(m.publisher || '-') + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;' + bg + '">' + escHtml(m.jurisdiction || '-') + '</td>';
      html += '</tr>';
    });

    html += '</tbody></table>';
    return html;
  }

  function renderDeployStatusSection(primary) {
    var history = AppState.getDeploymentHistory ? AppState.getDeploymentHistory() : [];
    if (history.length === 0) return '';

    var success = history.filter(function (h) { return h.status === 'success'; }).length;
    var failed = history.filter(function (h) { return h.status === 'failed'; }).length;
    var recent = history.slice(0, 20);

    var html = '<div class="rpt-section-head" style="color:' + primary + ';border-bottom:2px solid ' + primary + '">Deployment Status</div>';

    // Summary KPIs
    html += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px">';
    html += kpiBox('Total Deployments', history.length, primary);
    html += kpiBox('Successful', success, '#16a34a');
    html += kpiBox('Failed', failed, '#dc2626');
    html += '</div>';

    // Recent deployments table
    html += '<table style="width:100%;border-collapse:collapse;font-size:.72rem;margin-bottom:20px;page-break-inside:avoid">';
    html += '<thead><tr>';
    ['Policy', 'Date', 'Status', 'Detail'].forEach(function (h) {
      html += '<th style="background:' + primary + ';color:white;padding:6px 10px;text-align:left;font-size:.6rem;text-transform:uppercase;letter-spacing:.05em">' + h + '</th>';
    });
    html += '</tr></thead><tbody>';

    recent.forEach(function (h, i) {
      var bg = i % 2 ? 'background:#f8f9fc;' : '';
      var d = new Date(h.timestamp);
      var ts = d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
      var statusColor = h.status === 'success' ? '#16a34a' : h.status === 'failed' ? '#dc2626' : '#d97706';
      html += '<tr>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-family:\'IBM Plex Mono\',monospace;font-size:.66rem;color:' + primary + ';font-weight:600;' + bg + '">' + escHtml(h.policyId) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-size:.66rem;' + bg + '">' + escHtml(ts) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;color:' + statusColor + ';font-weight:600;' + bg + '">' + escHtml(h.status) + '</td>';
      html += '<td style="padding:5px 10px;border-bottom:1px solid #d8dce6;font-size:.66rem;color:#9ca3af;' + bg + '">' + escHtml(h.detail || '-') + '</td>';
      html += '</tr>';
    });

    html += '</tbody></table>';
    if (history.length > 20) {
      html += '<div style="font-size:.62rem;color:#9ca3af">Showing 20 of ' + history.length + ' entries. Export full log from the application.</div>';
    }
    return html;
  }

  function exportPDF() {
    window.print();
  }

  function exportHTML() {
    const canvas = document.getElementById('report-canvas');
    if (!canvas) return;
    const orgName = val('rpt-org-name') || 'report';
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Compliance Report - ${escHtml(orgName)}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Plus Jakarta Sans',sans-serif;background:white;color:#111827;max-width:900px;margin:0 auto}
</style>
</head>
<body>
${canvas.innerHTML}
</body>
</html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `M365-Compliance-Report-${orgName.replace(/[^a-z0-9]/gi, '_')}.html`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Report exported as HTML');
  }

  function shadeColour(hex, amt) {
    const num = parseInt(hex.slice(1), 16);
    const r = Math.max(0, Math.min(255, (num >> 16) + amt));
    const g = Math.max(0, Math.min(255, ((num >> 8) & 0xff) + amt));
    const b = Math.max(0, Math.min(255, (num & 0xff) + amt));
    return '#' + [r, g, b].map(v => v.toString(16).padStart(2, '0')).join('');
  }

  // ── Excel Export ──
  function exportExcel() {
    if (typeof XLSX === 'undefined') {
      showToast('SheetJS library not loaded — Excel export unavailable');
      return;
    }

    var orgName = val('rpt-org-name') || 'Organisation';
    var wb = XLSX.utils.book_new();

    // Sheet 1: Summary
    var stats = AppState.getScoreStats();
    var summaryData = [
      ['M365 Compliance Assessment Report'],
      ['Organisation', orgName],
      ['Date', new Date().toLocaleDateString()],
      [''],
      ['Compliance Score', stats.score + '%'],
      ['Controls Implemented', stats.done],
      ['Gaps Identified', stats.gap],
      ['Not Reviewed', stats.unrev],
      ['Total Controls', stats.total],
      ['Frameworks Assessed', AppState.get('selectedFrameworks').size],
    ];

    // Add scan summary if available
    var scanResults = AppState.get('tenantScanResults') || {};
    var scanKeys = Object.keys(scanResults);
    if (scanKeys.length > 0) {
      var scanSummary = { configured: 0, missing: 0, manual: 0, total: scanKeys.length };
      scanKeys.forEach(function (id) {
        var s = scanResults[id].status;
        if (s === 'configured') scanSummary.configured++;
        else if (s === 'missing') scanSummary.missing++;
        else if (s === 'manual') scanSummary.manual++;
      });
      summaryData.push(['']);
      summaryData.push(['Tenant Scan Results']);
      summaryData.push(['Policies Configured', scanSummary.configured]);
      summaryData.push(['Policies Missing', scanSummary.missing]);
      summaryData.push(['Manual Verification', scanSummary.manual]);
      summaryData.push(['Total Policies', scanSummary.total]);
    }

    var ws1 = XLSX.utils.aoa_to_sheet(summaryData);
    ws1['!cols'] = [{ wch: 25 }, { wch: 20 }];
    XLSX.utils.book_append_sheet(wb, ws1, 'Summary');

    // Sheet 2: Gap Register
    var gaps = AppState.getGaps();
    var gapData = [['Check ID', 'Control', 'Category', 'Level', 'Priority', 'Impact (Frameworks)']];
    gaps.forEach(function (g) {
      gapData.push([g.id, g.name, g.cat, g.level, g.tier, g.impact]);
    });
    var ws2 = XLSX.utils.aoa_to_sheet(gapData);
    ws2['!cols'] = [{ wch: 12 }, { wch: 50 }, { wch: 15 }, { wch: 8 }, { wch: 10 }, { wch: 18 }];
    XLSX.utils.book_append_sheet(wb, ws2, 'Gap Register');

    // Sheet 3: Framework Coverage
    var fwCoverage = AppState.getFrameworkCoverage();
    var fwData = [['Framework', 'Done', 'Total', 'Coverage %']];
    fwCoverage.forEach(function (fw) {
      fwData.push([fw.fw, fw.done, fw.total, fw.pct]);
    });
    var ws3 = XLSX.utils.aoa_to_sheet(fwData);
    ws3['!cols'] = [{ wch: 40 }, { wch: 8 }, { wch: 8 }, { wch: 12 }];
    XLSX.utils.book_append_sheet(wb, ws3, 'Framework Coverage');

    // Sheet 4: Scan Results (if available)
    if (scanKeys.length > 0) {
      var policies = AppState.get('policies') || [];
      var scanData = [['Policy ID', 'Type', 'Status', 'Source', 'Detail']];
      scanKeys.sort().forEach(function (id) {
        var r = scanResults[id];
        var pol = policies.find(function (p) { return p.id === id; });
        scanData.push([id, pol ? pol.type : '', r.status, r.source || '', r.detail || '']);
      });
      var ws4 = XLSX.utils.aoa_to_sheet(scanData);
      ws4['!cols'] = [{ wch: 10 }, { wch: 20 }, { wch: 12 }, { wch: 15 }, { wch: 50 }];
      XLSX.utils.book_append_sheet(wb, ws4, 'Scan Results');
    }

    // Sheet 5: Scan History (from IndexedDB — async, so write what's available)
    var historyData = [['Date', 'Score %', 'Configured', 'Missing', 'Manual', 'Total']];
    var deployHistory = AppState.getDeploymentHistory();
    if (deployHistory.length > 0) {
      var deployData = [['Timestamp', 'Policy ID', 'Status', 'Type', 'Detail']];
      deployHistory.slice(0, 50).forEach(function (h) {
        deployData.push([new Date(h.timestamp).toLocaleString(), h.policyId, h.status, h.type, h.detail]);
      });
      var ws5 = XLSX.utils.aoa_to_sheet(deployData);
      ws5['!cols'] = [{ wch: 22 }, { wch: 10 }, { wch: 10 }, { wch: 15 }, { wch: 40 }];
      XLSX.utils.book_append_sheet(wb, ws5, 'Deployment History');
    }

    var filename = 'M365-Compliance-' + orgName.replace(/[^a-z0-9]/gi, '_') + '-' + new Date().toISOString().slice(0, 10) + '.xlsx';
    XLSX.writeFile(wb, filename);
    showToast('Excel report exported');
  }

  return { init, render, preview, exportPDF, exportHTML, exportExcel, handleLogo };
})();
