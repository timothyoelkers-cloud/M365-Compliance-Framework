/* ═══════════════════════════════════════════
   REPORTS — Compliance report generator
═══════════════════════════════════════════ */
const Reports = (() => {
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

      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="btn btn-primary" onclick="Reports.exportPDF()">Export PDF</button>
        <button class="btn btn-amber" onclick="Reports.exportHTML()">Export HTML</button>
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
      <div class="rpt-cover" style="background:linear-gradient(135deg, ${primary} 0%, ${shadeColour(primary,-40)} 100%)">
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

  return { init, render, preview, exportPDF, exportHTML };
})();
