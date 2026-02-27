/* ═══════════════════════════════════════════
   DASHBOARD — Compliance status overview
═══════════════════════════════════════════ */
const Dashboard = (() => {
  function init() {
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

    let html = '';

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
      for (const bar of fwCoverage) {
        const clr = bar.pct > 80 ? 'var(--green)' : bar.pct > 50 ? 'var(--amber2)' : 'var(--red)';
        html += `<div class="fw-bar">
          <div class="fw-bar-name" title="${bar.fw}">${bar.fw.length > 24 ? bar.fw.slice(0, 22) + '...' : bar.fw}</div>
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

    container.innerHTML = html;
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

  return { init, render };
})();
