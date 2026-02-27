/* ═══════════════════════════════════════════
   ASSESSMENT — 3-step compliance wizard
═══════════════════════════════════════════ */
const Assessment = (() => {
  let initialized = false;
  let sortCol = 'id', sortAsc = true;

  function init() {
    if (!initialized) {
      initialized = true;
      AppState.on('selectedFrameworks', () => {
        if (AppState.get('currentPage') === 'assessment') renderCurrentStep();
      });
    }
    renderStepBar();
    renderCurrentStep();
    renderSidebar();
  }

  function goStep(n) {
    AppState.set('assessmentStep', n);
    renderStepBar();
    renderCurrentStep();
  }

  function renderStepBar() {
    const step = AppState.get('assessmentStep');
    const bar = document.getElementById('assessment-steps');
    if (!bar) return;
    bar.innerHTML = [
      { n: 1, label: '01 Select Frameworks' },
      { n: 2, label: '02 Review Checks' },
      { n: 3, label: '03 Mark Status' },
    ].map(s => {
      const cls = s.n === step ? 'active' : s.n < step ? 'done' : '';
      return `<button class="step-pill ${cls}" onclick="Assessment.goStep(${s.n})">${s.label}</button>`;
    }).join('');
  }

  function renderCurrentStep() {
    const step = AppState.get('assessmentStep');
    const container = document.getElementById('assessment-content');
    if (!container) return;

    if (step === 1) renderStep1(container);
    else if (step === 2) renderStep2(container);
    else if (step === 3) renderStep3(container);
  }

  // ── SIDEBAR ──────────────────────────────
  function renderSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar || AppState.get('currentPage') !== 'assessment') return;

    const fwGroups = AppState.get('fwGroups');
    const sel = AppState.get('selectedFrameworks');

    let html = `<div class="sb-label">Frameworks <span class="text-mono text-xs">${sel.size} selected</span></div>`;

    for (const [group, fws] of Object.entries(fwGroups)) {
      const groupSel = fws.filter(f => sel.has(f)).length;
      html += `<div class="sb-group-hdr${groupSel > 0 ? ' open' : ''}" onclick="this.classList.toggle('open')">
        ${group} <span class="sb-count">${groupSel}/${fws.length}</span>
        <span class="chevron">&#9654;</span>
      </div>
      <div class="sb-group-body">`;
      for (const fw of fws) {
        html += `<label class="sb-item${sel.has(fw) ? ' active' : ''}">
          <input type="checkbox" ${sel.has(fw) ? 'checked' : ''} onchange="Assessment.toggleFw('${escHtml(fw)}')">
          <span class="truncate">${fw}</span>
        </label>`;
      }
      html += `</div>`;
    }

    sidebar.innerHTML = html;
  }

  function toggleFw(fw) {
    AppState.toggleInSet('selectedFrameworks', fw);
    renderSidebar();
    renderCurrentStep();
  }

  // ── STEP 1: Framework Selection ──────────
  function renderStep1(container) {
    const fwGroups = AppState.get('fwGroups');
    const orgProfiles = AppState.get('orgProfiles');
    const sel = AppState.get('selectedFrameworks');

    const groupColors = {
      'EU Regulatory': 'var(--blue)', 'ISO Standards': 'var(--teal)',
      'NIST / US Federal': 'var(--red)', 'US Sector': 'var(--amber)',
      'UK & Ireland': 'var(--purple)', 'APAC & Other': 'var(--green)',
      'Regional': 'var(--amber2)', 'Sector Specific': 'var(--red)',
      'Cloud & Tech': 'var(--teal)',
    };

    let html = `<div class="section-hdr">Organisation Profiles</div>
      <p style="font-size:.74rem;color:var(--ink3);margin-bottom:12px">Select a pre-built profile or choose frameworks manually below.</p>
      <div class="profile-grid">`;

    for (const [name, fws] of Object.entries(orgProfiles)) {
      const isActive = fws.every(f => sel.has(f)) && fws.length > 0;
      html += `<div class="profile-card${isActive ? ' active' : ''}" onclick="Assessment.applyProfile('${escHtml(name)}')">
        <h4>${name}</h4>
        <div class="fw-count">${fws.length} frameworks</div>
      </div>`;
    }
    html += `</div>`;

    html += `<div class="section-hdr" style="margin-top:28px">Framework Groups</div>
      <div class="card-grid">`;

    for (const [group, fws] of Object.entries(fwGroups)) {
      const clr = groupColors[group] || 'var(--ink3)';
      const groupSel = fws.filter(f => sel.has(f)).length;
      html += `<div class="group-card animate-in">
        <div class="group-card-hdr" onclick="this.parentElement.querySelector('.group-card-body').style.display = this.parentElement.querySelector('.group-card-body').style.display === 'none' ? 'block' : 'none'">
          <div class="dot" style="background:${clr}"></div>
          <h4>${group}</h4>
          <span class="badge badge-dark">${groupSel}/${fws.length}</span>
        </div>
        <div class="group-card-body">`;
      for (const fw of fws) {
        html += `<label class="group-fw-item">
          <input type="checkbox" ${sel.has(fw) ? 'checked' : ''} onchange="Assessment.toggleFw('${escHtml(fw)}')">
          ${fw}
        </label>`;
      }
      html += `</div></div>`;
    }
    html += `</div>`;

    if (sel.size > 0) {
      const reqChecks = AppState.getRequiredChecks();
      html += `<div style="margin-top:24px;padding:16px;background:var(--accent-lt);border:1px solid var(--accent-lt2);display:flex;align-items:center;justify-content:space-between">
        <div>
          <strong style="color:var(--accent)">${sel.size}</strong> frameworks selected &mdash;
          <strong style="color:var(--accent)">${reqChecks.length}</strong> checks required
        </div>
        <button class="btn btn-primary" onclick="Assessment.goStep(2)">Next: Review Checks &rarr;</button>
      </div>`;
    }

    container.innerHTML = html;
  }

  function applyProfile(name) {
    const profiles = AppState.get('orgProfiles');
    const fws = profiles[name];
    if (!fws) return;
    const sel = AppState.get('selectedFrameworks');
    // If all are already selected, deselect them
    if (fws.every(f => sel.has(f))) {
      fws.forEach(f => sel.delete(f));
    } else {
      fws.forEach(f => sel.add(f));
    }
    AppState.notify('selectedFrameworks');
    renderSidebar();
    renderStep1(document.getElementById('assessment-content'));
  }

  // ── STEP 2: Review Checks ───────────────
  function renderStep2(container) {
    const checks = AppState.getRequiredChecks();
    const categories = AppState.get('categories');
    const catFilter = AppState.get('catFilter');

    if (checks.length === 0) {
      container.innerHTML = `<div class="card" style="text-align:center;padding:40px">
        <h3 style="color:var(--ink3)">No frameworks selected</h3>
        <p style="color:var(--ink4);margin:8px 0">Go back to Step 1 and select at least one framework.</p>
        <button class="btn btn-amber" onclick="Assessment.goStep(1)">&larr; Back to Step 1</button>
      </div>`;
      return;
    }

    let html = `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
      <div>
        <span class="badge badge-green">${checks.length} checks</span>
        <span class="badge badge-blue">${AppState.get('selectedFrameworks').size} frameworks</span>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-sm" onclick="Assessment.toggleHeatmap()">Heatmap</button>
        <button class="btn btn-primary btn-sm" onclick="Assessment.goStep(3)">Next: Mark Status &rarr;</button>
      </div>
    </div>`;

    // Category pills
    html += `<div class="filter-bar">
      <button class="filter-pill${!catFilter ? ' active' : ''}" onclick="Assessment.setCatFilter('')">All</button>`;
    for (const cat of categories) {
      const count = checks.filter(c => c.cat === cat).length;
      if (count > 0) {
        html += `<button class="filter-pill${catFilter === cat ? ' active' : ''}" onclick="Assessment.setCatFilter('${escHtml(cat)}')">${cat} <span class="text-mono text-xs">${count}</span></button>`;
      }
    }
    html += `</div>`;

    // Heatmap container
    html += `<div id="heatmap-container" class="hidden" style="margin-bottom:20px;overflow-x:auto"></div>`;

    // Table
    const filtered = catFilter ? checks.filter(c => c.cat === catFilter) : checks;
    const sorted = [...filtered].sort((a, b) => {
      let va = a[sortCol], vb = b[sortCol];
      if (sortCol === 'impact') {
        va = AppState.getCheckFwsInScope(a).length;
        vb = AppState.getCheckFwsInScope(b).length;
      }
      if (typeof va === 'string') return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      return sortAsc ? va - vb : vb - va;
    });

    html += `<table class="data-table">
      <thead><tr>
        <th onclick="Assessment.sort('id')" style="width:70px">ID ${sortIcon('id')}</th>
        <th onclick="Assessment.sort('name')">Control ${sortIcon('name')}</th>
        <th onclick="Assessment.sort('cat')" style="width:120px">Category ${sortIcon('cat')}</th>
        <th onclick="Assessment.sort('level')" style="width:60px">Level ${sortIcon('level')}</th>
        <th onclick="Assessment.sort('impact')" style="width:80px">Impact ${sortIcon('impact')}</th>
      </tr></thead>
      <tbody>`;

    for (const c of sorted) {
      const impact = AppState.getCheckFwsInScope(c).length;
      const lvlClr = c.level === 'L1' ? 'var(--green)' : 'var(--amber)';
      html += `<tr>
        <td class="text-mono" style="font-size:.67rem;color:var(--blue);font-weight:600">${c.id}</td>
        <td style="font-size:.74rem">${c.name}</td>
        <td><span class="badge badge-blue">${c.cat}</span></td>
        <td><span class="text-mono" style="font-weight:600;color:${lvlClr}">${c.level}</span></td>
        <td class="text-mono" style="font-size:.67rem">${impact} fw</td>
      </tr>`;
    }
    html += `</tbody></table>`;

    container.innerHTML = html;
  }

  function sort(col) {
    if (sortCol === col) sortAsc = !sortAsc;
    else { sortCol = col; sortAsc = true; }
    renderCurrentStep();
  }

  function sortIcon(col) {
    if (sortCol !== col) return '';
    return sortAsc ? '&#9650;' : '&#9660;';
  }

  function setCatFilter(cat) {
    AppState.set('catFilter', cat);
    renderCurrentStep();
  }

  function toggleHeatmap() {
    const el = document.getElementById('heatmap-container');
    if (!el) return;
    if (el.classList.contains('hidden')) {
      el.classList.remove('hidden');
      renderHeatmap(el);
    } else {
      el.classList.add('hidden');
    }
  }

  function renderHeatmap(container) {
    const checks = AppState.getRequiredChecks();
    const fws = [...AppState.get('selectedFrameworks')];
    if (fws.length === 0 || checks.length === 0) return;

    const maxFws = Math.min(fws.length, 20); // Limit for readability
    const displayFws = fws.slice(0, maxFws);

    let html = `<div class="heatmap-grid" style="--fw-count:${displayFws.length}">`;
    // Header row
    html += `<div class="heatmap-cell" style="background:var(--dark-bg)"></div>`;
    for (const fw of displayFws) {
      html += `<div class="heatmap-header">${fw.length > 18 ? fw.slice(0, 16) + '...' : fw}</div>`;
    }

    // Data rows (limit to 30 for performance)
    const displayChecks = checks.slice(0, 30);
    for (const c of displayChecks) {
      html += `<div class="heatmap-check-name" title="${c.id} - ${escHtml(c.name)}">${c.id} ${c.name.length > 30 ? c.name.slice(0, 28) + '...' : c.name}</div>`;
      for (const fw of displayFws) {
        const on = c.fws.includes(fw);
        html += `<div class="heatmap-cell ${on ? 'heatmap-on' : 'heatmap-off'}">${on ? '&#10003;' : ''}</div>`;
      }
    }
    html += `</div>`;
    if (checks.length > 30) {
      html += `<div style="font-size:.65rem;color:var(--ink4);margin-top:4px">Showing first 30 of ${checks.length} checks</div>`;
    }
    container.innerHTML = html;
  }

  // ── STEP 3: Mark Status ──────────────────
  function renderStep3(container) {
    const checks = AppState.getRequiredChecks();
    const status = AppState.get('checkStatus');
    const statusFilter = AppState.get('statusFilter');
    const catFilter = AppState.get('catFilter');

    if (checks.length === 0) {
      container.innerHTML = `<div class="card" style="text-align:center;padding:40px">
        <h3 style="color:var(--ink3)">No frameworks selected</h3>
        <button class="btn btn-amber" onclick="Assessment.goStep(1)">&larr; Back to Step 1</button>
      </div>`;
      return;
    }

    const done = checks.filter(c => status[c.id] === 'done').length;
    const gap = checks.filter(c => status[c.id] === 'gap').length;
    const unrev = checks.length - done - gap;

    let html = `<div class="kpi-row">
      <div class="kpi" style="cursor:pointer" onclick="Assessment.setStatusFilter('')">
        <div class="kpi-num" style="color:var(--blue)">${checks.length}</div>
        <div class="kpi-label">Total Checks</div>
      </div>
      <div class="kpi" style="cursor:pointer" onclick="Assessment.setStatusFilter('done')">
        <div class="kpi-num" style="color:var(--green)">${done}</div>
        <div class="kpi-label">Implemented</div>
      </div>
      <div class="kpi" style="cursor:pointer" onclick="Assessment.setStatusFilter('gap')">
        <div class="kpi-num" style="color:var(--red)">${gap}</div>
        <div class="kpi-label">Gaps</div>
      </div>
      <div class="kpi" style="cursor:pointer" onclick="Assessment.setStatusFilter('')">
        <div class="kpi-num" style="color:var(--ink4)">${unrev}</div>
        <div class="kpi-label">Not Reviewed</div>
      </div>
    </div>`;

    // Bulk actions
    html += `<div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
      <button class="btn btn-sm btn-primary" onclick="Assessment.markAllDone()">Mark All Done</button>
      <button class="btn btn-sm" onclick="Assessment.markAllGap()">Mark All Gap</button>
      <button class="btn btn-sm" onclick="Assessment.clearAllStatus()">Clear All</button>
      <div style="flex:1"></div>
      <button class="btn btn-sm btn-amber" onclick="Router.navigate('dashboard')">View Dashboard &rarr;</button>
    </div>`;

    // Filter bar
    const categories = AppState.get('categories');
    html += `<div class="filter-bar">
      <button class="filter-pill${!statusFilter ? ' active' : ''}" onclick="Assessment.setStatusFilter('')">All</button>
      <button class="filter-pill${statusFilter === 'done' ? ' active' : ''}" onclick="Assessment.setStatusFilter('done')">Done</button>
      <button class="filter-pill${statusFilter === 'gap' ? ' active' : ''}" onclick="Assessment.setStatusFilter('gap')">Gap</button>
      <button class="filter-pill${statusFilter === 'unrev' ? ' active' : ''}" onclick="Assessment.setStatusFilter('unrev')">Not Reviewed</button>
      <span style="width:1px;background:var(--border);margin:0 4px"></span>`;
    for (const cat of categories) {
      const count = checks.filter(c => c.cat === cat).length;
      if (count > 0) {
        html += `<button class="filter-pill${catFilter === cat ? ' active' : ''}" onclick="Assessment.setCatFilter('${escHtml(cat)}')">${cat}</button>`;
      }
    }
    html += `</div>`;

    // Filter checks
    let filtered = checks;
    if (statusFilter === 'done') filtered = filtered.filter(c => status[c.id] === 'done');
    else if (statusFilter === 'gap') filtered = filtered.filter(c => status[c.id] === 'gap');
    else if (statusFilter === 'unrev') filtered = filtered.filter(c => !status[c.id]);
    if (catFilter) filtered = filtered.filter(c => c.cat === catFilter);

    // Table
    html += `<table class="data-table">
      <thead><tr>
        <th style="width:70px">ID</th>
        <th>Control</th>
        <th style="width:100px">Category</th>
        <th style="width:50px">Level</th>
        <th style="width:70px">Impact</th>
        <th style="width:140px">Status</th>
      </tr></thead>
      <tbody>`;

    for (const c of filtered) {
      const s = status[c.id] || '';
      const impact = AppState.getCheckFwsInScope(c).length;
      const lvlClr = c.level === 'L1' ? 'var(--green)' : 'var(--amber)';
      html += `<tr>
        <td class="text-mono" style="font-size:.67rem;color:var(--blue);font-weight:600">${c.id}</td>
        <td style="font-size:.74rem">${c.name}</td>
        <td><span class="badge badge-blue">${c.cat}</span></td>
        <td><span class="text-mono" style="font-weight:600;color:${lvlClr}">${c.level}</span></td>
        <td class="text-mono" style="font-size:.67rem">${impact} fw</td>
        <td>
          <div style="display:flex;gap:4px">
            <button class="btn btn-sm${s === 'done' ? ' btn-primary' : ''}" onclick="Assessment.setStatus('${c.id}','done')" style="font-size:.6rem">Done</button>
            <button class="btn btn-sm${s === 'gap' ? '' : ''}" onclick="Assessment.setStatus('${c.id}','gap')" style="font-size:.6rem;${s === 'gap' ? 'background:var(--red);color:#fff;border-color:var(--red)' : ''}">Gap</button>
            ${s ? `<button class="btn btn-sm btn-icon" onclick="Assessment.setStatus('${c.id}','')" style="font-size:.6rem" title="Clear">&times;</button>` : ''}
          </div>
        </td>
      </tr>`;
    }
    html += `</tbody></table>`;

    container.innerHTML = html;
  }

  function setStatus(id, status) {
    const cs = AppState.get('checkStatus');
    if (status) cs[id] = status;
    else delete cs[id];
    AppState.notify('checkStatus');
    renderStep3(document.getElementById('assessment-content'));
  }

  function setStatusFilter(f) {
    AppState.set('statusFilter', f);
    renderCurrentStep();
  }

  function markAllDone() {
    const checks = AppState.getRequiredChecks();
    const cs = AppState.get('checkStatus');
    checks.forEach(c => cs[c.id] = 'done');
    AppState.notify('checkStatus');
    renderCurrentStep();
  }

  function markAllGap() {
    const checks = AppState.getRequiredChecks();
    const cs = AppState.get('checkStatus');
    checks.forEach(c => cs[c.id] = 'gap');
    AppState.notify('checkStatus');
    renderCurrentStep();
  }

  function clearAllStatus() {
    AppState.set('checkStatus', {});
    renderCurrentStep();
  }

  return {
    init, goStep, toggleFw, applyProfile,
    sort, setCatFilter, setStatusFilter,
    toggleHeatmap, setStatus,
    markAllDone, markAllGap, clearAllStatus,
  };
})();
