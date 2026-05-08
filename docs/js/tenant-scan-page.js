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

    // Sections are wrapped in <section id="scan-section-*"> so the sticky TOC
    // can deep-link them and highlight as the user scrolls.
    const sections = [
      { id: 'overview',       label: 'Overview',         html: renderTenantOverview() },
      { id: 'provenance',     label: 'Provenance',       html: renderProvenance(scanData) },
      { id: 'schedule',       label: 'Schedule',         html: renderScheduleStrip() },
      { id: 'dashboard',      label: 'Coverage',         html: renderDashboard(scanData, analysis), count: analysis ? analysis.score : null, countSuffix: '/100' },
      { id: 'trend',          label: 'Trend',            html: renderTrendSection() },
      { id: 'drift',          label: 'Drift',            html: renderDriftSection() },
      { id: 'templates',      label: 'Templates',        html: renderTemplatesSection(scanData) },
      { id: 'recommended',    label: 'Recommended',      html: renderRecommendedActions(analysis), count: analysis ? Math.min(10, (analysis.findings || []).filter(f => f.severity !== 'info').length) : null },
      { id: 'frameworks',     label: 'Frameworks',       html: renderFrameworkAlignmentSection() },
      { id: 'flow-cards',     label: 'CA flow cards',    html: renderCAFlowCardsSection(scanData) },
      { id: 'findings',       label: 'Findings',         html: renderFindingsSection(analysis), count: analysis ? (analysis.findings || []).length : null },
      { id: 'inventory',      label: 'Inventory',        html: renderInventorySection(scanData) },
      { id: 'github-compare', label: 'Compare repo',     html: renderGitHubCompareSection() },
    ];

    let mainHtml = '';
    const tocItems = [];
    for (const s of sections) {
      if (!s.html) continue;
      mainHtml += '<section id="scan-section-' + s.id + '">' + s.html + '</section>';
      tocItems.push({ id: s.id, label: s.label, count: s.count, countSuffix: s.countSuffix });
    }

    let html = '<div class="scan-layout">';
    html += '<div class="scan-main">' + mainHtml + '</div>';
    html += _renderTOC(tocItems);
    html += '</div>';

    root.innerHTML = html;
    _attachScrollSpy();

    // Persist this scan into history for the trend chart (idempotent — same
    // tenantId + same timestamp won't add a duplicate).
    if (typeof ScanHistory !== 'undefined' && ScanHistory.saveScan && analysis) {
      try {
        ScanHistory.saveScan(scanData, AppState.get('tenantScanResults') || {}, analysis.counts || {}, analysis.score);
      } catch (e) { /* non-fatal */ }
    }

    // Async-populate trend chart + drift card + tenant overview from IndexedDB.
    setTimeout(() => _loadTrendChart().catch(e => console.warn('[Scan] trend load failed:', e)), 50);
    setTimeout(() => _loadDriftCard().catch(e => console.warn('[Scan] drift load failed:', e)), 75);
    setTimeout(() => _loadTenantOverview().catch(e => console.warn('[Scan] overview load failed:', e)), 100);
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

  // ── Best-practice template matching (CA) ─────────────────────────────
  // Derives a fingerprint from each of our 18 deployable CA policies and
  // scores every tenant CA policy against it. Result per template:
  //   present (≥80% match) / partial (40-79%) / missing (<40% or no match).
  // Mirrors jhope188/ca-policy-analyzer's approach but uses our own
  // policy library as the source of truth instead of his 39 templates.

  function _fingerprintFromPolicy(p) {
    if (!p || !p.conditions) return null;
    return {
      includeUsers:      (p.conditions.users && p.conditions.users.includeUsers) || [],
      includeRoles:      (p.conditions.users && p.conditions.users.includeRoles) || [],
      includeApps:       (p.conditions.applications && p.conditions.applications.includeApplications) || [],
      includeUserActions:(p.conditions.applications && p.conditions.applications.includeUserActions) || [],
      clientAppTypes:    p.conditions.clientAppTypes || [],
      signInRiskLevels:  p.conditions.signInRiskLevels || [],
      userRiskLevels:    p.conditions.userRiskLevels || [],
      grantControls:     (p.grantControls && p.grantControls.builtInControls) || [],
      hasAuthStrength:   !!(p.grantControls && p.grantControls.authenticationStrength),
      sessionSignInFreq: !!(p.sessionControls && p.sessionControls.signInFrequency),
      sessionPersist:    !!(p.sessionControls && p.sessionControls.persistentBrowser),
    };
  }

  function _scoreFingerprint(tenantFp, templateFp) {
    let total = 0, matched = 0;
    function setOverlap(a, b) {
      if (!Array.isArray(a) || !Array.isArray(b)) return false;
      const setA = new Set(a.map(x => String(x).toLowerCase()));
      for (const x of b) if (setA.has(String(x).toLowerCase())) return true;
      return false;
    }
    if (templateFp.includeApps.length > 0) {
      total += 25;
      if (setOverlap(templateFp.includeApps, tenantFp.includeApps)) matched += 25;
    }
    if (templateFp.includeUserActions.length > 0) {
      total += 15;
      if (setOverlap(templateFp.includeUserActions, tenantFp.includeUserActions)) matched += 15;
    }
    if (templateFp.grantControls.length > 0 || templateFp.hasAuthStrength) {
      total += 25;
      const tenantHasMfa = tenantFp.grantControls.includes('mfa') || tenantFp.hasAuthStrength;
      const templateRequiresMfa = templateFp.grantControls.includes('mfa') || templateFp.hasAuthStrength;
      if (templateRequiresMfa && tenantHasMfa) matched += 25;
      else if (setOverlap(templateFp.grantControls, tenantFp.grantControls)) matched += 25;
    }
    if (templateFp.includeRoles.length > 0) {
      total += 15;
      if (setOverlap(templateFp.includeRoles, tenantFp.includeRoles)) matched += 15;
    } else if (templateFp.includeUsers.includes('All')) {
      total += 15;
      if (tenantFp.includeUsers.includes('All')) matched += 15;
    }
    if (templateFp.signInRiskLevels.length > 0) {
      total += 10;
      if (setOverlap(templateFp.signInRiskLevels, tenantFp.signInRiskLevels)) matched += 10;
    }
    if (templateFp.userRiskLevels.length > 0) {
      total += 10;
      if (setOverlap(templateFp.userRiskLevels, tenantFp.userRiskLevels)) matched += 10;
    }
    if (templateFp.clientAppTypes.length > 0) {
      total += 5;
      if (setOverlap(templateFp.clientAppTypes, tenantFp.clientAppTypes)) matched += 5;
    }
    return total > 0 ? Math.round((matched / total) * 100) : 0;
  }

  function renderTemplatesSection(scanData) {
    const allPolicies = AppState.get('policies') || [];
    const data = scanData && scanData.data;
    if (!data || allPolicies.length === 0) return '';

    const blocks = [];
    const caBlock      = _matchCATemplates(allPolicies, data);
    if (caBlock)      blocks.push(caBlock);
    const intuneBlock  = _matchIntuneTemplates(allPolicies, data);
    if (intuneBlock)  blocks.push(intuneBlock);
    const mdeBlock     = _matchMDETemplates(allPolicies, data);
    if (mdeBlock)     blocks.push(mdeBlock);
    const mdoBlock     = _matchMDOTemplates(allPolicies, data);
    if (mdoBlock)     blocks.push(mdoBlock);
    const exoBlock     = _matchEXOTemplates(allPolicies, data);
    if (exoBlock)     blocks.push(exoBlock);
    const purviewBlock = _matchPurviewTemplates(allPolicies, data);
    if (purviewBlock) blocks.push(purviewBlock);
    const entraBlock   = _matchEntraTemplates(allPolicies, data);
    if (entraBlock)   blocks.push(entraBlock);
    const spoBlock     = _matchSPOTemplates(allPolicies, data);
    if (spoBlock)     blocks.push(spoBlock);
    if (blocks.length === 0) return '';

    // Aggregate counts
    let totalPresent = 0, totalPartial = 0, totalMissing = 0, totalCount = 0;
    for (const b of blocks) {
      totalPresent += b.summary.present;
      totalPartial += b.summary.partial;
      totalMissing += b.summary.missing;
      totalCount   += b.summary.total;
    }
    const overall = totalCount > 0 ? Math.round((totalPresent / totalCount) * 100) : 0;
    const colour = overall >= 70 ? 'var(--green)' : overall >= 40 ? 'var(--amber)' : 'var(--red)';

    let html = '<div class="card" style="padding:16px 20px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">Best-practice templates — fingerprint match</strong>';
    html += '<span style="font-size:.66rem;color:var(--ink3)">' + totalPresent + ' present / ' + totalPartial + ' partial / ' + totalMissing + ' missing of ' + totalCount + ' templates · ' + blocks.length + ' workloads</span>';
    html += '<div style="flex:1"></div>';
    html += '<span style="font-size:.74rem;font-weight:600;color:' + colour + '">' + overall + '% coverage</span>';
    html += '</div>';
    html += '<p style="font-size:.62rem;color:var(--ink4);margin:0 0 14px;line-height:1.6">Each template fingerprint is derived from our deployment-ready catalogue. Tenant policies are scored by structure — naming conventions are ignored. Click a missing row to deploy that template.</p>';

    for (const b of blocks) {
      html += '<details ' + (b.summary.missing > 0 ? 'open' : '') + ' style="margin-bottom:10px">';
      html += '<summary style="cursor:pointer;display:flex;align-items:center;gap:10px;padding:6px 0;font-size:.74rem;color:var(--ink2)">';
      html += '<strong>' + escHtml(b.workload) + '</strong>';
      html += '<span style="font-size:.62rem;color:var(--ink3)">' + b.summary.present + ' present / ' + b.summary.partial + ' partial / ' + b.summary.missing + ' missing of ' + b.summary.total + '</span>';
      html += '<div style="flex:1"></div>';
      const wlScore = b.summary.total > 0 ? Math.round((b.summary.present / b.summary.total) * 100) : 0;
      const wlColour = wlScore >= 70 ? 'var(--green)' : wlScore >= 40 ? 'var(--amber)' : 'var(--red)';
      html += '<span style="font-size:.7rem;font-weight:600;color:' + wlColour + '">' + wlScore + '%</span>';
      html += '</summary>';
      html += _renderTemplateMatchTable(b.matches);
      html += '</details>';
    }

    html += '</div>';
    return html;
  }

  function _renderTemplateMatchTable(matches) {
    let html = '<table style="width:100%;border-collapse:collapse;font-size:.66rem;margin-top:6px">';
    html += '<thead><tr style="text-align:left;color:var(--ink3);border-bottom:1px solid var(--border)">' +
            '<th style="padding:6px">Template</th><th style="padding:6px">Status</th><th style="padding:6px">Best match (tenant)</th><th style="padding:6px">Score</th><th style="padding:6px"></th></tr></thead><tbody>';
    matches.sort((a, b) => {
      const order = { missing: 0, partial: 1, present: 2 };
      return order[a.status] - order[b.status] || a.template.id.localeCompare(b.template.id);
    });
    for (const m of matches) {
      const colour = m.status === 'present' ? 'var(--green)' : m.status === 'partial' ? 'var(--amber)' : 'var(--red)';
      html += '<tr style="border-bottom:1px solid var(--border)">';
      html += '<td style="padding:6px;color:var(--ink)"><code style="color:var(--ink3)">' + escHtml(m.template.id) + '</code> ' + escHtml(m.template.displayName || '') + '</td>';
      html += '<td style="padding:6px"><span style="color:' + colour + ';font-weight:600;text-transform:uppercase;font-size:.58rem">' + m.status + '</span></td>';
      html += '<td style="padding:6px;color:var(--ink3)">' + escHtml(m.matchedTenantPolicy ? (m.matchedTenantPolicy.displayName || m.matchedTenantPolicy.name || m.matchedTenantPolicy.id || '') : '—') + '</td>';
      html += '<td style="padding:6px;color:var(--ink4)">' + m.score + '%</td>';
      html += '<td style="padding:6px">' + (m.status === 'missing' ? '<button class="btn btn-sm btn-deploy" onclick="TenantScanPage.deployFix(\'' + escHtml(m.template.id) + '\')">Deploy</button>' : '') + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    return html;
  }

  // Canonical CA fingerprints derived from JH's policy-templates.ts
  // (https://github.com/Jhope188/ca-policy-analyzer). These complement
  // our 18 deployable CA policies — they match by structure only; the
  // template stub provides only id + displayName for the Templates view.
  const JH_CANONICAL_CA = [
    { id: 'JH-FOUND-DEVICECODE',        displayName: 'JH | Block Device Code Auth Flow',          fp: { authenticationFlows: ['deviceCodeFlow'], grantControls: ['block'], includeApps: ['All'], includeUsers: ['All'] } },
    { id: 'JH-FOUND-COUNTRIES',         displayName: 'JH | Block Sign-In from Disallowed Countries', fp: { grantControls: ['block'], includeApps: ['All'], includeUsers: ['All'] /* requires named locations */ } },
    { id: 'JH-FOUND-PLATFORMS',         displayName: 'JH | Block Unsupported Device Platforms',   fp: { grantControls: ['block'], includeApps: ['All'], includeUsers: ['All'] /* uses platforms.exclude */ } },
    { id: 'JH-BASE-MFA-GUESTS',         displayName: 'JH | MFA for External / Guest Users',       fp: { grantControls: ['mfa'], includeApps: ['All'] /* targetsGuests */ } },
    { id: 'JH-BASE-AUTHTRANSFER',       displayName: 'JH | Block Authentication Transfer',        fp: { authenticationFlows: ['authenticationTransfer'], grantControls: ['block'], includeApps: ['All'], includeUsers: ['All'] } },
    { id: 'JH-BASE-SERVICE-ACCOUNTS',   displayName: 'JH | Block Service Accounts',               fp: { grantControls: ['block'] /* targets service-account group */ } },
    { id: 'JH-BASE-REGSECINFO',         displayName: 'JH | MFA for Register Security Info',        fp: { includeUserActions: ['urn:user:registersecurityinfo'], grantControls: ['mfa'] } },
    { id: 'JH-BASE-ADMIN-SESSION',      displayName: 'JH | Session: Admin Persistence (1h)',       fp: { includeRoles: ['*'], sessionSignInFreq: true, sessionPersist: true } },
    { id: 'JH-BASE-USER-SESSION',       displayName: 'JH | Session: User Persistence (9-12h)',    fp: { includeUsers: ['All'], sessionSignInFreq: true, sessionPersist: true, includeApps: ['All'] } },
    { id: 'JH-APP-O365-TIMEOUT',        displayName: 'JH | O365 Session Timeout',                  fp: { includeApps: ['Office365'], sessionSignInFreq: true } },
    { id: 'JH-APP-SP-NONTRUSTED',       displayName: 'JH | Block SharePoint from non-trusted locations', fp: { includeApps: ['00000003-0000-0ff1-ce00-000000000000'], grantControls: ['block'] } },
    { id: 'JH-APP-AVD-NONTRUSTED',      displayName: 'JH | Block AVD from non-trusted locations',  fp: { includeApps: ['9cdead84-a844-4324-93f2-b2e6bb768d07'], grantControls: ['block'] } },
  ];

  // Cache of per-template real-JSON fingerprints. Lazily populated by
  // _loadRealCAFingerprints() (which reads the CA policy files via
  // DataStore.loadPolicy and extracts the actual conditions/grantControls).
  // Until populated, the matcher falls back to the name-derived heuristic.
  const _caFingerprintCache = {};
  let _caFingerprintsLoading = false;
  async function _loadRealCAFingerprints() {
    if (_caFingerprintsLoading) return;
    if (typeof DataStore === 'undefined' || !DataStore.loadPolicy) return;
    _caFingerprintsLoading = true;
    const policies = (AppState.get('policies') || []).filter(p => p.type === 'conditional-access');
    let any = false;
    for (const p of policies) {
      if (_caFingerprintCache[p.id]) continue;
      try {
        const raw = await DataStore.loadPolicy(p.type, p.file);
        _caFingerprintCache[p.id] = _fingerprintFromPolicy(raw);
        any = true;
      } catch (e) { /* ignore — will fall back to heuristic */ }
    }
    if (any) render();  // re-render with the deeper fingerprints
  }

  function _matchCATemplates(allPolicies, data) {
    const tenantPolicies = data.conditionalAccess;
    if (!Array.isArray(tenantPolicies)) return null;
    const caTemplates = allPolicies.filter(p => p.type === 'conditional-access');
    if (caTemplates.length === 0 && JH_CANONICAL_CA.length === 0) return null;
    // Kick off a deeper fingerprint load (non-blocking).
    setTimeout(() => _loadRealCAFingerprints().catch(() => {}), 0);

    // Each template needs the deployable JSON loaded to extract its fingerprint.
    // We'll do this lazily — for the initial render we score against in-memory
    // template metadata only (frameworks + cisChecks list). The first user
    // interaction can deepen the match.
    // For now: use a quick name-derived fingerprint heuristic — every CA
    // policy in our catalogue has a stable naming convention indicating its
    // intent (e.g. "CA01 | Block Legacy Authentication").
    const fingerprints = caTemplates.map(t => {
      // Prefer the JSON-derived fingerprint loaded async by
      // _loadRealCAFingerprints; fall back to name regex while loading.
      if (_caFingerprintCache[t.id]) {
        return { template: t, fp: _caFingerprintCache[t.id] };
      }
      const name = (t.displayName || '').toLowerCase();
      const fp = {
        includeUsers: [], includeRoles: [], includeApps: [], includeUserActions: [],
        clientAppTypes: [], signInRiskLevels: [], userRiskLevels: [],
        grantControls: [], hasAuthStrength: false, sessionSignInFreq: false, sessionPersist: false,
      };
      if (/legacy auth/.test(name))         { fp.clientAppTypes = ['exchangeActiveSync', 'other']; fp.grantControls = ['block']; fp.includeApps = ['All']; fp.includeUsers = ['All']; }
      else if (/mfa.*all|all.*mfa/.test(name)) { fp.grantControls = ['mfa']; fp.includeApps = ['All']; fp.includeUsers = ['All']; }
      else if (/admin.*mfa|mfa.*admin|priv.*role/.test(name)) { fp.grantControls = ['mfa']; fp.hasAuthStrength = true; fp.includeRoles = ['*']; }
      else if (/sign-in risk|signin risk/.test(name))  { fp.signInRiskLevels = ['high']; fp.grantControls = ['block']; }
      else if (/user risk/.test(name))      { fp.userRiskLevels = ['high']; fp.grantControls = ['passwordChange']; }
      else if (/compliant device/.test(name))      { fp.grantControls = ['compliantDevice']; fp.includeApps = ['All']; }
      else if (/managed device|hybrid join/.test(name)) { fp.grantControls = ['domainJoinedDevice']; }
      else if (/location|country/.test(name)) { fp.grantControls = ['block']; fp.includeApps = ['All']; }
      else if (/persistent browser/.test(name)) { fp.sessionPersist = true; }
      else if (/sign.in frequency/.test(name)) { fp.sessionSignInFreq = true; }
      else if (/azure.*management|azure.*portal/.test(name)) { fp.includeApps = ['797f4846-ba00-4fd7-ba43-dac1f8f63013']; fp.grantControls = ['mfa']; }
      else { fp.grantControls = ['mfa']; fp.includeApps = ['All']; }
      return { template: t, fp: fp };
    });

    // Mix in the JH canonical templates — they have explicit fingerprints
    // already, so we just normalise to the same shape used by _scoreFingerprint.
    for (const jh of JH_CANONICAL_CA) {
      const fp = Object.assign({
        includeUsers: [], includeRoles: [], includeApps: [], includeUserActions: [],
        clientAppTypes: [], signInRiskLevels: [], userRiskLevels: [],
        grantControls: [], hasAuthStrength: false, sessionSignInFreq: false, sessionPersist: false,
        authenticationFlows: [],
      }, jh.fp);
      fingerprints.push({ template: { id: jh.id, displayName: jh.displayName }, fp });
    }

    const tenantFps = tenantPolicies.map(p => ({ policy: p, fp: _fingerprintFromPolicy(p) }));

    // Score each template against best-matching tenant policy
    const matches = fingerprints.map(({ template, fp }) => {
      let bestScore = 0, bestTenant = null;
      for (const t of tenantFps) {
        const s = _scoreFingerprint(t.fp, fp);
        if (s > bestScore) { bestScore = s; bestTenant = t.policy; }
      }
      let status = 'missing';
      if (bestScore >= 80) status = 'present';
      else if (bestScore >= 40) status = 'partial';
      return { template, status, score: bestScore, matchedTenantPolicy: bestTenant };
    });

    return {
      workload: 'Conditional Access',
      matches: matches,
      summary: {
        present: matches.filter(m => m.status === 'present').length,
        partial: matches.filter(m => m.status === 'partial').length,
        missing: matches.filter(m => m.status === 'missing').length,
        total:   matches.length,
      },
    };
  }

  // ── Intune compliance template matching ─────────────────────────────
  // Match each IN* template against tenant compliancePolicies by platform
  // and feature requirements (encryption, password, OS minimum version).
  function _matchIntuneTemplates(allPolicies, data) {
    const tenantPolicies = data.compliancePolicies;
    if (!Array.isArray(tenantPolicies)) return null;
    const intuneTemplates = allPolicies.filter(p => p.type === 'intune');
    if (intuneTemplates.length === 0) return null;

    function platformOf(odata) {
      const t = String(odata || '').toLowerCase();
      if (t.indexOf('windows10') !== -1 || t.indexOf('windows1011') !== -1) return 'windows';
      if (t.indexOf('macos') !== -1) return 'macos';
      if (t.indexOf('ios') !== -1) return 'ios';
      if (t.indexOf('androidwork') !== -1) return 'android-work';
      if (t.indexOf('android') !== -1) return 'android';
      return 'unknown';
    }
    function platformFromName(name) {
      const n = (name || '').toLowerCase();
      if (n.indexOf('windows') !== -1) return 'windows';
      if (n.indexOf('macos') !== -1 || n.indexOf('mac os') !== -1) return 'macos';
      if (n.indexOf('ios') !== -1 || n.indexOf('iphone') !== -1) return 'ios';
      if (n.indexOf('android work') !== -1) return 'android-work';
      if (n.indexOf('android') !== -1) return 'android';
      return 'unknown';
    }

    const matches = intuneTemplates.map(t => {
      const tPlatform = platformFromName(t.displayName);
      let bestScore = 0, bestTenant = null;
      for (const tp of tenantPolicies) {
        const tpPlatform = platformOf(tp['@odata.type']);
        let score = 0, total = 100;
        // 50% — platform matches
        if (tPlatform === tpPlatform && tPlatform !== 'unknown') score += 50;
        // 25% — has password / PIN requirement
        if (tp.passwordRequired || tp.passcodeRequired) score += 25;
        // 25% — has encryption
        if (tp.storageRequireEncryption || tp.deviceThreatProtectionEnabled) score += 25;
        if (score > bestScore) { bestScore = score; bestTenant = tp; }
      }
      let status = 'missing';
      if (bestScore >= 80) status = 'present';
      else if (bestScore >= 40) status = 'partial';
      return { template: t, status, score: bestScore, matchedTenantPolicy: bestTenant };
    });

    return {
      workload: 'Intune / Device Management',
      matches,
      summary: {
        present: matches.filter(m => m.status === 'present').length,
        partial: matches.filter(m => m.status === 'partial').length,
        missing: matches.filter(m => m.status === 'missing').length,
        total: matches.length,
      },
    };
  }

  // ── Defender for Endpoint template-family matching ────────────────────
  // Each MDE template is mapped to one of Microsoft's templateFamily
  // values. A template is "present" if the tenant has at least one
  // configurationPolicy in that family.
  function _matchMDETemplates(allPolicies, data) {
    const tenantPolicies = data.configurationPolicies;
    if (!Array.isArray(tenantPolicies)) return null;
    const mdeTemplates = allPolicies.filter(p => p.type === 'defender-endpoint');
    if (mdeTemplates.length === 0) return null;

    // Map our policy IDs/names to Microsoft templateFamily values.
    function familyOf(template) {
      const n = (template.displayName || '').toLowerCase();
      if (n.indexOf('antivirus') !== -1 || n.indexOf('defender av') !== -1) return 'endpointSecurityAntivirus';
      if (n.indexOf('attack surface') !== -1 || n.indexOf('asr') !== -1) return 'endpointSecurityAttackSurfaceReduction';
      if (n.indexOf('edr') !== -1 || n.indexOf('endpoint detection') !== -1) return 'endpointSecurityEndpointDetectionAndResponse';
      if (n.indexOf('firewall') !== -1) return 'endpointSecurityFirewall';
      if (n.indexOf('disk encryption') !== -1 || n.indexOf('bitlocker') !== -1 || n.indexOf('filevault') !== -1) return 'endpointSecurityDiskEncryption';
      if (n.indexOf('account protection') !== -1 || n.indexOf('account protect') !== -1) return 'endpointSecurityAccountProtection';
      if (n.indexOf('privilege') !== -1) return 'endpointSecurityEndpointPrivilegeManagement';
      return null;
    }

    // Pre-index tenant policies by family.
    const tenantByFamily = {};
    for (const p of tenantPolicies) {
      const fam = p.templateReference && p.templateReference.templateFamily;
      if (!fam) continue;
      (tenantByFamily[fam] = tenantByFamily[fam] || []).push(p);
    }

    const matches = mdeTemplates.map(t => {
      const fam = familyOf(t);
      let status = 'missing', score = 0, matched = null;
      if (fam && tenantByFamily[fam] && tenantByFamily[fam].length > 0) {
        status = 'present'; score = 100; matched = tenantByFamily[fam][0];
      } else if (!fam) {
        // Couldn't map the template — show as partial so user can verify
        status = 'partial'; score = 50;
      }
      return { template: t, status, score, matchedTenantPolicy: matched };
    });

    return {
      workload: 'Defender for Endpoint',
      matches,
      summary: {
        present: matches.filter(m => m.status === 'present').length,
        partial: matches.filter(m => m.status === 'partial').length,
        missing: matches.filter(m => m.status === 'missing').length,
        total: matches.length,
      },
    };
  }

  // ── Entra ID settings template matching ───────────────────────────────
  // Each ENT* template controls a specific Entra setting. We check the
  // matching field on authorizationPolicy / adminConsentPolicy /
  // authMethodsPolicy against the expected value.
  function _matchEntraTemplates(allPolicies, data) {
    const auth = data.authorizationPolicy || null;
    const consent = data.adminConsentPolicy || null;
    const authMethods = data.authMethodsPolicy || null;
    const entraTemplates = allPolicies.filter(p => p.type === 'entra');
    if (entraTemplates.length === 0) return null;
    if (!auth && !consent && !authMethods) return null;

    function getNested(obj, path) {
      return path.split('.').reduce((acc, k) => (acc == null ? acc : acc[k]), obj);
    }

    // Per-template rule definitions. Each entry maps a template ID to the
    // source object + setting path + expected value/check.
    const ENT_RULES = {
      ENT01: { source: 'auth',        path: 'defaultUserRolePermissions.allowedToCreateApps',          expected: false, mode: 'eq' },
      ENT02: { source: 'auth',        path: 'defaultUserRolePermissions.permissionGrantPoliciesAssigned', mode: 'restrictiveConsent' },
      ENT03: { source: 'auth',        path: 'allowInvitesFrom',                                        expected: ['adminsAndGuestInviters', 'none'], mode: 'in' },
      ENT04: { source: 'auth',        path: 'allowedToSignUpEmailBasedSubscriptions',                  expected: false, mode: 'eq' },
      ENT05: { source: 'consent',     path: 'isEnabled',                                               expected: true,  mode: 'eq' },
      ENT06: { source: 'authMethods', path: 'authenticationMethodConfigurations',                      mode: 'authenticatorEnabled' },
      ENT07: { source: 'auth',        path: 'defaultUserRolePermissions.allowedToCreateSecurityGroups', expected: false, mode: 'eq' },
      ENT08: { source: 'auth',        path: 'defaultUserRolePermissions.allowedToCreateTenants',       expected: false, mode: 'eq' },
      ENT09: { source: 'auth',        path: 'guestUserRoleId',                                         mode: 'truthy' },
      ENT10: { source: 'auth',        path: 'defaultUserRolePermissions.allowedToReadOtherUsers',      expected: true,  mode: 'eq' },
    };

    const sources = { auth, consent, authMethods };

    const matches = entraTemplates.map(t => {
      const rule = ENT_RULES[t.id];
      if (!rule) return { template: t, status: 'partial', score: 50, matchedTenantPolicy: null };
      const src = sources[rule.source];
      if (!src) return { template: t, status: 'partial', score: 50, matchedTenantPolicy: null };
      const v = getNested(src, rule.path);

      let ok = false;
      if (rule.mode === 'eq')      ok = (v === rule.expected);
      else if (rule.mode === 'in') ok = (rule.expected.indexOf(v) !== -1);
      else if (rule.mode === 'truthy') ok = !!v;
      else if (rule.mode === 'restrictiveConsent') {
        // Permission-grant policies should NOT include user-default-low (the
        // permissive "users can consent to anything" policy).
        const list = Array.isArray(v) ? v : [];
        ok = !list.some(p => /user-default-low/i.test(String(p)));
      }
      else if (rule.mode === 'authenticatorEnabled') {
        const list = Array.isArray(v) ? v : [];
        ok = list.some(m => m.id === 'MicrosoftAuthenticator' && m.state === 'enabled');
      }
      const status = ok ? 'present' : 'missing';
      return {
        template: t,
        status,
        score: ok ? 100 : 0,
        matchedTenantPolicy: ok ? { displayName: rule.source + '.' + rule.path + ' = ' + JSON.stringify(v).substring(0, 60) } : null,
      };
    });

    return {
      workload: 'Entra ID',
      matches,
      summary: {
        present: matches.filter(m => m.status === 'present').length,
        partial: matches.filter(m => m.status === 'partial').length,
        missing: matches.filter(m => m.status === 'missing').length,
        total: matches.length,
      },
    };
  }

  // ── Defender for O365 template matching ──────────────────────────────
  // Each DEF template matches a Microsoft Secure Score control. We can't
  // see the underlying Defender policies (CORS-blocked InvokeCommand) so
  // we use Microsoft's own evaluation as the source of truth.
  function _matchMDOTemplates(allPolicies, data) {
    const scoreSnap = (data.secureScores && data.secureScores[0]) || null;
    const controlScores = (scoreSnap && scoreSnap.controlScores) || [];
    const defTemplates = allPolicies.filter(p => p.type === 'defender');
    if (defTemplates.length === 0) return null;
    if (controlScores.length === 0) {
      // No Secure Score data — surface as 'partial' for every template so
      // the user knows we couldn't evaluate (rather than false 'missing').
      const matches = defTemplates.map(t => ({
        template: t, status: 'partial', score: 0,
        matchedTenantPolicy: { displayName: 'Secure Score not retrieved — manual verification required' },
      }));
      return _summariseBlock('Defender for O365', matches);
    }

    // Map each DEF template name → Secure Score control IDs that should be
    // implemented for it to count as "present".
    const NAME_TO_CONTROL = [
      { name: /anti.?phish/i,        controls: ['AntiPhishingPolicy', 'TargetedAntiPhishing'] },
      { name: /safe link/i,           controls: ['EnableSafeLinks', 'SafeLinksClickTracking'] },
      { name: /safe attachment/i,     controls: ['EnableSafeAttachments', 'SafeAttachmentsForSPO'] },
      { name: /anti.?malware/i,       controls: ['AntiMalwarePolicy'] },
      { name: /anti.?spam.*inbound/i, controls: ['BlockListsExternalSenders', 'EnableMailboxIntelligence'] },
      { name: /anti.?spam.*outbound/i,controls: ['OutboundSpam'] },
      { name: /sharepoint|onedrive|teams/i, controls: ['SafeAttachmentsForSPO'] },
      { name: /attachment.*filter|common attachment/i, controls: ['CommonAttachmentTypesFilter'] },
    ];

    function isImplemented(controlIds) {
      for (const cs of controlScores) {
        const id = cs.controlName || cs.id || '';
        if (!controlIds.some(c => id.toLowerCase().indexOf(c.toLowerCase()) !== -1)) continue;
        const score = cs.score != null ? cs.score : 0;
        const max = cs.maxScore != null ? cs.maxScore : null;
        if (cs.implementationStatus === 'Implemented') return { ok: true, evidence: cs };
        if (max != null && score >= max && max > 0) return { ok: true, evidence: cs };
      }
      return { ok: false, evidence: null };
    }

    const matches = defTemplates.map(t => {
      const lower = (t.displayName || '').toLowerCase();
      const matchRule = NAME_TO_CONTROL.find(r => r.name.test(lower));
      if (!matchRule) return { template: t, status: 'partial', score: 50, matchedTenantPolicy: null };
      const result = isImplemented(matchRule.controls);
      return {
        template: t,
        status: result.ok ? 'present' : 'missing',
        score: result.ok ? 100 : 0,
        matchedTenantPolicy: result.evidence ? { displayName: 'Secure Score: ' + (result.evidence.controlName || '') + ' implemented' } : null,
      };
    });

    return _summariseBlock('Defender for O365', matches);
  }

  // ── Exchange Online template matching ────────────────────────────────
  // Same approach as DfO — Exchange policy state is only visible via Secure
  // Score from the browser. Map each EXO template to one or more Secure
  // Score controls.
  function _matchEXOTemplates(allPolicies, data) {
    const scoreSnap = (data.secureScores && data.secureScores[0]) || null;
    const controlScores = (scoreSnap && scoreSnap.controlScores) || [];
    const exoTemplates = allPolicies.filter(p => p.type === 'exchange');
    if (exoTemplates.length === 0) return null;
    if (controlScores.length === 0) {
      const matches = exoTemplates.map(t => ({
        template: t, status: 'partial', score: 0,
        matchedTenantPolicy: { displayName: 'Secure Score not retrieved — manual verification required' },
      }));
      return _summariseBlock('Exchange Online', matches);
    }

    const NAME_TO_CONTROL = [
      { name: /dkim/i,                         controls: ['DKIMSigning'] },
      { name: /dmarc/i,                        controls: ['DMARCEnforcement'] },
      { name: /external.*forward|auto.?forward/i, controls: ['DisableAutoForwarding'] },
      { name: /basic auth|disable basic/i,     controls: ['BlockBasicAuth'] },
      { name: /modern auth/i,                  controls: ['EnableModernAuth'] },
      { name: /transport.*rule|whitelist/i,    controls: ['BlockListsExternalSenders'] },
      { name: /calendar/i,                     controls: ['CalendarSharing'] },
      { name: /report message/i,               controls: ['ReportMessage'] },
      { name: /public folder/i,                controls: ['PublicFolderEmail'] },
      { name: /direct send|preventdirectmail/i, controls: ['PreventDirectMail'] },
    ];

    function isImplemented(controlIds) {
      for (const cs of controlScores) {
        const id = cs.controlName || cs.id || '';
        if (!controlIds.some(c => id.toLowerCase().indexOf(c.toLowerCase()) !== -1)) continue;
        if (cs.implementationStatus === 'Implemented') return { ok: true, evidence: cs };
        const score = cs.score != null ? cs.score : 0;
        const max = cs.maxScore != null ? cs.maxScore : null;
        if (max != null && score >= max && max > 0) return { ok: true, evidence: cs };
      }
      return { ok: false, evidence: null };
    }

    const matches = exoTemplates.map(t => {
      const lower = (t.displayName || '').toLowerCase();
      const matchRule = NAME_TO_CONTROL.find(r => r.name.test(lower));
      if (!matchRule) return { template: t, status: 'partial', score: 50, matchedTenantPolicy: null };
      const result = isImplemented(matchRule.controls);
      return {
        template: t,
        status: result.ok ? 'present' : 'missing',
        score: result.ok ? 100 : 0,
        matchedTenantPolicy: result.evidence ? { displayName: 'Secure Score: ' + (result.evidence.controlName || '') + ' implemented' } : null,
      };
    });

    return _summariseBlock('Exchange Online', matches);
  }

  // ── Purview template matching ────────────────────────────────────────
  // We can see sensitivity labels, retention labels, and DLP policies via
  // Graph (partial coverage). Each PV template maps to a category — we
  // count it "present" if at least one matching item exists in the tenant.
  function _matchPurviewTemplates(allPolicies, data) {
    const sensitivityLabels = Array.isArray(data.sensitivityLabels) ? data.sensitivityLabels : null;
    const retentionLabels   = Array.isArray(data.retentionLabels) ? data.retentionLabels : null;
    const dlpPolicies       = Array.isArray(data.dlpPolicies) ? data.dlpPolicies : null;
    const pvTemplates = allPolicies.filter(p => p.type === 'purview');
    if (pvTemplates.length === 0) return null;
    // If none of the three sources returned data, surface partial across the board.
    if (sensitivityLabels === null && retentionLabels === null && dlpPolicies === null) {
      const matches = pvTemplates.map(t => ({
        template: t, status: 'partial', score: 0,
        matchedTenantPolicy: { displayName: 'Purview endpoints not available — verify in Purview portal' },
      }));
      return _summariseBlock('Purview / Data Protection', matches);
    }

    function pvCategory(name) {
      const n = (name || '').toLowerCase();
      if (/dlp|data loss/.test(n))                     return 'dlp';
      if (/sensitivity|sensitive|label.*sharepoint|auto.?label|container/.test(n)) return 'sensitivity';
      if (/retention|disposition|records|regulatory hold/.test(n)) return 'retention';
      if (/insider risk/.test(n))                      return 'insider';
      if (/audit/.test(n))                              return 'audit';
      if (/communication compliance/.test(n))           return 'comms';
      if (/information barrier/.test(n))                return 'barriers';
      if (/ediscovery/.test(n))                         return 'ediscovery';
      if (/adaptive protection/.test(n))                return 'adaptive';
      return 'other';
    }

    const matches = pvTemplates.map(t => {
      const cat = pvCategory(t.displayName);
      let evidence = null;
      let ok = false;
      if (cat === 'dlp' && Array.isArray(dlpPolicies)) {
        if (dlpPolicies.length > 0) { ok = true; evidence = dlpPolicies[0]; }
      } else if (cat === 'sensitivity' && Array.isArray(sensitivityLabels)) {
        if (sensitivityLabels.length > 0) { ok = true; evidence = sensitivityLabels[0]; }
      } else if (cat === 'retention' && Array.isArray(retentionLabels)) {
        if (retentionLabels.length > 0) { ok = true; evidence = retentionLabels[0]; }
      }
      const status = ok ? 'present' : (cat === 'other' || cat === 'insider' || cat === 'comms' || cat === 'barriers' || cat === 'ediscovery' || cat === 'adaptive' || cat === 'audit' ? 'partial' : 'missing');
      return {
        template: t,
        status,
        score: ok ? 100 : (status === 'partial' ? 50 : 0),
        matchedTenantPolicy: evidence ? { displayName: cat + ' detected: ' + (evidence.displayName || evidence.name || evidence.id || '') } : null,
      };
    });

    return _summariseBlock('Purview / Data Protection', matches);
  }

  function _summariseBlock(workload, matches) {
    return {
      workload, matches,
      summary: {
        present: matches.filter(m => m.status === 'present').length,
        partial: matches.filter(m => m.status === 'partial').length,
        missing: matches.filter(m => m.status === 'missing').length,
        total: matches.length,
      },
    };
  }

  // ── SharePoint admin settings template matching ──────────────────────
  // Most SPO templates set a single tenant-wide property. We check the
  // sharepointSettings response against the expected value per template.
  function _matchSPOTemplates(allPolicies, data) {
    const settings = data.sharepointSettings;
    if (!settings || typeof settings !== 'object') return null;
    const spoTemplates = allPolicies.filter(p => p.type === 'sharepoint');
    if (spoTemplates.length === 0) return null;

    // Map template ID → {prop, expected, mode}
    // mode 'eq' = strict equality, 'ne' = not equal, 'truthy' = truthy
    const SPO_EXPECTED = {
      SPO01: { prop: 'sharingCapability',                       expected: ['existingExternalUserSharingOnly', 'externalUserSharingOnly', 'disabled'], mode: 'in' },
      SPO02: { prop: 'defaultSharingLinkType',                  expected: ['internal', 'direct'], mode: 'in' },
      SPO03: { prop: 'anonymousLinkExpirationRestrictionDays',  mode: 'gt0' },
      SPO07: { prop: 'sharingCapability',                       expected: ['existingExternalUserSharingOnly', 'externalUserSharingOnly'], mode: 'in' },
      SPO09: { prop: 'isLegacyAuthProtocolsEnabled',            expected: false, mode: 'eq' },
      SPO13: { prop: 'sharingDomainRestrictionMode',            expected: ['allowList', 'blockList'], mode: 'in' },
      SPO14: { prop: 'isUnmanagedSyncAppForTenantRestricted',   expected: true,  mode: 'eq' },
      SPO15: { prop: 'idleSessionSignOut',                      mode: 'enabled' },
      SPO19: { prop: 'isResharingByExternalUsersEnabled',       expected: false, mode: 'eq' },
    };

    const matches = spoTemplates.map(t => {
      const rule = SPO_EXPECTED[t.id];
      if (!rule) return { template: t, status: 'partial', score: 50, matchedTenantPolicy: null };
      const v = settings[rule.prop];
      let ok = false;
      if (rule.mode === 'eq')      ok = (v === rule.expected);
      else if (rule.mode === 'in') ok = (rule.expected.indexOf(v) !== -1);
      else if (rule.mode === 'gt0') ok = (typeof v === 'number' && v > 0);
      else if (rule.mode === 'enabled') ok = !!(v && v.isEnabled);
      const status = ok ? 'present' : 'missing';
      return {
        template: t,
        status,
        score: ok ? 100 : 0,
        matchedTenantPolicy: ok ? { displayName: 'Tenant setting: ' + rule.prop + ' = ' + JSON.stringify(v) } : null,
      };
    });

    return {
      workload: 'SharePoint / OneDrive',
      matches,
      summary: {
        present: matches.filter(m => m.status === 'present').length,
        partial: matches.filter(m => m.status === 'partial').length,
        missing: matches.filter(m => m.status === 'missing').length,
        total: matches.length,
      },
    };
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

  // ── Sticky in-page TOC ──────────────────────────────────────────────
  function _renderTOC(items) {
    if (!items || items.length === 0) return '';
    let html = '<aside class="scan-toc"><div class="scan-toc-title">On this page</div>';
    for (const it of items) {
      const countHtml = (it.count != null && it.count !== '')
        ? '<span class="toc-count">' + escHtml(it.count + (it.countSuffix || '')) + '</span>'
        : '';
      html += '<a href="#scan-section-' + it.id + '" data-toc="' + it.id + '">' + escHtml(it.label) + countHtml + '</a>';
    }
    html += '</aside>';
    return html;
  }

  function _attachScrollSpy() {
    const links = document.querySelectorAll('.scan-toc a[data-toc]');
    if (!links.length) return;
    const sections = Array.from(document.querySelectorAll('[id^="scan-section-"]'));
    if (!sections.length) return;

    function update() {
      let active = sections[0].id;
      const fromTop = window.scrollY + 110;
      for (const s of sections) {
        if (s.offsetTop <= fromTop) active = s.id;
      }
      const slug = active.replace('scan-section-', '');
      links.forEach(a => a.classList.toggle('active', a.dataset.toc === slug));
    }
    update();
    window.removeEventListener('scroll', _scanScrollHandler);
    window.addEventListener('scroll', update, { passive: true });
    _scanScrollHandler = update;

    // Smooth scroll on click instead of instant jump.
    links.forEach(a => {
      a.addEventListener('click', (e) => {
        const href = a.getAttribute('href');
        if (!href) return;
        const target = document.querySelector(href);
        if (!target) return;
        e.preventDefault();
        window.scrollTo({ top: target.offsetTop - 80, behavior: 'smooth' });
      });
    });
  }
  let _scanScrollHandler = null;

  // ── Multi-tenant overview ───────────────────────────────────────────
  // When TenantManager has more than one known tenant, render a strip at
  // the top with a card per tenant. Each card shows the most recent scan
  // score from IndexedDB so the user can see all customer tenants at once.
  function renderTenantOverview() {
    if (typeof TenantManager === 'undefined' || !TenantManager.getTenants) return '';
    const tenants = TenantManager.getTenants();
    if (!Array.isArray(tenants) || tenants.length < 2) return '';
    const acct = TenantAuth.getAccount();
    const currentId = acct && acct.tenantId;

    let html = '<div class="card" style="padding:14px 18px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap">';
    html += '<strong style="font-size:.78rem;color:var(--ink)">All tenants</strong>';
    html += '<span style="font-size:.62rem;color:var(--ink4)">' + tenants.length + ' connected · click a card to switch</span>';
    html += '</div>';
    html += '<div id="tenant-overview-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px"></div>';
    html += '</div>';
    return html;
  }

  async function _loadTenantOverview() {
    const grid = document.getElementById('tenant-overview-grid');
    if (!grid) return;
    if (typeof TenantManager === 'undefined') return;
    const tenants = TenantManager.getTenants() || [];
    const acct = TenantAuth.getAccount();
    const currentId = acct && acct.tenantId;

    let html = '';
    for (const t of tenants) {
      let scoreLabel = '—', colour = 'var(--ink4)', ts = '', findingsCount = 0;
      if (typeof ScanHistory !== 'undefined' && ScanHistory.getScans) {
        try {
          const scans = await ScanHistory.getScans(t.id, 1);
          if (scans && scans.length > 0) {
            const s = scans[0];
            const score = s.score != null ? s.score : null;
            if (score != null) {
              scoreLabel = score;
              colour = score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--amber)' : 'var(--red)';
            }
            ts = s.timestamp ? new Date(s.timestamp).toLocaleDateString() : '';
            findingsCount = (s.summary && (s.summary.critical || 0) + (s.summary.high || 0)) || 0;
          }
        } catch (e) { /* ignore */ }
      }
      const isCurrent = t.id === currentId;
      html += '<div class="tenant-overview-card" onclick="TenantScanPage.switchTenant(\'' + escHtml(t.id) + '\')" style="cursor:pointer;background:var(--surface2);border:' + (isCurrent ? '2px solid var(--primary)' : '1px solid var(--border)') + ';border-radius:8px;padding:12px 14px">';
      html += '<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:4px"><strong style="flex:1;font-size:.7rem;color:var(--ink);overflow:hidden;text-overflow:ellipsis">' + escHtml(t.displayName || t.id) + '</strong>';
      if (isCurrent) html += '<span style="font-size:.52rem;color:var(--blue);text-transform:uppercase;letter-spacing:.5px">current</span>';
      html += '</div>';
      html += '<div style="display:flex;align-items:center;gap:8px;margin-top:6px">';
      html += '<span style="font-size:1.2rem;font-weight:700;color:' + colour + '">' + scoreLabel + '</span>';
      html += '<span style="font-size:.56rem;color:var(--ink4)">/ 100</span>';
      if (findingsCount > 0) html += '<span style="margin-left:auto;font-size:.6rem;color:var(--red)">' + findingsCount + ' crit/high</span>';
      html += '</div>';
      if (ts) html += '<div style="font-size:.56rem;color:var(--ink4);margin-top:4px">scanned ' + escHtml(ts) + '</div>';
      else html += '<div style="font-size:.56rem;color:var(--ink4);margin-top:4px">no scan yet</div>';
      html += '</div>';
    }
    grid.innerHTML = html;
  }

  async function switchTenant(tenantId) {
    if (typeof TenantManager !== 'undefined' && TenantManager.switchTenant) {
      await TenantManager.switchTenant(tenantId);
      render();  // re-render the page for the now-current tenant
    }
  }

  // ── Scheduled scans strip ────────────────────────────────────────────
  function renderScheduleStrip() {
    if (typeof ScanScheduler === 'undefined') return '';
    const isRunning = ScanScheduler.isRunning && ScanScheduler.isRunning();
    const intervalKey = ScanScheduler.getIntervalKey && ScanScheduler.getIntervalKey();

    const intervals = [
      { key: 'hourly',  label: 'Hourly' },
      { key: 'daily',   label: 'Daily' },
      { key: 'weekly',  label: 'Weekly' },
    ];

    let html = '<div class="card" style="padding:10px 18px;margin-bottom:14px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;font-size:.66rem">';
    html += '<strong style="color:var(--ink)">Scheduled scans</strong>';
    if (isRunning) {
      html += '<span style="color:var(--green);font-weight:600">● Active</span>';
      html += '<span style="color:var(--ink3)">' + escHtml(intervalKey || '') + '</span>';
      html += '<span id="scan-countdown" style="color:var(--ink4)"></span>';
      html += '<button class="btn btn-sm" onclick="TenantScanPage.scheduleStop()">Stop</button>';
    } else {
      html += '<span style="color:var(--ink3)">Off — auto-scan this tenant on a schedule</span>';
      for (const iv of intervals) {
        html += '<button class="btn btn-sm" onclick="TenantScanPage.scheduleStart(\'' + iv.key + '\')">' + iv.label + '</button>';
      }
    }
    html += '</div>';
    return html;
  }

  function scheduleStart(intervalKey) {
    if (typeof ScanScheduler === 'undefined' || !ScanScheduler.start) return;
    ScanScheduler.start(intervalKey);
    showToast('Scheduled ' + intervalKey + ' scans');
    render();
  }

  function scheduleStop() {
    if (typeof ScanScheduler === 'undefined' || !ScanScheduler.stop) return;
    ScanScheduler.stop();
    showToast('Scheduled scans stopped');
    render();
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
    html += '<button class="btn btn-sm" onclick="TenantScanPage.generateReport()" title="Open a printable customer report in a new tab">Report</button>';
    html += '<button class="btn btn-sm" onclick="TenantScanPage.openAttestation()" title="Generate a formal compliance attestation against a chosen framework">Attestation</button>';
    html += '<button class="btn btn-sm" onclick="TenantScanPage.openCompare()" title="Side-by-side compare with another connected tenant">Compare</button>';
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
    let html = '<div class="card" style="padding:24px 26px;margin-bottom:14px">';
    html += '<div class="coverage-dash">';

    // Donut (CSS classes)
    html += '<div>';
    html += '<div class="coverage-donut" style="background:conic-gradient(' + sColour + ' ' + (score * 3.6) + 'deg, var(--surface2) 0deg)">';
    html += '<div class="coverage-donut-inner">';
    html += '<div class="coverage-donut-num" style="color:' + sColour + '">' + score + '</div>';
    html += '<div class="coverage-donut-suffix">/ 100</div>';
    html += '</div>';
    html += '</div>';
    html += '<div class="coverage-donut-label">Coverage Score</div>';
    html += '</div>';

    // Severity strip + per-workload bars
    html += '<div>';
    html += '<div style="font-size:.6rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.6px;font-weight:600;margin-bottom:8px">Findings by severity</div>';
    html += '<div style="display:flex;gap:6px;margin-bottom:18px;flex-wrap:wrap">';
    let anySev = false;
    ['critical', 'high', 'medium', 'low', 'info'].forEach(sev => {
      const def = Findings.SEVERITY[sev];
      const c = counts[sev] || 0;
      if (c === 0) return;
      anySev = true;
      html += '<span class="sev-pill" style="background:' + def.colour + '22;color:' + def.colour + '">' + def.label + ': ' + c + '</span>';
    });
    if (!anySev) html += '<span style="color:var(--green);font-size:.74rem;font-weight:600">✓ No findings — every analyzer ran clean.</span>';
    html += '</div>';

    html += '<div style="font-size:.6rem;color:var(--ink4);text-transform:uppercase;letter-spacing:.6px;font-weight:600;margin-bottom:8px">By workload</div>';
    html += '<div class="coverage-bars">';
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
        html += '<div class="coverage-bar-row">';
        html += '<strong>' + escHtml(meta.label) + '</strong>';
        html += '<div class="coverage-bar">';
        if (c.critical) html += '<div style="background:var(--red);width:' + (c.critical / total * 100) + '%" title="' + c.critical + ' critical"></div>';
        if (c.high)     html += '<div style="background:#e84393;width:' + (c.high / total * 100) + '%" title="' + c.high + ' high"></div>';
        if (c.medium)   html += '<div style="background:var(--amber);width:' + (c.medium / total * 100) + '%" title="' + c.medium + ' medium"></div>';
        if (c.low)      html += '<div style="background:var(--blue);width:' + (c.low / total * 100) + '%" title="' + c.low + ' low"></div>';
        if (c.info)     html += '<div style="background:var(--ink4);width:' + (c.info / total * 100) + '%" title="' + c.info + ' info"></div>';
        html += '</div>';
        html += '<span style="text-align:right;color:var(--ink3);font-variant-numeric:tabular-nums">' + total + '</span>';
        html += '</div>';
      }
    }
    html += '</div></div></div></div>';
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

  function openAttestation() {
    if (typeof ComplianceAttestation === 'undefined') { showToast('Attestation module not loaded'); return; }
    ComplianceAttestation.generate();  // no framework arg → opens the chooser
  }

  function openCompare() {
    if (typeof TenantCompare === 'undefined') { showToast('Compare module not loaded'); return; }
    TenantCompare.open();
  }

  // ── Custom GitHub repo compare section ──────────────────────────────
  // Preset shortcuts let users compare against well-known reference repos
  // in one click, including this framework's own canonical CA policies.
  const GH_REPO_PRESETS = [
    { label: 'This framework',     url: 'github.com/timothyoelkers-cloud/M365-Compliance-Framework/tree/main/docs/data/policies/conditional-access' },
    { label: 'JH baseline',        url: 'github.com/Jhope188/ConditionalAccessPolicies' },
    { label: 'JH analyzer source', url: 'github.com/Jhope188/ca-policy-analyzer' },
  ];

  function renderGitHubCompareSection() {
    let html = '<div class="card" style="padding:16px 20px;margin-bottom:14px">';
    html += '<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap">';
    html += '<strong style="font-size:.82rem;color:var(--ink)">Compare against a GitHub repo</strong>';
    html += '<span style="font-size:.62rem;color:var(--ink4)">point at any public CA-policy repository to score it against this tenant</span>';
    html += '</div>';

    // Preset chips
    html += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px">';
    for (const p of GH_REPO_PRESETS) {
      html += '<button class="btn btn-sm" onclick="TenantScanPage.useRepoPreset(\'' + escHtml(p.url).replace(/\\'/g, '\\\\\'') + '\')">' + escHtml(p.label) + '</button>';
    }
    html += '</div>';

    html += '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px">';
    html += '<input id="gh-repo-input" placeholder="github.com/owner/repo or owner/repo or full URL" style="flex:1;min-width:280px;padding:6px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--ink);font-family:\'JetBrains Mono\',monospace;font-size:.7rem">';
    html += '<button class="btn btn-sm btn-primary" onclick="TenantScanPage.compareGitHub()">Compare</button>';
    html += '</div>';
    html += '<div id="gh-repo-result"></div>';
    html += '</div>';
    return html;
  }

  function useRepoPreset(url) {
    const input = document.getElementById('gh-repo-input');
    if (!input) return;
    input.value = url;
    compareGitHub();
  }

  function compareGitHub() {
    if (typeof GitHubTemplates === 'undefined') { showToast('GitHub module not loaded'); return; }
    GitHubTemplates.compare();
  }

  return {
    init, render, scan, filterWorkload,
    exportFindingsJson, exportFindingsCsv, exportInventoryJson, exportInventoryCsv,
    deployFix, generateReport, openAttestation, openCompare, compareGitHub, useRepoPreset,
    switchTenant, scheduleStart, scheduleStop,
  };
})();
