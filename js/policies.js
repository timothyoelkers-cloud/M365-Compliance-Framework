/* ═══════════════════════════════════════════
   POLICY LIBRARY — Browse, filter, deploy, download
═══════════════════════════════════════════ */
const Policies = (() => {
  function init() {
    render();
  }

  function render() {
    const container = document.getElementById('policies-content');
    if (!container) return;

    const policies = AppState.get('policies');
    const policyTypes = AppState.get('policyTypes');
    const sel = AppState.get('selectedPolicies');
    const typeFilter = AppState.get('polTypeFilter');
    const fwFilter = AppState.get('polFwFilter');
    const searchQuery = AppState.get('searchQuery');
    const selectedFws = AppState.get('selectedFrameworks');
    const isConnected = TenantAuth.isAuthenticated();

    // Filter policies
    let filtered = policies;
    if (typeFilter) filtered = filtered.filter(p => p.type === typeFilter);
    if (fwFilter.size > 0) filtered = filtered.filter(p => p.frameworks.some(fw => fwFilter.has(fw)));
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(p =>
        p.displayName.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q)
      );
    }

    // Group by type
    const types = Object.keys(policyTypes);
    const byType = {};
    types.forEach(t => { byType[t] = filtered.filter(p => p.type === t); });

    const typeColors = {
      'conditional-access': 'var(--blue)',
      'defender': 'var(--red)',
      'defender-endpoint': '#e84393',
      'exchange': 'var(--amber)',
      'sharepoint': 'var(--teal)',
      'teams': 'var(--purple)',
      'intune': '#00b894',
      'purview': '#6c5ce7',
      'governance': 'var(--ink3)',
      'entra': '#0984e3',
    };

    let html = '';

    // Selection bar
    html += `<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
      <span class="badge badge-dark">${filtered.length} policies</span>
      <span class="badge badge-green">${sel.size} selected</span>`;

    if (selectedFws.size > 0) {
      const relevantCount = policies.filter(p => p.frameworks.some(fw => selectedFws.has(fw))).length;
      html += `<button class="btn btn-sm btn-amber" onclick="Policies.filterByAssessment()">
        Show ${relevantCount} policies for your ${selectedFws.size} frameworks
      </button>`;
    }

    html += `<div style="flex:1"></div>`;
    if (sel.size > 0) {
      html += `<button class="btn btn-sm btn-primary" onclick="Policies.downloadBundle()">Download Bundle (${sel.size})</button>`;

      // Bulk deploy button (Graph API policies only)
      if (isConnected) {
        const deployable = policies.filter(p => sel.has(p.id) && DeployEngine.isGraphDeployable(p.type));
        if (deployable.length > 0) {
          html += ` <button class="btn btn-sm btn-deploy" onclick="Policies.deploySelected()">Deploy ${deployable.length} to Tenant</button>`;
        }
      }

      // Bulk script button (PowerShell policies only)
      const scriptable = policies.filter(p => sel.has(p.id) && DeployEngine.isPowerShellOnly(p.type));
      if (scriptable.length > 0) {
        html += ` <button class="btn btn-sm btn-script" onclick="Policies.downloadScriptBundle()">Generate ${scriptable.length} Scripts</button>`;
      }

      html += ` <button class="btn btn-sm" onclick="Policies.clearSelection()">Clear</button>`;
    }
    html += `<button class="btn btn-sm" onclick="Policies.selectAll()">Select All</button>
    </div>`;

    // Search
    html += `<input class="search-input" type="text" placeholder="Search policies..." value="${escHtml(searchQuery)}" oninput="Policies.search(this.value)" style="margin-bottom:12px">`;

    // Type filter pills
    html += `<div class="filter-bar">
      <button class="filter-pill${!typeFilter ? ' active' : ''}" onclick="Policies.filterType('')">All Types</button>`;
    for (const t of types) {
      const count = policies.filter(p => p.type === t).length;
      if (count > 0) {
        const label = policyTypes[t]?.label || t;
        html += `<button class="filter-pill${typeFilter === t ? ' active' : ''}" onclick="Policies.filterType('${t}')">${label.split('(')[0].trim()} <span class="text-mono text-xs">${count}</span></button>`;
      }
    }
    html += `</div>`;

    // Policy type sections
    for (const type of types) {
      const typePols = byType[type];
      if (!typePols || typePols.length === 0) continue;

      const info = policyTypes[type] || {};
      const clr = typeColors[type] || 'var(--ink3)';
      const typeSel = typePols.filter(p => sel.has(p.id)).length;
      const isGraph = DeployEngine.isGraphDeployable(type);

      html += `<div class="policy-type-section">
        <div class="policy-type-hdr" style="border-left:3px solid ${clr}" onclick="this.classList.toggle('open');this.nextElementSibling.style.display=this.classList.contains('open')?'block':'none'">
          <h3 style="color:${clr}">${info.label || type}</h3>
          ${isGraph ? '<span class="badge badge-blue" style="font-size:.54rem">Graph API</span>' : '<span class="badge badge-amber" style="font-size:.54rem">PowerShell</span>'}
          ${typeSel > 0 ? `<span class="badge badge-green">${typeSel} selected</span>` : ''}
          <span class="count-badge" style="background:${clr}">${typePols.length}</span>
          <span class="chevron">&#9654;</span>
        </div>
        <div class="policy-type-body" style="display:none">`;

      if (info.guideSteps) {
        html += `<div style="padding:10px 14px;background:var(--surface2);border-bottom:1px solid var(--border);font-size:.68rem;color:var(--ink3)">
          <strong style="color:var(--ink2)">Import:</strong> ${info.importMethod || ''}<br>`;
        if (info.requiredLicence) html += `<strong style="color:var(--ink2)">Licence:</strong> ${info.requiredLicence}<br>`;
        html += `</div>`;
      }

      for (const pol of typePols) {
        const isSelected = sel.has(pol.id);
        const ds = DeployEngine.getDeploymentStatus(pol.id);

        html += `<div class="policy-card">
          <input type="checkbox" ${isSelected ? 'checked' : ''} onchange="Policies.togglePolicy('${pol.id}')">
          <div style="flex:1;min-width:0">
            <div class="policy-name">${pol.displayName}`;

        // Inline deployment status
        if (ds) {
          if (ds.status === 'success') html += ` <span class="deploy-status deploy-status-success">deployed</span>`;
          else if (ds.status === 'exists') html += ` <span class="deploy-status deploy-status-exists">exists</span>`;
          else if (ds.status === 'failed') html += ` <span class="deploy-status deploy-status-failed" title="${escHtml(ds.detail)}">failed</span>`;
          else if (ds.status === 'deploying') html += ` <span class="deploy-status deploy-status-deploying">deploying...</span>`;
        }

        html += `</div>
            <div class="policy-desc">${pol.description}</div>
            <div class="policy-meta">
              ${pol.cisChecks.map(c => `<span class="badge badge-blue">${c}</span>`).join('')}
              ${pol.requiredLicence ? `<span class="badge badge-amber" title="${escHtml(pol.requiredLicence)}">Licence</span>` : ''}
              ${pol.deployState ? `<span class="badge badge-green">${pol.deployState.replace(/([A-Z])/g, ' $1').trim()}</span>` : ''}
            </div>
          </div>
          <div style="display:flex;flex-direction:column;gap:4px;flex-shrink:0">
            <button class="btn btn-sm" onclick="Policies.downloadSingle('${pol.id}')" title="Download JSON">JSON</button>
            <button class="btn btn-sm" onclick="Policies.viewDetail('${pol.id}')" title="View details">View</button>`;

        // Deploy or Script button
        if (isGraph) {
          if (ds && ds.status === 'success') {
            html += `<button class="btn btn-sm btn-deployed" disabled>Deployed</button>`;
          } else if (ds && ds.status === 'deploying') {
            html += `<button class="btn btn-sm loading" disabled>...</button>`;
          } else if (ds && ds.status === 'exists') {
            html += `<button class="btn btn-sm btn-exists" disabled>Exists</button>`;
          } else if (ds && ds.status === 'failed') {
            html += `<button class="btn btn-sm btn-failed" onclick="Policies.deploy('${pol.id}')">Retry</button>`;
          } else if (isConnected) {
            html += `<button class="btn btn-sm btn-deploy" onclick="Policies.deploy('${pol.id}')">Deploy</button>`;
          } else {
            html += `<button class="btn btn-sm btn-deploy" onclick="handleConnectTenant()" title="Connect tenant to deploy">Deploy</button>`;
          }
        } else {
          html += `<button class="btn btn-sm btn-script" onclick="Policies.generateScript('${pol.id}')" title="Download PowerShell script">PS1</button>`;
        }

        html += `</div>
        </div>`;
      }

      html += `</div></div>`;
    }

    container.innerHTML = html;
  }

  function togglePolicy(id) {
    AppState.toggleInSet('selectedPolicies', id);
    render();
  }

  function selectAll() {
    const policies = AppState.get('policies');
    const typeFilter = AppState.get('polTypeFilter');
    let filtered = policies;
    if (typeFilter) filtered = filtered.filter(p => p.type === typeFilter);
    filtered.forEach(p => AppState.get('selectedPolicies').add(p.id));
    AppState.notify('selectedPolicies');
    render();
  }

  function clearSelection() {
    AppState.set('selectedPolicies', new Set());
    render();
  }

  function filterType(type) {
    AppState.set('polTypeFilter', type);
    render();
  }

  function filterByAssessment() {
    AppState.set('polFwFilter', new Set(AppState.get('selectedFrameworks')));
    render();
  }

  function search(q) {
    AppState.set('searchQuery', q);
    render();
  }

  function downloadSingle(id) {
    const pol = AppState.get('policies').find(p => p.id === id);
    if (!pol) return;
    const json = JSON.stringify({
      _meta: {
        source: 'M365 Compliance Framework',
        version: AppState.get('manifest').version,
        exportDate: new Date().toISOString().split('T')[0],
      },
      ...pol,
    }, null, 2);
    downloadFile(json, `${pol.file}`, 'application/json');
    showToast(`Downloaded ${pol.id}`);
  }

  function downloadBundle() {
    const sel = AppState.get('selectedPolicies');
    const policies = AppState.get('policies').filter(p => sel.has(p.id));
    if (policies.length === 0) return;

    const bundle = {
      _meta: {
        source: 'M365 Compliance Framework',
        version: AppState.get('manifest').version,
        exportDate: new Date().toISOString().split('T')[0],
        totalPolicies: policies.length,
      },
      policies: policies.map(p => ({
        id: p.id, file: p.file, type: p.type,
        displayName: p.displayName, description: p.description,
        frameworks: p.frameworks, cisChecks: p.cisChecks,
        importMethod: p.importMethod, deployState: p.deployState,
        requiredLicence: p.requiredLicence,
      })),
    };
    downloadFile(JSON.stringify(bundle, null, 2), `M365-Policy-Bundle-${policies.length}policies.json`, 'application/json');
    showToast(`Downloaded bundle: ${policies.length} policies`);
  }

  function viewDetail(id) {
    const pol = AppState.get('policies').find(p => p.id === id);
    if (!pol) return;

    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    const isGraph = DeployEngine.isGraphDeployable(pol.type);
    const isConnected = TenantAuth.isAuthenticated();
    const perms = DeployEngine.getRequiredPermissions(pol.type);
    const roles = DeployEngine.getRequiredRoles(pol.type);

    let actionHtml = '';
    if (isGraph) {
      if (isConnected) {
        actionHtml += `<button class="btn btn-deploy" onclick="Policies.deploy('${pol.id}');document.getElementById('modal-overlay').classList.remove('open')">Deploy to Tenant</button>`;
      } else {
        actionHtml += `<button class="btn" onclick="handleConnectTenant()">Connect Tenant to Deploy</button>`;
      }
    } else {
      actionHtml += `<button class="btn btn-script" onclick="Policies.generateScript('${pol.id}');document.getElementById('modal-overlay').classList.remove('open')">Generate PowerShell Script</button>`;
    }

    let permHtml = '';
    if (perms.length > 0 || roles.length > 0) {
      permHtml = `<div class="section-hdr" style="margin-top:20px">Required for Deployment</div>`;
      if (perms.length > 0) {
        permHtml += `<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px">
          ${perms.map(p => '<span class="badge badge-blue">' + p + '</span>').join('')}
        </div>`;
      }
      if (roles.length > 0) {
        permHtml += `<div style="font-size:.68rem;color:var(--ink3)">Admin roles: ${roles.join(', ')}</div>`;
      }
    }

    modal.innerHTML = `<div class="modal-header">
      <h3>${pol.displayName}</h3>
      <button class="modal-close" onclick="document.getElementById('modal-overlay').classList.remove('open')">&times;</button>
    </div>
    <div class="modal-body">
      <p style="margin-bottom:16px;font-size:.78rem;color:var(--ink2);line-height:1.6">${pol.description}</p>

      <div class="section-hdr">Details</div>
      <table class="data-table" style="margin-bottom:20px">
        <tbody>
          <tr><td style="font-weight:600;width:140px">Type</td><td>${pol.type}</td></tr>
          <tr><td style="font-weight:600">Deploy Method</td><td>${isGraph ? '<span class="badge badge-blue">Graph API</span>' : '<span class="badge badge-amber">PowerShell</span>'}</td></tr>
          <tr><td style="font-weight:600">Import Method</td><td>${pol.importMethod || 'N/A'}</td></tr>
          <tr><td style="font-weight:600">Deploy State</td><td>${pol.deployState || 'N/A'}</td></tr>
          <tr><td style="font-weight:600">Version</td><td>${pol.version || '1.0'}</td></tr>
          ${pol.requiredLicence ? `<tr><td style="font-weight:600">Required Licence</td><td>${pol.requiredLicence}</td></tr>` : ''}
        </tbody>
      </table>

      <div class="section-hdr">CIS Checks</div>
      <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:16px">
        ${pol.cisChecks.map(c => `<span class="badge badge-blue">${c}</span>`).join('')}
      </div>

      <div class="section-hdr">Frameworks (${pol.frameworks.length})</div>
      <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:16px">
        ${pol.frameworks.map(f => `<span class="fw-tag">${f}</span>`).join('')}
      </div>

      <div style="display:flex;gap:8px;margin-top:16px;flex-wrap:wrap">
        <button class="btn btn-primary" onclick="Policies.downloadSingle('${pol.id}')">Download JSON</button>
        ${actionHtml}
      </div>
      ${permHtml}
    </div>`;

    overlay.classList.add('open');
  }

  // ── Deployment ──
  async function deploy(id) {
    if (!TenantAuth.isAuthenticated()) {
      handleConnectTenant();
      return;
    }
    await DeployEngine.deploySinglePolicy(id);
    render();
  }

  async function deploySelected() {
    if (!TenantAuth.isAuthenticated()) {
      handleConnectTenant();
      return;
    }
    const sel = AppState.get('selectedPolicies');
    const ids = AppState.get('policies')
      .filter(p => sel.has(p.id) && DeployEngine.isGraphDeployable(p.type))
      .map(p => p.id);
    if (ids.length === 0) return;
    showToast(`Deploying ${ids.length} policies...`);
    await DeployEngine.deployBulk(ids);
    render();
  }

  async function generateScript(id) {
    const pol = AppState.get('policies').find(p => p.id === id);
    if (!pol) return;
    try {
      const rawPolicy = await DataStore.loadPolicy(pol.type, pol.file);
      const script = DeployEngine.generateScript(rawPolicy, pol.type);
      downloadFile(script, `${pol.id}.ps1`, 'text/plain');
      showToast(`Downloaded ${pol.id}.ps1`);
    } catch (err) {
      showToast('Failed to generate script: ' + err.message);
    }
  }

  async function downloadScriptBundle() {
    const sel = AppState.get('selectedPolicies');
    const policies = AppState.get('policies').filter(p =>
      sel.has(p.id) && DeployEngine.isPowerShellOnly(p.type)
    );
    if (policies.length === 0) return;

    let combined = '# M365 Compliance Framework - Policy Deployment Script Bundle\n';
    combined += `# Generated: ${new Date().toISOString().split('T')[0]}\n`;
    combined += `# Policies: ${policies.length}\n\n`;

    for (const pol of policies) {
      try {
        const rawPolicy = await DataStore.loadPolicy(pol.type, pol.file);
        combined += '\n' + '#'.repeat(60) + '\n';
        combined += `# ${pol.id} - ${pol.displayName}\n`;
        combined += '#'.repeat(60) + '\n\n';
        combined += DeployEngine.generateScript(rawPolicy, pol.type);
        combined += '\n';
      } catch (err) {
        combined += `# ERROR loading ${pol.id}: ${err.message}\n\n`;
      }
    }

    downloadFile(combined, `M365-Deploy-${policies.length}policies.ps1`, 'text/plain');
    showToast(`Downloaded script bundle: ${policies.length} policies`);
  }

  function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }

  return {
    init, render, togglePolicy, selectAll, clearSelection,
    filterType, filterByAssessment, search,
    downloadSingle, downloadBundle, viewDetail,
    deploy, deploySelected,
    generateScript, downloadScriptBundle,
  };
})();
