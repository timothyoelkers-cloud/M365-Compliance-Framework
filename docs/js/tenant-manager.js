/* ═══════════════════════════════════════════
   TENANT MANAGER — Multi-tenant support with
   per-tenant data isolation, tenant switcher,
   and management UI.
═══════════════════════════════════════════ */
const TenantManager = (() => {
  const TENANT_LIST_KEY = 'm365-tenant-list';
  let currentTenantId = null;
  let switcherRendered = false;

  // ─── Registry ───

  function getTenants() {
    try {
      var raw = localStorage.getItem(TENANT_LIST_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) { return []; }
  }

  function saveTenants(tenants) {
    try {
      localStorage.setItem(TENANT_LIST_KEY, JSON.stringify(tenants));
    } catch (e) {}
  }

  function addTenant(id, displayName) {
    if (!id) return;
    var tenants = getTenants();
    var existing = tenants.find(function (t) { return t.id === id; });
    if (existing) {
      existing.displayName = displayName || existing.displayName;
      existing.lastSeen = Date.now();
    } else {
      tenants.push({
        id: id,
        displayName: displayName || id,
        name: displayName || id,
        addedAt: Date.now(),
        lastSeen: Date.now(),
        lastScanAt: null,
      });
    }
    saveTenants(tenants);
    currentTenantId = id;
    renderSwitcher();
  }

  function removeTenant(id) {
    var tenants = getTenants().filter(function (t) { return t.id !== id; });
    saveTenants(tenants);

    // Clean up IndexedDB data for this tenant
    if (typeof ScanHistory !== 'undefined') {
      ScanHistory.getScans(id, 999).then(function (scans) {
        scans.forEach(function (s) { ScanHistory.deleteScan(s.id); });
      }).catch(function () {});
    }

    renderSwitcher();
  }

  function renameTenant(id, newName) {
    var tenants = getTenants();
    var tenant = tenants.find(function (t) { return t.id === id; });
    if (tenant) {
      tenant.name = newName;
      tenant.displayName = newName;
      saveTenants(tenants);
      renderSwitcher();
    }
  }

  function updateLastScan(id) {
    var tenants = getTenants();
    var tenant = tenants.find(function (t) { return t.id === id; });
    if (tenant) {
      tenant.lastScanAt = Date.now();
      saveTenants(tenants);
    }
  }

  function getCurrentTenantId() { return currentTenantId; }

  // ─── Tenant Switching ───

  async function switchTenant(targetTenantId) {
    if (targetTenantId === currentTenantId) return;

    // Save current state
    if (currentTenantId && typeof ScanHistory !== 'undefined') {
      try {
        await ScanHistory.saveTenantState(currentTenantId, {
          selectedFrameworks: [...AppState.get('selectedFrameworks')],
          checkStatus: AppState.get('checkStatus'),
          assessmentStep: AppState.get('assessmentStep'),
          selectedPolicies: [...AppState.get('selectedPolicies')],
        });
      } catch (e) {
        console.warn('[TenantManager] Failed to save state for tenant:', currentTenantId, e);
      }
    }

    // Load target state
    currentTenantId = targetTenantId;
    if (typeof ScanHistory !== 'undefined') {
      try {
        var state = await ScanHistory.loadTenantState(targetTenantId);
        if (state) {
          AppState.state.selectedFrameworks = new Set(state.selectedFrameworks || []);
          AppState.state.checkStatus = state.checkStatus || {};
          AppState.state.assessmentStep = state.assessmentStep || 1;
          AppState.state.selectedPolicies = new Set(state.selectedPolicies || []);
          AppState.notify('selectedFrameworks');
          AppState.notify('checkStatus');
          AppState.notify('assessmentStep');
        } else {
          // Fresh tenant — reset assessment
          AppState.resetAssessment();
        }
      } catch (e) {
        console.warn('[TenantManager] Failed to load state for tenant:', targetTenantId, e);
      }
    }

    // Clear scan cache
    AppState.state.tenantScanResults = {};
    AppState.notify('tenantScanResults');

    // Update tenant ID in state
    AppState.state.authTenantId = targetTenantId;

    renderSwitcher();
    showToast('Switched to tenant: ' + getTenantDisplayName(targetTenantId));

    // Re-render current page
    if (typeof Router !== 'undefined') {
      var page = AppState.get('currentPage');
      AppState.notify('currentPage');
    }
  }

  function getTenantDisplayName(id) {
    var tenants = getTenants();
    var t = tenants.find(function (t) { return t.id === id; });
    return t ? (t.name || t.displayName || id) : id;
  }

  // ─── UI ───

  function renderSwitcher() {
    var el = document.getElementById('tenant-switcher');
    if (!el) return;

    var tenants = getTenants();
    if (tenants.length <= 1) {
      el.style.display = 'none';
      return;
    }

    el.style.display = 'inline-flex';
    var current = currentTenantId || AppState.get('authTenantId');

    var html = '<select onchange="TenantManager.switchTenant(this.value)" style="font-size:.62rem;padding:2px 6px;border-radius:4px;border:1px solid var(--border);background:var(--bg2);color:var(--ink1);max-width:180px">';
    for (var i = 0; i < tenants.length; i++) {
      var t = tenants[i];
      var label = t.name || t.displayName || t.id.substring(0, 8) + '...';
      html += '<option value="' + escHtml(t.id) + '" ' + (t.id === current ? 'selected' : '') + '>' + escHtml(label) + '</option>';
    }
    html += '</select>';
    html += '<button class="btn btn-sm" onclick="TenantManager.renderManagementModal()" style="font-size:.55rem;margin-left:4px;padding:2px 6px" title="Manage tenants">&#9881;</button>';

    el.innerHTML = html;
    switcherRendered = true;
  }

  function renderManagementModal() {
    var tenants = getTenants();
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var html = '<div class="modal-header">';
    html += '<h3>Manage Tenants</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';

    if (tenants.length === 0) {
      html += '<div style="color:var(--ink4);font-size:.72rem;text-align:center;padding:20px">No tenants registered. Connect to a tenant to add it.</div>';
    } else {
      html += '<table class="data-table" style="font-size:.68rem"><thead><tr><th>Name</th><th>Tenant ID</th><th>Last Scan</th><th style="width:100px">Actions</th></tr></thead><tbody>';
      for (var i = 0; i < tenants.length; i++) {
        var t = tenants[i];
        var isCurrent = t.id === currentTenantId;
        var lastScan = t.lastScanAt ? new Date(t.lastScanAt).toLocaleDateString() : 'Never';
        html += '<tr' + (isCurrent ? ' style="background:rgba(96,165,250,.08)"' : '') + '>';
        html += '<td>' + escHtml(t.name || t.displayName) + (isCurrent ? ' <span class="badge badge-blue" style="font-size:.5rem">Active</span>' : '') + '</td>';
        html += '<td class="text-mono" style="font-size:.58rem">' + escHtml(t.id.substring(0, 12)) + '...</td>';
        html += '<td style="font-size:.62rem">' + lastScan + '</td>';
        html += '<td>';
        if (!isCurrent) {
          html += '<button class="btn btn-sm" onclick="TenantManager.switchTenant(\'' + escHtml(t.id) + '\');document.getElementById(\'modal-overlay\').classList.remove(\'open\')" style="font-size:.52rem">Switch</button> ';
        }
        html += '<button class="btn btn-sm" onclick="TenantManager.promptRename(\'' + escHtml(t.id) + '\')" style="font-size:.52rem">Rename</button> ';
        if (!isCurrent) {
          html += '<button class="btn btn-sm" onclick="TenantManager.confirmRemove(\'' + escHtml(t.id) + '\')" style="font-size:.52rem;color:var(--red)">Remove</button>';
        }
        html += '</td></tr>';
      }
      html += '</tbody></table>';
    }

    html += '<div class="config-actions" style="margin-top:12px">';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '</div></div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  function promptRename(id) {
    var current = getTenantDisplayName(id);
    var name = prompt('Enter new name for tenant:', current);
    if (name && name.trim()) {
      renameTenant(id, name.trim());
      renderManagementModal(); // Refresh modal
    }
  }

  function confirmRemove(id) {
    var name = getTenantDisplayName(id);
    if (confirm('Remove tenant "' + name + '"? This will delete all scan history for this tenant.')) {
      removeTenant(id);
      renderManagementModal(); // Refresh modal
    }
  }

  // ─── Auto-register on auth ───

  function initFromAuth() {
    var account = (typeof TenantAuth !== 'undefined' && TenantAuth.getAccount) ? TenantAuth.getAccount() : null;
    if (account && account.tenantId) {
      addTenant(account.tenantId, account.name || account.username || account.tenantId);
      currentTenantId = account.tenantId;
    }
  }

  return {
    getTenants: getTenants,
    addTenant: addTenant,
    removeTenant: removeTenant,
    renameTenant: renameTenant,
    updateLastScan: updateLastScan,
    getCurrentTenantId: getCurrentTenantId,
    switchTenant: switchTenant,
    renderSwitcher: renderSwitcher,
    renderManagementModal: renderManagementModal,
    promptRename: promptRename,
    confirmRemove: confirmRemove,
    initFromAuth: initFromAuth,
  };
})();
