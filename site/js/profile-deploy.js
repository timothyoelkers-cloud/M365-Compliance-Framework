/* ═══════════════════════════════════════════
   PROFILE DEPLOY — One-click deployment flow
   for organisation profiles (e.g. "Financial
   Services", "Healthcare", "Government").
   Uses BulkConfig for merged config form.
═══════════════════════════════════════════ */
const ProfileDeploy = (() => {

  function getProfilePolicies(profileName) {
    var profiles = AppState.get('orgProfiles') || {};
    var fws = profiles[profileName];
    if (!fws || !Array.isArray(fws)) return [];

    var fwSet = new Set(fws);
    var policies = AppState.get('policies') || [];
    return policies.filter(function (p) {
      return p.frameworks && p.frameworks.some(function (fw) { return fwSet.has(fw); });
    });
  }

  function getProfileStats(profileName) {
    var pols = getProfilePolicies(profileName);
    var byType = {};
    pols.forEach(function (p) {
      byType[p.type] = (byType[p.type] || 0) + 1;
    });
    var deployable = pols.filter(function (p) {
      return DeployEngine.isDeployable(p.type, p.id);
    }).length;
    return { total: pols.length, byType: byType, deployable: deployable };
  }

  function showProfileModal(profileName) {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var profiles = AppState.get('orgProfiles') || {};
    var fws = profiles[profileName];
    if (!fws) return;

    var pols = getProfilePolicies(profileName);
    var stats = getProfileStats(profileName);
    var policyTypes = AppState.get('policyTypes') || {};
    var isConnected = TenantAuth.isAuthenticated();

    var html = '<div class="modal-header">';
    html += '<h3>Deploy Profile: ' + escHtml(profileName) + '</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';

    // Framework list
    html += '<div class="section-hdr" style="margin-top:0">Frameworks (' + fws.length + ')</div>';
    html += '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:16px">';
    fws.forEach(function (fw) {
      html += '<span class="fw-tag">' + escHtml(fw) + '</span>';
    });
    html += '</div>';

    // Policy breakdown by type
    html += '<div class="section-hdr">Policies (' + stats.total + ')</div>';
    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:16px">';
    Object.keys(stats.byType).sort().forEach(function (type) {
      var label = (policyTypes[type] && policyTypes[type].label) || type;
      html += '<div style="font-size:.72rem;display:flex;justify-content:space-between;padding:4px 8px;background:var(--glass-bg2);border-radius:4px">';
      html += '<span style="color:var(--ink2)">' + escHtml(label.split('(')[0].trim()) + '</span>';
      html += '<span style="font-family:\'IBM Plex Mono\',monospace;color:var(--ink4)">' + stats.byType[type] + '</span>';
      html += '</div>';
    });
    html += '</div>';

    if (stats.deployable > 0) {
      html += '<div style="font-size:.72rem;color:var(--ink3);margin-bottom:16px">' +
        stats.deployable + ' policies can be deployed via API. Remaining require PowerShell scripts.</div>';
    }

    // Actions
    html += '<div class="config-actions" style="border-top:none;padding-top:0">';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '<button class="btn btn-script" onclick="ProfileDeploy.generateProfileScripts(\'' + escHtml(profileName).replace(/'/g, "\\'") + '\')">Generate Scripts (' + pols.length + ')</button>';
    if (isConnected && stats.deployable > 0) {
      html += '<button class="btn btn-deploy" onclick="ProfileDeploy.deployProfile(\'' + escHtml(profileName).replace(/'/g, "\\'") + '\')">Deploy ' + stats.deployable + ' Policies</button>';
    } else if (!isConnected) {
      html += '<button class="btn" onclick="handleConnectTenant()">Connect Tenant to Deploy</button>';
    }
    html += '</div>';

    html += '</div>';
    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  async function deployProfile(profileName) {
    document.getElementById('modal-overlay').classList.remove('open');

    var pols = getProfilePolicies(profileName);
    var deployableIds = pols
      .filter(function (p) { return DeployEngine.isDeployable(p.type, p.id); })
      .map(function (p) { return p.id; });

    if (deployableIds.length === 0) {
      showToast('No deployable policies in this profile');
      return;
    }

    // Route through BulkConfig
    if (typeof BulkConfig !== 'undefined') {
      await BulkConfig.startBulk(deployableIds, 'deploy');
    } else {
      await DeployEngine.deployBulk(deployableIds);
    }
  }

  async function generateProfileScripts(profileName) {
    document.getElementById('modal-overlay').classList.remove('open');

    var pols = getProfilePolicies(profileName);
    var scriptableIds = pols
      .filter(function (p) { return DeployEngine.hasScript(p.type); })
      .map(function (p) { return p.id; });

    if (scriptableIds.length === 0) {
      showToast('No scriptable policies in this profile');
      return;
    }

    // Route through BulkConfig
    if (typeof BulkConfig !== 'undefined') {
      await BulkConfig.startBulk(scriptableIds, 'script');
    } else {
      showToast('BulkConfig not available');
    }
  }

  return {
    getProfilePolicies: getProfilePolicies,
    getProfileStats: getProfileStats,
    showProfileModal: showProfileModal,
    deployProfile: deployProfile,
    generateProfileScripts: generateProfileScripts,
  };
})();
