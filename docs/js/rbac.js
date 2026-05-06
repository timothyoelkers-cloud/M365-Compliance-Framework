/* ═══════════════════════════════════════════
   RBAC — Role-Based Access Check
   Detects signed-in user's admin roles and
   warns about missing permissions for scan
   endpoints.
═══════════════════════════════════════════ */
const RBACCheck = (() => {
  let userRoles = null;
  let fetchedOnce = false;

  // Map scan endpoints to required Azure AD roles
  const ENDPOINT_ROLES = {
    conditionalAccess:        ['Conditional Access Administrator', 'Security Administrator', 'Global Administrator'],
    compliancePolicies:       ['Intune Administrator', 'Global Administrator'],
    deviceConfigurations:     ['Intune Administrator', 'Global Administrator'],
    configurationPolicies:    ['Intune Administrator', 'Global Administrator'],
    authorizationPolicy:      ['Global Administrator'],
    adminConsentPolicy:       ['Global Administrator'],
    deviceRegistrationPolicy: ['Global Administrator', 'Cloud Device Administrator'],
    authMethodsPolicy:        ['Authentication Policy Administrator', 'Global Administrator'],
    authenticatorConfig:      ['Authentication Policy Administrator', 'Global Administrator'],
    organization:             ['Global Reader', 'Global Administrator'],
    groupSettings:            ['Global Reader', 'Global Administrator'],
    sharepointSettings:       ['SharePoint Administrator', 'Global Administrator'],
    secureScores:             ['Security Reader', 'Security Administrator', 'Global Administrator'],
    secureScoreProfiles:      ['Security Reader', 'Security Administrator', 'Global Administrator'],
    sensitivityLabels:        ['Compliance Administrator', 'Information Protection Administrator', 'Global Administrator'],
  };

  // Friendly descriptions for roles
  const ROLE_DESCRIPTIONS = {
    'Global Administrator': 'Full access to all admin features',
    'Security Administrator': 'Manages security-related features',
    'Security Reader': 'Read-only access to security features',
    'Conditional Access Administrator': 'Manages Conditional Access policies',
    'Intune Administrator': 'Manages Intune device management',
    'SharePoint Administrator': 'Manages SharePoint Online',
    'Compliance Administrator': 'Manages compliance features',
    'Authentication Policy Administrator': 'Manages authentication methods',
    'Information Protection Administrator': 'Manages sensitivity labels',
    'Global Reader': 'Read-only access across all admin features',
    'Cloud Device Administrator': 'Manages cloud device settings',
  };

  // ─── Role Fetching ───

  async function fetchUserRoles() {
    if (!TenantAuth || !TenantAuth.isAuthenticated()) {
      userRoles = [];
      return [];
    }

    try {
      var token = await TenantAuth.getGraphToken();
      if (!token) { userRoles = []; return []; }

      var response = await fetch('https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName,@odata.type', {
        headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }
      });

      if (!response.ok) {
        console.warn('[RBAC] Failed to fetch roles:', response.status);
        userRoles = [];
        return [];
      }

      var data = await response.json();
      userRoles = (data.value || [])
        .filter(function (m) { return m['@odata.type'] === '#microsoft.graph.directoryRole'; })
        .map(function (r) { return r.displayName; });

      fetchedOnce = true;
      return userRoles;
    } catch (e) {
      console.warn('[RBAC] Error fetching roles:', e);
      userRoles = [];
      return [];
    }
  }

  function getUserRoles() { return userRoles || []; }
  function hasFetched() { return fetchedOnce; }

  // ─── Access Checking ───

  function checkEndpointAccess(endpointKey) {
    if (!userRoles || userRoles.length === 0) return true; // Assume OK if roles unknown
    var required = ENDPOINT_ROLES[endpointKey];
    if (!required) return true;

    // Global Admin has access to everything
    if (userRoles.indexOf('Global Administrator') !== -1) return true;

    return required.some(function (role) {
      return userRoles.indexOf(role) !== -1;
    });
  }

  function getMissingRoles(endpointKey) {
    if (!userRoles || !fetchedOnce) return [];
    var required = ENDPOINT_ROLES[endpointKey];
    if (!required) return [];

    if (userRoles.indexOf('Global Administrator') !== -1) return [];

    var hasAccess = required.some(function (role) { return userRoles.indexOf(role) !== -1; });
    if (hasAccess) return [];

    return required;
  }

  function getInaccessibleEndpoints() {
    if (!userRoles || !fetchedOnce) return [];
    return Object.keys(ENDPOINT_ROLES).filter(function (key) {
      return !checkEndpointAccess(key);
    });
  }

  // ─── UI Rendering ───

  function renderWarningBadge(endpointKey) {
    if (!fetchedOnce || checkEndpointAccess(endpointKey)) return '';

    var missing = getMissingRoles(endpointKey);
    var tip = 'Requires: ' + missing.join(' or ');
    return '<span class="scan-badge scan-badge-manual" title="' + escHtml(tip) + '" style="cursor:help;font-size:.55rem">No Access</span>';
  }

  function renderPermissionSummary() {
    if (!fetchedOnce) return '<div style="color:var(--ink4);font-size:.72rem">Connect to a tenant to check role access.</div>';

    var html = '<div style="margin-bottom:12px">';
    html += '<div class="section-hdr">Your Roles</div>';

    if (userRoles.length === 0) {
      html += '<div style="color:var(--amber2);font-size:.72rem">No admin roles detected. You may have limited scan coverage.</div>';
    } else {
      html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px">';
      for (var i = 0; i < userRoles.length; i++) {
        html += '<span class="badge badge-blue" title="' + escHtml(ROLE_DESCRIPTIONS[userRoles[i]] || '') + '">' + escHtml(userRoles[i]) + '</span>';
      }
      html += '</div>';
    }

    // Endpoint access table
    var inaccessible = getInaccessibleEndpoints();
    if (inaccessible.length > 0) {
      html += '<div class="section-hdr" style="margin-top:12px">Limited Access Endpoints</div>';
      html += '<table class="data-table" style="font-size:.68rem"><thead><tr><th>Endpoint</th><th>Required Roles</th></tr></thead><tbody>';
      for (var j = 0; j < inaccessible.length; j++) {
        var ep = inaccessible[j];
        var roles = ENDPOINT_ROLES[ep] || [];
        html += '<tr>';
        html += '<td class="text-mono">' + escHtml(ep) + '</td>';
        html += '<td>' + roles.map(function (r) { return '<span class="badge badge-amber" style="font-size:.55rem">' + escHtml(r) + '</span>'; }).join(' ') + '</td>';
        html += '</tr>';
      }
      html += '</tbody></table>';
    } else if (userRoles.length > 0) {
      html += '<div style="color:var(--green);font-size:.72rem">Full access to all scan endpoints.</div>';
    }

    html += '</div>';
    return html;
  }

  return {
    fetchUserRoles: fetchUserRoles,
    getUserRoles: getUserRoles,
    hasFetched: hasFetched,
    checkEndpointAccess: checkEndpointAccess,
    getMissingRoles: getMissingRoles,
    getInaccessibleEndpoints: getInaccessibleEndpoints,
    renderWarningBadge: renderWarningBadge,
    renderPermissionSummary: renderPermissionSummary,
  };
})();
