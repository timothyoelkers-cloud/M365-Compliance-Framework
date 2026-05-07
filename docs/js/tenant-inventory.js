/* ═══════════════════════════════════════════
   TENANT INVENTORY — Decode raw scan data into a clean,
   exportable list of what's actually configured in the tenant.

   This is decoupled from our 143-policy catalogue: it just shows
   what the customer has, period. The policy-matcher.js compares
   against the catalogue separately.
═══════════════════════════════════════════ */
const TenantInventory = (() => {

  // Each "source" is a function (raw, label) → array of inventory items.
  // An item has: { name, kind, summary, state, raw, links? }
  // - name: human-readable name
  // - kind: short type label (e.g. "CA Policy")
  // - summary: 1-line description of what it does (key settings)
  // - state: 'enabled' | 'disabled' | 'reportOnly' | 'unknown'
  // - raw: the original Graph object (for export)

  const SOURCES = {
    conditionalAccess: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(p => ({
        name: p.displayName || '(unnamed)',
        kind: 'CA Policy',
        summary: summariseCA(p),
        state: p.state === 'enabled' ? 'enabled' :
               p.state === 'enabledForReportingButNotEnforced' ? 'reportOnly' :
               'disabled',
        id: p.id,
        raw: p,
      }));
    },

    namedLocations: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(loc => ({
        name: loc.displayName || '(unnamed)',
        kind: 'Named Location',
        summary: loc['@odata.type'] && loc['@odata.type'].indexOf('country') !== -1
          ? 'Country: ' + (loc.countriesAndRegions || []).join(', ')
          : 'IP ranges: ' + ((loc.ipRanges || []).map(r => r.cidrAddress).join(', ') || 'none'),
        state: loc.isTrusted ? 'enabled' : 'unknown',
        id: loc.id,
        raw: loc,
      }));
    },

    compliancePolicies: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(p => ({
        name: p.displayName || '(unnamed)',
        kind: 'Intune Compliance',
        summary: 'Platform: ' + ((p['@odata.type'] || '').split('.').pop().replace(/CompliancePolicy$/, '') || 'unknown'),
        state: 'enabled',
        id: p.id,
        raw: p,
      }));
    },

    deviceConfigurations: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(p => ({
        name: p.displayName || '(unnamed)',
        kind: 'Intune Device Config',
        summary: ((p['@odata.type'] || '').split('.').pop()),
        state: 'enabled',
        id: p.id,
        raw: p,
      }));
    },

    configurationPolicies: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(p => ({
        name: p.name || p.displayName || '(unnamed)',
        kind: 'Endpoint Security / Settings Catalog',
        summary: 'Platforms: ' + (p.platforms || 'all') + ', Tech: ' + (p.technologies || 'mdm'),
        state: 'enabled',
        id: p.id,
        raw: p,
      }));
    },

    appProtection: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(p => ({
        name: p.displayName || '(unnamed)',
        kind: 'App Protection Policy',
        summary: ((p['@odata.type'] || '').split('.').pop()),
        state: 'enabled',
        id: p.id,
        raw: p,
      }));
    },

    permissionGrantPolicies: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(p => ({
        name: p.displayName || p.id || '(unnamed)',
        kind: 'Permission Grant Policy',
        summary: p.description || '',
        state: 'enabled',
        id: p.id,
        raw: p,
      }));
    },

    sensitivityLabels: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(l => ({
        name: l.name || l.displayName || '(unnamed)',
        kind: 'Sensitivity Label',
        summary: l.description || '',
        state: l.isActive ? 'enabled' : 'disabled',
        id: l.id,
        raw: l,
      }));
    },

    retentionLabels: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(l => ({
        name: l.displayName || l.name || '(unnamed)',
        kind: 'Retention Label',
        summary: 'Retain ' + (l.retentionDuration ? JSON.stringify(l.retentionDuration) : 'n/a'),
        state: l.isInUse ? 'enabled' : 'unknown',
        id: l.id,
        raw: l,
      }));
    },

    dlpPolicies: function (list) {
      if (!Array.isArray(list)) return [];
      return list.map(p => ({
        name: p.displayName || p.name || '(unnamed)',
        kind: 'DLP Policy',
        summary: p.description || (p.workloadProfile || ''),
        state: p.state || 'unknown',
        id: p.id,
        raw: p,
      }));
    },

    sharepointSettings: function (s) {
      if (!s || typeof s !== 'object') return [];
      const items = [
        { key: 'sharingCapability', label: 'External sharing' },
        { key: 'defaultSharingLinkType', label: 'Default sharing link' },
        { key: 'defaultLinkPermission', label: 'Default link permission' },
        { key: 'isLegacyAuthProtocolsEnabled', label: 'Legacy auth allowed' },
        { key: 'isResharingByExternalUsersEnabled', label: 'Guest re-sharing' },
        { key: 'isUnmanagedSyncAppForTenantRestricted', label: 'Restrict unmanaged sync' },
        { key: 'anonymousLinkExpirationRestrictionDays', label: 'Anonymous link expiry (days)' },
        { key: 'sharingDomainRestrictionMode', label: 'Domain restriction mode' },
      ];
      return items.filter(i => s[i.key] !== undefined).map(i => ({
        name: i.label,
        kind: 'SharePoint Setting',
        summary: String(s[i.key]),
        state: 'enabled',
        id: i.key,
        raw: { [i.key]: s[i.key] },
      }));
    },

    organization: function (list) {
      if (!Array.isArray(list) || !list[0]) return [];
      const o = list[0];
      const skus = (o.assignedPlans || []).filter(p => p.capabilityStatus === 'Enabled')
        .map(p => p.service).filter((v, i, a) => a.indexOf(v) === i);
      return [{
        name: o.displayName,
        kind: 'Tenant',
        summary: 'Verified domains: ' + (o.verifiedDomains || []).map(d => d.name).join(', ') + ' • Services: ' + skus.length,
        state: 'enabled',
        id: o.id,
        raw: { id: o.id, displayName: o.displayName, country: o.country, services: skus },
      }];
    },

    secureScores: function (list) {
      if (!Array.isArray(list) || !list[0]) return [];
      const s = list[0];
      const pct = s.maxScore ? Math.round((s.currentScore / s.maxScore) * 100) : null;
      return [{
        name: 'Secure Score',
        kind: 'Security Posture',
        summary: (s.currentScore != null ? s.currentScore.toFixed(0) : '?') + ' / ' + (s.maxScore || '?') + (pct !== null ? ' (' + pct + '%)' : ''),
        state: 'enabled',
        id: s.id,
        raw: { currentScore: s.currentScore, maxScore: s.maxScore, createdDateTime: s.createdDateTime },
      }];
    },
  };

  // ── Helpers ──

  function summariseCA(p) {
    const conds = p.conditions || {};
    const apps = (conds.applications && conds.applications.includeApplications) || [];
    const users = (conds.users && conds.users.includeUsers) || [];
    const roles = (conds.users && conds.users.includeRoles) || [];
    const grant = (p.grantControls && p.grantControls.builtInControls) || [];
    const session = p.sessionControls || {};
    const targets = [];
    if (users.includes('All')) targets.push('All users');
    else if (users.length) targets.push(users.length + ' user(s)');
    if (roles.length) targets.push(roles.length + ' role(s)');
    const apptargets = apps.includes('All') ? 'all apps' : apps.length ? apps.length + ' app(s)' : 'no apps';
    const controls = [];
    if (grant.includes('block')) controls.push('block');
    if (grant.includes('mfa')) controls.push('MFA');
    if (grant.includes('compliantDevice')) controls.push('compliant device');
    if (grant.includes('domainJoinedDevice')) controls.push('hybrid joined');
    if (grant.includes('passwordChange')) controls.push('pw change');
    if (p.grantControls && p.grantControls.authenticationStrength) controls.push('auth strength');
    if (session.signInFrequency) controls.push('sign-in frequency');
    if (session.persistentBrowser) controls.push('persistent browser');
    return (targets.join(' + ') || 'unspecified') + ' → ' + apptargets + (controls.length ? ' → ' + controls.join(', ') : '');
  }

  // ── Public API ──

  /**
   * Build an inventory from a raw scan result.
   * Returns:
   *   {
   *     scannedAt, tenantId, tenantName, scannedBy,
   *     totals: { items, byCategory: { Identity: 12, ... } },
   *     groups: [
   *       { source, label, category, count, items[], available: true/false, error?: '…' }
   *     ]
   *   }
   */
  function build(scanCache, scanEndpoints) {
    if (!scanCache || !scanCache.data) return null;
    const data = scanCache.data;
    const errorsByKey = {};
    (scanCache.errors || []).forEach(e => {
      const idx = e.indexOf(':');
      if (idx > -1) errorsByKey[e.substring(0, idx).trim()] = e.substring(idx + 1).trim();
    });

    const groups = [];
    let totalItems = 0;
    const byCategory = {};

    for (const key of Object.keys(scanEndpoints)) {
      const def = scanEndpoints[key];
      const decoder = SOURCES[key];
      const raw = data[key];
      const error = errorsByKey[key];

      if (!decoder) continue;

      let items = [];
      let available = true;
      try {
        items = decoder(raw, def.label) || [];
      } catch (e) {
        items = [];
        available = false;
      }

      if (raw === null || raw === undefined) {
        available = false;
      }

      groups.push({
        source: key,
        label: def.label || key,
        category: def.category || 'Other',
        count: items.length,
        items: items,
        available: available,
        error: error || null,
      });

      totalItems += items.length;
      byCategory[def.category || 'Other'] = (byCategory[def.category || 'Other'] || 0) + items.length;
    }

    // Sort groups by category then label.
    groups.sort((a, b) => a.category.localeCompare(b.category) || a.label.localeCompare(b.label));

    return {
      scannedAt: scanCache.timestamp,
      tenantId: scanCache.tenantId,
      tenantName: null,  // filled below from organization data if present
      scannedBy: scanCache.scannedBy,
      totals: { items: totalItems, byCategory: byCategory },
      groups: groups,
    };
  }

  /** Export the inventory as JSON (downloadable). */
  function toJson(inventory) {
    return JSON.stringify(inventory, null, 2);
  }

  /** Export the inventory as CSV (one row per item). */
  function toCsv(inventory) {
    const headers = ['Category', 'Source', 'Kind', 'Name', 'State', 'Summary', 'Id'];
    const rows = [headers.join(',')];
    for (const group of inventory.groups) {
      for (const item of group.items) {
        rows.push([
          group.category,
          group.label,
          item.kind,
          item.name,
          item.state || '',
          item.summary || '',
          item.id || '',
        ].map(csvCell).join(','));
      }
    }
    return rows.join('\n');
  }

  function csvCell(v) {
    var s = String(v == null ? '' : v);
    if (s.indexOf(',') > -1 || s.indexOf('"') > -1 || s.indexOf('\n') > -1) {
      s = '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  return { build, toJson, toCsv };
})();
