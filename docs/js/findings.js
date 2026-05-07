/* ═══════════════════════════════════════════
   FINDINGS — Per-workload tenant analyzers that emit ranked findings.

   Inspired by Jhope188/ca-policy-analyzer:
     - Severity-ranked issues (Critical → Info)
     - Each finding has title, description, remediation, refs
     - Pluggable analyzer per workload (CA, Intune, Entra, etc.)

   This is the framework + registry. The actual rules live in
   docs/js/analyzers/<workload>-analyzer.js.
═══════════════════════════════════════════ */
const Findings = (() => {

  // ── Severity model ──
  // Higher number = more severe. Numbers used for sorting + scoring.
  const SEVERITY = {
    critical: { label: 'Critical', rank: 4, colour: 'var(--red)' },
    high:     { label: 'High',     rank: 3, colour: '#e84393' },
    medium:   { label: 'Medium',   rank: 2, colour: 'var(--amber)' },
    low:      { label: 'Low',      rank: 1, colour: 'var(--blue)' },
    info:     { label: 'Info',     rank: 0, colour: 'var(--ink3)' },
  };

  // ── Pluggable analyzer registry ──
  const analyzers = [];

  /**
   * Register an analyzer.
   *   workload: short slug ('conditional-access', 'intune', 'entra', ...)
   *   label:    human display label
   *   analyze:  function (scanData, context) → array<Finding>
   */
  function register(workload, label, analyze) {
    analyzers.push({ workload, label, analyze });
  }

  /** Run every registered analyzer over a scan and aggregate findings. */
  function analyzeAll(scanData) {
    const all = [];
    if (!scanData || !scanData.data) return { findings: all, score: null };

    const context = {
      tenantId: scanData.tenantId,
      scannedAt: scanData.timestamp,
    };

    // Scan-diagnostics group always comes first when there are errors —
    // a failed scan often masquerades as "tenant has nothing configured",
    // so we surface this prominently before any analyzer-emitted findings.
    const scanErrors = Array.isArray(scanData.errors) ? scanData.errors : [];
    if (scanErrors.length > 0) {
      // Sometimes EVERY endpoint failed → almost certainly a permissions issue
      // affecting the whole scan. Promote that to a single critical finding.
      const everythingFailed = scanData.endpointCount && scanErrors.length >= scanData.endpointCount - 1;
      all.push({
        workload: '_scan',
        workloadLabel: 'Scan diagnostics',
        severity: everythingFailed ? 'critical' : 'high',
        id: '_scan-failures',
        ruleId: 'scan-failures',
        title: scanErrors.length + ' Graph endpoint' + (scanErrors.length > 1 ? 's' : '') + ' failed during scan' +
          (everythingFailed ? ' — entire scan may be invalid' : ''),
        description: 'The findings below may report "no policies configured" when the real cause is a failed scan. Each failed endpoint is listed here with its error.',
        remediation: 'Most common: missing admin consent for required Graph permissions, or signing in as a user without admin role. Verify both. Reconnect Tenant.',
        refs: scanErrors.map(e => e.length > 200 ? e.substring(0, 200) + '…' : e),
      });
    }

    for (const a of analyzers) {
      try {
        const out = a.analyze(scanData.data, context) || [];
        for (const f of out) {
          if (!f) continue;
          // Normalise + stamp workload info onto each finding.
          all.push(Object.assign({
            workload: a.workload,
            workloadLabel: a.label,
            severity: 'info',
            id: a.workload + '-' + (f.ruleId || 'unknown'),
          }, f));
        }
      } catch (err) {
        console.error('[Findings] analyzer ' + a.workload + ' threw:', err);
      }
    }

    // Sort by severity (highest first), then by workload, then by title.
    all.sort((a, b) => {
      const ra = (SEVERITY[a.severity] || SEVERITY.info).rank;
      const rb = (SEVERITY[b.severity] || SEVERITY.info).rank;
      if (rb !== ra) return rb - ra;
      if (a.workload !== b.workload) return a.workload.localeCompare(b.workload);
      return (a.title || '').localeCompare(b.title || '');
    });

    return {
      findings: all,
      score: computeCoverageScore(all),
      counts: countBySeverity(all),
    };
  }

  // ── Scoring ──
  // 100 = no findings. Each finding deducts based on severity.
  // Critical -15, High -8, Medium -4, Low -2, Info 0.
  // Floor at 0; scoring is heuristic, not precise.
  function computeCoverageScore(findings) {
    let score = 100;
    for (const f of findings) {
      switch (f.severity) {
        case 'critical': score -= 15; break;
        case 'high':     score -= 8;  break;
        case 'medium':   score -= 4;  break;
        case 'low':      score -= 2;  break;
      }
    }
    return Math.max(0, score);
  }

  function countBySeverity(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const sev = f.severity || 'info';
      if (counts[sev] !== undefined) counts[sev]++;
    }
    return counts;
  }

  // ── State helpers ──
  // Distinguish three states for any scan source:
  //   notScanned (undefined)   — endpoint not in scan map / not run
  //   scanFailed (null)        — endpoint in scan map but request errored
  //   scanned    (array/object)— endpoint returned data (which may be empty)
  function sourceState(value) {
    if (value === undefined) return 'notScanned';
    if (value === null) return 'scanFailed';
    return 'scanned';
  }
  // True only when we have positive evidence of empty (not when scan failed).
  function isGenuinelyEmpty(value) {
    return Array.isArray(value) && value.length === 0;
  }

  // ── Helpers analyzers can use ──
  function isCAEnabled(p) { return p && p.state === 'enabled'; }
  function isCAReportOnly(p) { return p && p.state === 'enabledForReportingButNotEnforced'; }
  function targetsAllUsers(p) {
    return p && p.conditions && p.conditions.users &&
      Array.isArray(p.conditions.users.includeUsers) &&
      p.conditions.users.includeUsers.indexOf('All') !== -1;
  }
  function hasUserExclusions(p) {
    if (!p || !p.conditions || !p.conditions.users) return false;
    const u = p.conditions.users;
    return (u.excludeUsers || []).length > 0 ||
           (u.excludeGroups || []).length > 0 ||
           (u.excludeRoles || []).length > 0;
  }
  function grantControls(p) {
    return (p && p.grantControls && p.grantControls.builtInControls) || [];
  }
  function isBlockPolicy(p) {
    return grantControls(p).indexOf('block') !== -1;
  }
  function targetsAllApps(p) {
    return p && p.conditions && p.conditions.applications &&
      Array.isArray(p.conditions.applications.includeApplications) &&
      p.conditions.applications.includeApplications.indexOf('All') !== -1;
  }

  return {
    register, analyzeAll,
    computeCoverageScore, countBySeverity,
    SEVERITY,
    helpers: {
      isCAEnabled, isCAReportOnly,
      targetsAllUsers, hasUserExclusions,
      grantControls, isBlockPolicy, targetsAllApps,
      sourceState, isGenuinelyEmpty,
    },
  };
})();
