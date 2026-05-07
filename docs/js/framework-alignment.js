/* ═══════════════════════════════════════════
   FRAMEWORK ALIGNMENT — for each framework, compute the % of CIS controls
   that the tenant has at least one matching configured policy for.

   Inputs (already loaded into AppState):
     - checks       — array of CIS checks; each has fws[] + cat
     - frameworks   — array of framework names
     - policies     — our 143 policies; each has frameworks[] + cisChecks[]
     - scanResults  — output of PolicyMatcher.matchAll(policies)
                      keyed by policy id → { status: configured|missing|manual|… }

   Output:
     {
       overall: { score, configured, total, missing, manual },
       byFramework: [
         { framework, configured, total, manual, score, controls: [{id,name,status}] }
       ],
     }
═══════════════════════════════════════════ */
const FrameworkAlignment = (() => {

  // Pull a check's matching policies' status from the scan results.
  // A check is "configured" if ANY mapped policy is configured.
  function statusForCheck(check, policies, scanResults) {
    const matchingPolicies = policies.filter(p =>
      Array.isArray(p.cisChecks) && p.cisChecks.indexOf(check.id) !== -1
    );
    if (matchingPolicies.length === 0) return 'unmapped';

    let any = null;
    for (const p of matchingPolicies) {
      const r = scanResults && scanResults[p.id];
      if (!r) continue;
      if (r.status === 'configured') return 'configured';  // short-circuit
      if (r.status === 'missing') any = any || 'missing';
      if (r.status === 'manual') any = any || 'manual';
    }
    return any || 'unmapped';
  }

  function computeAlignment() {
    const checks = AppState.get('checks') || [];
    const frameworks = AppState.get('frameworks') || [];
    const policies = AppState.get('policies') || [];
    const scanResults = AppState.get('tenantScanResults') || null;

    if (!scanResults) return null;

    // Score each check once
    const checkStatus = {};
    for (const c of checks) checkStatus[c.id] = statusForCheck(c, policies, scanResults);

    const byFramework = {};
    for (const fw of frameworks) byFramework[fw] = { framework: fw, configured: 0, missing: 0, manual: 0, total: 0, controls: [] };

    for (const c of checks) {
      const fws = Array.isArray(c.fws) ? c.fws : [];
      const status = checkStatus[c.id];
      for (const fw of fws) {
        if (!byFramework[fw]) continue;
        byFramework[fw].total++;
        if (status === 'configured') byFramework[fw].configured++;
        else if (status === 'missing') byFramework[fw].missing++;
        else if (status === 'manual') byFramework[fw].manual++;
        // unmapped checks still count toward total (a gap)
        byFramework[fw].controls.push({ id: c.id, name: c.name, cat: c.cat, level: c.level, status });
      }
    }

    const list = Object.values(byFramework)
      .filter(f => f.total > 0)
      .map(f => Object.assign({}, f, { score: Math.round((f.configured / f.total) * 100) }))
      .sort((a, b) => b.score - a.score || a.framework.localeCompare(b.framework));

    let overall = { configured: 0, manual: 0, missing: 0, total: checks.length, score: 0 };
    for (const c of checks) {
      if (checkStatus[c.id] === 'configured') overall.configured++;
      else if (checkStatus[c.id] === 'manual') overall.manual++;
      else if (checkStatus[c.id] === 'missing') overall.missing++;
    }
    overall.score = checks.length > 0 ? Math.round((overall.configured / checks.length) * 100) : 0;

    return { overall, byFramework: list };
  }

  return { computeAlignment };
})();
