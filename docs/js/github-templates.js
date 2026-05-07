/* ═══════════════════════════════════════════
   GITHUB TEMPLATES — Compare tenant policies against any public GitHub
   repository's CA policy JSONs. Mirrors jhope188/ca-policy-analyzer's
   "Compare Custom Repo" feature.

   Accepts:
     - github.com URLs (any depth: blob/HEAD/branch/path)
     - owner/repo shorthand
     - raw.githubusercontent.com URLs
   Discovers JSON files via GitHub Tree API, fetches each, treats them
   as candidate CA templates, and scores against the tenant.
═══════════════════════════════════════════ */
const GitHubTemplates = (() => {

  const GH_API = 'https://api.github.com';

  function _esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /**
   * Parse user input into { owner, repo, branch, path }.
   * Accepts any of:
   *   https://github.com/owner/repo
   *   https://github.com/owner/repo/tree/main
   *   https://github.com/owner/repo/tree/main/policies
   *   https://github.com/owner/repo/blob/main/policies/foo.json
   *   owner/repo
   */
  function parseInput(input) {
    if (!input) return null;
    input = input.trim();

    // Shorthand: owner/repo
    const shorthand = /^([\w.-]+)\/([\w.-]+)$/.exec(input);
    if (shorthand) return { owner: shorthand[1], repo: shorthand[2], branch: null, path: '' };

    let url;
    try { url = new URL(input); } catch (e) { return null; }
    if (url.hostname !== 'github.com' && url.hostname !== 'raw.githubusercontent.com') return null;

    const segs = url.pathname.replace(/^\//, '').split('/');
    if (segs.length < 2) return null;
    const owner = segs[0], repo = segs[1];
    let branch = null, path = '';
    if (url.hostname === 'github.com') {
      // /owner/repo/tree/<branch>/<path...> OR /owner/repo/blob/<branch>/<path>
      if ((segs[2] === 'tree' || segs[2] === 'blob') && segs.length >= 4) {
        branch = segs[3];
        path = segs.slice(4).join('/');
      }
    } else {
      // raw.githubusercontent.com/owner/repo/<branch>/<path>
      if (segs.length >= 4) {
        branch = segs[2];
        path = segs.slice(3).join('/');
      }
    }
    return { owner, repo, branch, path };
  }

  /** GitHub Tree API — list every file in the repo (or under a subpath). */
  async function listJsonFiles(target) {
    const owner = target.owner, repo = target.repo;
    let branch = target.branch;
    if (!branch) {
      // Fetch repo metadata to discover the default branch
      const repoMeta = await fetch(GH_API + '/repos/' + owner + '/' + repo);
      if (!repoMeta.ok) throw new Error('Repo lookup failed: HTTP ' + repoMeta.status);
      const repoJson = await repoMeta.json();
      branch = repoJson.default_branch || 'main';
    }

    // Use the Trees API to list every file recursively in one call
    const treeRes = await fetch(GH_API + '/repos/' + owner + '/' + repo + '/git/trees/' + encodeURIComponent(branch) + '?recursive=1');
    if (!treeRes.ok) throw new Error('Tree fetch failed: HTTP ' + treeRes.status);
    const treeJson = await treeRes.json();

    const allFiles = (treeJson.tree || []).filter(n => n.type === 'blob');
    const filtered = allFiles.filter(n => {
      if (!n.path.toLowerCase().endsWith('.json')) return false;
      if (target.path && n.path.indexOf(target.path) !== 0) return false;
      return true;
    });
    return { branch, files: filtered };
  }

  /** Pull each file via raw.githubusercontent.com, parse JSON, drop garbage. */
  async function fetchFiles(target, branch, files) {
    const owner = target.owner, repo = target.repo;
    const out = [];
    // Limit concurrency by batching
    const BATCH = 8;
    for (let i = 0; i < files.length; i += BATCH) {
      const slice = files.slice(i, i + BATCH);
      const fetched = await Promise.all(slice.map(async f => {
        const url = 'https://raw.githubusercontent.com/' + owner + '/' + repo + '/' + branch + '/' + f.path;
        try {
          const res = await fetch(url);
          if (!res.ok) return null;
          const text = await res.text();
          const parsed = JSON.parse(text);
          return { path: f.path, data: parsed };
        } catch (e) { return null; }
      }));
      fetched.forEach(x => { if (x) out.push(x); });
    }
    return out;
  }

  /** Pick out objects that look like CA policies (have conditions + grantControls). */
  function asCATemplates(files) {
    const templates = [];
    for (const f of files) {
      const items = Array.isArray(f.data) ? f.data : [f.data];
      for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        if (!item.conditions || !item.grantControls) continue;
        templates.push({
          id: item.templateId || item.id || f.path,
          displayName: item.displayName || f.path,
          state: item.state,
          conditions: item.conditions,
          grantControls: item.grantControls,
          sessionControls: item.sessionControls || null,
          source: f.path,
        });
      }
    }
    return templates;
  }

  /** Run the comparison and render results into the supplied container. */
  async function compare() {
    const input = document.getElementById('gh-repo-input');
    const out = document.getElementById('gh-repo-result');
    if (!input || !out) return;
    const value = input.value.trim();
    if (!value) { out.innerHTML = '<div style="color:var(--amber);font-size:.7rem">Enter a GitHub URL or owner/repo</div>'; return; }
    const target = parseInput(value);
    if (!target) { out.innerHTML = '<div style="color:var(--red);font-size:.7rem">Could not parse — use a github.com URL or owner/repo</div>'; return; }

    out.innerHTML = '<div style="color:var(--ink3);font-size:.7rem">Discovering files in <code>' + _esc(target.owner) + '/' + _esc(target.repo) + '</code>…</div>';

    let listed;
    try { listed = await listJsonFiles(target); }
    catch (e) { out.innerHTML = '<div style="color:var(--red);font-size:.7rem">' + _esc(e.message) + '</div>'; return; }

    if (listed.files.length === 0) {
      out.innerHTML = '<div style="color:var(--amber);font-size:.7rem">No JSON files found' + (target.path ? ' under ' + _esc(target.path) : '') + '.</div>';
      return;
    }

    out.innerHTML = '<div style="color:var(--ink3);font-size:.7rem">Found ' + listed.files.length + ' JSON files. Fetching…</div>';
    const fetched = await fetchFiles(target, listed.branch, listed.files);
    const templates = asCATemplates(fetched);

    if (templates.length === 0) {
      out.innerHTML = '<div style="color:var(--amber);font-size:.7rem">' + listed.files.length + ' JSON files fetched but none look like CA policies (missing conditions / grantControls).</div>';
      return;
    }

    // Score each template against the tenant's CA policies
    const scanData = (typeof TenantScanner !== 'undefined') ? TenantScanner.getScanResults() : null;
    const tenantPolicies = (scanData && scanData.data && scanData.data.conditionalAccess) || [];

    const results = templates.map(t => {
      let bestScore = 0, bestPolicy = null;
      for (const p of tenantPolicies) {
        const s = _scoreTemplate(t, p);
        if (s > bestScore) { bestScore = s; bestPolicy = p; }
      }
      let status = 'missing';
      if (bestScore >= 80) status = 'present';
      else if (bestScore >= 40) status = 'partial';
      return { template: t, status, score: bestScore, matchedTenantPolicy: bestPolicy };
    });

    let html = '<div style="margin-top:10px">';
    const present = results.filter(r => r.status === 'present').length;
    const partial = results.filter(r => r.status === 'partial').length;
    const missing = results.filter(r => r.status === 'missing').length;
    html += '<div style="font-size:.7rem;color:var(--ink2);margin-bottom:10px">' + templates.length + ' templates from <code>' + _esc(target.owner) + '/' + _esc(target.repo) + '@' + _esc(listed.branch) + '</code> · ' +
      present + ' present, ' + partial + ' partial, ' + missing + ' missing</div>';
    html += '<table style="width:100%;border-collapse:collapse;font-size:.62rem">';
    html += '<thead><tr style="text-align:left;color:var(--ink3);border-bottom:1px solid var(--border)"><th style="padding:5px">Template</th><th style="padding:5px">Status</th><th style="padding:5px">Best match</th><th style="padding:5px">Score</th><th style="padding:5px">Source</th></tr></thead><tbody>';
    results.sort((a, b) => {
      const order = { missing: 0, partial: 1, present: 2 };
      return order[a.status] - order[b.status];
    });
    for (const r of results) {
      const colour = r.status === 'present' ? 'var(--green)' : r.status === 'partial' ? 'var(--amber)' : 'var(--red)';
      html += '<tr style="border-bottom:1px solid var(--border)">';
      html += '<td style="padding:5px;color:var(--ink)">' + _esc(r.template.displayName || '—') + '</td>';
      html += '<td style="padding:5px"><span style="color:' + colour + ';font-weight:600;text-transform:uppercase;font-size:.54rem">' + r.status + '</span></td>';
      html += '<td style="padding:5px;color:var(--ink3)">' + _esc(r.matchedTenantPolicy ? (r.matchedTenantPolicy.displayName || r.matchedTenantPolicy.id || '') : '—') + '</td>';
      html += '<td style="padding:5px;color:var(--ink4)">' + r.score + '%</td>';
      html += '<td style="padding:5px;color:var(--ink4);font-family:monospace;font-size:.55rem">' + _esc(r.template.source || '') + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table></div>';
    out.innerHTML = html;
  }

  function _scoreTemplate(template, tenantPolicy) {
    let total = 0, matched = 0;
    function setOverlap(a, b) {
      if (!Array.isArray(a) || !Array.isArray(b) || a.length === 0 || b.length === 0) return false;
      const setA = new Set(a.map(x => String(x).toLowerCase()));
      for (const x of b) if (setA.has(String(x).toLowerCase())) return true;
      return false;
    }
    const tCond = template.conditions || {};
    const pCond = tenantPolicy.conditions || {};

    if ((tCond.applications && tCond.applications.includeApplications || []).length > 0) {
      total += 25;
      if (setOverlap(tCond.applications.includeApplications, (pCond.applications && pCond.applications.includeApplications) || [])) matched += 25;
    }
    if ((tCond.users && tCond.users.includeRoles || []).length > 0) {
      total += 15;
      if (setOverlap(tCond.users.includeRoles, (pCond.users && pCond.users.includeRoles) || [])) matched += 15;
    } else if (((tCond.users && tCond.users.includeUsers) || []).indexOf('All') !== -1) {
      total += 15;
      if (((pCond.users && pCond.users.includeUsers) || []).indexOf('All') !== -1) matched += 15;
    }
    const tGrant = (template.grantControls && template.grantControls.builtInControls) || [];
    const pGrant = (tenantPolicy.grantControls && tenantPolicy.grantControls.builtInControls) || [];
    if (tGrant.length > 0) {
      total += 30;
      if (setOverlap(tGrant, pGrant)) matched += 30;
    }
    if ((tCond.signInRiskLevels || []).length > 0) {
      total += 10;
      if (setOverlap(tCond.signInRiskLevels, pCond.signInRiskLevels || [])) matched += 10;
    }
    if ((tCond.userRiskLevels || []).length > 0) {
      total += 10;
      if (setOverlap(tCond.userRiskLevels, pCond.userRiskLevels || [])) matched += 10;
    }
    if ((tCond.clientAppTypes || []).length > 0) {
      total += 10;
      if (setOverlap(tCond.clientAppTypes, pCond.clientAppTypes || [])) matched += 10;
    }
    return total > 0 ? Math.round((matched / total) * 100) : 0;
  }

  return { compare, parseInput };
})();
