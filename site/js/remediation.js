/* ═══════════════════════════════════════════
   REMEDIATION — Synthesises remediation guidance
   from existing policy JSON data. No new JSON
   fields needed — reads _notes, postDeployment,
   _configFields, steps, etc.
═══════════════════════════════════════════ */
const Remediation = (() => {

  var cache = {};

  /**
   * Build structured remediation for a single policy.
   * Loads the full policy JSON via DataStore.
   * @param {string} policyId
   * @returns {Promise<Object|null>}
   */
  async function getRemediation(policyId) {
    if (cache[policyId]) return cache[policyId];

    var policies = AppState.get('policies') || [];
    var polSummary = policies.find(function (p) { return p.id === policyId; });
    if (!polSummary) return null;

    var fullPolicy;
    try {
      fullPolicy = await DataStore.loadPolicy(polSummary.type, polSummary.file);
    } catch (e) {
      return null;
    }

    var meta = fullPolicy._metadata || {};
    var notes = fullPolicy._notes || {};
    var configFields = fullPolicy._configFields || [];
    var postDeploy = fullPolicy.postDeployment || [];
    var steps = fullPolicy.steps || [];
    var psCommands = fullPolicy.powershellCommands ? Object.keys(fullPolicy.powershellCommands) : [];

    // Collect deployment steps from various sources
    var deploySteps = [];
    if (Array.isArray(notes.deploymentSteps)) {
      deploySteps = notes.deploymentSteps;
    } else if (typeof notes.deploymentSteps === 'string') {
      deploySteps = [notes.deploymentSteps];
    }
    // If no explicit steps, synthesise from steps[] or powershellCommands
    if (deploySteps.length === 0 && steps.length > 0) {
      deploySteps = steps.map(function (s, i) {
        return 'Run ' + (s.cmdlet || 'step ' + (i + 1)) + (s.parameters && s.parameters.Name ? ' — "' + s.parameters.Name + '"' : '');
      });
    }
    if (deploySteps.length === 0 && psCommands.length > 0) {
      deploySteps = psCommands.map(function (k) {
        var cmd = fullPolicy.powershellCommands[k];
        return 'Run ' + (cmd.cmdlet || k);
      });
    }

    // Collect prerequisites
    var prereqs = [];
    if (Array.isArray(notes.prerequisites)) prereqs = notes.prerequisites;
    else if (typeof notes.prerequisites === 'string') prereqs = [notes.prerequisites];

    // Derive effort
    var stepCount = deploySteps.length + configFields.length;
    var effort = stepCount <= 2 ? 'Low' : stepCount <= 5 ? 'Medium' : 'High';

    // Collect verification commands
    var verification = postDeploy.slice();
    var rule = (typeof PolicyMatcher !== 'undefined') ? PolicyMatcher.MATCH_RULES[policyId] : null;
    if (rule && rule.verifyCommand && verification.indexOf(rule.verifyCommand) === -1) {
      verification.push(rule.verifyCommand);
    }

    var result = {
      policyId: policyId,
      title: meta.title || polSummary.displayName || policyId,
      description: polSummary.description || meta.description || '',
      severity: meta.severity || 'Medium',
      category: polSummary.type || meta.category || '',
      requiredLicence: meta.requiredLicence || meta.requiredLicences || polSummary.requiredLicence || '',
      effort: effort,
      frameworkCount: (polSummary.frameworks || []).length,
      prerequisites: prereqs,
      deploymentSteps: deploySteps,
      rollbackProcedure: notes.rollbackProcedure || '',
      verificationCommands: verification,
      configFields: configFields.map(function (f) {
        return { label: f.label, description: f.description || '', required: !!f.required, default: f.default || '' };
      }),
      deploymentNotes: meta.deploymentNotes || '',
    };

    cache[policyId] = result;
    return result;
  }

  /**
   * Get remediation data for all missing/gap policies from scan results.
   * @param {number} [limit] — max number to load (default 15)
   * @returns {Promise<Object[]>}
   */
  async function getRemediationsForGaps(limit) {
    limit = limit || 15;
    var scanResults = AppState.get('tenantScanResults') || {};
    var missingIds = Object.keys(scanResults).filter(function (id) {
      return scanResults[id].status === 'missing';
    });

    // Sort by framework count (policies with more framework impact first)
    var policies = AppState.get('policies') || [];
    var polMap = {};
    policies.forEach(function (p) { polMap[p.id] = p; });

    missingIds.sort(function (a, b) {
      var pa = polMap[a], pb = polMap[b];
      var fa = pa ? (pa.frameworks || []).length : 0;
      var fb = pb ? (pb.frameworks || []).length : 0;
      return fb - fa;
    });

    var sliced = missingIds.slice(0, limit);
    var results = [];
    for (var i = 0; i < sliced.length; i++) {
      var r = await getRemediation(sliced[i]);
      if (r) results.push(r);
    }

    // Sort by severity then framework count
    var sevOrder = { High: 0, Medium: 1, Low: 2 };
    results.sort(function (a, b) {
      var sa = sevOrder[a.severity] !== undefined ? sevOrder[a.severity] : 1;
      var sb = sevOrder[b.severity] !== undefined ? sevOrder[b.severity] : 1;
      if (sa !== sb) return sa - sb;
      return b.frameworkCount - a.frameworkCount;
    });

    return results;
  }

  /**
   * Render a single remediation card as HTML.
   * @param {Object} rem — remediation object from getRemediation()
   * @returns {string} HTML string
   */
  function renderCard(rem) {
    var borderClr = rem.severity === 'High' ? 'var(--red)' : rem.severity === 'Medium' ? 'var(--amber2)' : 'var(--green)';
    var sevBadge = rem.severity === 'High' ? 'badge-red' : rem.severity === 'Medium' ? 'badge-amber' : 'badge-green';
    var effortBadge = rem.effort === 'High' ? 'badge-red' : rem.effort === 'Medium' ? 'badge-amber' : 'badge-green';

    var html = '<div class="remediation-card" style="border-left:3px solid ' + borderClr + '">';

    // Header
    html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">';
    html += '<span class="text-mono" style="font-size:.67rem;color:var(--blue);font-weight:600">' + escHtml(rem.policyId) + '</span>';
    html += '<strong style="font-size:.74rem">' + escHtml(rem.title) + '</strong>';
    html += '<span class="badge ' + sevBadge + '">' + rem.severity + '</span>';
    html += '<span class="badge ' + effortBadge + '">' + rem.effort + ' effort</span>';
    if (rem.frameworkCount > 0) {
      html += '<span class="badge badge-blue">' + rem.frameworkCount + ' frameworks</span>';
    }
    html += '</div>';

    // Description
    if (rem.description) {
      html += '<p style="font-size:.68rem;color:var(--ink3);margin:0 0 8px 0">' + escHtml(rem.description.length > 200 ? rem.description.slice(0, 200) + '...' : rem.description) + '</p>';
    }

    // Licence
    if (rem.requiredLicence) {
      var lic = Array.isArray(rem.requiredLicence) ? rem.requiredLicence.join(', ') : rem.requiredLicence;
      html += '<div style="font-size:.62rem;color:var(--ink4);margin-bottom:6px">Licence: ' + escHtml(lic) + '</div>';
    }

    // Prerequisites
    if (rem.prerequisites.length > 0) {
      html += '<details class="remediation-collapse"><summary>Prerequisites (' + rem.prerequisites.length + ')</summary>';
      html += '<ul style="margin:4px 0 0 16px;font-size:.68rem;color:var(--ink2)">';
      rem.prerequisites.forEach(function (p) { html += '<li>' + escHtml(p) + '</li>'; });
      html += '</ul></details>';
    }

    // Deployment Steps
    if (rem.deploymentSteps.length > 0) {
      html += '<details class="remediation-collapse" open><summary>Remediation Steps (' + rem.deploymentSteps.length + ')</summary>';
      html += '<ol style="margin:4px 0 0 16px;font-size:.68rem;color:var(--ink2)">';
      rem.deploymentSteps.forEach(function (s) { html += '<li>' + escHtml(s) + '</li>'; });
      html += '</ol></details>';
    }

    // Verification
    if (rem.verificationCommands.length > 0) {
      html += '<details class="remediation-collapse"><summary>Verification Commands (' + rem.verificationCommands.length + ')</summary>';
      html += '<div style="margin-top:4px">';
      rem.verificationCommands.forEach(function (cmd) {
        html += '<pre class="ps-cmd" onclick="navigator.clipboard.writeText(this.textContent);showToast(\'Copied\')" title="Click to copy">' + escHtml(cmd) + '</pre>';
      });
      html += '</div></details>';
    }

    // Rollback
    if (rem.rollbackProcedure) {
      html += '<details class="remediation-collapse"><summary>Rollback Procedure</summary>';
      html += '<p style="font-size:.66rem;color:var(--ink3);margin:4px 0 0 0">' + escHtml(rem.rollbackProcedure) + '</p>';
      html += '</details>';
    }

    // Actions
    html += '<div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap;align-items:center">';
    html += '<button class="btn btn-sm btn-primary" onclick="Router.navigate(\'policies\');setTimeout(function(){Policies.viewDetail(\'' + escHtml(rem.policyId) + '\')},300)">View Policy</button>';

    // One-click deploy button (if Graph-deployable and tenant connected)
    if (typeof DeployEngine !== 'undefined' && typeof TenantAuth !== 'undefined') {
      var policies = AppState.get('policies') || [];
      var polSummary2 = policies.find(function (p) { return p.id === rem.policyId; });
      if (polSummary2 && DeployEngine.isDeployable && DeployEngine.isDeployable(polSummary2.type)) {
        if (TenantAuth.isAuthenticated()) {
          var deployStatus = DeployEngine.getDeploymentStatus ? DeployEngine.getDeploymentStatus(rem.policyId) : null;
          if (deployStatus && deployStatus.status === 'success') {
            html += '<span class="badge badge-green" style="font-size:.56rem">Deployed</span>';
          } else {
            html += '<button class="btn btn-sm btn-amber" id="rem-deploy-btn-' + escHtml(rem.policyId) + '" onclick="Remediation.deployFromCard(\'' + escHtml(rem.policyId) + '\')" style="font-size:.6rem">Deploy Now</button>';
          }
        } else {
          html += '<span style="font-size:.58rem;color:var(--ink4)">Connect tenant to deploy</span>';
        }
      }
    }

    html += '<span id="rem-deploy-result-' + escHtml(rem.policyId) + '" style="font-size:.6rem"></span>';
    html += '</div>';

    html += '</div>';
    return html;
  }

  /**
   * Deploy a policy directly from the remediation card.
   */
  async function deployFromCard(policyId) {
    var btn = document.getElementById('rem-deploy-btn-' + policyId);
    var result = document.getElementById('rem-deploy-result-' + policyId);
    if (btn) { btn.disabled = true; btn.textContent = 'Deploying...'; }
    if (result) result.innerHTML = '<span style="color:var(--amber2)">&#9881; Deploying...</span>';

    try {
      // Check for pre-deploy config
      if (typeof PreDeployConfig !== 'undefined' && PreDeployConfig.hasConfigFields && PreDeployConfig.hasConfigFields(policyId)) {
        PreDeployConfig.showConfigModal(policyId);
        if (btn) { btn.disabled = false; btn.textContent = 'Deploy Now'; }
        if (result) result.innerHTML = '';
        return;
      }

      var deployResult = await DeployEngine.deploySinglePolicy(policyId);
      if (deployResult && (deployResult.status === 'success' || deployResult.status === 'exists')) {
        if (result) result.innerHTML = '<span style="color:var(--green)">&#10003; ' + (deployResult.status === 'exists' ? 'Already exists' : 'Deployed') + '</span>';
        if (btn) btn.style.display = 'none';
      } else {
        var errMsg = (deployResult && deployResult.detail) || 'Deployment failed';
        if (result) result.innerHTML = '<span style="color:var(--red)">&#10007; ' + escHtml(errMsg) + '</span>';
        if (btn) { btn.disabled = false; btn.textContent = 'Retry'; }
      }

      // Audit trail
      if (typeof AuditTrail !== 'undefined') {
        AuditTrail.log('deploy.single', 'Deployed ' + policyId + ' from remediation card', {
          policyId: policyId,
          status: deployResult ? deployResult.status : 'unknown',
        });
      }
    } catch (e) {
      if (result) result.innerHTML = '<span style="color:var(--red)">&#10007; ' + escHtml(e.message) + '</span>';
      if (btn) { btn.disabled = false; btn.textContent = 'Retry'; }
    }
  }

  /** Clear the remediation cache. */
  function clearCache() { cache = {}; }

  return {
    getRemediation: getRemediation,
    getRemediationsForGaps: getRemediationsForGaps,
    renderCard: renderCard,
    deployFromCard: deployFromCard,
    clearCache: clearCache,
  };
})();
