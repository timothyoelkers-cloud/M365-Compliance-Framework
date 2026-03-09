/* ═══════════════════════════════════════════
   DEPENDENCY GRAPH — Policy prerequisites
   and deployment ordering
═══════════════════════════════════════════ */
const DependencyGraph = (() => {

  let graphBuilt = false;
  let adjacency = {};   // policyId → { requires: [], recommendsBefore: [] }

  function buildGraph() {
    if (graphBuilt) return;
    var policies = AppState.get('policies') || [];
    adjacency = {};
    policies.forEach(function (p) {
      if (p._dependencies) {
        adjacency[p.id] = {
          requires: p._dependencies.requires || [],
          recommendsBefore: p._dependencies.recommendsBefore || [],
        };
      }
    });
    graphBuilt = true;
  }

  function invalidate() { graphBuilt = false; }

  function getDeps(policyId) {
    buildGraph();
    return adjacency[policyId] || { requires: [], recommendsBefore: [] };
  }

  function checkPrerequisites(policyId) {
    buildGraph();
    var deps = adjacency[policyId];
    if (!deps) return { satisfied: true, missing: [], warnings: [] };

    var deployStatus = AppState.get('deploymentStatus') || {};
    var history = AppState.getDeploymentHistory ? AppState.getDeploymentHistory() : [];
    var missing = [];
    var warnings = [];

    // Check hard requirements
    (deps.requires || []).forEach(function (reqId) {
      var status = deployStatus[reqId];
      var everDeployed = history.some(function (h) { return h.policyId === reqId && h.status === 'success'; });
      if (!status && !everDeployed) {
        missing.push(reqId);
      }
    });

    // Check recommendations
    (deps.recommendsBefore || []).forEach(function (recId) {
      var status = deployStatus[recId];
      var everDeployed = history.some(function (h) { return h.policyId === recId && h.status === 'success'; });
      if (!status && !everDeployed) {
        warnings.push(recId);
      }
    });

    return { satisfied: missing.length === 0, missing: missing, warnings: warnings };
  }

  // Topological sort — Kahn's algorithm
  function suggestOrder(policyIds) {
    buildGraph();
    var idSet = new Set(policyIds);
    var inDegree = {};
    var edges = {};

    policyIds.forEach(function (id) {
      inDegree[id] = 0;
      edges[id] = [];
    });

    // Build edges within the selected set
    policyIds.forEach(function (id) {
      var deps = adjacency[id];
      if (!deps) return;
      (deps.requires || []).forEach(function (reqId) {
        if (idSet.has(reqId)) {
          edges[reqId].push(id);
          inDegree[id]++;
        }
      });
      (deps.recommendsBefore || []).forEach(function (recId) {
        if (idSet.has(recId)) {
          edges[recId].push(id);
          inDegree[id]++;
        }
      });
    });

    // Kahn's algorithm
    var queue = policyIds.filter(function (id) { return inDegree[id] === 0; });
    var sorted = [];
    while (queue.length > 0) {
      var node = queue.shift();
      sorted.push(node);
      (edges[node] || []).forEach(function (neighbor) {
        inDegree[neighbor]--;
        if (inDegree[neighbor] === 0) queue.push(neighbor);
      });
    }

    // Append any remaining (cycles) at the end
    policyIds.forEach(function (id) {
      if (sorted.indexOf(id) === -1) sorted.push(id);
    });

    return sorted;
  }

  function renderDependencyView(policyId) {
    var deps = getDeps(policyId);
    if (deps.requires.length === 0 && deps.recommendsBefore.length === 0) return '';

    var html = '<div class="section-hdr" style="margin-top:16px">Dependencies</div>';

    if (deps.requires.length > 0) {
      html += '<div class="dep-section"><strong>Requires:</strong></div>';
      deps.requires.forEach(function (reqId) {
        var status = (AppState.get('deploymentStatus') || {})[reqId];
        var icon = status && status.status === 'success' ? '<span style="color:var(--green)">&#10003;</span>' : '<span style="color:var(--red)">&#10007;</span>';
        html += '<div class="dep-tree-item">' + icon + ' ' + escHtml(reqId) + '</div>';
      });
    }

    if (deps.recommendsBefore.length > 0) {
      html += '<div class="dep-section"><strong>Recommended first:</strong></div>';
      deps.recommendsBefore.forEach(function (recId) {
        var status = (AppState.get('deploymentStatus') || {})[recId];
        var icon = status && status.status === 'success' ? '<span style="color:var(--green)">&#10003;</span>' : '<span style="color:var(--amber)">!</span>';
        html += '<div class="dep-tree-item">' + icon + ' ' + escHtml(recId) + '</div>';
      });
    }

    return html;
  }

  function renderPrereqWarning(policyId) {
    var prereqs = checkPrerequisites(policyId);
    if (prereqs.satisfied && prereqs.warnings.length === 0) return '';

    var html = '';
    if (prereqs.missing.length > 0) {
      html += '<div class="dep-warning"><strong>Missing prerequisites:</strong> ' +
        prereqs.missing.map(escHtml).join(', ') +
        '. Deploy these first for correct operation.</div>';
    }
    if (prereqs.warnings.length > 0) {
      html += '<div class="dep-info"><strong>Recommended first:</strong> ' +
        prereqs.warnings.map(escHtml).join(', ') + '</div>';
    }
    return html;
  }

  return {
    buildGraph, invalidate, getDeps,
    checkPrerequisites, suggestOrder,
    renderDependencyView, renderPrereqWarning,
  };
})();
