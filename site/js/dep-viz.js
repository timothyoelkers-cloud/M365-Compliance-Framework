/* ═══════════════════════════════════════════
   DEP-VIZ — Interactive SVG visualization
   of policy dependency graph using
   hierarchical layout.
═══════════════════════════════════════════ */
const DepViz = (() => {

  /**
   * Build graph data from DependencyGraph adjacency.
   * @returns {{ nodes: Array, edges: Array }}
   */
  function buildGraphData() {
    if (typeof DependencyGraph === 'undefined') return { nodes: [], edges: [] };

    DependencyGraph.buildGraph();
    var adj = DependencyGraph.getAdjacency ? DependencyGraph.getAdjacency() : {};
    var policyIds = Object.keys(adj);
    if (policyIds.length === 0) return { nodes: [], edges: [] };

    var deployStatus = AppState.get('deploymentStatus') || {};
    var history = typeof AppState.getDeploymentHistory === 'function' ? AppState.getDeploymentHistory() : [];

    // Build nodes
    var nodes = [];
    var nodeMap = {};
    var allIds = new Set(policyIds);

    // Also include targets of edges
    policyIds.forEach(function (id) {
      var deps = adj[id];
      (deps.requires || []).forEach(function (r) { allIds.add(r); });
      (deps.recommendsBefore || []).forEach(function (r) { allIds.add(r); });
    });

    allIds.forEach(function (id) {
      var status = deployStatus[id];
      var everDeployed = history.some(function (h) { return h.policyId === id && h.status === 'success'; });
      var deployed = (status && status.status === 'success') || everDeployed;
      var deploying = status && status.status === 'deploying';

      var policies = AppState.get('policies') || [];
      var pol = policies.find(function (p) { return p.id === id; });

      nodes.push({
        id: id,
        type: pol ? pol.type : 'unknown',
        deployed: deployed,
        deploying: deploying,
        label: id,
      });
      nodeMap[id] = nodes.length - 1;
    });

    // Build edges
    var edges = [];
    policyIds.forEach(function (id) {
      var deps = adj[id];
      (deps.requires || []).forEach(function (reqId) {
        if (nodeMap[reqId] !== undefined) {
          edges.push({ from: reqId, to: id, type: 'requires' });
        }
      });
      (deps.recommendsBefore || []).forEach(function (recId) {
        if (nodeMap[recId] !== undefined) {
          edges.push({ from: recId, to: id, type: 'recommends' });
        }
      });
    });

    return { nodes: nodes, edges: edges };
  }

  /**
   * Assign hierarchical layout using topological levels.
   */
  function layoutHierarchical(nodes, edges, width, height) {
    if (nodes.length === 0) return;

    // Build adjacency for topological sort
    var inDegree = {};
    var children = {};
    nodes.forEach(function (n) { inDegree[n.id] = 0; children[n.id] = []; });

    edges.forEach(function (e) {
      if (inDegree[e.to] !== undefined) inDegree[e.to]++;
      if (children[e.from]) children[e.from].push(e.to);
    });

    // Kahn's algorithm for level assignment
    var levels = {};
    var queue = [];
    nodes.forEach(function (n) {
      if (inDegree[n.id] === 0) {
        queue.push(n.id);
        levels[n.id] = 0;
      }
    });

    var maxLevel = 0;
    while (queue.length > 0) {
      var curr = queue.shift();
      var currLevel = levels[curr];
      (children[curr] || []).forEach(function (child) {
        inDegree[child]--;
        levels[child] = Math.max(levels[child] || 0, currLevel + 1);
        maxLevel = Math.max(maxLevel, levels[child]);
        if (inDegree[child] === 0) queue.push(child);
      });
    }

    // Handle any remaining nodes (cycles)
    nodes.forEach(function (n) {
      if (levels[n.id] === undefined) {
        levels[n.id] = maxLevel + 1;
        maxLevel = levels[n.id];
      }
    });

    // Group nodes by level
    var byLevel = {};
    nodes.forEach(function (n) {
      var lev = levels[n.id];
      if (!byLevel[lev]) byLevel[lev] = [];
      byLevel[lev].push(n);
    });

    // Assign coordinates
    var padding = 40;
    var levelCount = maxLevel + 1;
    var yStep = (height - 2 * padding) / Math.max(levelCount - 1, 1);

    for (var lev in byLevel) {
      var group = byLevel[lev];
      var xStep = (width - 2 * padding) / Math.max(group.length + 1, 2);
      for (var gi = 0; gi < group.length; gi++) {
        group[gi].x = padding + xStep * (gi + 1);
        group[gi].y = padding + yStep * parseInt(lev);
      }
    }
  }

  /**
   * Render the dependency graph as an interactive SVG.
   */
  function renderSVG(containerId) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var graph = buildGraphData();
    if (graph.nodes.length === 0) {
      container.innerHTML = '<div style="font-size:.68rem;color:var(--ink4);text-align:center;padding:16px">No dependency data available.</div>';
      return;
    }

    var width = Math.max(600, graph.nodes.length * 60);
    var height = Math.max(300, graph.nodes.length * 30);
    layoutHierarchical(graph.nodes, graph.edges, width, height);

    // Build node lookup
    var nodeById = {};
    graph.nodes.forEach(function (n) { nodeById[n.id] = n; });

    var svg = '<svg viewBox="0 0 ' + width + ' ' + height + '" style="width:100%;height:auto;max-height:400px;border:1px solid var(--border);border-radius:8px;background:var(--surface)">';

    // Render edges
    for (var ei = 0; ei < graph.edges.length; ei++) {
      var edge = graph.edges[ei];
      var fromNode = nodeById[edge.from];
      var toNode = nodeById[edge.to];
      if (!fromNode || !toNode) continue;

      var dashArray = edge.type === 'recommends' ? 'stroke-dasharray="5,3"' : '';
      var edgeColor = edge.type === 'requires' ? 'var(--ink4)' : 'var(--border2)';
      svg += '<line x1="' + fromNode.x + '" y1="' + fromNode.y + '" x2="' + toNode.x + '" y2="' + toNode.y + '" stroke="' + edgeColor + '" stroke-width="1.5" ' + dashArray + '/>';

      // Arrow head
      var angle = Math.atan2(toNode.y - fromNode.y, toNode.x - fromNode.x);
      var arrowLen = 8;
      var ax = toNode.x - Math.cos(angle) * 18;
      var ay = toNode.y - Math.sin(angle) * 18;
      svg += '<polygon points="' +
        (ax + arrowLen * Math.cos(angle)) + ',' + (ay + arrowLen * Math.sin(angle)) + ' ' +
        (ax + arrowLen * 0.5 * Math.cos(angle - 2.3)) + ',' + (ay + arrowLen * 0.5 * Math.sin(angle - 2.3)) + ' ' +
        (ax + arrowLen * 0.5 * Math.cos(angle + 2.3)) + ',' + (ay + arrowLen * 0.5 * Math.sin(angle + 2.3)) +
        '" fill="' + edgeColor + '"/>';
    }

    // Render nodes
    for (var ni = 0; ni < graph.nodes.length; ni++) {
      var node = graph.nodes[ni];
      var nodeColor = node.deployed ? 'var(--green)' : node.deploying ? 'var(--amber2)' : 'var(--red)';
      var fillColor = node.deployed ? 'rgba(22,163,74,0.15)' : node.deploying ? 'rgba(240,165,0,0.15)' : 'rgba(220,38,38,0.15)';
      var radius = 16;

      svg += '<g class="dep-viz-node" style="cursor:pointer" onclick="DepViz.onNodeClick(\'' + escHtml(node.id) + '\')">';
      svg += '<circle cx="' + node.x + '" cy="' + node.y + '" r="' + radius + '" fill="' + fillColor + '" stroke="' + nodeColor + '" stroke-width="2"/>';
      svg += '<text x="' + node.x + '" y="' + (node.y + 28) + '" text-anchor="middle" fill="var(--ink3)" style="font-size:9px;font-family:IBM Plex Mono,monospace">' + escHtml(node.id) + '</text>';

      // Status icon inside circle
      if (node.deployed) {
        svg += '<text x="' + node.x + '" y="' + (node.y + 4) + '" text-anchor="middle" fill="' + nodeColor + '" style="font-size:12px">&#10003;</text>';
      } else {
        svg += '<text x="' + node.x + '" y="' + (node.y + 4) + '" text-anchor="middle" fill="' + nodeColor + '" style="font-size:12px">&#10007;</text>';
      }

      svg += '</g>';
    }

    // Legend
    svg += '<g transform="translate(10,' + (height - 40) + ')">';
    svg += '<circle cx="10" cy="10" r="6" fill="rgba(22,163,74,0.15)" stroke="var(--green)" stroke-width="1.5"/>';
    svg += '<text x="22" y="14" fill="var(--ink3)" style="font-size:9px">Deployed</text>';
    svg += '<circle cx="80" cy="10" r="6" fill="rgba(220,38,38,0.15)" stroke="var(--red)" stroke-width="1.5"/>';
    svg += '<text x="92" y="14" fill="var(--ink3)" style="font-size:9px">Not deployed</text>';
    svg += '<line x1="160" y1="10" x2="185" y2="10" stroke="var(--ink4)" stroke-width="1.5"/>';
    svg += '<text x="190" y="14" fill="var(--ink3)" style="font-size:9px">Requires</text>';
    svg += '<line x1="240" y1="10" x2="265" y2="10" stroke="var(--border2)" stroke-width="1.5" stroke-dasharray="5,3"/>';
    svg += '<text x="270" y="14" fill="var(--ink3)" style="font-size:9px">Recommends</text>';
    svg += '</g>';

    svg += '</svg>';

    container.innerHTML = '<div class="section-hdr" style="margin-top:28px">Dependency Map</div>' + svg;
  }

  /**
   * Handle click on a graph node.
   */
  function onNodeClick(policyId) {
    if (typeof Policies !== 'undefined' && Policies.viewDetail) {
      Router.navigate('policies');
      setTimeout(function () { Policies.viewDetail(policyId); }, 300);
    }
  }

  return {
    buildGraphData: buildGraphData,
    renderSVG: renderSVG,
    onNodeClick: onNodeClick,
  };
})();
