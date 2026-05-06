/* ═══════════════════════════════════════════
   FRAMEWORK OVERLAP MATRIX — Interactive
   heatmap showing shared CIS checks between
   selected compliance frameworks.
═══════════════════════════════════════════ */
const OverlapMatrix = (() => {

  /**
   * Compute NxN overlap matrix for selected frameworks.
   * @param {Array} checks - All CIS checks with framework associations
   * @param {Set|Array} selectedFrameworks - Frameworks to compare
   * @returns {{ matrix, frameworks, sharedChecks, maxOverlap, perFramework }}
   */
  function computeOverlap(checks, selectedFrameworks) {
    var fws = Array.isArray(selectedFrameworks) ? selectedFrameworks : [...selectedFrameworks];
    if (fws.length < 2) return null;

    var n = fws.length;
    var matrix = [];
    var sharedChecks = {};
    var perFramework = {};

    // Map each framework to its set of check IDs
    for (var f = 0; f < n; f++) {
      perFramework[fws[f]] = new Set();
    }

    for (var c = 0; c < checks.length; c++) {
      var check = checks[c];
      var checkFws = check.frameworks || check.fw || [];
      if (!Array.isArray(checkFws)) continue;

      for (var fi = 0; fi < fws.length; fi++) {
        if (checkFws.indexOf(fws[fi]) !== -1) {
          perFramework[fws[fi]].add(check.id);
        }
      }
    }

    // Build overlap matrix
    for (var i = 0; i < n; i++) {
      matrix[i] = [];
      for (var j = 0; j < n; j++) {
        if (i === j) {
          matrix[i][j] = perFramework[fws[i]].size;
        } else {
          var shared = [];
          perFramework[fws[i]].forEach(function (checkId) {
            if (perFramework[fws[j]].has(checkId)) {
              shared.push(checkId);
            }
          });
          matrix[i][j] = shared.length;
          var key = i < j ? fws[i] + '|' + fws[j] : fws[j] + '|' + fws[i];
          if (!sharedChecks[key]) {
            sharedChecks[key] = shared;
          }
        }
      }
    }

    var maxOverlap = 0;
    for (var mi = 0; mi < n; mi++) {
      for (var mj = 0; mj < n; mj++) {
        if (mi !== mj && matrix[mi][mj] > maxOverlap) maxOverlap = matrix[mi][mj];
      }
    }

    return {
      matrix: matrix,
      frameworks: fws,
      sharedChecks: sharedChecks,
      maxOverlap: maxOverlap,
      perFramework: perFramework,
    };
  }

  /**
   * Render interactive heatmap as an HTML table.
   */
  function renderHeatmap(containerId, overlapData) {
    var container = document.getElementById(containerId);
    if (!container || !overlapData) return;

    var fws = overlapData.frameworks;
    var matrix = overlapData.matrix;
    var maxOvlp = Math.max(overlapData.maxOverlap, 1);
    var n = fws.length;

    var html = '<div class="section-hdr" style="margin-top:28px">Framework Overlap Matrix</div>';
    html += '<div style="overflow-x:auto;margin-bottom:16px">';
    html += '<table class="data-table overlap-table" style="font-size:.62rem;text-align:center">';

    // Header row
    html += '<thead><tr><th style="min-width:100px"></th>';
    for (var h = 0; h < n; h++) {
      var shortName = fws[h].length > 16 ? fws[h].substring(0, 14) + '..' : fws[h];
      html += '<th class="overlap-header" title="' + escHtml(fws[h]) + '" style="max-width:80px;font-size:.55rem;writing-mode:vertical-lr;transform:rotate(180deg);height:100px">' + escHtml(shortName) + '</th>';
    }
    html += '</tr></thead><tbody>';

    // Data rows
    for (var i = 0; i < n; i++) {
      html += '<tr>';
      var rowName = fws[i].length > 20 ? fws[i].substring(0, 18) + '..' : fws[i];
      html += '<td style="text-align:left;font-weight:600;white-space:nowrap" title="' + escHtml(fws[i]) + '">' + escHtml(rowName) + '</td>';

      for (var j = 0; j < n; j++) {
        var count = matrix[i][j];
        var cellStyle = '';

        if (i === j) {
          // Diagonal — framework total
          cellStyle = 'background:var(--blue-lt2);font-weight:700;color:var(--blue)';
        } else if (count === 0) {
          cellStyle = 'background:var(--surface2);color:var(--ink4)';
        } else {
          var pct = count / maxOvlp;
          var r = Math.round(22 + (1 - pct) * 210);
          var g = Math.round(163 + (1 - pct) * 70);
          var b = Math.round(74 + (1 - pct) * 140);
          cellStyle = 'background:rgba(' + r + ',' + g + ',' + b + ',0.15);color:var(--ink2);cursor:pointer;font-weight:600';
        }

        var onclick = '';
        if (i !== j && count > 0) {
          onclick = ' onclick="OverlapMatrix.showSharedControls(\'' + escHtml(fws[i]).replace(/'/g, "\\'") + '\',\'' + escHtml(fws[j]).replace(/'/g, "\\'") + '\')"';
        }

        html += '<td class="overlap-cell" style="' + cellStyle + '"' + onclick + ' title="' + count + ' shared checks">' + count + '</td>';
      }
      html += '</tr>';
    }

    html += '</tbody></table></div>';
    container.innerHTML = html;
  }

  /**
   * Show modal listing shared CIS check IDs between two frameworks.
   */
  function showSharedControls(fw1, fw2) {
    var checks = AppState.get('checks') || [];
    var sel = AppState.get('selectedFrameworks');
    var overlap = computeOverlap(checks, sel);
    if (!overlap) return;

    var key1 = fw1 + '|' + fw2;
    var key2 = fw2 + '|' + fw1;
    var shared = overlap.sharedChecks[key1] || overlap.sharedChecks[key2] || [];

    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var html = '<div class="modal-header">';
    html += '<h3>Shared Controls</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';
    html += '<div style="font-size:.72rem;color:var(--ink3);margin-bottom:12px">';
    html += '<strong>' + escHtml(fw1) + '</strong> and <strong>' + escHtml(fw2) + '</strong> share <strong>' + shared.length + '</strong> CIS checks</div>';

    if (shared.length > 0) {
      html += '<table class="data-table" style="font-size:.68rem"><thead><tr><th>Check ID</th><th>Control</th></tr></thead><tbody>';
      for (var i = 0; i < shared.length; i++) {
        var check = checks.find(function (c) { return c.id === shared[i]; });
        html += '<tr>';
        html += '<td class="text-mono" style="font-size:.62rem;color:var(--blue);font-weight:600">' + escHtml(shared[i]) + '</td>';
        html += '<td style="font-size:.68rem">' + escHtml(check ? check.name : shared[i]) + '</td>';
        html += '</tr>';
      }
      html += '</tbody></table>';
    }

    html += '<div style="margin-top:12px;text-align:right">';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '</div></div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  return {
    computeOverlap: computeOverlap,
    renderHeatmap: renderHeatmap,
    showSharedControls: showSharedControls,
  };
})();
