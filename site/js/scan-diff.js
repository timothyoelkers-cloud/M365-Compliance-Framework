/* ═══════════════════════════════════════════
   SCAN DIFF — Side-by-side comparison of
   recommended policy settings vs. current
   tenant configuration from scan results.
═══════════════════════════════════════════ */
const ScanDiff = (() => {

  // ─── JSON Path accessor ───

  function getPath(obj, path) {
    if (!obj || !path) return undefined;
    var segs = path.replace(/\[(\d+)\]/g, '.$1').split('.');
    var cur = obj;
    for (var i = 0; i < segs.length; i++) {
      if (cur == null || typeof cur !== 'object') return undefined;
      cur = cur[segs[i]];
    }
    return cur;
  }

  function formatValue(val) {
    if (val === undefined || val === null) return '<span style="color:var(--ink4)">—</span>';
    if (typeof val === 'boolean') return val ? 'true' : 'false';
    if (Array.isArray(val)) return val.length === 0 ? '[]' : val.join(', ');
    if (typeof val === 'object') return JSON.stringify(val);
    return String(val);
  }

  // ─── Build Diff ───

  function buildPolicyDiff(policy, scanData) {
    var rule = PolicyMatcher.MATCH_RULES[policy.id];
    if (!rule) {
      return { policyId: policy.id, status: 'no-rule', diffs: [] };
    }

    // Manual / PS-only policies can't be diff'd
    if (rule.status === 'manual') {
      return {
        policyId: policy.id,
        status: 'manual',
        diffs: [],
        verifyCommand: rule.verifyCommand || null,
      };
    }

    var scanSource = rule.scanSource;
    var items = scanData && scanData.data ? scanData.data[scanSource] : null;
    if (!items || !Array.isArray(items) || items.length === 0) {
      return { policyId: policy.id, status: 'no-scan-data', diffs: [] };
    }

    // Find the matched item (same logic as PolicyMatcher)
    var matchResult = AppState.get('tenantScanResults') ? AppState.get('tenantScanResults')[policy.id] : null;
    var matchedItem = matchResult && matchResult.matchedItem ? matchResult.matchedItem : null;

    // If no specific match, try first item for the source
    var target = matchedItem || items[0];

    var conditions = rule.conditions || [];
    var diffs = [];

    conditions.forEach(function (cond) {
      var actualVal = getPath(target, cond.path);
      var expectedVal = cond.value !== undefined ? cond.value : (cond.values || null);
      var match = false;

      switch (cond.op) {
        case 'equals':
          match = actualVal === expectedVal;
          break;
        case 'contains':
          match = Array.isArray(actualVal) ? actualVal.indexOf(expectedVal) !== -1 : actualVal === expectedVal;
          break;
        case 'containsAny':
          match = Array.isArray(actualVal) && Array.isArray(expectedVal) &&
            expectedVal.some(function (v) { return actualVal.indexOf(v) !== -1; });
          break;
        case 'isNotEmpty':
          match = actualVal !== undefined && actualVal !== null &&
            (Array.isArray(actualVal) ? actualVal.length > 0 : String(actualVal).length > 0);
          expectedVal = '(non-empty)';
          break;
        case 'exists':
          match = actualVal !== undefined && actualVal !== null;
          expectedVal = '(exists)';
          break;
        case 'isTrue':
          match = actualVal === true;
          expectedVal = true;
          break;
        case 'isFalse':
          match = actualVal === false;
          expectedVal = false;
          break;
        case 'gte':
          match = typeof actualVal === 'number' && actualVal >= expectedVal;
          break;
        case 'lte':
          match = typeof actualVal === 'number' && actualVal <= expectedVal;
          break;
        default:
          match = false;
      }

      diffs.push({
        field: cond.path,
        expected: expectedVal,
        actual: actualVal,
        match: match,
      });
    });

    var allMatch = diffs.every(function (d) { return d.match; });

    return {
      policyId: policy.id,
      status: allMatch ? 'configured' : 'mismatch',
      matchedItem: target,
      diffs: diffs,
    };
  }

  // ─── Modal ───

  function showDiffModal(policyId) {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var policies = AppState.get('policies') || [];
    var pol = policies.find(function (p) { return p.id === policyId; });
    if (!pol) return;

    var scanData = TenantScanner.getScanResults();
    if (!scanData) {
      showToast('No scan data available. Run a tenant scan first.');
      return;
    }

    var diff = buildPolicyDiff(pol, scanData);

    var html = '<div class="modal-header">';
    html += '<h3>Setting Comparison: ' + escHtml(pol.id) + '</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';

    html += '<p style="font-size:.74rem;color:var(--ink2);margin-bottom:16px">' + escHtml(pol.displayName) + '</p>';

    if (diff.status === 'manual') {
      html += '<div class="dep-info"><strong>PowerShell verification required</strong> — This policy cannot be checked via API.</div>';
      if (diff.verifyCommand) {
        html += '<pre style="background:var(--surface2);padding:8px;border-radius:4px;font-size:.62rem;margin-top:8px;cursor:pointer;overflow-x:auto" onclick="navigator.clipboard.writeText(this.textContent);showToast(\'Copied\')" title="Click to copy">' + escHtml(diff.verifyCommand) + '</pre>';
      }
    } else if (diff.status === 'no-scan-data') {
      html += '<div class="dep-info">No scan data available for this policy type. Run a tenant scan first.</div>';
    } else if (diff.status === 'no-rule') {
      html += '<div class="dep-info">No match rule defined for this policy.</div>';
    } else if (diff.diffs.length > 0) {
      // Diff table
      var matchCount = diff.diffs.filter(function (d) { return d.match; }).length;
      var mismatchCount = diff.diffs.length - matchCount;

      html += '<div style="display:flex;gap:12px;margin-bottom:12px">';
      html += '<span class="badge badge-green">' + matchCount + ' match</span>';
      if (mismatchCount > 0) html += '<span class="badge badge-red">' + mismatchCount + ' mismatch</span>';
      html += '</div>';

      html += '<table class="data-table diff-table">';
      html += '<thead><tr><th>Setting</th><th>Recommended</th><th>Current</th><th>Status</th></tr></thead>';
      html += '<tbody>';

      diff.diffs.forEach(function (d) {
        var statusIcon = d.match
          ? '<span style="color:var(--green)">&#10003;</span>'
          : '<span style="color:var(--red)">&#10007;</span>';
        var rowClass = d.match ? '' : ' style="background:rgba(220,38,38,.04)"';

        html += '<tr' + rowClass + '>';
        html += '<td style="font-family:\'IBM Plex Mono\',monospace;font-size:.62rem;word-break:break-all">' + escHtml(d.field) + '</td>';
        html += '<td style="font-size:.66rem">' + formatValue(d.expected) + '</td>';
        html += '<td style="font-size:.66rem">' + formatValue(d.actual) + '</td>';
        html += '<td style="text-align:center">' + statusIcon + '</td>';
        html += '</tr>';
      });

      html += '</tbody></table>';

      if (diff.matchedItem && diff.matchedItem.displayName) {
        html += '<div style="font-size:.62rem;color:var(--ink4);margin-top:8px">Compared against: <strong>' + escHtml(diff.matchedItem.displayName) + '</strong></div>';
      }
    } else {
      html += '<div class="dep-info">No conditions to compare for this policy.</div>';
    }

    html += '<div class="config-actions">';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '</div>';

    html += '</div>';
    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  return {
    buildPolicyDiff: buildPolicyDiff,
    showDiffModal: showDiffModal,
  };
})();
