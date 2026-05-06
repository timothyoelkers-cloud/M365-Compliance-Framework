/* ═══════════════════════════════════════════
   CHANGE TRACKER — Detects field-level
   changes in policy configurations between
   consecutive tenant scans.
═══════════════════════════════════════════ */
const ChangeTracker = (() => {

  /**
   * Deep diff two objects and return list of field-level changes.
   * @param {Object} older - Previous object
   * @param {Object} newer - Current object
   * @param {string} prefix - Path prefix for recursion
   * @returns {Array<{field, oldValue, newValue}>}
   */
  function deepDiff(older, newer, prefix) {
    prefix = prefix || '';
    var diffs = [];

    if (older === newer) return diffs;
    if (older === null || older === undefined || newer === null || newer === undefined) {
      if (older !== newer) {
        diffs.push({ field: prefix || '(root)', oldValue: older, newValue: newer });
      }
      return diffs;
    }

    if (typeof older !== typeof newer) {
      diffs.push({ field: prefix || '(root)', oldValue: older, newValue: newer });
      return diffs;
    }

    if (typeof older !== 'object') {
      if (older !== newer) {
        diffs.push({ field: prefix || '(root)', oldValue: older, newValue: newer });
      }
      return diffs;
    }

    if (Array.isArray(older) || Array.isArray(newer)) {
      if (JSON.stringify(older) !== JSON.stringify(newer)) {
        diffs.push({ field: prefix || '(root)', oldValue: older, newValue: newer });
      }
      return diffs;
    }

    // Object comparison
    var allKeys = new Set(Object.keys(older).concat(Object.keys(newer)));
    allKeys.forEach(function (key) {
      // Skip metadata fields
      if (key.startsWith('@odata') || key === 'id' || key === 'createdDateTime' || key === 'modifiedDateTime') return;
      var subPrefix = prefix ? prefix + '.' + key : key;
      var subDiffs = deepDiff(older[key], newer[key], subPrefix);
      diffs = diffs.concat(subDiffs);
    });

    return diffs;
  }

  /**
   * Compare match results for a specific policy between two scans.
   * @param {Object} olderMatch - Older matchResult for policy
   * @param {Object} newerMatch - Newer matchResult for policy
   * @returns {Array<{field, oldValue, newValue, severity}>}
   */
  function diffPolicyFields(olderMatch, newerMatch) {
    if (!olderMatch || !newerMatch) return [];

    // Status change is a significant diff
    var diffs = [];
    if (olderMatch.status !== newerMatch.status) {
      var severity = 'medium';
      if (olderMatch.status === 'configured' && newerMatch.status === 'missing') severity = 'high';
      if (olderMatch.status === 'missing' && newerMatch.status === 'configured') severity = 'low';
      diffs.push({
        field: 'status',
        oldValue: olderMatch.status,
        newValue: newerMatch.status,
        severity: severity,
      });
    }

    // Matched item field-level diff
    if (olderMatch.matchedItem && newerMatch.matchedItem) {
      var fieldDiffs = deepDiff(olderMatch.matchedItem, newerMatch.matchedItem);
      for (var i = 0; i < fieldDiffs.length; i++) {
        fieldDiffs[i].severity = 'medium';
      }
      diffs = diffs.concat(fieldDiffs);
    }

    return diffs;
  }

  /**
   * Get change history for a specific policy across stored scans.
   * @param {string} policyId
   * @param {number} limit - Max scans to check
   * @returns {Promise<Array<{timestamp, changes, scanId}>>}
   */
  async function getPolicyChangeHistory(policyId, limit) {
    if (typeof ScanHistory === 'undefined') return [];

    limit = limit || 10;
    var tenantId = AppState.get('authTenantId');
    var scans = await ScanHistory.getScans(tenantId, limit);
    if (scans.length < 2) return [];

    var history = [];
    for (var i = 0; i < scans.length - 1; i++) {
      var newer = scans[i];
      var older = scans[i + 1];

      var newerMatch = newer.matchResults ? newer.matchResults[policyId] : null;
      var olderMatch = older.matchResults ? older.matchResults[policyId] : null;

      if (!newerMatch && !olderMatch) continue;

      var changes = diffPolicyFields(olderMatch || {}, newerMatch || {});
      if (changes.length > 0) {
        history.push({
          timestamp: newer.timestamp,
          scanId: newer.id,
          changes: changes,
        });
      }
    }

    return history;
  }

  /**
   * Detect unexpected changes between two scan snapshots across all policies.
   * @param {Object} olderScan
   * @param {Object} newerScan
   * @returns {Array<{policyId, field, oldValue, newValue, severity}>}
   */
  function detectUnexpectedChanges(olderScan, newerScan) {
    if (!olderScan || !newerScan) return [];
    var olderResults = olderScan.matchResults || {};
    var newerResults = newerScan.matchResults || {};

    var changes = [];
    var allPolicyIds = new Set(Object.keys(olderResults).concat(Object.keys(newerResults)));

    allPolicyIds.forEach(function (policyId) {
      var older = olderResults[policyId];
      var newer = newerResults[policyId];

      var diffs = diffPolicyFields(older || {}, newer || {});
      for (var i = 0; i < diffs.length; i++) {
        changes.push({
          policyId: policyId,
          field: diffs[i].field,
          oldValue: diffs[i].oldValue,
          newValue: diffs[i].newValue,
          severity: diffs[i].severity,
        });
      }
    });

    return changes;
  }

  /**
   * Render change alerts banner on dashboard.
   */
  async function renderChangeAlerts(containerId) {
    var container = document.getElementById(containerId);
    if (!container || typeof ScanHistory === 'undefined') return;

    var tenantId = AppState.get('authTenantId');
    var scans = await ScanHistory.getScans(tenantId, 2);
    if (scans.length < 2) return;

    var changes = detectUnexpectedChanges(scans[1], scans[0]);
    if (changes.length === 0) return;

    var highSeverity = changes.filter(function (c) { return c.severity === 'high'; });
    var medSeverity = changes.filter(function (c) { return c.severity === 'medium'; });

    var borderColor = highSeverity.length > 0 ? 'var(--red)' : 'var(--amber2)';
    var bgColor = highSeverity.length > 0 ? 'var(--red-lt)' : 'var(--amber-lt)';

    var html = '<div class="card change-alert" style="border-left:3px solid ' + borderColor + ';background:' + bgColor + ';padding:12px 16px;margin-bottom:16px">';
    html += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">';
    html += '<div style="font-size:.74rem;font-weight:600">';
    if (highSeverity.length > 0) {
      html += '<span style="color:var(--red)">' + highSeverity.length + ' regression' + (highSeverity.length > 1 ? 's' : '') + '</span>';
    }
    if (medSeverity.length > 0) {
      html += (highSeverity.length > 0 ? ' &middot; ' : '') + '<span style="color:var(--amber)">' + medSeverity.length + ' change' + (medSeverity.length > 1 ? 's' : '') + '</span>';
    }
    html += ' detected since last scan</div>';
    html += '<button class="btn btn-sm" onclick="ChangeTracker.showChangesModal()" style="font-size:.6rem">View Details</button>';
    html += '</div></div>';

    container.innerHTML = html;
  }

  /**
   * Show changes modal with full detail.
   */
  async function showChangesModal() {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal || typeof ScanHistory === 'undefined') return;

    var tenantId = AppState.get('authTenantId');
    var scans = await ScanHistory.getScans(tenantId, 2);
    if (scans.length < 2) return;

    var changes = detectUnexpectedChanges(scans[1], scans[0]);

    var html = '<div class="modal-header">';
    html += '<h3>Policy Changes</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body" style="max-height:500px;overflow-y:auto">';

    if (changes.length === 0) {
      html += '<div style="text-align:center;color:var(--ink4);padding:20px">No changes detected between last two scans.</div>';
    } else {
      html += '<div style="font-size:.68rem;color:var(--ink3);margin-bottom:12px">' + changes.length + ' change(s) detected between scans at ' +
        new Date(scans[1].timestamp).toLocaleString() + ' and ' + new Date(scans[0].timestamp).toLocaleString() + '</div>';

      html += '<table class="data-table" style="font-size:.65rem">';
      html += '<thead><tr><th>Policy</th><th>Field</th><th>Previous</th><th>Current</th><th>Severity</th></tr></thead><tbody>';

      for (var i = 0; i < changes.length; i++) {
        var c = changes[i];
        var sevBadge = c.severity === 'high' ? 'badge-red' : c.severity === 'medium' ? 'badge-amber' : 'badge-blue';
        html += '<tr>';
        html += '<td class="text-mono" style="font-size:.58rem;font-weight:600;color:var(--blue)">' + escHtml(c.policyId) + '</td>';
        html += '<td style="font-size:.6rem">' + escHtml(c.field) + '</td>';
        html += '<td style="font-size:.58rem;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escHtml(formatValue(c.oldValue)) + '">' + escHtml(formatValue(c.oldValue)) + '</td>';
        html += '<td style="font-size:.58rem;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escHtml(formatValue(c.newValue)) + '">' + escHtml(formatValue(c.newValue)) + '</td>';
        html += '<td><span class="badge ' + sevBadge + '" style="font-size:.5rem">' + escHtml(c.severity) + '</span></td>';
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

  /**
   * Render change history for a specific policy.
   */
  async function renderChangeHistory(policyId, containerId) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var history = await getPolicyChangeHistory(policyId);
    if (history.length === 0) {
      container.innerHTML = '<div style="font-size:.68rem;color:var(--ink4);padding:8px">No changes detected in recent scans.</div>';
      return;
    }

    var html = '<div style="font-size:.72rem;font-weight:600;margin-bottom:8px">Change History (' + history.length + ')</div>';
    for (var i = 0; i < history.length; i++) {
      var entry = history[i];
      html += '<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:.65rem">';
      html += '<div style="font-weight:600;color:var(--ink3);margin-bottom:2px">' + new Date(entry.timestamp).toLocaleString() + '</div>';
      for (var j = 0; j < entry.changes.length; j++) {
        var c = entry.changes[j];
        html += '<div style="margin-left:8px"><span style="color:var(--ink4)">' + escHtml(c.field) + ':</span> ';
        html += '<span style="color:var(--red);text-decoration:line-through">' + escHtml(formatValue(c.oldValue)) + '</span>';
        html += ' &rarr; <span style="color:var(--green)">' + escHtml(formatValue(c.newValue)) + '</span></div>';
      }
      html += '</div>';
    }

    container.innerHTML = html;
  }

  function formatValue(val) {
    if (val === null || val === undefined) return '(none)';
    if (typeof val === 'object') {
      try { return JSON.stringify(val).substring(0, 80); } catch (e) { return String(val); }
    }
    return String(val);
  }

  return {
    deepDiff: deepDiff,
    diffPolicyFields: diffPolicyFields,
    getPolicyChangeHistory: getPolicyChangeHistory,
    detectUnexpectedChanges: detectUnexpectedChanges,
    renderChangeAlerts: renderChangeAlerts,
    showChangesModal: showChangesModal,
    renderChangeHistory: renderChangeHistory,
  };
})();
