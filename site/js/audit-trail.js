/* ═══════════════════════════════════════════
   AUDIT TRAIL — Logs all user actions into
   IndexedDB for accountability, compliance
   evidence, and troubleshooting.
═══════════════════════════════════════════ */
const AuditTrail = (() => {
  const STORE_NAME = 'auditLog';
  const MAX_ENTRIES = 5000;
  const DEFAULT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000; // 90 days

  // ─── Logging ───

  async function log(action, detail, metadata) {
    try {
      if (typeof ScanHistory === 'undefined') return;
      var db = await ScanHistory.openDB();
      var tx = db.transaction(STORE_NAME, 'readwrite');
      var store = tx.objectStore(STORE_NAME);

      var account = (typeof TenantAuth !== 'undefined' && TenantAuth.getAccount) ? TenantAuth.getAccount() : null;

      var entry = {
        timestamp: Date.now(),
        action: action,
        userId: account ? (account.email || account.username || '') : '',
        tenantId: (typeof AppState !== 'undefined' ? AppState.get('authTenantId') : null) || '',
        detail: detail || '',
        metadata: metadata || {},
      };

      store.add(entry);

      return new Promise(function (resolve, reject) {
        tx.oncomplete = function () { resolve(entry); };
        tx.onerror = function () { reject(tx.error); };
      });
    } catch (e) {
      console.warn('[AuditTrail] Log failed:', e);
    }
  }

  // ─── Querying ───

  async function query(filters, limit, offset) {
    filters = filters || {};
    limit = limit || 100;
    offset = offset || 0;

    try {
      var db = await ScanHistory.openDB();
      var tx = db.transaction(STORE_NAME, 'readonly');
      var store = tx.objectStore(STORE_NAME);

      return new Promise(function (resolve, reject) {
        var results = [];
        var skipped = 0;

        // Use timestamp index for ordering (descending)
        var idx = store.index('timestamp');
        var request = idx.openCursor(null, 'prev');

        request.onsuccess = function (event) {
          var cursor = event.target.result;
          if (!cursor || results.length >= limit) {
            resolve(results);
            return;
          }

          var entry = cursor.value;
          var match = true;

          // Apply filters
          if (filters.action && entry.action !== filters.action) match = false;
          if (filters.startDate && entry.timestamp < filters.startDate) match = false;
          if (filters.endDate && entry.timestamp > filters.endDate) match = false;
          if (filters.search) {
            var q = filters.search.toLowerCase();
            var searchable = (entry.detail + ' ' + entry.action + ' ' + entry.userId).toLowerCase();
            if (searchable.indexOf(q) === -1) match = false;
          }

          if (match) {
            if (skipped < offset) {
              skipped++;
            } else {
              results.push(entry);
            }
          }

          cursor.continue();
        };

        request.onerror = function () { reject(request.error); };
      });
    } catch (e) {
      console.warn('[AuditTrail] Query failed:', e);
      return [];
    }
  }

  // ─── Count ───

  async function count() {
    try {
      var db = await ScanHistory.openDB();
      var tx = db.transaction(STORE_NAME, 'readonly');
      var store = tx.objectStore(STORE_NAME);
      return new Promise(function (resolve) {
        var req = store.count();
        req.onsuccess = function () { resolve(req.result); };
        req.onerror = function () { resolve(0); };
      });
    } catch (e) { return 0; }
  }

  // ─── Viewer UI ───

  function renderViewer() {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var html = '<div class="modal-header">';
    html += '<h3>Audit Trail</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';

    // Filter bar
    html += '<div class="audit-filter-bar" style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">';
    html += '<input type="text" id="audit-search" class="search-input" placeholder="Search..." style="flex:1;min-width:150px;font-size:.68rem;padding:4px 8px" oninput="AuditTrail._refreshViewer()">';
    html += '<select id="audit-action-filter" style="font-size:.68rem;padding:4px 6px;border-radius:4px;border:1px solid var(--border);background:var(--surface)" onchange="AuditTrail._refreshViewer()">';
    html += '<option value="">All Actions</option>';
    var actions = ['scan.start', 'scan.complete', 'deploy.single', 'deploy.bulk', 'export.pdf', 'export.html', 'export.excel', 'export.evidence', 'config.webhook', 'config.theme', 'auth.login', 'auth.logout', 'assessment.reset', 'tenant.switch'];
    for (var i = 0; i < actions.length; i++) {
      html += '<option value="' + actions[i] + '">' + actions[i] + '</option>';
    }
    html += '</select>';
    html += '<button class="btn btn-sm" onclick="AuditTrail.exportLog(\'csv\')" style="font-size:.62rem">Export CSV</button>';
    html += '<button class="btn btn-sm" onclick="AuditTrail.exportLog(\'json\')" style="font-size:.62rem">Export JSON</button>';
    html += '</div>';

    // Results container
    html += '<div id="audit-results" style="max-height:400px;overflow-y:auto"></div>';

    // Pagination
    html += '<div id="audit-pagination" style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;font-size:.62rem"></div>';

    html += '</div>';

    modal.innerHTML = html;
    overlay.classList.add('open');

    _currentPage = 0;
    _refreshViewer();
  }

  var _currentPage = 0;
  var PAGE_SIZE = 50;

  async function _refreshViewer() {
    var resultsEl = document.getElementById('audit-results');
    var paginationEl = document.getElementById('audit-pagination');
    if (!resultsEl) return;

    var searchInput = document.getElementById('audit-search');
    var actionFilter = document.getElementById('audit-action-filter');

    var filters = {};
    if (searchInput && searchInput.value) filters.search = searchInput.value;
    if (actionFilter && actionFilter.value) filters.action = actionFilter.value;

    var entries = await query(filters, PAGE_SIZE, _currentPage * PAGE_SIZE);
    var totalCount = await count();

    if (entries.length === 0) {
      resultsEl.innerHTML = '<div style="text-align:center;color:var(--ink4);font-size:.72rem;padding:20px">No audit entries found.</div>';
      if (paginationEl) paginationEl.innerHTML = '';
      return;
    }

    var html = '<table class="data-table" style="font-size:.65rem">';
    html += '<thead><tr><th style="width:130px">Timestamp</th><th style="width:110px">Action</th><th>User</th><th>Detail</th></tr></thead><tbody>';

    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var ts = new Date(e.timestamp);
      var dateStr = ts.toLocaleDateString() + ' ' + ts.toLocaleTimeString();
      var actionBadge = getActionBadge(e.action);
      html += '<tr>';
      html += '<td class="text-mono" style="font-size:.58rem;white-space:nowrap">' + dateStr + '</td>';
      html += '<td>' + actionBadge + '</td>';
      html += '<td style="font-size:.6rem">' + escHtml(e.userId || '-') + '</td>';
      html += '<td style="font-size:.62rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escHtml(e.detail) + '">' + escHtml(e.detail || '-') + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    resultsEl.innerHTML = html;

    // Pagination
    if (paginationEl) {
      var totalPages = Math.ceil(totalCount / PAGE_SIZE);
      var pgHtml = '<span style="color:var(--ink4)">' + totalCount + ' entries</span>';
      pgHtml += '<div style="display:flex;gap:4px">';
      if (_currentPage > 0) {
        pgHtml += '<button class="btn btn-sm" onclick="AuditTrail._goPage(' + (_currentPage - 1) + ')" style="font-size:.58rem">&laquo; Prev</button>';
      }
      pgHtml += '<span style="color:var(--ink3);padding:2px 6px">Page ' + (_currentPage + 1) + '/' + Math.max(totalPages, 1) + '</span>';
      if (_currentPage < totalPages - 1) {
        pgHtml += '<button class="btn btn-sm" onclick="AuditTrail._goPage(' + (_currentPage + 1) + ')" style="font-size:.58rem">Next &raquo;</button>';
      }
      pgHtml += '</div>';
      paginationEl.innerHTML = pgHtml;
    }
  }

  function _goPage(page) {
    _currentPage = page;
    _refreshViewer();
  }

  function getActionBadge(action) {
    var colors = {
      'scan': 'var(--blue)', 'deploy': 'var(--green)', 'export': 'var(--teal)',
      'config': 'var(--purple)', 'auth': 'var(--amber)', 'assessment': 'var(--red)',
      'tenant': 'var(--amber2)',
    };
    var prefix = action.split('.')[0];
    var clr = colors[prefix] || 'var(--ink3)';
    return '<span class="badge" style="background:' + clr + '15;color:' + clr + ';font-size:.52rem">' + escHtml(action) + '</span>';
  }

  // ─── Export ───

  async function exportLog(format) {
    var entries = await query({}, 10000, 0);
    if (entries.length === 0) {
      showToast('No audit entries to export');
      return;
    }

    var content, filename, mime;

    if (format === 'csv') {
      var lines = ['Timestamp,Action,User,TenantId,Detail'];
      for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        lines.push([
          new Date(e.timestamp).toISOString(),
          e.action,
          '"' + (e.userId || '').replace(/"/g, '""') + '"',
          e.tenantId || '',
          '"' + (e.detail || '').replace(/"/g, '""') + '"',
        ].join(','));
      }
      content = lines.join('\n');
      filename = 'audit-trail-' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv';
      mime = 'text/csv';
    } else {
      content = JSON.stringify(entries, null, 2);
      filename = 'audit-trail-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
      mime = 'application/json';
    }

    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Audit trail exported (' + entries.length + ' entries)');
  }

  // ─── Pruning ───

  async function prune(maxAgeMs) {
    maxAgeMs = maxAgeMs || DEFAULT_RETENTION_MS;
    var cutoff = Date.now() - maxAgeMs;

    try {
      var db = await ScanHistory.openDB();
      var tx = db.transaction(STORE_NAME, 'readwrite');
      var store = tx.objectStore(STORE_NAME);
      var idx = store.index('timestamp');
      var range = IDBKeyRange.upperBound(cutoff);
      var request = idx.openCursor(range);

      var deleted = 0;
      request.onsuccess = function (event) {
        var cursor = event.target.result;
        if (cursor) {
          cursor.delete();
          deleted++;
          cursor.continue();
        }
      };

      return new Promise(function (resolve) {
        tx.oncomplete = function () {
          if (deleted > 0) console.log('[AuditTrail] Pruned ' + deleted + ' old entries');
          resolve(deleted);
        };
      });
    } catch (e) {
      console.warn('[AuditTrail] Prune failed:', e);
      return 0;
    }
  }

  return {
    log: log,
    query: query,
    count: count,
    renderViewer: renderViewer,
    exportLog: exportLog,
    prune: prune,
    _refreshViewer: _refreshViewer,
    _goPage: _goPage,
  };
})();
