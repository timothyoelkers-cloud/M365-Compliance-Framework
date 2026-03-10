/* ═══════════════════════════════════════════
   SCAN HISTORY — IndexedDB persistence layer
   for scan snapshots, drift detection, and
   compliance timeline tracking.
═══════════════════════════════════════════ */
const ScanHistory = (() => {
  const DB_NAME = 'm365-compliance';
  const DB_VERSION = 1;
  const MAX_SCANS_PER_TENANT = 50;

  let db = null;

  // ─── IndexedDB Init ───

  function openDB() {
    return new Promise(function (resolve, reject) {
      if (db) { resolve(db); return; }
      var request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = function (event) {
        var d = event.target.result;

        // Scan snapshots
        if (!d.objectStoreNames.contains('scans')) {
          var store = d.createObjectStore('scans', { keyPath: 'id' });
          store.createIndex('tenantId', 'tenantId', { unique: false });
          store.createIndex('timestamp', 'timestamp', { unique: false });
          store.createIndex('tenantTimestamp', ['tenantId', 'timestamp'], { unique: false });
        }

        // Offline policy JSON cache
        if (!d.objectStoreNames.contains('policyCache')) {
          d.createObjectStore('policyCache', { keyPath: 'key' });
        }

        // Compliance evidence attachments
        if (!d.objectStoreNames.contains('evidence')) {
          var evStore = d.createObjectStore('evidence', { keyPath: 'id' });
          evStore.createIndex('tenantId', 'tenantId', { unique: false });
          evStore.createIndex('timestamp', 'timestamp', { unique: false });
        }

        // Per-tenant assessment state (for multi-tenant)
        if (!d.objectStoreNames.contains('tenantState')) {
          d.createObjectStore('tenantState', { keyPath: 'tenantId' });
        }
      };

      request.onsuccess = function (event) {
        db = event.target.result;
        resolve(db);
      };

      request.onerror = function (event) {
        console.warn('[ScanHistory] IndexedDB open failed:', event.target.error);
        reject(event.target.error);
      };
    });
  }

  function generateId() {
    return Date.now().toString(36) + '-' + Math.random().toString(36).substr(2, 9);
  }

  // ─── Scan Storage ───

  async function saveScan(scanResult) {
    if (!db) await openDB();

    var tenantId = scanResult.tenantId || (typeof TenantAuth !== 'undefined' && TenantAuth.getAccount() ? TenantAuth.getAccount().tenantId : 'unknown');

    // Build match results summary
    var matchResults = AppState.get('tenantScanResults') || {};
    var summary = { configured: 0, missing: 0, manual: 0, error: 0, total: 0 };
    for (var id in matchResults) {
      summary.total++;
      var s = matchResults[id].status;
      if (s === 'configured') summary.configured++;
      else if (s === 'missing') summary.missing++;
      else if (s === 'manual') summary.manual++;
      else if (s === 'error') summary.error++;
    }
    var score = summary.total > 0 ? Math.round(summary.configured / summary.total * 100) : 0;

    var record = {
      id: generateId(),
      tenantId: tenantId,
      timestamp: Date.now(),
      scanTime: scanResult.scanTime || 0,
      scannedBy: scanResult.scannedBy || '',
      endpointCount: scanResult.endpointCount || 0,
      successCount: scanResult.successCount || 0,
      data: scanResult.data || {},
      errors: scanResult.errors || [],
      matchResults: matchResults,
      summary: summary,
      score: score,
    };

    return new Promise(function (resolve, reject) {
      var tx = db.transaction('scans', 'readwrite');
      var store = tx.objectStore('scans');
      store.put(record);
      tx.oncomplete = function () {
        pruneOldScans(tenantId);
        resolve(record);
      };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  async function pruneOldScans(tenantId) {
    if (!db) return;
    var scans = await getScans(tenantId, 999);
    if (scans.length <= MAX_SCANS_PER_TENANT) return;

    var toDelete = scans.slice(MAX_SCANS_PER_TENANT);
    var tx = db.transaction('scans', 'readwrite');
    var store = tx.objectStore('scans');
    for (var i = 0; i < toDelete.length; i++) {
      store.delete(toDelete[i].id);
    }
  }

  function getScans(tenantId, limit) {
    limit = limit || 50;
    if (!db) return Promise.resolve([]);

    return new Promise(function (resolve, reject) {
      var tx = db.transaction('scans', 'readonly');
      var store = tx.objectStore('scans');
      var results = [];

      if (tenantId) {
        var index = store.index('tenantId');
        var request = index.openCursor(IDBKeyRange.only(tenantId), 'prev');
        request.onsuccess = function (event) {
          var cursor = event.target.result;
          if (cursor && results.length < limit) {
            results.push(cursor.value);
            cursor.continue();
          }
        };
      } else {
        var allRequest = store.openCursor(null, 'prev');
        allRequest.onsuccess = function (event) {
          var cursor = event.target.result;
          if (cursor && results.length < limit) {
            results.push(cursor.value);
            cursor.continue();
          }
        };
      }

      tx.oncomplete = function () { resolve(results); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  function getScan(scanId) {
    if (!db) return Promise.resolve(null);
    return new Promise(function (resolve, reject) {
      var tx = db.transaction('scans', 'readonly');
      var request = tx.objectStore('scans').get(scanId);
      request.onsuccess = function () { resolve(request.result || null); };
      request.onerror = function () { reject(request.error); };
    });
  }

  function deleteScan(scanId) {
    if (!db) return Promise.resolve();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction('scans', 'readwrite');
      tx.objectStore('scans').delete(scanId);
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  // ─── Diff Engine ───

  function diffScans(scanA, scanB) {
    var resultA = scanA.matchResults || {};
    var resultB = scanB.matchResults || {};
    var allIds = new Set([...Object.keys(resultA), ...Object.keys(resultB)]);

    var added = [];
    var removed = [];
    var changed = [];
    var regressions = [];

    allIds.forEach(function (id) {
      var a = resultA[id];
      var b = resultB[id];

      if (!a && b) {
        added.push({ id: id, status: b.status });
      } else if (a && !b) {
        removed.push({ id: id, status: a.status });
      } else if (a && b && a.status !== b.status) {
        changed.push({ id: id, from: a.status, to: b.status });
        if (a.status === 'configured' && b.status === 'missing') {
          regressions.push({ id: id, from: a.status, to: b.status });
        }
      }
    });

    return { added: added, removed: removed, changed: changed, regressions: regressions };
  }

  function findRegressions(olderScan, newerScan) {
    var diff = diffScans(olderScan, newerScan);
    return diff.regressions;
  }

  function buildTimeline(scans) {
    return scans.map(function (s) {
      return {
        id: s.id,
        date: new Date(s.timestamp),
        timestamp: s.timestamp,
        score: s.score,
        configured: s.summary ? s.summary.configured : 0,
        missing: s.summary ? s.summary.missing : 0,
        manual: s.summary ? s.summary.manual : 0,
        total: s.summary ? s.summary.total : 0,
      };
    }).sort(function (a, b) { return a.timestamp - b.timestamp; });
  }

  // ─── UI Rendering ───

  async function renderTimeline(containerId) {
    var el = document.getElementById(containerId);
    if (!el) return;

    var tenantId = AppState.get('authTenantId') || 'unknown';
    var scans = await getScans(tenantId, 20);

    if (scans.length < 2) {
      el.innerHTML = '';
      return;
    }

    var timeline = buildTimeline(scans);
    var latest = scans[0];
    var previous = scans[1];
    var diff = diffScans(previous, latest);

    var html = '<div class="section-hdr" style="margin-top:28px">Scan History (' + scans.length + ' scans)</div>';

    // Regression alert
    if (diff.regressions.length > 0) {
      html += '<div class="card" style="border-color:var(--red);background:rgba(220,38,38,.06);padding:12px;margin-bottom:12px">';
      html += '<strong style="color:var(--red)">Drift Detected</strong> &mdash; ';
      html += diff.regressions.length + ' policies regressed since last scan:';
      html += '<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px">';
      for (var r = 0; r < Math.min(diff.regressions.length, 10); r++) {
        html += '<span class="badge badge-red">' + escHtml(diff.regressions[r].id) + '</span>';
      }
      if (diff.regressions.length > 10) {
        html += '<span class="badge" style="color:var(--ink4)">+' + (diff.regressions.length - 10) + ' more</span>';
      }
      html += '</div></div>';
    }

    // Score sparkline (SVG)
    if (timeline.length >= 2) {
      html += renderSparkline(timeline);
    }

    // Recent scans table
    html += '<div style="max-height:200px;overflow-y:auto">';
    html += '<table class="data-table" style="font-size:.68rem">';
    html += '<thead><tr><th>Date</th><th>Score</th><th style="width:70px">Configured</th><th style="width:60px">Missing</th><th style="width:60px">Manual</th><th style="width:80px">Actions</th></tr></thead>';
    html += '<tbody>';
    for (var i = 0; i < Math.min(scans.length, 10); i++) {
      var s = scans[i];
      var d = new Date(s.timestamp);
      var dateStr = d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      var scoreClr = s.score >= 80 ? 'var(--green)' : s.score >= 50 ? 'var(--amber2)' : 'var(--red)';
      html += '<tr>';
      html += '<td>' + dateStr + '</td>';
      html += '<td class="text-mono" style="font-weight:600;color:' + scoreClr + '">' + s.score + '%</td>';
      html += '<td style="color:var(--green)">' + (s.summary ? s.summary.configured : '—') + '</td>';
      html += '<td style="color:var(--red)">' + (s.summary ? s.summary.missing : '—') + '</td>';
      html += '<td style="color:var(--blue)">' + (s.summary ? s.summary.manual : '—') + '</td>';
      html += '<td>';
      if (i < scans.length - 1) {
        html += '<button class="btn btn-sm" onclick="ScanHistory.renderDiffModal(\'' + s.id + '\',\'' + scans[i + 1].id + '\')" style="font-size:.58rem">Diff</button>';
      }
      html += '</td>';
      html += '</tr>';
    }
    html += '</tbody></table></div>';

    el.innerHTML = html;
  }

  function renderSparkline(timeline) {
    var width = 600;
    var height = 80;
    var padX = 30;
    var padY = 10;
    var drawW = width - padX * 2;
    var drawH = height - padY * 2;

    var minScore = Math.min.apply(null, timeline.map(function (t) { return t.score; }));
    var maxScore = Math.max.apply(null, timeline.map(function (t) { return t.score; }));
    var range = Math.max(maxScore - minScore, 10);

    var points = timeline.map(function (t, i) {
      var x = padX + (i / Math.max(timeline.length - 1, 1)) * drawW;
      var y = padY + drawH - ((t.score - minScore) / range) * drawH;
      return x + ',' + y;
    });

    var lineColor = timeline[timeline.length - 1].score >= timeline[0].score ? 'var(--green)' : 'var(--red)';

    var svg = '<svg width="' + width + '" height="' + height + '" viewBox="0 0 ' + width + ' ' + height + '" style="width:100%;height:auto;margin-bottom:12px">';
    // Grid lines
    for (var g = 0; g <= 4; g++) {
      var gy = padY + (g / 4) * drawH;
      var label = Math.round(maxScore - (g / 4) * range);
      svg += '<line x1="' + padX + '" y1="' + gy + '" x2="' + (width - padX) + '" y2="' + gy + '" stroke="var(--border)" stroke-width="0.5" stroke-dasharray="2,2"/>';
      svg += '<text x="' + (padX - 4) + '" y="' + (gy + 3) + '" fill="var(--ink4)" font-size="8" text-anchor="end">' + label + '%</text>';
    }
    // Line
    svg += '<polyline points="' + points.join(' ') + '" fill="none" stroke="' + lineColor + '" stroke-width="2" stroke-linejoin="round"/>';
    // Dots
    timeline.forEach(function (t, i) {
      var parts = points[i].split(',');
      var dotClr = t.score >= 80 ? 'var(--green)' : t.score >= 50 ? 'var(--amber2)' : 'var(--red)';
      svg += '<circle cx="' + parts[0] + '" cy="' + parts[1] + '" r="3" fill="' + dotClr + '"/>';
    });
    svg += '</svg>';
    return svg;
  }

  async function renderDiffModal(scanIdA, scanIdB) {
    var scanA = await getScan(scanIdA);
    var scanB = await getScan(scanIdB);
    if (!scanA || !scanB) { showToast('Could not load scan data'); return; }

    // Ensure A is newer, B is older
    if (scanA.timestamp < scanB.timestamp) { var tmp = scanA; scanA = scanB; scanB = tmp; }

    var diff = diffScans(scanB, scanA);
    var dateA = new Date(scanA.timestamp).toLocaleString();
    var dateB = new Date(scanB.timestamp).toLocaleString();

    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var html = '<div class="modal-header">';
    html += '<h3>Scan Comparison</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';

    // Summary
    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">';
    html += '<div class="card" style="padding:12px"><strong style="font-size:.68rem">Older Scan</strong><br>';
    html += '<span style="font-size:.62rem;color:var(--ink4)">' + dateB + '</span><br>';
    html += '<span class="text-mono" style="font-size:1rem;font-weight:700;color:' + (scanB.score >= 80 ? 'var(--green)' : scanB.score >= 50 ? 'var(--amber2)' : 'var(--red)') + '">' + scanB.score + '%</span>';
    html += '</div>';
    html += '<div class="card" style="padding:12px"><strong style="font-size:.68rem">Newer Scan</strong><br>';
    html += '<span style="font-size:.62rem;color:var(--ink4)">' + dateA + '</span><br>';
    html += '<span class="text-mono" style="font-size:1rem;font-weight:700;color:' + (scanA.score >= 80 ? 'var(--green)' : scanA.score >= 50 ? 'var(--amber2)' : 'var(--red)') + '">' + scanA.score + '%</span>';
    html += '</div></div>';

    // Delta
    var delta = scanA.score - scanB.score;
    var deltaClr = delta > 0 ? 'var(--green)' : delta < 0 ? 'var(--red)' : 'var(--ink4)';
    var deltaSign = delta > 0 ? '+' : '';
    html += '<div style="text-align:center;margin-bottom:16px">';
    html += '<span class="text-mono" style="font-size:1.2rem;font-weight:700;color:' + deltaClr + '">' + deltaSign + delta + '%</span>';
    html += '<div style="font-size:.58rem;color:var(--ink4)">Score Change</div></div>';

    // Changes table
    if (diff.changed.length > 0 || diff.added.length > 0 || diff.removed.length > 0) {
      html += '<table class="data-table" style="font-size:.68rem"><thead><tr><th>Policy</th><th>Change</th><th>From</th><th>To</th></tr></thead><tbody>';

      for (var r = 0; r < diff.regressions.length; r++) {
        html += '<tr style="background:rgba(220,38,38,.06)">';
        html += '<td class="text-mono" style="font-weight:600;color:var(--red)">' + escHtml(diff.regressions[r].id) + '</td>';
        html += '<td><span class="badge badge-red">Regression</span></td>';
        html += '<td style="color:var(--green)">configured</td>';
        html += '<td style="color:var(--red)">missing</td></tr>';
      }

      var otherChanges = diff.changed.filter(function (c) {
        return !(c.from === 'configured' && c.to === 'missing');
      });
      for (var c = 0; c < otherChanges.length; c++) {
        var improvement = otherChanges[c].to === 'configured';
        html += '<tr>';
        html += '<td class="text-mono" style="font-weight:600;color:var(--blue)">' + escHtml(otherChanges[c].id) + '</td>';
        html += '<td><span class="badge ' + (improvement ? 'badge-green' : 'badge-amber') + '">' + (improvement ? 'Improved' : 'Changed') + '</span></td>';
        html += '<td>' + otherChanges[c].from + '</td>';
        html += '<td>' + otherChanges[c].to + '</td></tr>';
      }

      html += '</tbody></table>';
    } else {
      html += '<div style="text-align:center;color:var(--ink4);font-size:.74rem;padding:16px">No changes detected between scans.</div>';
    }

    html += '<div class="config-actions" style="margin-top:12px">';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '</div></div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  // ─── Policy Cache (for offline) ───

  async function cachePolicyData(key, data) {
    if (!db) await openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction('policyCache', 'readwrite');
      tx.objectStore('policyCache').put({ key: key, data: data, cachedAt: Date.now() });
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  async function getCachedPolicyData(key) {
    if (!db) await openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction('policyCache', 'readonly');
      var request = tx.objectStore('policyCache').get(key);
      request.onsuccess = function () { resolve(request.result ? request.result.data : null); };
      request.onerror = function () { resolve(null); };
    });
  }

  // ─── Tenant State (for multi-tenant) ───

  async function saveTenantState(tenantId, stateData) {
    if (!db) await openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction('tenantState', 'readwrite');
      tx.objectStore('tenantState').put({ tenantId: tenantId, ...stateData, savedAt: Date.now() });
      tx.oncomplete = function () { resolve(); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  async function loadTenantState(tenantId) {
    if (!db) await openDB();
    return new Promise(function (resolve, reject) {
      var tx = db.transaction('tenantState', 'readonly');
      var request = tx.objectStore('tenantState').get(tenantId);
      request.onsuccess = function () { resolve(request.result || null); };
      request.onerror = function () { resolve(null); };
    });
  }

  // ─── Evidence Store ───

  async function saveEvidence(tenantId, type, name, data) {
    if (!db) await openDB();
    var record = {
      id: generateId(),
      tenantId: tenantId,
      timestamp: Date.now(),
      type: type,
      name: name,
      data: data,
    };
    return new Promise(function (resolve, reject) {
      var tx = db.transaction('evidence', 'readwrite');
      tx.objectStore('evidence').put(record);
      tx.oncomplete = function () { resolve(record); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  async function getEvidence(tenantId, limit) {
    limit = limit || 20;
    if (!db) return [];
    return new Promise(function (resolve, reject) {
      var tx = db.transaction('evidence', 'readonly');
      var index = tx.objectStore('evidence').index('tenantId');
      var results = [];
      var request = index.openCursor(IDBKeyRange.only(tenantId), 'prev');
      request.onsuccess = function (event) {
        var cursor = event.target.result;
        if (cursor && results.length < limit) {
          results.push(cursor.value);
          cursor.continue();
        }
      };
      tx.oncomplete = function () { resolve(results); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  return {
    openDB: openDB,
    saveScan: saveScan,
    getScans: getScans,
    getScan: getScan,
    deleteScan: deleteScan,
    diffScans: diffScans,
    findRegressions: findRegressions,
    buildTimeline: buildTimeline,
    renderTimeline: renderTimeline,
    renderDiffModal: renderDiffModal,
    cachePolicyData: cachePolicyData,
    getCachedPolicyData: getCachedPolicyData,
    saveTenantState: saveTenantState,
    loadTenantState: loadTenantState,
    saveEvidence: saveEvidence,
    getEvidence: getEvidence,
  };
})();
