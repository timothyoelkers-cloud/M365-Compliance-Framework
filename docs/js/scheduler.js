/* ═══════════════════════════════════════════
   SCAN SCHEDULER — Background re-scan timer
   with drift detection and notification hooks.
═══════════════════════════════════════════ */
const ScanScheduler = (() => {
  let timerId = null;
  let intervalMs = 0;
  let intervalKey = null;
  let lastScanTime = null;
  let nextScanTime = null;
  let indicatorTimerId = null;
  let paused = false;

  const INTERVALS = {
    '15min': 15 * 60 * 1000,
    '30min': 30 * 60 * 1000,
    '1hr':   60 * 60 * 1000,
    '4hr':   4 * 60 * 60 * 1000,
  };

  // ─── Lifecycle ───

  function start(key) {
    if (!INTERVALS[key]) return;
    stop();

    intervalKey = key;
    intervalMs = INTERVALS[key];
    lastScanTime = Date.now();
    nextScanTime = Date.now() + intervalMs;
    paused = false;

    timerId = setInterval(executeScheduledScan, intervalMs);

    // Persist preference
    AppState.set('scanScheduleInterval', key);

    startIndicatorUpdates();
    updateIndicator();
    showToast('Scheduled scan every ' + key);
  }

  function stop() {
    if (timerId) { clearInterval(timerId); timerId = null; }
    if (indicatorTimerId) { clearInterval(indicatorTimerId); indicatorTimerId = null; }
    intervalMs = 0;
    intervalKey = null;
    nextScanTime = null;
    paused = false;
    AppState.set('scanScheduleInterval', null);
    updateIndicator();
  }

  function pause() {
    if (timerId) { clearInterval(timerId); timerId = null; }
    paused = true;
    updateIndicator();
  }

  function resume() {
    if (!intervalKey || !paused) return;
    paused = false;
    nextScanTime = Date.now() + intervalMs;
    timerId = setInterval(executeScheduledScan, intervalMs);
    updateIndicator();
  }

  function isRunning() { return !!timerId && !paused; }
  function isPaused() { return paused; }
  function getIntervalKey() { return intervalKey; }

  function getCountdown() {
    if (!nextScanTime || paused) return 0;
    return Math.max(0, Math.round((nextScanTime - Date.now()) / 1000));
  }

  // ─── Scheduled Scan ───

  async function executeScheduledScan() {
    if (typeof TenantScanner === 'undefined' || typeof PolicyMatcher === 'undefined') return;
    if (!TenantAuth || !TenantAuth.isAuthenticated()) {
      pause();
      showToast('Scheduled scan paused — please re-authenticate');
      return;
    }

    // Get previous scan for drift comparison
    var previousScan = null;
    if (typeof ScanHistory !== 'undefined') {
      var tenantId = AppState.get('authTenantId') || 'unknown';
      var prevScans = await ScanHistory.getScans(tenantId, 1);
      if (prevScans.length > 0) previousScan = prevScans[0];
    }

    try {
      // Attempt token refresh
      var token = await TenantAuth.getGraphToken();
      if (!token) {
        pause();
        showToast('Token expired — re-authenticate to resume scheduled scans');
        return;
      }

      // Run scan
      var scanResult = await TenantScanner.scanTenant();
      if (!scanResult.success) {
        console.warn('[Scheduler] Scan failed:', scanResult.error);
        return;
      }

      // Match policies
      var policies = AppState.get('policies') || [];
      PolicyMatcher.matchAll(policies, scanResult.data);

      lastScanTime = Date.now();
      nextScanTime = Date.now() + intervalMs;

      // Drift detection
      if (previousScan && typeof ScanHistory !== 'undefined') {
        var currentTenantId = AppState.get('authTenantId') || 'unknown';
        var currentScans = await ScanHistory.getScans(currentTenantId, 1);
        if (currentScans.length > 0) {
          var diff = ScanHistory.diffScans(previousScan, currentScans[0]);

          if (diff.regressions.length > 0) {
            showToast('Drift detected: ' + diff.regressions.length + ' policies regressed');
          }

          // Notify via webhook if configured
          if (typeof WebhookNotifier !== 'undefined') {
            var prevScore = previousScan.score || 0;
            var currScore = currentScans[0].score || 0;
            WebhookNotifier.checkAndNotify(currScore, prevScore, diff.regressions);
          }
        }
      }

      updateIndicator();
    } catch (e) {
      console.warn('[Scheduler] Scheduled scan error:', e);
      if (e.name === 'InteractionRequiredAuthError' || (e.message && e.message.indexOf('interaction_required') !== -1)) {
        pause();
        showToast('Authentication required — scheduled scans paused');
      }
    }
  }

  // ─── UI ───

  function startIndicatorUpdates() {
    if (indicatorTimerId) clearInterval(indicatorTimerId);
    indicatorTimerId = setInterval(updateIndicator, 10000); // Update every 10s
  }

  function updateIndicator() {
    var el = document.getElementById('scan-schedule-indicator');
    if (!el) return;

    if (!intervalKey) {
      el.style.display = 'none';
      return;
    }

    el.style.display = 'inline-flex';

    var parts = [];
    if (lastScanTime) {
      var agoMs = Date.now() - lastScanTime;
      parts.push('Last: ' + formatDuration(agoMs) + ' ago');
    }

    if (paused) {
      parts.push('<span style="color:var(--amber2)">Paused</span>');
    } else {
      var countdown = getCountdown();
      parts.push('Next: ' + formatDuration(countdown * 1000));
    }

    el.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:' + (paused ? 'var(--amber2)' : 'var(--green)') + ';margin-right:4px;animation:' + (paused ? 'none' : 'pulse 2s infinite') + '"></span>' + parts.join(' | ');
  }

  function formatDuration(ms) {
    var s = Math.round(ms / 1000);
    if (s < 60) return s + 's';
    var m = Math.round(s / 60);
    if (m < 60) return m + 'm';
    var h = Math.floor(m / 60);
    var rm = m % 60;
    return h + 'h' + (rm > 0 ? rm + 'm' : '');
  }

  function renderSettingsUI() {
    var current = intervalKey || '';
    var html = '<div style="display:flex;align-items:center;gap:8px;font-size:.72rem">';
    html += '<label style="color:var(--ink4)">Auto-scan:</label>';
    html += '<select id="scan-schedule-select" onchange="ScanScheduler.handleIntervalChange(this.value)" style="font-size:.68rem;padding:2px 6px;border-radius:4px;border:1px solid var(--border);background:var(--bg2);color:var(--ink1)">';
    html += '<option value="" ' + (current === '' ? 'selected' : '') + '>Off</option>';
    for (var key in INTERVALS) {
      html += '<option value="' + key + '" ' + (current === key ? 'selected' : '') + '>' + key + '</option>';
    }
    html += '</select>';

    if (paused) {
      html += '<button class="btn btn-sm" onclick="ScanScheduler.resume()" style="font-size:.58rem">Resume</button>';
    }

    html += '</div>';
    return html;
  }

  function handleIntervalChange(value) {
    if (value && INTERVALS[value]) {
      start(value);
    } else {
      stop();
      showToast('Scheduled scanning disabled');
    }
  }

  return {
    start: start,
    stop: stop,
    pause: pause,
    resume: resume,
    isRunning: isRunning,
    isPaused: isPaused,
    getIntervalKey: getIntervalKey,
    getCountdown: getCountdown,
    renderSettingsUI: renderSettingsUI,
    handleIntervalChange: handleIntervalChange,
    INTERVALS: INTERVALS,
  };
})();
