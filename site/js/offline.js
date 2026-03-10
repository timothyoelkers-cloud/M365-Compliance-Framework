/* ═══════════════════════════════════════════
   OFFLINE MANAGER — Online/offline detection,
   IndexedDB data cache fallback, and operation
   queueing for when network is unavailable.
═══════════════════════════════════════════ */
const OfflineManager = (() => {
  let online = navigator.onLine;
  const operationQueue = [];

  // ─── Init ───

  function init() {
    window.addEventListener('online', function () {
      online = true;
      updateIndicator();
      showToast('Back online');
      syncQueue();
    });

    window.addEventListener('offline', function () {
      online = false;
      updateIndicator();
      showToast('You are offline — cached data still available');
    });

    updateIndicator();
  }

  function isOnline() { return online; }

  // ─── UI Indicator ───

  function updateIndicator() {
    var el = document.getElementById('offline-indicator');
    if (!el) return;

    if (online) {
      el.style.display = 'none';
    } else {
      el.style.display = 'inline-flex';
      el.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:var(--red);margin-right:4px"></span>Offline';
    }
  }

  // ─── IndexedDB Policy Cache ───

  async function cachePolicyData(key, data) {
    if (typeof ScanHistory !== 'undefined') {
      return ScanHistory.cachePolicyData(key, data);
    }
  }

  async function getCachedData(key) {
    if (typeof ScanHistory !== 'undefined') {
      return ScanHistory.getCachedPolicyData(key);
    }
    return null;
  }

  // ─── Operation Queue ───

  function queueOperation(op) {
    operationQueue.push({
      timestamp: Date.now(),
      operation: op,
    });
  }

  async function syncQueue() {
    if (!online || operationQueue.length === 0) return;

    var toSync = operationQueue.splice(0, operationQueue.length);
    var failed = [];

    for (var i = 0; i < toSync.length; i++) {
      try {
        if (typeof toSync[i].operation === 'function') {
          await toSync[i].operation();
        }
      } catch (e) {
        console.warn('[Offline] Failed to sync queued operation:', e);
        failed.push(toSync[i]);
      }
    }

    if (failed.length > 0) {
      operationQueue.push.apply(operationQueue, failed);
    }

    if (toSync.length - failed.length > 0) {
      showToast('Synced ' + (toSync.length - failed.length) + ' queued operations');
    }
  }

  function getQueueLength() { return operationQueue.length; }

  // ─── Enhanced Fetch with Cache Fallback ───

  async function fetchWithFallback(url, options) {
    if (online) {
      try {
        var response = await fetch(url, options);
        if (response.ok) {
          var clone = response.clone();
          var data = await clone.json();
          // Cache successful fetches
          await cachePolicyData(url, data);
          return data;
        }
      } catch (e) {
        // Network failed, fall through to cache
      }
    }

    // Try IndexedDB cache
    var cached = await getCachedData(url);
    if (cached) return cached;

    throw new Error('Network unavailable and no cached data for: ' + url);
  }

  return {
    init: init,
    isOnline: isOnline,
    cachePolicyData: cachePolicyData,
    getCachedData: getCachedData,
    queueOperation: queueOperation,
    syncQueue: syncQueue,
    getQueueLength: getQueueLength,
    fetchWithFallback: fetchWithFallback,
  };
})();
