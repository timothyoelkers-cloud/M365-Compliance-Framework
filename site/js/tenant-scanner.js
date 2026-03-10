/* ═══════════════════════════════════════════
   TENANT SCANNER — Graph API tenant configuration reader
   Scans connected M365 tenant for current policy & config state
═══════════════════════════════════════════ */
const TenantScanner = (() => {
  const GRAPH_BASE = 'https://graph.microsoft.com';
  const MAX_PAGES = 3;
  const REQUEST_TIMEOUT_MS = 15000;

  let scanCache = null;
  let scanning = false;

  // ─── Endpoints ───
  const SCAN_ENDPOINTS = {
    conditionalAccess:       { url: '/v1.0/identity/conditionalAccess/policies',     isList: true  },
    compliancePolicies:      { url: '/v1.0/deviceManagement/deviceCompliancePolicies', isList: true },
    deviceConfigurations:    { url: '/v1.0/deviceManagement/deviceConfigurations',    isList: true  },
    configurationPolicies:   { url: '/beta/deviceManagement/configurationPolicies',   isList: true  },
    authorizationPolicy:     { url: '/v1.0/policies/authorizationPolicy',             isList: false },
    adminConsentPolicy:      { url: '/v1.0/policies/adminConsentRequestPolicy',       isList: false },
    deviceRegistrationPolicy:{ url: '/v1.0/policies/deviceRegistrationPolicy',        isList: false },
    authMethodsPolicy:       { url: '/v1.0/policies/authenticationMethodsPolicy',     isList: false },
    authenticatorConfig:     { url: '/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator', isList: false },
    organization:            { url: '/v1.0/organization',                             isList: true  },
    groupSettings:           { url: '/v1.0/groupSettings',                            isList: true  },
    // ── Extended coverage ──
    sharepointSettings:      { url: '/v1.0/admin/sharepoint/settings',               isList: false },
    secureScores:            { url: '/v1.0/security/secureScores?$top=1',             isList: true  },
    secureScoreProfiles:     { url: '/v1.0/security/secureScoreControlProfiles',      isList: true  },
    sensitivityLabels:       { url: '/beta/security/informationProtection/sensitivityLabels', isList: true },
  };

  // ─── Graph Fetch Helpers ───

  /**
   * Perform a single GET request against the Graph API.
   * Returns the parsed JSON body or throws on HTTP / network errors.
   */
  async function graphGet(url, token) {
    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json',
          'ConsistencyLevel': 'eventual',
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => '');
        let detail = '';
        try {
          const parsed = JSON.parse(errorBody);
          detail = (parsed.error && parsed.error.message) ? parsed.error.message : errorBody;
        } catch (_) {
          detail = errorBody;
        }
        throw new Error('HTTP ' + response.status + (detail ? ': ' + detail : ''));
      }

      return await response.json();
    } finally {
      clearTimeout(timerId);
    }
  }

  /**
   * Fetch a single endpoint (list or singleton).
   * For list endpoints, follows @odata.nextLink up to MAX_PAGES pages.
   * Returns { success: true, data } or { success: false, error }.
   */
  async function fetchEndpoint(endpointKey, endpointDef, token) {
    const fullUrl = GRAPH_BASE + endpointDef.url;

    try {
      if (!endpointDef.isList) {
        // ── Singleton endpoint ──
        const body = await graphGet(fullUrl, token);
        return { success: true, data: body };
      }

      // ── List endpoint with pagination ──
      let allItems = [];
      let nextLink = fullUrl;
      let page = 0;

      while (nextLink && page < MAX_PAGES) {
        const body = await graphGet(nextLink, token);
        const items = Array.isArray(body.value) ? body.value : [];
        allItems = allItems.concat(items);
        nextLink = body['@odata.nextLink'] || null;
        page++;
      }

      return {
        success: true,
        data: allItems,
        totalPages: page,
        hasMore: nextLink !== null,
      };
    } catch (err) {
      const message = err.name === 'AbortError'
        ? 'Request timed out after ' + (REQUEST_TIMEOUT_MS / 1000) + 's'
        : err.message || String(err);

      console.warn('[TenantScanner] ' + endpointKey + ' failed:', message);
      return { success: false, error: message };
    }
  }

  // ─── Batch API Support ───

  const BATCH_ENDPOINT = GRAPH_BASE + '/v1.0/$batch';
  const MAX_BATCH_SIZE = 20;

  /**
   * Execute a $batch request against the Graph API.
   * Groups up to 20 requests per batch call.
   */
  async function executeBatch(endpointKeys, token) {
    var requests = [];
    for (var i = 0; i < endpointKeys.length; i++) {
      var key = endpointKeys[i];
      var def = SCAN_ENDPOINTS[key];
      requests.push({
        id: key,
        method: 'GET',
        url: def.url,
      });
    }

    var controller = new AbortController();
    var timerId = setTimeout(function () { controller.abort(); }, REQUEST_TIMEOUT_MS * 2);

    try {
      var response = await fetch(BATCH_ENDPOINT, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ requests: requests }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error('Batch HTTP ' + response.status);
      }

      var body = await response.json();
      var resultMap = {};

      var responses = body.responses || [];
      for (var j = 0; j < responses.length; j++) {
        var r = responses[j];
        var endpointKey = r.id;
        var def2 = SCAN_ENDPOINTS[endpointKey];

        if (r.status >= 200 && r.status < 300) {
          if (def2 && !def2.isList) {
            resultMap[endpointKey] = { success: true, data: r.body };
          } else {
            var items = (r.body && Array.isArray(r.body.value)) ? r.body.value : [];
            var nextLink = r.body ? r.body['@odata.nextLink'] : null;
            resultMap[endpointKey] = { success: true, data: items, nextLink: nextLink };
          }
        } else {
          var errMsg = (r.body && r.body.error && r.body.error.message) || ('HTTP ' + r.status);
          resultMap[endpointKey] = { success: false, error: errMsg };
        }
      }

      return resultMap;
    } finally {
      clearTimeout(timerId);
    }
  }

  /**
   * Follow @odata.nextLink pagination for list endpoints that returned more data.
   */
  async function followPagination(endpointKey, items, nextLink, token) {
    var allItems = items.slice();
    var page = 1;
    var link = nextLink;

    while (link && page < MAX_PAGES) {
      try {
        var body = await graphGet(link, token);
        var pageItems = Array.isArray(body.value) ? body.value : [];
        allItems = allItems.concat(pageItems);
        link = body['@odata.nextLink'] || null;
        page++;
      } catch (e) {
        break;
      }
    }

    return allItems;
  }

  // ─── Main Scan ───

  /**
   * Scan the connected tenant by querying all configured Graph endpoints.
   * Uses $batch API by default for efficiency (1 request instead of 15+).
   *
   * @returns {{ success: boolean, data: object|null, errors: string[], scanTime: number }}
   */
  async function scanTenant() {
    // Prevent concurrent scans
    if (scanning) {
      console.warn('[TenantScanner] Scan already in progress');
      return { success: false, data: null, errors: ['A scan is already in progress'], scanTime: 0 };
    }

    // ── Auth checks ──
    if (!TenantAuth.isAuthenticated()) {
      if (typeof showToast === 'function') showToast('Please sign in before scanning the tenant.');
      return { success: false, data: null, errors: ['Not authenticated'], scanTime: 0 };
    }

    let token;
    try {
      token = await TenantAuth.getGraphToken();
    } catch (err) {
      const msg = 'Failed to acquire Graph token: ' + (err.message || err);
      if (typeof showToast === 'function') showToast(msg);
      return { success: false, data: null, errors: [msg], scanTime: 0 };
    }

    if (!token) {
      const msg = 'Graph token unavailable. Please re-authenticate.';
      if (typeof showToast === 'function') showToast(msg);
      return { success: false, data: null, errors: [msg], scanTime: 0 };
    }

    // ── Begin scan ──
    scanning = true;
    const startTime = Date.now();
    const endpointKeys = Object.keys(SCAN_ENDPOINTS);
    const total = endpointKeys.length;
    let completed = 0;

    AppState.set('scanProgress', { total, completed: 0, current: 'Initializing scan...' });

    // Audit trail
    if (typeof AuditTrail !== 'undefined') {
      AuditTrail.log('scan.start', 'Tenant scan initiated', { endpointCount: total });
    }

    try {
      const data = {};
      const errors = [];

      // ── Try $batch first for efficiency ──
      let usedBatch = false;
      try {
        AppState.set('scanProgress', { total, completed: 0, current: 'Batch request...' });
        var batchResults = await executeBatch(endpointKeys, token);
        usedBatch = true;

        // Process batch results
        for (var bi = 0; bi < endpointKeys.length; bi++) {
          var bKey = endpointKeys[bi];
          var bResult = batchResults[bKey];

          if (!bResult) {
            data[bKey] = null;
            errors.push(bKey + ': No response from batch');
          } else if (bResult.success) {
            // Follow pagination if needed
            if (bResult.nextLink) {
              data[bKey] = await followPagination(bKey, bResult.data, bResult.nextLink, token);
            } else {
              data[bKey] = bResult.data;
            }
          } else {
            data[bKey] = null;
            errors.push(bKey + ': ' + bResult.error);
          }

          completed++;
          AppState.set('scanProgress', {
            total,
            completed,
            current: bKey + (completed < total ? '' : ' (finalizing)'),
          });
        }
      } catch (batchErr) {
        // $batch failed entirely — fall back to individual parallel requests
        console.warn('[TenantScanner] Batch failed, falling back to parallel:', batchErr.message);
        usedBatch = false;
        completed = 0;

        const promises = endpointKeys.map(key => {
          const def = SCAN_ENDPOINTS[key];
          return fetchEndpoint(key, def, token).then(result => {
            completed++;
            AppState.set('scanProgress', {
              total,
              completed,
              current: key + (completed < total ? '' : ' (finalizing)'),
            });
            return { key, result };
          });
        });

        const settled = await Promise.allSettled(promises);

        for (const entry of settled) {
          if (entry.status === 'fulfilled') {
            const { key, result } = entry.value;
            if (result.success) {
              data[key] = result.data;
            } else {
              data[key] = null;
              errors.push(key + ': ' + result.error);
            }
          } else {
            errors.push('Unexpected rejection: ' + (entry.reason || 'unknown'));
          }
        }
      }

      const scanTime = Date.now() - startTime;
      const account = TenantAuth.getAccount();

      scanCache = {
        data,
        errors,
        scanTime,
        timestamp: Date.now(),
        tenantId: account ? account.tenantId : null,
        scannedBy: account ? account.email : null,
        endpointCount: total,
        successCount: total - errors.length,
      };

      AppState.set('tenantScan', scanCache);
      AppState.set('scanProgress', { total, completed: total, current: 'Complete' });

      // Save to IndexedDB for history/drift detection
      if (typeof ScanHistory !== 'undefined') {
        ScanHistory.saveScan(scanCache).catch(function (e) {
          console.warn('[TenantScanner] Failed to save scan to history:', e);
        });
      }
      // Update tenant manager last scan time
      if (typeof TenantManager !== 'undefined' && scanCache.tenantId) {
        TenantManager.updateLastScan(scanCache.tenantId);
      }

      // Audit trail
      if (typeof AuditTrail !== 'undefined') {
        AuditTrail.log('scan.complete', 'Scan finished in ' + (scanTime / 1000).toFixed(1) + 's', {
          scanTime: scanTime,
          endpointCount: total,
          successCount: total - errors.length,
          errorCount: errors.length,
          usedBatch: usedBatch,
        });
      }

      // Notify user
      if (errors.length === 0) {
        if (typeof showToast === 'function') showToast('Tenant scan completed successfully (' + (scanTime / 1000).toFixed(1) + 's)');
      } else {
        if (typeof showToast === 'function') showToast('Scan completed with ' + errors.length + ' error(s). Check console for details.');
        console.warn('[TenantScanner] Completed with errors:', errors);
      }

      return { success: true, data, errors, scanTime };
    } catch (err) {
      // Catastrophic / unexpected failure
      const msg = 'Scan failed unexpectedly: ' + (err.message || err);
      console.error('[TenantScanner]', msg, err);
      if (typeof showToast === 'function') showToast(msg);
      AppState.set('scanProgress', null);
      return { success: false, data: null, errors: [msg], scanTime: Date.now() - startTime };
    } finally {
      scanning = false;
    }
  }

  // ─── Cache Accessors ───

  /** Return the cached scan results, or null if no scan has been performed. */
  function getScanResults() {
    return scanCache;
  }

  /** True when a cached scan is available. */
  function isScanAvailable() {
    return scanCache !== null;
  }

  /** True while a scan is in progress. */
  function isScanning() {
    return scanning;
  }

  /** Clear cached results and reset AppState. */
  function clearCache() {
    scanCache = null;
    AppState.set('tenantScan', null);
    AppState.set('scanProgress', null);
  }

  /** Return the raw scan cache object (for evidence export). */
  function getScanCache() {
    return scanCache;
  }

  // ─── Public API ───
  return {
    scanTenant,
    getScanResults,
    getScanCache,
    isScanAvailable,
    isScanning,
    clearCache,
    SCAN_ENDPOINTS,
  };
})();
