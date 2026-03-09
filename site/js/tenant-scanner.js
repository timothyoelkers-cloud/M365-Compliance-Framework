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

  // ─── Main Scan ───

  /**
   * Scan the connected tenant by querying all configured Graph endpoints.
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

    try {
      // Launch all requests in parallel; track individual progress
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

      // ── Assemble results ──
      const data = {};
      const errors = [];

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
          // Promise itself rejected (should not happen, but guard anyway)
          errors.push('Unexpected rejection: ' + (entry.reason || 'unknown'));
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

  // ─── Public API ───
  return {
    scanTenant,
    getScanResults,
    isScanAvailable,
    isScanning,
    clearCache,
    SCAN_ENDPOINTS,
  };
})();
