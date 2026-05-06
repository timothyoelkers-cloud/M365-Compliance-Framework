/* ═══════════════════════════════════════════
   GDAP AUTH — Multi-tenant Partner Center integration
   Enables MSPs to manage customer tenants via GDAP
═══════════════════════════════════════════ */
var GDAPAuth = (function () {
  'use strict';

  var PARTNER_CENTER_SCOPE = 'https://api.partnercenter.microsoft.com/user_impersonation';
  var customerTenants = [];
  var activeTenantId = null;
  var tenantTokenCache = {};

  function init() {
    if (typeof TenantAuth === 'undefined' || !TenantAuth.isAuthenticated()) return;
    // Attempt to discover GDAP customer tenants
    fetchCustomerTenants().catch(function (e) {
      console.log('[GDAP] Not a partner tenant or GDAP not configured:', e.message);
    });
  }

  function getPartnerToken() {
    if (typeof TenantAuth === 'undefined') return Promise.resolve(null);
    // Acquire token for Partner Center API
    return TenantAuth.getTokenForResource
      ? TenantAuth.getTokenForResource([PARTNER_CENTER_SCOPE])
      : Promise.resolve(null);
  }

  function fetchCustomerTenants() {
    return getPartnerToken().then(function (token) {
      if (!token) return [];
      return fetch('https://api.partnercenter.microsoft.com/v1/customers', {
        headers: {
          'Authorization': 'Bearer ' + token,
          'Accept': 'application/json'
        }
      }).then(function (res) {
        if (!res.ok) throw new Error('Partner Center API: ' + res.status);
        return res.json();
      }).then(function (data) {
        var items = data.items || [];
        customerTenants = items.map(function (c) {
          var profile = c.companyProfile || {};
          return {
            id: c.id,
            tenantId: profile.tenantId || c.id,
            displayName: profile.companyName || c.id,
            domain: profile.domain || ''
          };
        });

        // Auto-register discovered tenants (respecting license limits)
        customerTenants.forEach(function (ct) {
          if (typeof License !== 'undefined' && !License.canAddTenant()) return;
          if (typeof TenantManager !== 'undefined' && typeof TenantManager.addTenant === 'function') {
            TenantManager.addTenant(ct.tenantId, ct.displayName);
          }
        });

        if (typeof AppState !== 'undefined') {
          AppState.set('gdapCustomerTenants', customerTenants);
        }

        return customerTenants;
      });
    });
  }

  function getTokenForTenant(tenantId, scopes) {
    var cacheKey = tenantId + ':' + scopes.join(',');
    var cached = tenantTokenCache[cacheKey];
    if (cached && cached.expiresAt > Date.now()) {
      return Promise.resolve(cached.token);
    }

    // Use MSAL with authority set to the customer tenant
    if (typeof TenantAuth !== 'undefined' && typeof TenantAuth.getTokenForTenantResource === 'function') {
      return TenantAuth.getTokenForTenantResource(tenantId, scopes).then(function (token) {
        if (token) {
          tenantTokenCache[cacheKey] = {
            token: token,
            expiresAt: Date.now() + 50 * 60 * 1000 // 50 min
          };
        }
        return token;
      });
    }

    // Fallback: use standard token (single tenant)
    return TenantAuth.getGraphToken();
  }

  function getCustomerTenants() {
    return customerTenants;
  }

  function getActiveTenantId() {
    return activeTenantId;
  }

  function setActiveTenant(tenantId) {
    activeTenantId = tenantId;
    if (typeof AppState !== 'undefined') {
      AppState.set('gdapActiveTenant', tenantId);
    }
    // Clear scan cache for new tenant context
    if (typeof TenantScanner !== 'undefined' && typeof TenantScanner.clearCache === 'function') {
      TenantScanner.clearCache();
    }
  }

  function clearCache() {
    tenantTokenCache = {};
  }

  function isPartnerMode() {
    return customerTenants.length > 0;
  }

  return {
    init: init,
    getPartnerToken: getPartnerToken,
    fetchCustomerTenants: fetchCustomerTenants,
    getTokenForTenant: getTokenForTenant,
    getCustomerTenants: getCustomerTenants,
    getActiveTenantId: getActiveTenantId,
    setActiveTenant: setActiveTenant,
    clearCache: clearCache,
    isPartnerMode: isPartnerMode
  };
})();
