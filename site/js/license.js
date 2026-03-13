/* ═══════════════════════════════════════════
   LICENSE — Free / Pro tier management
   Client-side license key validation
═══════════════════════════════════════════ */
var License = (function () {
  'use strict';

  var LICENSE_KEY = 'm365-license-key';
  var FREE_TENANT_LIMIT = 3;

  function init() {
    renderBadge();
  }

  function getLicenseKey() {
    return localStorage.getItem(LICENSE_KEY);
  }

  /** Validate key format: PRO-8HEX-8HEX */
  function validateKeyFormat(key) {
    return /^PRO-[A-F0-9]{8}-[A-F0-9]{8}$/i.test(key);
  }

  function isPro() {
    var key = getLicenseKey();
    return !!(key && validateKeyFormat(key));
  }

  function getTenantLimit() {
    return isPro() ? Infinity : FREE_TENANT_LIMIT;
  }

  function canAddTenant() {
    if (isPro()) return true;
    var tenants = (typeof TenantManager !== 'undefined' && typeof TenantManager.getTenants === 'function')
      ? TenantManager.getTenants()
      : [];
    return tenants.length < FREE_TENANT_LIMIT;
  }

  function activate(key) {
    if (!validateKeyFormat(key)) return false;
    localStorage.setItem(LICENSE_KEY, key);
    renderBadge();
    if (typeof showToast === 'function') showToast('Pro license activated');
    return true;
  }

  function deactivate() {
    localStorage.removeItem(LICENSE_KEY);
    renderBadge();
    if (typeof showToast === 'function') showToast('License deactivated');
  }

  function renderBadge() {
    var el = document.getElementById('license-badge');
    if (!el) return;
    if (isPro()) {
      el.innerHTML = '<span class="badge badge-blue" style="cursor:pointer" onclick="License.showModal()">PRO</span>';
    } else {
      el.innerHTML = '<span class="badge" style="cursor:pointer;background:var(--bg2);color:var(--ink2);border:1px solid var(--border)" onclick="License.showModal()">FREE</span>';
    }
  }

  function showModal() {
    var content = document.getElementById('license-modal-content');
    if (!content) return;
    var currentKey = getLicenseKey();
    content.innerHTML =
      '<div style="text-align:center;padding:16px 0">' +
        '<div style="font-size:2rem;margin-bottom:12px">' + (isPro() ? '&#9733;' : '&#9734;') + '</div>' +
        '<h4 style="margin-bottom:4px">' + (isPro() ? 'Pro License Active' : 'Free Plan') + '</h4>' +
        '<p style="font-size:.875rem;color:var(--ink2);margin-bottom:16px">' +
          (isPro()
            ? 'Unlimited tenants &middot; Priority support'
            : 'Limited to ' + FREE_TENANT_LIMIT + ' tenants') +
        '</p>' +
        '<div style="text-align:left;max-width:320px;margin:0 auto">' +
          '<label style="display:block;font-size:.75rem;font-weight:600;color:var(--ink2);margin-bottom:4px">License Key</label>' +
          '<input type="text" id="license-key-input" class="search-input" ' +
            'placeholder="PRO-XXXXXXXX-XXXXXXXX" ' +
            'value="' + (currentKey || '') + '" ' +
            'style="font-size:.875rem;margin-bottom:8px">' +
          '<div style="display:flex;gap:8px">' +
            '<button class="btn btn-primary" style="flex:1" onclick="License.activateFromInput()">Activate</button>' +
            (isPro() ? '<button class="btn btn-danger btn-sm" onclick="License.deactivate();License.showModal()">Remove</button>' : '') +
          '</div>' +
        '</div>' +
      '</div>';
    document.getElementById('license-modal-overlay').classList.add('open');
  }

  function activateFromInput() {
    var input = document.getElementById('license-key-input');
    if (!input) return;
    var key = input.value.trim();
    if (!key) return;
    if (activate(key)) {
      document.getElementById('license-modal-overlay').classList.remove('open');
    } else {
      if (typeof showToast === 'function') showToast('Invalid license key format');
    }
  }

  return {
    init: init,
    isPro: isPro,
    getTenantLimit: getTenantLimit,
    canAddTenant: canAddTenant,
    activate: activate,
    deactivate: deactivate,
    showModal: showModal,
    activateFromInput: activateFromInput,
    renderBadge: renderBadge,
    getLicenseKey: getLicenseKey,
    validateKeyFormat: validateKeyFormat,
    FREE_TENANT_LIMIT: FREE_TENANT_LIMIT
  };
})();
