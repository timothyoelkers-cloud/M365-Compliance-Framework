/* ═══════════════════════════════════════════
   ACCESS GATE — Password-protected entry point
   SHA-256 hash validation, sessionStorage persistence
═══════════════════════════════════════════ */
var AccessGate = (function () {
  'use strict';

  var GATE_HASH = '29352a43448317a963073bb9349844a2a2c993bf8072ff612be31e5943c40a47';
  var GATE_TOKEN_KEY = 'm365-gate-token';
  var _onGranted = null;

  function sha256(text) {
    var data = new TextEncoder().encode(text);
    return crypto.subtle.digest('SHA-256', data).then(function (buf) {
      return Array.from(new Uint8Array(buf))
        .map(function (b) { return b.toString(16).padStart(2, '0'); })
        .join('');
    });
  }

  /** One-time migration from localStorage to sessionStorage */
  function migrateStorage() {
    var oldToken = localStorage.getItem(GATE_TOKEN_KEY);
    if (oldToken === GATE_HASH) {
      sessionStorage.setItem(GATE_TOKEN_KEY, GATE_HASH);
      localStorage.removeItem(GATE_TOKEN_KEY);
    }
  }

  function checkAccess() {
    migrateStorage();
    var token = sessionStorage.getItem(GATE_TOKEN_KEY);
    if (token === GATE_HASH) {
      grantAccess();
    } else {
      var gate = document.getElementById('access-gate');
      if (gate) gate.classList.remove('hidden');
      var input = document.getElementById('gate-input');
      if (input) input.focus();
    }
  }

  function validate() {
    var input = document.getElementById('gate-input');
    if (!input || !input.value) return;
    sha256(input.value).then(function (hash) {
      if (hash === GATE_HASH) {
        sessionStorage.setItem(GATE_TOKEN_KEY, GATE_HASH);
        grantAccess();
      } else {
        var card = document.querySelector('.gate-card');
        var error = document.getElementById('gate-error');
        if (error) error.classList.add('visible');
        if (card) {
          card.classList.add('shake');
          setTimeout(function () { card.classList.remove('shake'); }, 400);
        }
        input.value = '';
        input.focus();
      }
    });
  }

  function grantAccess() {
    var gate = document.getElementById('access-gate');
    if (gate) gate.classList.add('hidden');
    if (typeof _onGranted === 'function') _onGranted();
  }

  /**
   * Initialize the access gate.
   * @param {Function} onGranted — callback to run when access is granted (typically bootstrap)
   */
  function init(onGranted) {
    _onGranted = onGranted;
    var input = document.getElementById('gate-input');
    if (input) {
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') validate();
      });
    }
    var btn = document.getElementById('gate-btn');
    if (btn) btn.onclick = validate;
    checkAccess();
  }

  return {
    init: init,
    validate: validate,
    checkAccess: checkAccess
  };
})();
