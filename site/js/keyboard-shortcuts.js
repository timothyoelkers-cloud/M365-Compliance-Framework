/* ═══════════════════════════════════════════
   KEYBOARD SHORTCUTS — Global hotkeys for
   quick navigation and common actions.
═══════════════════════════════════════════ */
const KeyboardShortcuts = (() => {
  const shortcuts = [
    { key: 's', ctrl: true, desc: 'Trigger tenant scan', handler: triggerScan },
    { key: 'e', ctrl: true, desc: 'Export evidence package', handler: triggerExport },
    { key: '1', desc: 'Go to Home', handler: function () { Router.navigate('home'); } },
    { key: '2', desc: 'Go to Assessment', handler: function () { Router.navigate('assessment'); } },
    { key: '3', desc: 'Go to Dashboard', handler: function () { Router.navigate('dashboard'); } },
    { key: '4', desc: 'Go to Policies', handler: function () { Router.navigate('policies'); } },
    { key: '5', desc: 'Go to Reports', handler: function () { Router.navigate('reports'); } },
    { key: '/', desc: 'Focus search', handler: focusSearch },
    { key: 'Escape', desc: 'Close modal / blur input', handler: closeModal },
    { key: '?', shift: true, desc: 'Show keyboard shortcuts', handler: showHelpModal },
    { key: 't', desc: 'Toggle theme', handler: toggleTheme },
  ];

  function init() {
    document.addEventListener('keydown', handleKeyDown);
  }

  function handleKeyDown(e) {
    // Skip if access gate is visible
    var gate = document.getElementById('access-gate');
    if (gate && !gate.classList.contains('hidden')) return;

    // If typing in an input, only handle Escape
    var tag = e.target.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
      if (e.key === 'Escape') {
        e.target.blur();
        return;
      }
      return;
    }

    for (var i = 0; i < shortcuts.length; i++) {
      var s = shortcuts[i];
      var ctrlMatch = s.ctrl ? (e.ctrlKey || e.metaKey) : !(e.ctrlKey || e.metaKey);
      var shiftMatch = s.shift ? e.shiftKey : !e.shiftKey;
      if (e.key === s.key && ctrlMatch && shiftMatch && !e.altKey) {
        e.preventDefault();
        s.handler();
        return;
      }
    }
  }

  function triggerScan() {
    if (typeof TenantAuth !== 'undefined' && TenantAuth.isAuthenticated()) {
      if (typeof Policies !== 'undefined' && Policies.scanTenant) {
        Policies.scanTenant();
      } else if (typeof TenantScanner !== 'undefined') {
        TenantScanner.scanTenant();
      }
    } else if (typeof handleConnectTenant !== 'undefined') {
      handleConnectTenant();
    }
  }

  function triggerExport() {
    if (typeof EvidenceCollector !== 'undefined') {
      EvidenceCollector.collectEvidence();
    }
  }

  function focusSearch() {
    var el = document.querySelector('.search-input') || document.querySelector('input[type="search"]');
    if (el) el.focus();
  }

  function closeModal() {
    var overlay = document.getElementById('modal-overlay');
    if (overlay && overlay.classList.contains('open')) {
      if (typeof closeModalAccessible === 'function') {
        closeModalAccessible();
      } else {
        overlay.classList.remove('open');
      }
      return;
    }
    var tenantOverlay = document.getElementById('tenant-modal-overlay');
    if (tenantOverlay && tenantOverlay.classList.contains('open')) {
      tenantOverlay.classList.remove('open');
    }
  }

  function toggleTheme() {
    if (typeof ThemeToggle !== 'undefined') ThemeToggle.toggle();
  }

  function showHelpModal() {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var html = '<div class="modal-header">';
    html += '<h3>Keyboard Shortcuts</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';
    html += '<table class="data-table shortcuts-table" style="font-size:.72rem">';
    html += '<thead><tr><th style="width:120px">Shortcut</th><th>Action</th></tr></thead><tbody>';

    for (var i = 0; i < shortcuts.length; i++) {
      var s = shortcuts[i];
      var keyLabel = '';
      if (s.ctrl) keyLabel += '<kbd>Ctrl</kbd> + ';
      if (s.shift) keyLabel += '<kbd>Shift</kbd> + ';
      keyLabel += '<kbd>' + escHtml(s.key === ' ' ? 'Space' : s.key) + '</kbd>';
      html += '<tr><td>' + keyLabel + '</td><td>' + escHtml(s.desc) + '</td></tr>';
    }

    html += '</tbody></table>';
    html += '<div style="margin-top:12px;text-align:right">';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '</div></div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  return { init: init, showHelpModal: showHelpModal };
})();
