/* ═══════════════════════════════════════════
   THEME TOGGLE — Dark / light mode switch
   with localStorage persistence and system
   preference detection.
═══════════════════════════════════════════ */
const ThemeToggle = (() => {
  const STORAGE_KEY = 'm365-theme';

  function init() {
    var saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      applyTheme(saved);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      applyTheme('dark');
    } else {
      applyTheme('light');
    }

    // Listen for system preference changes (only if no manual override)
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function (e) {
        if (!localStorage.getItem(STORAGE_KEY)) {
          applyTheme(e.matches ? 'dark' : 'light');
        }
      });
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    var btn = document.getElementById('theme-toggle-btn');
    if (btn) {
      btn.textContent = theme === 'dark' ? '\u2600' : '\u263D';
      btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
    }
  }

  function toggle() {
    var current = document.documentElement.getAttribute('data-theme') || 'light';
    var next = current === 'dark' ? 'light' : 'dark';
    localStorage.setItem(STORAGE_KEY, next);
    applyTheme(next);
    if (typeof AuditTrail !== 'undefined') {
      AuditTrail.log('config.theme', 'Theme changed to ' + next);
    }
    if (typeof showToast !== 'undefined') {
      showToast('Theme: ' + next.charAt(0).toUpperCase() + next.slice(1));
    }
  }

  function getTheme() {
    return document.documentElement.getAttribute('data-theme') || 'light';
  }

  return { init: init, toggle: toggle, applyTheme: applyTheme, getTheme: getTheme };
})();
