/* ═══════════════════════════════════════════
   SLIDE-OVER — Right-side detail panel
═══════════════════════════════════════════ */
var SlideOver = (function () {
  'use strict';

  function open(title, html) {
    var el = document.getElementById('slide-over');
    if (!el) return;
    el.innerHTML =
      '<div class="slide-over-header">' +
        '<h3 style="font-size:.95rem;margin:0">' + (title || '') + '</h3>' +
        '<button class="btn btn-ghost" onclick="SlideOver.close()" style="font-size:1.2rem;padding:4px 8px">&times;</button>' +
      '</div>' +
      '<div class="slide-over-body">' + (html || '') + '</div>';
    el.classList.add('open');
    el.style.display = 'block';
  }

  function close() {
    var el = document.getElementById('slide-over');
    if (!el) return;
    el.classList.remove('open');
    setTimeout(function () {
      if (!el.classList.contains('open')) el.style.display = 'none';
    }, 300);
  }

  function isOpen() {
    var el = document.getElementById('slide-over');
    return el && el.classList.contains('open');
  }

  // Close on Escape key
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && isOpen()) close();
  });

  return {
    open: open,
    close: close,
    isOpen: isOpen
  };
})();
