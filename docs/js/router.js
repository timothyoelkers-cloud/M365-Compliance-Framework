/* ═══════════════════════════════════════════
   ROUTER — Hash-based page navigation
═══════════════════════════════════════════ */
const Router = (() => {
  const routes = {
    '':            'home',
    'home':        'home',
    'assessment':  'assessment',
    'dashboard':   'dashboard',
    'tenant-scan': 'tenant-scan',
    'policies':    'policies',
    'reports':     'reports',
  };

  const pageInitializers = {};

  function register(page, initFn) {
    // Auto-register the route so calling Router.register('foo', fn) is enough —
    // no need to also add 'foo' to the routes table by hand.
    if (!routes[page]) routes[page] = page;
    pageInitializers[page] = initFn;
  }

  function navigate(page) {
    window.location.hash = '#/' + page;
  }

  function getCurrentPage() {
    const hash = window.location.hash.replace('#/', '').split('?')[0];
    return routes[hash] || 'home';
  }

  function updateView() {
    const page = getCurrentPage();
    AppState.set('currentPage', page);

    // Update nav active states
    document.querySelectorAll('.nav-link').forEach(el => {
      el.classList.toggle('active', el.dataset.page === page);
    });

    // Show/hide pages
    document.querySelectorAll('.page').forEach(el => {
      el.classList.toggle('active', el.id === 'page-' + page);
    });

    // Close mobile nav
    document.querySelector('.topbar-nav')?.classList.remove('open');
    AppState.set('navOpen', false);

    // Initialize page if needed
    if (pageInitializers[page]) {
      pageInitializers[page]();
    }
  }

  function init() {
    window.addEventListener('hashchange', updateView);
    // Initial route
    if (!window.location.hash) {
      window.location.hash = '#/home';
    } else {
      updateView();
    }
  }

  return { register, navigate, init, getCurrentPage };
})();
