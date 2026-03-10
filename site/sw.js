/* ═══════════════════════════════════════════
   SERVICE WORKER — PWA + offline caching
═══════════════════════════════════════════ */
var CACHE_NAME = 'm365-compliance-v2';

var STATIC_ASSETS = [
  './',
  './index.html',
  './css/design-system.css',
  './css/layout.css',
  './css/components.css',
  './js/data.js',
  './js/state.js',
  './js/auth.js?v=3',
  './js/router.js',
  './js/scan-history.js',
  './js/offline.js',
  './js/deploy.js',
  './js/pre-deploy-config.js',
  './js/dependency-graph.js',
  './js/bulk-config.js',
  './js/profile-deploy.js',
  './js/tenant-scanner.js',
  './js/policy-matcher.js',
  './js/scan-diff.js',
  './js/ps-verify.js',
  './js/ps-deploy.js',
  './js/remediation.js',
  './js/rbac.js',
  './js/scheduler.js',
  './js/notifications.js',
  './js/evidence.js',
  './js/tenant-manager.js',
  './js/assessment.js',
  './js/dashboard.js',
  './js/policies.js',
  './js/reports.js',
  './js/audit-trail.js',
  './js/theme-toggle.js',
  './js/keyboard-shortcuts.js',
  './js/forecasting.js',
  './js/overlap-matrix.js',
  './js/change-tracker.js',
  './js/dep-viz.js',
  './js/integrations.js',
  './data/index.json',
  './data/checks.json',
  './data/frameworks.json',
  './data/policies-all.json',
  './data/policies/index.json',
];

// Network-only hosts (auth + live data)
var NETWORK_ONLY_HOSTS = [
  'graph.microsoft.com',
  'login.microsoftonline.com',
  'outlook.office365.com',
  'ps.compliance.protection.outlook.com',
];

// Install — cache static assets
self.addEventListener('install', function (event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      return cache.addAll(STATIC_ASSETS).catch(function (err) {
        console.warn('[SW] Some assets failed to cache:', err);
      });
    }).then(function () {
      return self.skipWaiting();
    })
  );
});

// Activate — clean old caches
self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(
        keys.filter(function (k) { return k !== CACHE_NAME; })
            .map(function (k) { return caches.delete(k); })
      );
    }).then(function () {
      return self.clients.claim();
    })
  );
});

// Fetch — strategy depends on request type
self.addEventListener('fetch', function (event) {
  var url = new URL(event.request.url);

  // Network-only for auth and Graph API
  if (NETWORK_ONLY_HOSTS.indexOf(url.hostname) !== -1) {
    event.respondWith(fetch(event.request));
    return;
  }

  // Stale-while-revalidate for data JSON files
  if (url.pathname.indexOf('/data/') !== -1 && url.pathname.endsWith('.json')) {
    event.respondWith(
      caches.open(CACHE_NAME).then(function (cache) {
        return cache.match(event.request).then(function (cached) {
          var fetchPromise = fetch(event.request).then(function (response) {
            if (response.ok) cache.put(event.request, response.clone());
            return response;
          }).catch(function () { return cached; });
          return cached || fetchPromise;
        });
      })
    );
    return;
  }

  // Cache-first for static assets
  event.respondWith(
    caches.match(event.request).then(function (cached) {
      return cached || fetch(event.request).then(function (response) {
        if (response.ok && event.request.method === 'GET') {
          var clone = response.clone();
          caches.open(CACHE_NAME).then(function (cache) { cache.put(event.request, clone); });
        }
        return response;
      });
    })
  );
});
