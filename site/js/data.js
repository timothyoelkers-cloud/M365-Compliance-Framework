/* ═══════════════════════════════════════════
   DATA LAYER — Async fetch + cache
═══════════════════════════════════════════ */
const DataStore = (() => {
  const cache = {};
  const BASE = 'data/';

  async function fetchJSON(path) {
    if (cache[path]) return cache[path];
    const res = await fetch(BASE + path);
    if (!res.ok) throw new Error(`Failed to load ${path}: ${res.status}`);
    const data = await res.json();
    cache[path] = data;
    return data;
  }

  async function loadAll() {
    const [manifest, checks, frameworks, policyIndex] = await Promise.all([
      fetchJSON('index.json'),
      fetchJSON('checks.json'),
      fetchJSON('frameworks.json'),
      fetchJSON('policies/index.json'),
    ]);
    return { manifest, checks, frameworks, policyTypes: policyIndex.policyTypes, totalPolicies: policyIndex.totalPolicies };
  }

  async function loadFramework(slug) {
    return fetchJSON(`frameworks/${slug}.json`);
  }

  async function loadPolicy(type, file) {
    return fetchJSON(`policies/${type}/${file}`);
  }

  async function loadAllPolicies() {
    if (cache._allPolicies) return cache._allPolicies;
    // Load the full manifest which contains all policies inline
    // We need to reconstruct from individual files or use a bulk approach
    // For efficiency, load all policy types at once
    const policyIndex = await fetchJSON('policies/index.json');
    const types = Object.keys(policyIndex.policyTypes);

    // We'll load the manifest from the main data.js embedded data
    // For now, return from cache if available
    return cache._allPolicies || [];
  }

  return { fetchJSON, loadAll, loadFramework, loadPolicy, loadAllPolicies };
})();
