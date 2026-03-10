/* ═══════════════════════════════════════════
   STATE — Global reactive state + persistence
═══════════════════════════════════════════ */
const AppState = (() => {
  const STORAGE_KEY = 'm365-compliance-state';
  const listeners = new Map();

  const state = {
    // Data (loaded async)
    checks: [],
    policies: [],
    frameworks: [],
    fwGroups: {},
    orgProfiles: {},
    policyTypes: {},
    categories: [],
    manifest: {},
    frameworkMeta: {},

    // Selection
    selectedFrameworks: new Set(),
    selectedPolicies: new Set(),

    // Assessment status per check: 'done' | 'gap' | '' (unreviewed)
    checkStatus: {},

    // Filters
    catFilter: '',
    statusFilter: '',
    polTypeFilter: '',
    polFwFilter: new Set(),
    searchQuery: '',

    // UI
    currentPage: 'home',
    assessmentStep: 1,
    sidebarOpen: false,
    navOpen: false,

    // Auth (session-only)
    authIsConnected: false,
    authAccount: null,
    authTenantId: null,

    // Deployment (session-only)
    deploymentStatus: {},
    deploymentProgress: null,

    // Deployment history (persisted)
    deploymentHistory: [],

    // Scan scheduling (persisted)
    scanScheduleInterval: null,
  };

  function get(key) {
    return state[key];
  }

  function set(key, value) {
    state[key] = value;
    notify(key);
    saveToStorage();
  }

  function toggleInSet(key, value) {
    const s = state[key];
    if (s.has(value)) s.delete(value);
    else s.add(value);
    notify(key);
    saveToStorage();
  }

  function on(key, fn) {
    if (!listeners.has(key)) listeners.set(key, []);
    listeners.get(key).push(fn);
  }

  function notify(key) {
    const fns = listeners.get(key) || [];
    fns.forEach(fn => fn(state[key]));
    // Also notify wildcard listeners
    const wild = listeners.get('*') || [];
    wild.forEach(fn => fn(key, state[key]));
  }

  function saveToStorage() {
    try {
      const toSave = {
        selectedFrameworks: [...state.selectedFrameworks],
        checkStatus: state.checkStatus,
        assessmentStep: state.assessmentStep,
        selectedPolicies: [...state.selectedPolicies],
        deploymentHistory: state.deploymentHistory.slice(0, 200),
        scanScheduleInterval: state.scanScheduleInterval,
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
    } catch (e) { /* storage full or unavailable */ }
  }

  function loadFromStorage() {
    try {
      const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
      if (!saved) return;
      if (saved.selectedFrameworks) state.selectedFrameworks = new Set(saved.selectedFrameworks);
      if (saved.checkStatus) state.checkStatus = saved.checkStatus;
      if (saved.assessmentStep) state.assessmentStep = saved.assessmentStep;
      if (saved.selectedPolicies) state.selectedPolicies = new Set(saved.selectedPolicies);
      if (saved.deploymentHistory) state.deploymentHistory = saved.deploymentHistory;
      if (saved.scanScheduleInterval) state.scanScheduleInterval = saved.scanScheduleInterval;
    } catch (e) { /* corrupt data */ }
  }

  function resetAssessment() {
    state.selectedFrameworks = new Set();
    state.checkStatus = {};
    state.assessmentStep = 1;
    state.selectedPolicies = new Set();
    saveToStorage();
    notify('selectedFrameworks');
    notify('checkStatus');
    notify('assessmentStep');
  }

  // Computed
  function getRequiredChecks() {
    if (state.selectedFrameworks.size === 0) return [];
    return state.checks.filter(c => c.fws.some(f => state.selectedFrameworks.has(f)));
  }

  function getCheckFwsInScope(check) {
    return check.fws.filter(f => state.selectedFrameworks.has(f));
  }

  function getScoreStats() {
    const required = getRequiredChecks();
    const total = required.length;
    const done = required.filter(c => state.checkStatus[c.id] === 'done').length;
    const gap = required.filter(c => state.checkStatus[c.id] === 'gap').length;
    const unrev = total - done - gap;
    const score = total > 0 ? Math.round(done / total * 100) : 0;
    return { total, done, gap, unrev, score };
  }

  function getFrameworkCoverage() {
    return [...state.selectedFrameworks].map(fw => {
      const fwChecks = state.checks.filter(c => c.fws.includes(fw));
      const fwDone = fwChecks.filter(c => state.checkStatus[c.id] === 'done').length;
      const pct = fwChecks.length > 0 ? Math.round(fwDone / fwChecks.length * 100) : 0;
      return { fw, done: fwDone, total: fwChecks.length, pct };
    }).sort((a, b) => b.pct - a.pct);
  }

  function getGaps() {
    return getRequiredChecks()
      .filter(c => state.checkStatus[c.id] === 'gap')
      .map(c => {
        const impact = c.fws.filter(f => state.selectedFrameworks.has(f)).length;
        const tier = c.level === 'L1' && impact >= 4 ? 'critical' : impact >= 6 || c.level === 'L1' ? 'high' : 'std';
        return { ...c, impact, tier };
      })
      .sort((a, b) => b.impact - a.impact);
  }

  // Deployment history
  function addDeploymentRecord(record) {
    state.deploymentHistory.unshift({
      policyId: record.policyId,
      timestamp: Date.now(),
      status: record.status,
      configUsed: record.configUsed || null,
      type: record.type || '',
      detail: record.detail || '',
    });
    if (state.deploymentHistory.length > 200) {
      state.deploymentHistory = state.deploymentHistory.slice(0, 200);
    }
    saveToStorage();
    notify('deploymentHistory');
  }

  function getDeploymentHistory(policyId) {
    if (!policyId) return state.deploymentHistory;
    return state.deploymentHistory.filter(function (h) { return h.policyId === policyId; });
  }

  function exportDeploymentLog() {
    return JSON.stringify({
      _meta: { type: 'M365-Deployment-Log', exportDate: new Date().toISOString() },
      entries: state.deploymentHistory,
    }, null, 2);
  }

  // Initialize
  loadFromStorage();

  return {
    get, set, toggleInSet, on, notify,
    resetAssessment, getRequiredChecks, getCheckFwsInScope,
    getScoreStats, getFrameworkCoverage, getGaps,
    addDeploymentRecord, getDeploymentHistory, exportDeploymentLog,
    state,
  };
})();
