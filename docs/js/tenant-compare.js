/* ═══════════════════════════════════════════
   TENANT COMPARE — Side-by-side diff of two tenant scans.
   Useful for "compare prod to staging" or "match customer to baseline".
═══════════════════════════════════════════ */
const TenantCompare = (() => {

  function _esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /**
   * Open a chooser modal listing the user's connected tenants.
   * The user picks two; the module fetches their latest scans from
   * IndexedDB and renders a side-by-side comparison.
   */
  async function open() {
    if (typeof TenantManager === 'undefined') { showToast('TenantManager not loaded'); return; }
    const tenants = TenantManager.getTenants ? TenantManager.getTenants() : [];
    if (tenants.length < 2) {
      showToast('Connect at least two tenants to compare');
      return;
    }
    _showChooser(tenants);
  }

  function _showChooser(tenants) {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    let html = '<div class="modal-header"><h3>Compare Tenants</h3>' +
      '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button></div>';
    html += '<div class="modal-body">';
    html += '<p style="font-size:.74rem;color:var(--ink2);line-height:1.6;margin-bottom:14px">Pick two tenants to compare. Each must have a saved scan in history.</p>';

    const optionsHtml = tenants.map(t =>
      '<option value="' + _esc(t.id) + '">' + _esc(t.displayName || t.id) + '</option>'
    ).join('');

    html += '<div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-bottom:14px">';
    html += '<div style="flex:1;min-width:200px"><label style="font-size:.62rem;color:var(--ink3);text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:4px">Tenant A</label>' +
      '<select id="tcompare-a" style="width:100%;padding:6px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--ink);font-size:.7rem">' +
      optionsHtml + '</select></div>';
    html += '<div style="flex:1;min-width:200px"><label style="font-size:.62rem;color:var(--ink3);text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:4px">Tenant B</label>' +
      '<select id="tcompare-b" style="width:100%;padding:6px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--ink);font-size:.7rem">' +
      optionsHtml + '</select></div>';
    html += '<button class="btn btn-primary btn-sm" onclick="TenantCompare.run()">Compare</button>';
    html += '</div>';
    html += '<div id="tcompare-result"></div>';
    html += '</div>';
    modal.innerHTML = html;
    overlay.classList.add('open');
    // Default selection: first tenant for A, second for B
    if (tenants.length >= 2) {
      document.getElementById('tcompare-a').value = tenants[0].id;
      document.getElementById('tcompare-b').value = tenants[1].id;
    }
  }

  async function run() {
    const aId = document.getElementById('tcompare-a').value;
    const bId = document.getElementById('tcompare-b').value;
    const result = document.getElementById('tcompare-result');
    if (!result) return;
    if (aId === bId) { result.innerHTML = '<div style="color:var(--amber);font-size:.7rem;margin-top:10px">Pick two different tenants.</div>'; return; }

    result.innerHTML = '<div style="color:var(--ink3);font-size:.7rem">Loading scans…</div>';

    if (typeof ScanHistory === 'undefined' || !ScanHistory.getScans) { result.innerHTML = '<div style="color:var(--red);font-size:.7rem">ScanHistory unavailable</div>'; return; }
    const [aScans, bScans] = await Promise.all([ScanHistory.getScans(aId, 1), ScanHistory.getScans(bId, 1)]);
    const a = aScans && aScans[0];
    const b = bScans && bScans[0];

    if (!a || !b) {
      result.innerHTML = '<div style="color:var(--amber);font-size:.7rem;margin-top:10px">' +
        (a ? '' : 'Tenant A has no scan history. ') +
        (b ? '' : 'Tenant B has no scan history. ') +
        'Run a scan from each tenant first.</div>';
      return;
    }

    result.innerHTML = _renderComparison(a, b);
  }

  function _renderComparison(a, b) {
    const aName = _tenantName(a.tenantId);
    const bName = _tenantName(b.tenantId);
    const aScore = a.score || 0;
    const bScore = b.score || 0;
    const aSum = a.summary || {};
    const bSum = b.summary || {};

    function col(n, total) { return total ? Math.round((n / total) * 100) : 0; }
    function deltaText(av, bv) {
      const d = av - bv;
      if (d === 0) return '';
      const colour = d > 0 ? 'var(--green)' : 'var(--red)';
      return ' <span style="color:' + colour + ';font-size:.6rem">(' + (d > 0 ? '+' : '') + d + ')</span>';
    }

    let html = '<div style="margin-top:14px">';
    html += '<table style="width:100%;border-collapse:collapse;font-size:.66rem">';
    html += '<thead><tr><th style="padding:6px;text-align:left">Metric</th><th style="padding:6px;text-align:right">' + _esc(aName) + '</th><th style="padding:6px;text-align:right">' + _esc(bName) + '</th><th style="padding:6px;text-align:right">Δ A − B</th></tr></thead><tbody>';
    html += _row('Coverage Score (/100)', aScore, bScore, true);
    html += _row('Critical findings', aSum.critical || 0, bSum.critical || 0, false);
    html += _row('High findings', aSum.high || 0, bSum.high || 0, false);
    html += _row('Medium findings', aSum.medium || 0, bSum.medium || 0, false);
    html += _row('CA policies', _len(a, 'conditionalAccess'), _len(b, 'conditionalAccess'), true);
    html += _row('Compliance policies', _len(a, 'compliancePolicies'), _len(b, 'compliancePolicies'), true);
    html += _row('Endpoint Security policies', _len(a, 'configurationPolicies'), _len(b, 'configurationPolicies'), true);
    html += _row('Sensitivity labels', _len(a, 'sensitivityLabels'), _len(b, 'sensitivityLabels'), true);
    html += _row('DLP policies', _len(a, 'dlpPolicies'), _len(b, 'dlpPolicies'), true);
    html += '</tbody></table>';

    // CA policies present in A vs B (by name)
    const aCANames = new Set((a.data && a.data.conditionalAccess || []).map(p => p.displayName));
    const bCANames = new Set((b.data && b.data.conditionalAccess || []).map(p => p.displayName));
    const onlyInA = Array.from(aCANames).filter(n => !bCANames.has(n));
    const onlyInB = Array.from(bCANames).filter(n => !aCANames.has(n));
    if (onlyInA.length > 0 || onlyInB.length > 0) {
      html += '<div style="margin-top:18px;display:grid;grid-template-columns:1fr 1fr;gap:16px;font-size:.66rem">';
      html += '<div><strong style="font-size:.7rem;color:var(--ink2)">CA policies only in ' + _esc(aName) + ' (' + onlyInA.length + ')</strong>';
      html += '<ul style="margin:6px 0;padding-left:18px;color:var(--ink3);line-height:1.6">';
      onlyInA.slice(0, 20).forEach(n => { html += '<li>' + _esc(n) + '</li>'; });
      if (onlyInA.length > 20) html += '<li style="color:var(--ink4)">+' + (onlyInA.length - 20) + ' more</li>';
      html += '</ul></div>';
      html += '<div><strong style="font-size:.7rem;color:var(--ink2)">CA policies only in ' + _esc(bName) + ' (' + onlyInB.length + ')</strong>';
      html += '<ul style="margin:6px 0;padding-left:18px;color:var(--ink3);line-height:1.6">';
      onlyInB.slice(0, 20).forEach(n => { html += '<li>' + _esc(n) + '</li>'; });
      if (onlyInB.length > 20) html += '<li style="color:var(--ink4)">+' + (onlyInB.length - 20) + ' more</li>';
      html += '</ul></div>';
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  function _row(label, a, b, higherIsBetter) {
    const d = a - b;
    let colour = 'var(--ink3)';
    if (d !== 0) {
      const aBetter = higherIsBetter ? d > 0 : d < 0;
      colour = aBetter ? 'var(--green)' : 'var(--red)';
    }
    const dStr = d === 0 ? '0' : (d > 0 ? '+' : '') + d;
    return '<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px;color:var(--ink2)">' + label + '</td>' +
      '<td style="padding:6px;text-align:right;color:var(--ink)">' + a + '</td>' +
      '<td style="padding:6px;text-align:right;color:var(--ink)">' + b + '</td>' +
      '<td style="padding:6px;text-align:right;color:' + colour + ';font-weight:600">' + dStr + '</td></tr>';
  }

  function _len(scan, key) {
    const v = scan && scan.data && scan.data[key];
    return Array.isArray(v) ? v.length : 0;
  }

  function _tenantName(tid) {
    if (typeof TenantManager === 'undefined') return tid;
    const tenants = TenantManager.getTenants ? TenantManager.getTenants() : [];
    const t = tenants.find(x => x.id === tid);
    return (t && t.displayName) || tid;
  }

  return { open, run };
})();
