/* ═══════════════════════════════════════════
   COMPLIANCE ATTESTATION — Generates a formal customer-deliverable
   document asserting alignment with a chosen framework as of the
   scan timestamp. Different from the scan report: this is for audit
   submission rather than internal review.
═══════════════════════════════════════════ */
const ComplianceAttestation = (() => {

  function _esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  /** Generate a printable attestation for the given framework. */
  function generate(frameworkName) {
    if (!frameworkName) {
      // No framework picked — show a chooser instead.
      _showChooser();
      return;
    }
    const scanData = (typeof TenantScanner !== 'undefined') ? TenantScanner.getScanResults() : null;
    if (!scanData) { showToast('Run a tenant scan first'); return; }

    const alignment = (typeof FrameworkAlignment !== 'undefined') ? FrameworkAlignment.computeAlignment() : null;
    if (!alignment) { showToast('Framework alignment data not available'); return; }
    const frameworkData = (alignment.byFramework || []).find(f => f.framework === frameworkName);
    if (!frameworkData) { showToast('Framework not found in alignment data'); return; }

    const acct = (typeof TenantAuth !== 'undefined') ? TenantAuth.getAccount() : null;
    const tenantId = scanData.tenantId || (acct && acct.tenantId);
    const tenantName = (acct && acct.name) || tenantId || '—';
    const scannedBy = scanData.scannedBy || (acct && acct.email) || '—';
    const scanTime = scanData.timestamp ? new Date(scanData.timestamp).toLocaleString() : '';
    const today = new Date().toLocaleDateString();

    const html = _renderHtml({
      tenantId, tenantName, scannedBy, scanTime, today,
      framework: frameworkData,
      orgName: (acct && acct.name) || '',
    });

    const win = window.open('', '_blank');
    if (!win) { showToast('Pop-up blocked — allow pop-ups to view the attestation'); return; }
    win.document.open();
    win.document.write(html);
    win.document.close();
  }

  function _showChooser() {
    const alignment = (typeof FrameworkAlignment !== 'undefined') ? FrameworkAlignment.computeAlignment() : null;
    if (!alignment || !alignment.byFramework || alignment.byFramework.length === 0) {
      showToast('Run a tenant scan first to generate an attestation');
      return;
    }
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById('modal');
    if (!overlay || !modal) { showToast('Modal unavailable'); return; }

    let html = '<div class="modal-header"><h3>Generate Compliance Attestation</h3>' +
      '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button></div>';
    html += '<div class="modal-body">';
    html += '<p style="font-size:.78rem;color:var(--ink2);line-height:1.6;margin-bottom:12px">An attestation is a formal customer-deliverable document declaring the tenant\'s alignment with a specific framework as of the most recent scan. Pick the framework to attest against.</p>';
    html += '<div style="max-height:60vh;overflow:auto">';
    html += '<table style="width:100%;border-collapse:collapse;font-size:.7rem">';
    html += '<thead><tr style="text-align:left;color:var(--ink3);border-bottom:1px solid var(--border)"><th style="padding:6px">Framework</th><th style="padding:6px">Coverage</th><th style="padding:6px">Configured</th><th style="padding:6px"></th></tr></thead><tbody>';
    for (const f of alignment.byFramework) {
      const colour = f.score >= 80 ? 'var(--green)' : f.score >= 50 ? 'var(--amber)' : 'var(--red)';
      html += '<tr style="border-bottom:1px solid var(--border)">';
      html += '<td style="padding:6px;color:var(--ink)">' + _esc(f.framework) + '</td>';
      html += '<td style="padding:6px;color:' + colour + ';font-weight:600">' + f.score + '%</td>';
      html += '<td style="padding:6px;color:var(--ink3)">' + f.configured + ' / ' + f.total + '</td>';
      html += '<td style="padding:6px"><button class="btn btn-sm btn-primary" onclick="ComplianceAttestation.generate(\'' + _esc(f.framework).replace(/\\'/g, '\\\\\'') + '\');document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Generate</button></td>';
      html += '</tr>';
    }
    html += '</tbody></table></div></div>';
    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  function _renderHtml(d) {
    const f = d.framework;
    const overall = f.score;
    const sc = overall >= 80 ? '#16a34a' : overall >= 50 ? '#d97706' : '#dc2626';

    let body = '';
    body += '<header class="att-header">';
    body += '<div class="att-brand">M365 Compliance Framework</div>';
    body += '<div class="att-doc-id">Document ID: ATT-' + Date.now().toString(36).toUpperCase() + '</div>';
    body += '</header>';

    body += '<section class="att-cover">';
    body += '<h1>Compliance Attestation</h1>';
    body += '<h2>' + _esc(f.framework) + '</h2>';
    body += '<div class="att-meta-block">';
    body += '<dl class="att-meta">';
    body += '<dt>Tenant identifier</dt><dd><code>' + _esc(d.tenantId) + '</code></dd>';
    body += '<dt>Organisation</dt><dd>' + _esc(d.tenantName || '—') + '</dd>';
    body += '<dt>Attesting individual</dt><dd>' + _esc(d.scannedBy) + '</dd>';
    body += '<dt>Scan basis date</dt><dd>' + _esc(d.scanTime) + '</dd>';
    body += '<dt>Attestation date</dt><dd>' + _esc(d.today) + '</dd>';
    body += '</dl>';
    body += '</div>';
    body += '</section>';

    body += '<section><h3>Statement of attestation</h3>';
    body += '<p>This document attests that, as of the scan basis date listed above, the Microsoft 365 tenant <code>' + _esc(d.tenantId) + '</code> demonstrates the configuration posture set out below in respect of the controls defined by <strong>' + _esc(f.framework) + '</strong>.</p>';
    body += '<p>This attestation is generated from automated detection of tenant configuration via Microsoft Graph and Microsoft Secure Score. It is a snapshot at a point in time and does not constitute a formal audit opinion. Where an entity requires audit-grade assurance, this document should be supplemented by an independent assessment.</p>';
    body += '</section>';

    body += '<section class="att-summary"><h3>Coverage summary</h3>';
    body += '<div class="att-score-block" style="--sc:' + sc + '">';
    body += '<div class="att-score-num">' + overall + '%</div>';
    body += '<div class="att-score-label">of mapped controls demonstrate configured policy alignment</div>';
    body += '</div>';
    body += '<table class="att-table">';
    body += '<thead><tr><th>Status</th><th style="text-align:right">Count</th><th style="text-align:right">% of total</th></tr></thead><tbody>';
    body += '<tr><td>Configured</td><td style="text-align:right">' + f.configured + '</td><td style="text-align:right">' + Math.round(f.configured / f.total * 100) + '%</td></tr>';
    body += '<tr><td>Manual verification required</td><td style="text-align:right">' + f.manual + '</td><td style="text-align:right">' + Math.round(f.manual / f.total * 100) + '%</td></tr>';
    body += '<tr><td>Missing or not detected</td><td style="text-align:right">' + f.missing + '</td><td style="text-align:right">' + Math.round(f.missing / f.total * 100) + '%</td></tr>';
    body += '<tr style="font-weight:600;background:#f9fafb"><td>Total mapped controls</td><td style="text-align:right">' + f.total + '</td><td style="text-align:right">100%</td></tr>';
    body += '</tbody></table>';
    body += '</section>';

    // Per-control table
    body += '<section><h3>Per-control status</h3>';
    body += '<p style="color:#586069;font-size:.92em">Each control listed below is mapped to one or more deployable policies in our catalogue. "Configured" indicates at least one mapped policy was detected as configured in the tenant.</p>';
    body += '<table class="att-table att-controls"><thead><tr><th>Control</th><th>Category</th><th>Status</th></tr></thead><tbody>';
    const sorted = (f.controls || []).slice().sort((a, b) => {
      const order = { missing: 0, manual: 1, unmapped: 2, configured: 3 };
      return (order[a.status] || 9) - (order[b.status] || 9) || a.id.localeCompare(b.id);
    });
    for (const c of sorted) {
      const sCol = { configured:'#16a34a', manual:'#d97706', missing:'#dc2626', unmapped:'#6b7280' }[c.status] || '#6b7280';
      body += '<tr><td><code>' + _esc(c.id) + '</code> ' + _esc(c.name || '') + '</td>' +
              '<td>' + _esc(c.cat || '') + '</td>' +
              '<td style="color:' + sCol + ';font-weight:600">' + _esc(c.status) + '</td></tr>';
    }
    body += '</tbody></table></section>';

    body += '<section class="att-disclaimer">';
    body += '<h3>Limitations and assumptions</h3>';
    body += '<ul>';
    body += '<li>The attestation reflects the tenant configuration retrievable via Microsoft Graph and Microsoft Secure Score at the scan basis date.</li>';
    body += '<li>Controls marked "manual verification required" indicate workload areas (Defender for O365, Exchange Online, Purview) where Microsoft does not expose state via Graph; their status would need to be confirmed by PowerShell or admin-portal review.</li>';
    body += '<li>This document does not constitute legal or audit certification. The attesting individual confirms that the underlying scan was performed against the named tenant.</li>';
    body += '<li>Policy detection is heuristic; an absence of a configured detection does not preclude an equivalent control implemented by other means.</li>';
    body += '</ul>';
    body += '</section>';

    body += '<section class="att-sig"><h3>Signature</h3>';
    body += '<div class="att-sig-block">';
    body += '<div class="att-sig-line"><span>Attesting individual</span><div class="att-sig-rule"></div></div>';
    body += '<div class="att-sig-line"><span>Title / role</span><div class="att-sig-rule"></div></div>';
    body += '<div class="att-sig-line"><span>Signature</span><div class="att-sig-rule"></div></div>';
    body += '<div class="att-sig-line"><span>Date</span><div class="att-sig-rule">' + _esc(d.today) + '</div></div>';
    body += '</div></section>';

    body += '<footer class="att-footer">M365 Compliance Framework · Attestation generated ' + _esc(d.today) + '</footer>';

    return [
      '<!doctype html>',
      '<html lang="en"><head><meta charset="utf-8">',
      '<title>Attestation — ' + _esc(f.framework) + ' — ' + _esc(d.tenantId) + '</title>',
      '<style>',
      'body{font-family:Georgia,"Times New Roman",serif;color:#0d1117;line-height:1.6;max-width:880px;margin:30px auto;padding:0 30px;font-size:13px}',
      'h1{font-size:32px;margin:8px 0 4px;color:#0d1117;font-weight:700}',
      'h2{font-size:20px;margin:0 0 14px;color:#374151;font-weight:500;font-style:italic}',
      'h3{font-size:16px;margin:24px 0 10px;color:#0d1117;border-bottom:1px solid #d1d5db;padding-bottom:4px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-weight:600}',
      'p{margin:8px 0}',
      'code{font-family:"JetBrains Mono",Consolas,monospace;font-size:.92em;background:#f6f8fa;padding:1px 5px;border-radius:3px}',
      '.att-header{display:flex;justify-content:space-between;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;border-bottom:2px solid #2563eb;padding-bottom:8px;margin-bottom:30px}',
      '.att-cover{padding:20px 0 20px;text-align:center;margin-bottom:30px}',
      '.att-meta-block{background:#f9fafb;padding:18px;border-radius:8px;margin:30px auto;max-width:520px;text-align:left}',
      '.att-meta{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;font-size:.92em;margin:0}',
      '.att-meta dt{color:#586069;font-weight:600}',
      '.att-meta dd{margin:0;color:#0d1117}',
      '.att-summary{margin:24px 0}',
      '.att-score-block{text-align:center;margin:20px auto;padding:18px;width:280px;border:3px solid var(--sc);border-radius:8px}',
      '.att-score-num{font-size:42px;font-weight:700;color:var(--sc);line-height:1;font-family:-apple-system,sans-serif}',
      '.att-score-label{font-size:11px;color:#586069;margin-top:6px;line-height:1.4}',
      '.att-table{width:100%;border-collapse:collapse;margin:14px 0;font-size:.9em;font-family:-apple-system,BlinkMacSystemFont,sans-serif}',
      '.att-table th{text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db;color:#586069;font-weight:600;font-size:.86em;text-transform:uppercase;letter-spacing:.5px}',
      '.att-table td{padding:8px 12px;border-bottom:1px solid #e5e7eb}',
      '.att-controls td{font-size:.92em}',
      '.att-disclaimer ul{padding-left:24px;font-size:.92em;color:#374151}',
      '.att-disclaimer li{margin-bottom:6px}',
      '.att-sig{margin-top:50px;page-break-inside:avoid}',
      '.att-sig-block{margin-top:18px}',
      '.att-sig-line{display:flex;align-items:flex-end;gap:18px;margin-bottom:24px}',
      '.att-sig-line span{width:160px;font-size:.86em;color:#586069;font-family:-apple-system,sans-serif}',
      '.att-sig-rule{flex:1;border-bottom:1px solid #6b7280;padding:0 6px 4px;min-height:28px;font-size:.92em}',
      '.att-footer{margin-top:50px;padding-top:14px;border-top:1px solid #e5e7eb;text-align:center;font-size:11px;color:#6b7280}',
      '@media print{body{margin:0;padding:0 20mm;font-size:11pt;max-width:none}h1,h3{page-break-after:avoid}.att-table tr{page-break-inside:avoid}}',
      '</style></head><body>',
      body,
      '<script>window.addEventListener("load", function() { setTimeout(function() { window.print(); }, 600); });</script>',
      '</body></html>',
    ].join('\n');
  }

  return { generate };
})();
