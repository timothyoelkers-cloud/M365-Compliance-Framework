/* ═══════════════════════════════════════════
   SCAN REPORT — Generates a printable, customer-deliverable HTML
   report from the latest tenant scan. Opens in a new window so
   customers can save it as PDF via their browser.
═══════════════════════════════════════════ */
const ScanReport = (() => {

  function _esc(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function generate() {
    const scanData = (typeof TenantScanner !== 'undefined') ? TenantScanner.getScanResults() : null;
    if (!scanData) { showToast('No scan available — run one first'); return; }
    const analysis = (typeof Findings !== 'undefined') ? Findings.analyzeAll(scanData) : null;
    const alignment = (typeof FrameworkAlignment !== 'undefined') ? FrameworkAlignment.computeAlignment() : null;

    const acct = (typeof TenantAuth !== 'undefined') ? TenantAuth.getAccount() : null;
    const tenantId = scanData.tenantId || (acct && acct.tenantId);
    const scannedBy = scanData.scannedBy || (acct && acct.email);
    const scanTime = scanData.timestamp ? new Date(scanData.timestamp).toLocaleString() : '';
    const score = analysis ? analysis.score : null;
    const findings = analysis ? analysis.findings : [];
    const counts = analysis ? analysis.counts : {};

    const html = _renderHtml({ tenantId, scannedBy, scanTime, score, findings, counts, alignment, scanData });

    const win = window.open('', '_blank');
    if (!win) { showToast('Pop-up blocked — allow pop-ups to view the report'); return; }
    win.document.open();
    win.document.write(html);
    win.document.close();
  }

  function _renderHtml(d) {
    const today = new Date().toLocaleDateString();
    const sevColour = (sev) => ({ critical:'#dc2626', high:'#e84393', medium:'#d97706', low:'#2563eb', info:'#6e7681' }[sev] || '#6e7681');
    const scoreColour = d.score == null ? '#6e7681' : d.score >= 80 ? '#16a34a' : d.score >= 60 ? '#d97706' : '#dc2626';

    let body = '';

    // Cover
    body += '<section class="rpt-cover">';
    body += '<div class="rpt-brand">M365 Compliance Framework</div>';
    body += '<h1>Tenant Scan Report</h1>';
    body += '<dl class="rpt-meta">';
    body += '<dt>Tenant</dt><dd><code>' + _esc(d.tenantId || '—') + '</code></dd>';
    body += '<dt>Signed in as</dt><dd>' + _esc(d.scannedBy || '—') + '</dd>';
    body += '<dt>Scanned</dt><dd>' + _esc(d.scanTime) + '</dd>';
    body += '<dt>Report generated</dt><dd>' + _esc(today) + '</dd>';
    body += '</dl>';

    // Coverage score
    if (d.score != null) {
      body += '<div class="rpt-score" style="--score-c:' + scoreColour + '">';
      body += '<div class="rpt-score-num">' + d.score + '</div>';
      body += '<div class="rpt-score-label">/ 100 Coverage Score</div>';
      body += '</div>';
    }

    // Severity strip
    body += '<div class="rpt-sev-strip">';
    ['critical','high','medium','low','info'].forEach(sev => {
      const n = (d.counts && d.counts[sev]) || 0;
      if (n === 0) return;
      body += '<span class="rpt-pill" style="background:' + sevColour(sev) + '22;color:' + sevColour(sev) + '"><strong>' + n + '</strong> ' + sev + '</span>';
    });
    if ((d.findings || []).length === 0) body += '<span class="rpt-pill" style="background:#16a34a22;color:#16a34a">No findings</span>';
    body += '</div>';
    body += '</section>';

    // Executive summary section
    body += '<section><h2>Executive summary</h2>';
    body += '<p>This report captures the live state of the tenant\'s Microsoft 365 security configuration as of <strong>' + _esc(d.scanTime) + '</strong>. ';
    body += 'Findings are derived from analyzers across Conditional Access, Intune, Entra ID, SharePoint, Defender for Endpoint, Defender for Office 365 and Purview.';
    body += '</p>';
    if (d.findings.length > 0) {
      body += '<p>Of ' + d.findings.length + ' total findings, ' + (d.counts.critical || 0) + ' are <strong>Critical</strong> and ' + (d.counts.high || 0) + ' are <strong>High</strong> — these merit immediate attention.</p>';
    } else {
      body += '<p>All analyzers ran clean against this tenant.</p>';
    }
    body += '</section>';

    // Top recommended actions
    const recs = (d.findings || []).filter(f => f.severity !== 'info').slice(0, 10);
    if (recs.length > 0) {
      body += '<section class="rpt-recs"><h2>Top recommended actions</h2><ol>';
      recs.forEach(f => {
        body += '<li>';
        body += '<span class="rpt-pill" style="background:' + sevColour(f.severity) + '22;color:' + sevColour(f.severity) + '">' + f.severity + '</span> ';
        body += '<strong>' + _esc(f.title) + '</strong>';
        if (f.remediation) body += '<div class="rpt-rem">' + _esc(f.remediation) + '</div>';
        body += '</li>';
      });
      body += '</ol></section>';
    }

    // Framework alignment
    if (d.alignment && d.alignment.byFramework && d.alignment.byFramework.length > 0) {
      body += '<section><h2>Framework alignment</h2><p>For each framework, "configured" indicates at least one mapped policy was detected as configured in the tenant. "Manual" indicates a control that requires PowerShell verification.</p>';
      body += '<table><thead><tr><th>Framework</th><th>Configured</th><th>Manual</th><th>Missing</th><th>Score</th></tr></thead><tbody>';
      for (const fw of d.alignment.byFramework) {
        const sc = fw.score >= 80 ? '#16a34a' : fw.score >= 50 ? '#d97706' : '#dc2626';
        body += '<tr><td>' + _esc(fw.framework) + '</td><td>' + fw.configured + '</td><td>' + fw.manual + '</td><td>' + fw.missing + '</td>';
        body += '<td style="color:' + sc + ';font-weight:600">' + fw.score + '%</td></tr>';
      }
      body += '</tbody></table></section>';
    }

    // Full findings list
    if (d.findings.length > 0) {
      body += '<section><h2>All findings</h2>';
      const byWl = {};
      for (const f of d.findings) (byWl[f.workloadLabel] = byWl[f.workloadLabel] || []).push(f);
      for (const wl of Object.keys(byWl)) {
        body += '<h3>' + _esc(wl) + ' (' + byWl[wl].length + ')</h3>';
        for (const f of byWl[wl]) {
          body += '<div class="rpt-finding" style="border-left-color:' + sevColour(f.severity) + '">';
          body += '<div class="rpt-finding-head"><span class="rpt-pill" style="background:' + sevColour(f.severity) + '22;color:' + sevColour(f.severity) + '">' + f.severity + '</span> <strong>' + _esc(f.title) + '</strong></div>';
          if (f.description) body += '<p>' + _esc(f.description) + '</p>';
          if (f.remediation) body += '<p class="rpt-rem"><strong>Remediation:</strong> ' + _esc(f.remediation) + '</p>';
          if (f.refs && f.refs.length) body += '<p class="rpt-refs">Related: ' + f.refs.map(r => '<code>' + _esc(r) + '</code>').join(', ') + '</p>';
          body += '</div>';
        }
      }
      body += '</section>';
    }

    // Footer
    body += '<footer class="rpt-footer">Generated by M365 Compliance Framework · ' + _esc(today) + '</footer>';

    return [
      '<!doctype html>',
      '<html lang="en"><head><meta charset="utf-8">',
      '<title>Tenant Scan Report — ' + _esc(d.tenantId || '') + '</title>',
      '<style>',
      'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;color:#0d1117;line-height:1.6;max-width:900px;margin:30px auto;padding:0 30px;font-size:14px}',
      'h1{font-size:32px;margin:0 0 8px;color:#0d1117}',
      'h2{font-size:22px;margin:30px 0 12px;color:#0d1117;border-bottom:2px solid #e1e4e8;padding-bottom:6px}',
      'h3{font-size:16px;margin:20px 0 10px;color:#24292e}',
      'p{margin:8px 0}',
      'code{font-family:"JetBrains Mono",Consolas,monospace;font-size:.9em;background:#f6f8fa;padding:1px 6px;border-radius:3px}',
      'table{width:100%;border-collapse:collapse;margin:10px 0;font-size:.92em}',
      'th{text-align:left;padding:6px 10px;border-bottom:2px solid #d1d5da;color:#586069;font-weight:600}',
      'td{padding:6px 10px;border-bottom:1px solid #e1e4e8}',
      '.rpt-cover{padding:30px 0;border-bottom:3px solid #2563eb;margin-bottom:30px}',
      '.rpt-brand{font-size:12px;color:#586069;letter-spacing:1px;text-transform:uppercase;margin-bottom:10px}',
      '.rpt-meta{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;font-size:.92em;margin:18px 0}',
      '.rpt-meta dt{color:#586069;font-weight:600}',
      '.rpt-meta dd{margin:0;color:#0d1117}',
      '.rpt-score{text-align:center;margin:30px auto;padding:18px;width:200px;border:3px solid var(--score-c);border-radius:12px}',
      '.rpt-score-num{font-size:48px;font-weight:700;color:var(--score-c);line-height:1}',
      '.rpt-score-label{font-size:11px;color:#586069;text-transform:uppercase;letter-spacing:1px;margin-top:4px}',
      '.rpt-sev-strip{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}',
      '.rpt-pill{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}',
      '.rpt-recs ol{padding-left:24px}',
      '.rpt-recs li{margin-bottom:14px}',
      '.rpt-rem{font-size:.92em;color:#586069;margin-top:4px}',
      '.rpt-finding{border-left:3px solid #6e7681;background:#f6f8fa;padding:10px 14px;margin-bottom:8px;border-radius:0 6px 6px 0}',
      '.rpt-finding-head{font-size:.95em;margin-bottom:4px}',
      '.rpt-refs{font-size:.85em;color:#586069}',
      '.rpt-footer{margin-top:50px;padding-top:14px;border-top:1px solid #e1e4e8;text-align:center;font-size:11px;color:#586069}',
      '@media print{body{margin:0;padding:0 20mm;font-size:11pt;max-width:none}.rpt-cover,h2{page-break-after:avoid}.rpt-finding{page-break-inside:avoid}}',
      '</style>',
      '</head><body>',
      body,
      '<script>window.addEventListener("load", function() { setTimeout(function() { window.print(); }, 400); });</script>',
      '</body></html>',
    ].join('\n');
  }

  return { generate };
})();
