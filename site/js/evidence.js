/* ═══════════════════════════════════════════
   EVIDENCE COLLECTOR — Generates downloadable
   ZIP evidence packages with scan results,
   match results, assessment state, and reports.
═══════════════════════════════════════════ */
const EvidenceCollector = (() => {

  async function collectEvidence() {
    if (typeof JSZip === 'undefined') {
      showToast('JSZip library not loaded');
      return;
    }

    var zip = new JSZip();
    var timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    var account = (typeof TenantAuth !== 'undefined' && TenantAuth.getAccount) ? TenantAuth.getAccount() : null;
    var tenantId = AppState.get('authTenantId') || 'unknown';

    showToast('Collecting evidence...');

    // 1. Summary JSON
    var summary = {
      _meta: { type: 'M365-Evidence-Package', version: '1.0', exportDate: new Date().toISOString() },
      tenant: account ? { tenantId: account.tenantId || tenantId, name: account.name || '', username: account.username || '' } : null,
      assessment: {
        score: AppState.getScoreStats(),
        frameworkCoverage: AppState.getFrameworkCoverage(),
        gapCount: AppState.getGaps().length,
        selectedFrameworks: [...AppState.get('selectedFrameworks')],
      },
    };

    // Add scan summary if available
    var scanResults = AppState.get('tenantScanResults');
    if (scanResults) {
      var scanSummary = { configured: 0, missing: 0, manual: 0, error: 0, total: 0 };
      for (var id in scanResults) {
        scanSummary.total++;
        var s = scanResults[id].status;
        if (scanSummary[s] !== undefined) scanSummary[s]++;
      }
      summary.scanSummary = scanSummary;
    }

    zip.file('summary.json', JSON.stringify(summary, null, 2));

    // 2. Scan results per endpoint
    if (typeof TenantScanner !== 'undefined' && TenantScanner.getScanCache) {
      var scanCache = TenantScanner.getScanCache();
      if (scanCache && scanCache.data) {
        var scanFolder = zip.folder('scan-results');

        for (var key in scanCache.data) {
          if (scanCache.data[key]) {
            scanFolder.file(key + '.json', JSON.stringify(scanCache.data[key], null, 2));
          }
        }

        scanFolder.file('_metadata.json', JSON.stringify({
          timestamp: scanCache.timestamp || Date.now(),
          tenantId: scanCache.tenantId || tenantId,
          scanTime: scanCache.scanTime || 0,
          endpointCount: scanCache.endpointCount || 0,
          successCount: scanCache.successCount || 0,
          errors: scanCache.errors || [],
        }, null, 2));
      }
    }

    // 3. Match results
    if (scanResults) {
      zip.file('match-results.json', JSON.stringify(scanResults, null, 2));
    }

    // 4. Assessment state
    zip.file('assessment.json', JSON.stringify({
      selectedFrameworks: [...AppState.get('selectedFrameworks')],
      checkStatus: AppState.get('checkStatus'),
      assessmentStep: AppState.get('assessmentStep'),
    }, null, 2));

    // 5. Gap register
    var gaps = AppState.getGaps();
    if (gaps.length > 0) {
      zip.file('gap-register.json', JSON.stringify(gaps.map(function (g) {
        return { id: g.id, name: g.name, category: g.cat, level: g.level, impact: g.impact, tier: g.tier };
      }), null, 2));
    }

    // 6. Framework coverage
    var coverage = AppState.getFrameworkCoverage();
    if (coverage.length > 0) {
      zip.file('framework-coverage.json', JSON.stringify(coverage, null, 2));
    }

    // 7. Deployment history
    var history = AppState.getDeploymentHistory();
    if (history.length > 0) {
      zip.file('deployment-history.json', JSON.stringify(history, null, 2));
    }

    // 8. Scan history from IndexedDB
    if (typeof ScanHistory !== 'undefined') {
      try {
        var scans = await ScanHistory.getScans(tenantId, 10);
        if (scans.length > 0) {
          zip.file('scan-history.json', JSON.stringify(scans.map(function (s) {
            return {
              id: s.id,
              timestamp: s.timestamp,
              score: s.score,
              summary: s.summary,
              scannedBy: s.scannedBy,
              endpointCount: s.endpointCount,
            };
          }), null, 2));
        }
      } catch (e) {
        console.warn('[Evidence] Could not read scan history:', e);
      }
    }

    // 9. Report HTML (if generated)
    var reportCanvas = document.getElementById('report-canvas');
    if (reportCanvas && reportCanvas.innerHTML.trim().length > 50) {
      zip.file('report.html', buildStandaloneHtml(reportCanvas.innerHTML));
    }

    // Generate and download ZIP
    try {
      var blob = await zip.generateAsync({
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: 6 },
      });

      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = 'M365-Evidence-' + timestamp + '.zip';
      a.click();
      URL.revokeObjectURL(url);

      showToast('Evidence package exported');

      // Save evidence record to IndexedDB
      if (typeof ScanHistory !== 'undefined') {
        ScanHistory.saveEvidence(tenantId, 'export', 'Evidence package', {
          exportDate: new Date().toISOString(),
          fileCount: Object.keys(zip.files).length,
          assessmentScore: summary.assessment.score.score,
        }).catch(function () {});
      }
    } catch (e) {
      console.error('[Evidence] ZIP generation failed:', e);
      showToast('Evidence export failed: ' + e.message);
    }
  }

  function buildStandaloneHtml(content) {
    return '<!DOCTYPE html>\n' +
      '<html lang="en">\n' +
      '<head>\n' +
      '<meta charset="UTF-8">\n' +
      '<title>M365 Compliance Report</title>\n' +
      '<style>\n' +
      '  body { font-family: system-ui, sans-serif; margin: 20px; color: #333; }\n' +
      '  table { border-collapse: collapse; width: 100%; }\n' +
      '  th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: .8rem; }\n' +
      '  th { background: #f8f9fa; }\n' +
      '  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .7rem; }\n' +
      '</style>\n' +
      '</head>\n' +
      '<body>\n' +
      content + '\n' +
      '</body>\n' +
      '</html>';
  }

  function renderExportButton() {
    return '<button class="btn" onclick="EvidenceCollector.collectEvidence()" style="font-size:.68rem">' +
      '<span style="margin-right:4px">&#128230;</span>Export Evidence Package</button>';
  }

  return {
    collectEvidence: collectEvidence,
    renderExportButton: renderExportButton,
  };
})();
