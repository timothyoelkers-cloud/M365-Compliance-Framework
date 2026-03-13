/* ═══════════════════════════════════════════
   PS VERIFY — PowerShell verification script
   generator for manual-only policies.
   Generates .ps1 scripts users can run locally
   and paste results back into the SPA.
═══════════════════════════════════════════ */
const PSVerify = (() => {

  // ─── Module groups ───
  const MODULE_GROUPS = {
    ExchangeOnline: {
      connect: 'Connect-ExchangeOnline',
      module: 'ExchangeOnlineManagement',
      policies: ['DEF01','DEF02','DEF03','DEF04','DEF05','DEF06','DEF07','DEF08',
                 'EXO01','EXO02','EXO03','EXO04','EXO05','EXO06','EXO07','EXO08','EXO09','EXO10'],
    },
    MicrosoftTeams: {
      connect: 'Connect-MicrosoftTeams',
      module: 'MicrosoftTeams',
      policies: ['TEA01','TEA02','TEA03','TEA04','TEA05','TEA06','TEA07','TEA08','TEA09','TEA10'],
    },
    IPPSSession: {
      connect: 'Connect-IPPSSession',
      module: 'ExchangeOnlineManagement',
      policies: ['PV01','PV02','PV03','PV04','PV05','PV06','PV07','PV08','PV09',
                 'PV11','PV12','PV13','PV15','PV16','PV17','PV18','PV19',
                 'PV20','PV21','PV22','PV23','PV24','PV25','PV26','PV27','PV28','PV29','PV30'],
    },
    PnPOnline: {
      connect: 'Connect-PnPOnline -Url "https://$tenantName-admin.sharepoint.com" -Interactive',
      module: 'PnP.PowerShell',
      policies: ['SPO02','SPO03','SPO04','SPO05','SPO06','SPO10','SPO11','SPO12','SPO14','SPO16','SPO17','SPO18','SPO20'],
    },
  };

  /**
   * Generate a consolidated PowerShell verification script.
   * @param {string[]} policyIds — subset of policies to verify (or all manual if empty)
   * @returns {string} PowerShell script content
   */
  function generateScript(policyIds) {
    var rules = (typeof PolicyMatcher !== 'undefined') ? PolicyMatcher.MATCH_RULES : {};

    // If no specific IDs, collect all manual policies
    if (!policyIds || policyIds.length === 0) {
      policyIds = Object.keys(rules).filter(function (id) {
        var r = rules[id];
        return r && r.status === 'manual';
      });
    }

    // Group requested policies by module
    var grouped = {};
    for (var g in MODULE_GROUPS) {
      var matching = policyIds.filter(function (id) {
        return MODULE_GROUPS[g].policies.indexOf(id) !== -1;
      });
      if (matching.length > 0) grouped[g] = matching;
    }

    var lines = [];
    lines.push('#═══════════════════════════════════════════════════════════');
    lines.push('# M365 Compliance Framework — Policy Verification Script');
    lines.push('# Generated: ' + new Date().toISOString());
    lines.push('# Policies: ' + policyIds.length);
    lines.push('#═══════════════════════════════════════════════════════════');
    lines.push('');
    lines.push('$results = @{}');
    lines.push('');

    for (var group in grouped) {
      var info = MODULE_GROUPS[group];
      var ids = grouped[group];

      lines.push('#───────────────────────────────────────────────────────────');
      lines.push('# Module: ' + info.module);
      lines.push('#───────────────────────────────────────────────────────────');
      lines.push('try {');
      if (group === 'PnPOnline') {
        lines.push('  $tenantName = Read-Host "Enter your SharePoint tenant name (e.g. contoso)"');
      }
      lines.push('  ' + info.connect);
      lines.push('  Write-Host "[OK] Connected to ' + group + '" -ForegroundColor Green');
      lines.push('} catch {');
      lines.push('  Write-Host "[FAIL] Could not connect to ' + group + ': $_" -ForegroundColor Red');

      // Mark all as error if connect fails
      for (var e = 0; e < ids.length; e++) {
        lines.push('  $results["' + ids[e] + '"] = @{ status = "error"; detail = "Connection failed: $_" }');
      }
      lines.push('  # Skip to next module');
      lines.push('}');
      lines.push('');

      // Individual policy checks
      for (var p = 0; p < ids.length; p++) {
        var id = ids[p];
        var rule = rules[id];
        var cmd = (rule && rule.verifyCommand) ? rule.verifyCommand : '';

        // Extract just the check command (after Connect-*)
        var checkCmd = cmd;
        var semiIdx = cmd.indexOf(';');
        if (semiIdx !== -1) checkCmd = cmd.substring(semiIdx + 1).trim();

        lines.push('# Policy: ' + id);
        lines.push('try {');
        lines.push('  $output = ' + (checkCmd || 'Write-Output "(no verify command)"'));
        lines.push('  $results["' + id + '"] = @{ status = "checked"; detail = ($output | Out-String).Trim() }');
        lines.push('} catch {');
        lines.push('  $results["' + id + '"] = @{ status = "error"; detail = $_.Exception.Message }');
        lines.push('}');
        lines.push('');
      }
    }

    // Output
    lines.push('#───────────────────────────────────────────────────────────');
    lines.push('# Export results as JSON');
    lines.push('#───────────────────────────────────────────────────────────');
    lines.push('$jsonResults = @{}');
    lines.push('foreach ($key in $results.Keys) {');
    lines.push('  $jsonResults[$key] = @{ status = $results[$key].status; detail = $results[$key].detail }');
    lines.push('}');
    lines.push('$json = $jsonResults | ConvertTo-Json -Depth 3');
    lines.push('$json | Out-File -FilePath "./M365-Verification-Results.json" -Encoding UTF8');
    lines.push('Write-Host ""');
    lines.push('Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan');
    lines.push('Write-Host " Results saved to M365-Verification-Results.json" -ForegroundColor Cyan');
    lines.push('Write-Host " Copy the JSON below and paste it back into the SPA:" -ForegroundColor Cyan');
    lines.push('Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan');
    lines.push('Write-Host $json');

    return lines.join('\n');
  }

  /**
   * Parse JSON results pasted back from PowerShell script.
   * @param {string} jsonText — raw JSON string
   * @returns {Object|null} parsed { policyId: { status, detail } }
   */
  function parseResults(jsonText) {
    try {
      var data = JSON.parse(jsonText);
      if (!data || typeof data !== 'object') return null;
      return data;
    } catch (e) {
      return null;
    }
  }

  /**
   * Merge parsed PS results into AppState.tenantScanResults.
   * @param {Object} parsed — { policyId: { status, detail } }
   * @returns {number} count of policies updated
   */
  function mergeResults(parsed) {
    if (!parsed) return 0;
    var results = AppState.get('tenantScanResults') || {};
    var count = 0;
    for (var id in parsed) {
      var entry = parsed[id];
      var status = entry.status === 'checked' ? 'configured' : (entry.status || 'error');
      // If detail contains indicators of failure, mark as missing
      if (status === 'configured') {
        var detail = (entry.detail || '').toLowerCase();
        if (detail.indexOf('not found') !== -1 || detail.indexOf('no results') !== -1 || detail.length === 0) {
          status = 'missing';
        }
      }
      results[id] = {
        status: status,
        confidence: 'medium',
        matchedItem: null,
        detail: entry.detail || '',
        source: 'powershell',
      };
      count++;
    }
    AppState.set('tenantScanResults', results);
    return count;
  }

  // ─── Modals ───

  function showGenerateModal() {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var script = generateScript([]);

    var html = '<div class="modal-header">';
    html += '<h3>PowerShell Verification Script</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';
    html += '<p style="font-size:.74rem;color:var(--ink2);margin-bottom:12px">Run this script in PowerShell to verify policies that cannot be checked via Graph API. Copy the JSON output and use "Import Results" to merge findings.</p>';
    html += '<div style="max-height:400px;overflow:auto">';
    html += '<pre class="ps-cmd" style="white-space:pre-wrap;cursor:pointer;font-size:.58rem" onclick="navigator.clipboard.writeText(this.textContent);showToast(\'Copied to clipboard\')" title="Click to copy">' + escHtml(script) + '</pre>';
    html += '</div>';
    html += '<div class="config-actions" style="margin-top:12px">';
    html += '<button class="btn btn-primary" onclick="PSVerify.downloadScript()">Download .ps1</button>';
    html += '<button class="btn" onclick="navigator.clipboard.writeText(document.querySelector(\'.ps-cmd\').textContent);showToast(\'Copied\')">Copy to Clipboard</button>';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '</div></div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  function downloadScript() {
    var script = generateScript([]);
    var blob = new Blob([script], { type: 'text/plain' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'M365-Verify-' + new Date().toISOString().slice(0, 10) + '.ps1';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Script downloaded');
  }

  function showImportModal() {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var html = '<div class="modal-header">';
    html += '<h3>Import PowerShell Results</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';
    html += '<p style="font-size:.74rem;color:var(--ink2);margin-bottom:12px">Paste the JSON output from the verification script, or upload the results file.</p>';
    html += '<textarea id="ps-results-input" style="width:100%;height:200px;font-family:\'JetBrains Mono\',monospace;font-size:.6rem;background:var(--surface2);color:var(--ink1);border:1px solid var(--border);border-radius:4px;padding:8px;resize:vertical" placeholder="Paste JSON here..."></textarea>';
    html += '<div style="margin-top:8px"><input type="file" accept=".json" onchange="PSVerify.handleFileImport(this)" style="font-size:.68rem"></div>';
    html += '<div class="config-actions" style="margin-top:12px">';
    html += '<button class="btn btn-primary" onclick="PSVerify.importFromTextarea()">Import Results</button>';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '</div></div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  function importFromTextarea() {
    var textarea = document.getElementById('ps-results-input');
    if (!textarea || !textarea.value.trim()) {
      showToast('No data to import');
      return;
    }
    var parsed = parseResults(textarea.value.trim());
    if (!parsed) {
      showToast('Invalid JSON format');
      return;
    }
    var count = mergeResults(parsed);
    document.getElementById('modal-overlay').classList.remove('open');
    showToast('Imported results for ' + count + ' policies');
  }

  function handleFileImport(input) {
    var file = input.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function (ev) {
      var parsed = parseResults(ev.target.result);
      if (!parsed) {
        showToast('Invalid JSON file');
        return;
      }
      var count = mergeResults(parsed);
      document.getElementById('modal-overlay').classList.remove('open');
      showToast('Imported results for ' + count + ' policies');
    };
    reader.readAsText(file);
  }

  return {
    generateScript: generateScript,
    parseResults: parseResults,
    mergeResults: mergeResults,
    showGenerateModal: showGenerateModal,
    showImportModal: showImportModal,
    downloadScript: downloadScript,
    importFromTextarea: importFromTextarea,
    handleFileImport: handleFileImport,
  };
})();
