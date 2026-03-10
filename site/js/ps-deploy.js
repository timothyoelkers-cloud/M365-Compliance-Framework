/* ═══════════════════════════════════════════
   PS DEPLOY — Bulk PowerShell deployment script
   generator for missing policies. Generates
   New-[X]/Set-[X] cmdlets with rollback support.
═══════════════════════════════════════════ */
const PSDeploy = (() => {

  // Module groups (mirrors PSVerify)
  const MODULE_GROUPS = {
    ExchangeOnline: { module: 'ExchangeOnlineManagement', connect: 'Connect-ExchangeOnline', prefixes: ['DEF', 'EXO'] },
    MicrosoftTeams: { module: 'MicrosoftTeams', connect: 'Connect-MicrosoftTeams', prefixes: ['TEA'] },
    IPPSSession:    { module: 'ExchangeOnlineManagement', connect: 'Connect-IPPSSession', prefixes: ['PV'] },
    PnPOnline:      { module: 'PnP.PowerShell', connect: 'Connect-PnPOnline -Url "https://<tenant>-admin.sharepoint.com" -Interactive', prefixes: ['SPO'] },
  };

  // Cmdlet templates per policy type
  const DEPLOY_TEMPLATES = {
    // Defender for Office 365
    DEF01: { cmd: 'New-AntiPhishPolicy', params: { Name: 'CIS-AntiPhish', Enabled: '$true', PhishThresholdLevel: 3, EnableMailboxIntelligenceProtection: '$true', EnableSpoofIntelligence: '$true' }, undo: 'Remove-AntiPhishPolicy -Identity "CIS-AntiPhish" -Confirm:$false' },
    DEF02: { cmd: 'New-SafeLinksPolicy', params: { Name: 'CIS-SafeLinks', IsEnabled: '$true', ScanUrls: '$true', EnableForInternalSenders: '$true', DeliverMessageAfterScan: '$true' }, undo: 'Remove-SafeLinksPolicy -Identity "CIS-SafeLinks" -Confirm:$false' },
    DEF03: { cmd: 'New-SafeAttachmentPolicy', params: { Name: 'CIS-SafeAttach', Enable: '$true', Action: 'Block', ActionOnError: '$true' }, undo: 'Remove-SafeAttachmentPolicy -Identity "CIS-SafeAttach" -Confirm:$false' },
    DEF04: { cmd: 'Set-MalwareFilterPolicy', params: { Identity: 'Default', EnableFileFilter: '$true', ZapEnabled: '$true' }, undo: 'Set-MalwareFilterPolicy -Identity "Default" -EnableFileFilter $false' },
    DEF05: { cmd: 'Set-HostedContentFilterPolicy', params: { Identity: 'Default', MarkAsSpamBulkMail: 'On', SpamAction: 'MoveToJmf', HighConfidenceSpamAction: 'Quarantine' }, undo: 'Set-HostedContentFilterPolicy -Identity "Default" -MarkAsSpamBulkMail Off' },
    DEF06: { cmd: 'Set-HostedOutboundSpamFilterPolicy', params: { Identity: 'Default', AutoForwardingMode: 'Off', NotifyOutboundSpam: '$true' }, undo: 'Set-HostedOutboundSpamFilterPolicy -Identity "Default" -AutoForwardingMode Automatic' },
    DEF07: { cmd: 'Set-AtpPolicyForO365', params: { EnableATPForSPOTeamsODB: '$true', EnableSafeDocs: '$true' }, undo: 'Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $false' },
    DEF08: { cmd: 'Set-MalwareFilterPolicy', params: { Identity: 'Default', EnableFileFilter: '$true', FileTypes: '@("ace","apk","app","appx","ani","arj","bat","cab","cmd","com","deb","dex","dll","docm","elf","exe","hta","img","iso","jar","jnlp","kext","lha","lib","library","lnk","lzh","macho","msc","msi","msix","msp","mst","pif","ppa","ppam","reg","rev","scf","scr","sct","sys","uif","vb","vbe","vbs","vxd","wsc","wsf","wsh","xll","xz","z")' }, undo: '# Cannot undo — manually review file filter' },

    // Exchange Online
    EXO01: { cmd: 'Enable-DkimSigningConfig', params: { Identity: '<domain>', All: '$true' }, undo: 'Set-DkimSigningConfig -Identity "<domain>" -Enabled $false' },
    EXO03: { cmd: 'New-TransportRule', params: { Name: 'CIS-Block-AutoForward', Priority: 0, SentToScope: 'NotInOrganization', RejectMessageReasonText: 'Auto-forwarding disabled per CIS policy', FromScope: 'InOrganization', MessageTypeMatches: 'AutoForward' }, undo: 'Remove-TransportRule -Identity "CIS-Block-AutoForward" -Confirm:$false' },
    EXO04: { cmd: 'Set-AuthenticationPolicy', params: { Identity: 'Block Basic Auth', AllowBasicAuthActiveSync: '$false', AllowBasicAuthAutodiscover: '$false', AllowBasicAuthImap: '$false', AllowBasicAuthMapi: '$false', AllowBasicAuthOfflineAddressBook: '$false', AllowBasicAuthOutlookService: '$false', AllowBasicAuthPop: '$false', AllowBasicAuthReportingWebServices: '$false', AllowBasicAuthRest: '$false', AllowBasicAuthRpc: '$false', AllowBasicAuthSmtp: '$false', AllowBasicAuthWebServices: '$false', AllowBasicAuthPowershell: '$false' }, undo: '# Revert auth policy manually' },
    EXO07: { cmd: 'Set-SharingPolicy', params: { Identity: 'Default Sharing Policy', Enabled: '$false' }, undo: 'Set-SharingPolicy -Identity "Default Sharing Policy" -Enabled $true' },

    // Teams
    TEA01: { cmd: 'Set-CsTeamsMeetingPolicy', params: { Identity: 'Global', AllowAnonymousUsersToJoinMeeting: '$false' }, undo: 'Set-CsTeamsMeetingPolicy -Identity "Global" -AllowAnonymousUsersToJoinMeeting $true' },
    TEA02: { cmd: 'Set-CsTeamsMeetingPolicy', params: { Identity: 'Global', AutoAdmittedUsers: 'EveryoneInCompanyExcludingGuests' }, undo: 'Set-CsTeamsMeetingPolicy -Identity "Global" -AutoAdmittedUsers Everyone' },
    TEA04: { cmd: 'Set-CsTeamsClientConfiguration', params: { Identity: 'Global', AllowDropBox: '$false', AllowBox: '$false', AllowGoogleDrive: '$false', AllowShareFile: '$false', AllowEgnyte: '$false' }, undo: 'Set-CsTeamsClientConfiguration -Identity "Global" -AllowDropBox $true -AllowBox $true -AllowGoogleDrive $true' },
    TEA05: { cmd: 'Set-CsExternalAccessPolicy', params: { Identity: 'Global', EnableFederationAccess: '$false' }, undo: 'Set-CsExternalAccessPolicy -Identity "Global" -EnableFederationAccess $true' },
    TEA07: { cmd: 'Set-CsTeamsMeetingPolicy', params: { Identity: 'Global', AllowAnonymousUsersToStartMeeting: '$false' }, undo: 'Set-CsTeamsMeetingPolicy -Identity "Global" -AllowAnonymousUsersToStartMeeting $true' },

    // Purview
    PV11: { cmd: 'Set-AdminAuditLogConfig', params: { UnifiedAuditLogIngestionEnabled: '$true' }, undo: '# Do not disable unified audit log' },
    PV22: { cmd: 'New-RetentionCompliancePolicy', params: { Name: 'CIS-RetentionPolicy', ExchangeLocation: 'All', SharePointLocation: 'All', Enabled: '$true' }, undo: 'Remove-RetentionCompliancePolicy -Identity "CIS-RetentionPolicy" -Confirm:$false' },
  };

  // ─── Script Generation ───

  function generateDeployScript(policyIds) {
    if (!policyIds || policyIds.length === 0) return '# No missing policies to deploy.';

    var script = [];
    script.push('#Requires -Version 5.1');
    script.push('# ═══════════════════════════════════════════');
    script.push('# M365 Compliance Framework — Bulk Deployment');
    script.push('# Generated: ' + new Date().toISOString());
    script.push('# Policies: ' + policyIds.length);
    script.push('# ═══════════════════════════════════════════');
    script.push('');
    script.push('[CmdletBinding(SupportsShouldProcess)]');
    script.push('param(');
    script.push('    [switch]$DryRun');
    script.push(')');
    script.push('');
    script.push('$ErrorActionPreference = "Continue"');
    script.push('$results = @()');
    script.push('$rollbackActions = @()');
    script.push('$startTime = Get-Date');
    script.push('');

    // Group policies by module
    var groups = {};
    for (var key in MODULE_GROUPS) {
      var g = MODULE_GROUPS[key];
      var matching = policyIds.filter(function (id) {
        return g.prefixes.some(function (p) { return id.startsWith(p); });
      });
      if (matching.length > 0) {
        groups[key] = { config: g, ids: matching };
      }
    }

    // Generate per-group sections
    for (var groupName in groups) {
      var grp = groups[groupName];
      script.push('# ─── ' + groupName + ' (' + grp.ids.length + ' policies) ───');
      script.push('');
      script.push('try {');
      script.push('    Write-Host "[*] Connecting to ' + groupName + '..." -ForegroundColor Cyan');
      if (grp.config.module !== 'PnP.PowerShell') {
        script.push('    Import-Module ' + grp.config.module + ' -ErrorAction Stop');
      }
      script.push('    ' + grp.config.connect);
      script.push('    Write-Host "[OK] Connected to ' + groupName + '" -ForegroundColor Green');
      script.push('} catch {');
      script.push('    Write-Host "[FAIL] Could not connect to ' + groupName + ': $_" -ForegroundColor Red');
      script.push('    # Skip this group');
      script.push('}');
      script.push('');

      for (var i = 0; i < grp.ids.length; i++) {
        var policyId = grp.ids[i];
        script.push(generatePolicySection(policyId));
      }
    }

    // Summary and rollback
    script.push('');
    script.push('# ─── Summary ───');
    script.push('$elapsed = (Get-Date) - $startTime');
    script.push('Write-Host ""');
    script.push('Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan');
    script.push('Write-Host "Deployment Complete — $($elapsed.TotalSeconds.ToString("F1"))s" -ForegroundColor Cyan');
    script.push('$ok = ($results | Where-Object { $_.Status -eq "OK" }).Count');
    script.push('$fail = ($results | Where-Object { $_.Status -eq "FAIL" }).Count');
    script.push('$skip = ($results | Where-Object { $_.Status -eq "SKIP" }).Count');
    script.push('Write-Host "OK: $ok | Failed: $fail | Skipped: $skip" -ForegroundColor $(if ($fail -gt 0) { "Red" } else { "Green" })');
    script.push('');
    script.push('# Export results as JSON');
    script.push('$results | ConvertTo-Json -Depth 5 | Out-File -FilePath "deploy-results.json" -Encoding UTF8');
    script.push('Write-Host "Results saved to deploy-results.json" -ForegroundColor Gray');
    script.push('');
    script.push('# ─── Rollback Script ───');
    script.push('if ($rollbackActions.Count -gt 0) {');
    script.push('    $rollbackScript = $rollbackActions | ForEach-Object { "# Undo $($_.Policy)"; $_.Undo; "" }');
    script.push('    $rollbackScript | Out-File -FilePath "rollback.ps1" -Encoding UTF8');
    script.push('    Write-Host "Rollback script saved to rollback.ps1" -ForegroundColor Yellow');
    script.push('}');

    return script.join('\n');
  }

  function generatePolicySection(policyId) {
    var tmpl = DEPLOY_TEMPLATES[policyId];
    var lines = [];

    lines.push('# ── ' + policyId + ' ──');

    if (tmpl) {
      // Build param string
      var paramStr = Object.keys(tmpl.params).map(function (k) {
        var v = tmpl.params[k];
        if (typeof v === 'string' && (v.startsWith('$') || v.startsWith('@'))) {
          return '-' + k + ' ' + v;
        }
        return '-' + k + ' "' + v + '"';
      }).join(' ');

      lines.push('try {');
      if (tmpl.undo) {
        lines.push('    $rollbackActions += @{ Policy = "' + policyId + '"; Undo = \'' + tmpl.undo + '\' }');
      }
      lines.push('    if ($DryRun) {');
      lines.push('        Write-Host "[DRY-RUN] ' + policyId + ': ' + tmpl.cmd + ' ' + paramStr.replace(/"/g, '\\"').substring(0, 80) + '..." -ForegroundColor Yellow');
      lines.push('        $results += @{ Policy = "' + policyId + '"; Status = "SKIP"; Detail = "Dry run" }');
      lines.push('    } else {');
      lines.push('        ' + tmpl.cmd + ' ' + paramStr);
      lines.push('        Write-Host "[OK] ' + policyId + ' deployed" -ForegroundColor Green');
      lines.push('        $results += @{ Policy = "' + policyId + '"; Status = "OK"; Detail = "' + tmpl.cmd + '" }');
      lines.push('    }');
      lines.push('} catch {');
      lines.push('    Write-Host "[FAIL] ' + policyId + ': $_" -ForegroundColor Red');
      lines.push('    $results += @{ Policy = "' + policyId + '"; Status = "FAIL"; Detail = $_.Exception.Message }');
      lines.push('}');
    } else {
      // Generic fallback — remind admin to configure manually
      lines.push('# No automated deployment template for ' + policyId);
      lines.push('# Refer to CIS Benchmark documentation for manual configuration steps.');
      lines.push('Write-Host "[SKIP] ' + policyId + ' — manual configuration required" -ForegroundColor Yellow');
      lines.push('$results += @{ Policy = "' + policyId + '"; Status = "SKIP"; Detail = "Manual configuration required" }');
    }
    lines.push('');

    return lines.join('\n');
  }

  function generateRollbackScript(policyIds) {
    var lines = [];
    lines.push('#Requires -Version 5.1');
    lines.push('# ═══════════════════════════════════════════');
    lines.push('# M365 Compliance Framework — Rollback Script');
    lines.push('# Generated: ' + new Date().toISOString());
    lines.push('# WARNING: This will UNDO deployed policies!');
    lines.push('# ═══════════════════════════════════════════');
    lines.push('');
    lines.push('$ErrorActionPreference = "Continue"');
    lines.push('');

    for (var i = 0; i < policyIds.length; i++) {
      var tmpl = DEPLOY_TEMPLATES[policyIds[i]];
      if (tmpl && tmpl.undo) {
        lines.push('# Undo ' + policyIds[i]);
        lines.push('try {');
        lines.push('    ' + tmpl.undo);
        lines.push('    Write-Host "[OK] Rolled back ' + policyIds[i] + '" -ForegroundColor Green');
        lines.push('} catch {');
        lines.push('    Write-Host "[FAIL] Rollback ' + policyIds[i] + ': $_" -ForegroundColor Red');
        lines.push('}');
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  // ─── UI ───

  function getMissingPolicyIds() {
    var scanResults = AppState.get('tenantScanResults') || {};
    return Object.keys(scanResults).filter(function (id) {
      return scanResults[id].status === 'missing';
    });
  }

  function showDeployModal() {
    var missing = getMissingPolicyIds();
    if (missing.length === 0) {
      showToast('No missing policies detected — run a scan first');
      return;
    }

    var script = generateDeployScript(missing);
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var html = '<div class="modal-header">';
    html += '<h3>Bulk Deployment Script (' + missing.length + ' policies)</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';
    html += '<p style="font-size:.72rem;color:var(--ink4);margin-bottom:12px">';
    html += 'This PowerShell script will deploy <strong>' + missing.length + '</strong> missing policies. ';
    html += 'Use the <code>-DryRun</code> flag to preview changes without applying them.</p>';
    html += '<pre class="ps-cmd" style="max-height:400px;overflow:auto;font-size:.6rem;white-space:pre;tab-size:4">' + escHtml(script) + '</pre>';
    html += '<div class="config-actions" style="margin-top:12px">';
    html += '<button class="btn btn-primary" onclick="PSDeploy.downloadDeployScript()">Download .ps1</button> ';
    html += '<button class="btn" onclick="PSDeploy.copyScript()">Copy to Clipboard</button> ';
    html += '<button class="btn" onclick="PSDeploy.downloadRollback()">Download Rollback</button> ';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Close</button>';
    html += '</div></div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  function downloadDeployScript() {
    var missing = getMissingPolicyIds();
    var script = generateDeployScript(missing);
    downloadFile(script, 'M365-Deploy-' + new Date().toISOString().slice(0, 10) + '.ps1');
  }

  function downloadRollback() {
    var missing = getMissingPolicyIds();
    var script = generateRollbackScript(missing);
    downloadFile(script, 'M365-Rollback-' + new Date().toISOString().slice(0, 10) + '.ps1');
  }

  function copyScript() {
    var missing = getMissingPolicyIds();
    var script = generateDeployScript(missing);
    navigator.clipboard.writeText(script).then(function () {
      showToast('Script copied to clipboard');
    }).catch(function () {
      showToast('Copy failed — use the download button');
    });
  }

  function downloadFile(content, filename) {
    var blob = new Blob([content], { type: 'text/plain' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Downloaded ' + filename);
  }

  return {
    generateDeployScript: generateDeployScript,
    generateRollbackScript: generateRollbackScript,
    showDeployModal: showDeployModal,
    downloadDeployScript: downloadDeployScript,
    downloadRollback: downloadRollback,
    copyScript: copyScript,
  };
})();
