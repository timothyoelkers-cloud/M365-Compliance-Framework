/* ═══════════════════════════════════════════
   DEFENDER FOR ENDPOINT ANALYZER

   Sources:
     - configurationPolicies (Endpoint Security / Settings Catalog)
         → categorised by templateReference.templateFamily
     - deviceConfigurations (legacy MDE configuration profiles)
     - secureScores[0].controlScores (Microsoft's own evaluation)
     - compliancePolicies (Defender requirements baked into compliance)

   Rules check both presence (do they have any MDE policy at all?)
   and content via Microsoft's Secure Score evaluation where available.
═══════════════════════════════════════════ */
(function () {
  if (typeof Findings === 'undefined') return;

  // Endpoint Security template families we care about. The
  // templateReference.templateFamily field on configurationPolicies tells us
  // which template a policy was created from — so we can detect "is there an
  // ASR policy" without inspecting individual settings.
  const TEMPLATE_FAMILIES = {
    endpointSecurityAntivirus:                       { label: 'Antivirus / Defender AV',    severity: 'critical' },
    endpointSecurityAttackSurfaceReduction:          { label: 'Attack Surface Reduction',   severity: 'high' },
    endpointSecurityEndpointDetectionAndResponse:    { label: 'EDR onboarding',             severity: 'critical' },
    endpointSecurityFirewall:                        { label: 'Firewall',                   severity: 'medium' },
    endpointSecurityAccountProtection:               { label: 'Account Protection',         severity: 'medium' },
    endpointSecurityDiskEncryption:                  { label: 'Disk Encryption (BitLocker / FileVault)', severity: 'high' },
    endpointSecurityEndpointPrivilegeManagement:     { label: 'Endpoint Privilege Management', severity: 'low' },
  };

  // Secure Score control IDs that map to MDE features. When Microsoft has
  // already evaluated these, we forward the result rather than re-judging.
  // implementationStatus values: "ToAddress", "PlannedForReview", "Reviewed", "Implemented"
  // We surface findings only when score < maxScore on enabled controls.
  const SECURE_SCORE_MDE_CONTROLS = {
    'TamperProtection':            { severity: 'high',     label: 'Tamper Protection' },
    'EnableASRRules':              { severity: 'high',     label: 'Attack Surface Reduction rules' },
    'EnableNetworkProtection':     { severity: 'medium',   label: 'Network Protection' },
    'EnableControlledFolderAccess':{ severity: 'medium',   label: 'Controlled Folder Access (ransomware)' },
    'PUAProtection':               { severity: 'low',      label: 'Potentially Unwanted Application protection' },
    'EnableRealtimeProtection':    { severity: 'critical', label: 'Real-time Protection' },
    'CloudProtection':             { severity: 'medium',   label: 'Cloud-delivered Protection' },
    'WebContentFiltering':         { severity: 'medium',   label: 'Web Content Filtering' },
    'AutomatedInvestigation':      { severity: 'medium',   label: 'Automated Investigation & Response (AIR)' },
    'AttackSurfaceReductionRules': { severity: 'high',     label: 'ASR (alt id)' },
  };

  Findings.register('defender-endpoint', 'Defender for Endpoint', function (data) {
    const H = Findings.helpers;
    const findings = [];

    // Bail out cleanly if both Intune scan sources errored — don't claim "no MDE".
    const stateConfigPol = H.sourceState(data.configurationPolicies);
    const stateDevice    = H.sourceState(data.deviceConfigurations);
    if (stateConfigPol === 'scanFailed' && stateDevice === 'scanFailed') {
      return [{
        ruleId: 'mde-scan-failed',
        severity: 'high',
        title: 'Defender for Endpoint config could not be scanned',
        description: 'Both /beta/deviceManagement/configurationPolicies and /v1.0/deviceManagement/deviceConfigurations errored. Cannot tell if MDE is configured.',
        remediation: 'Verify DeviceManagementConfiguration.Read.All admin consent and reconnect.',
        refs: [],
      }];
    }

    const policies      = stateConfigPol === 'scanned' ? data.configurationPolicies : [];
    const oldConfigs    = stateDevice === 'scanned' ? data.deviceConfigurations : [];
    const scoreSnap     = (data.secureScores && data.secureScores[0]) || null;
    const controlScores = (scoreSnap && scoreSnap.controlScores) || [];
    const compliance    = Array.isArray(data.compliancePolicies) ? data.compliancePolicies : [];

    // Group configurationPolicies by templateFamily.
    const byFamily = {};
    for (const p of policies) {
      const fam = p.templateReference && p.templateReference.templateFamily;
      if (!fam) continue;
      (byFamily[fam] = byFamily[fam] || []).push(p);
    }

    // 1. No Endpoint Security policies — only when we have positive evidence both sources are empty
    const bothEmpty = stateConfigPol === 'scanned' && stateDevice === 'scanned' &&
                      Object.keys(byFamily).length === 0 && oldConfigs.length === 0;
    const totalEndpointPolicies = Object.values(byFamily).reduce((n, arr) => n + arr.length, 0);
    if (bothEmpty) {
      findings.push({
        ruleId: 'no-mde-policies',
        severity: 'critical',
        title: 'No Defender for Endpoint policies configured',
        description: 'No configurationPolicies use an Endpoint Security template, and no legacy device configurations are present. Without policy coverage, MDE relies on whatever settings shipped with the OS image.',
        remediation: 'In Intune → Endpoint Security, deploy at minimum: Antivirus (Defender AV), EDR onboarding, Attack Surface Reduction, Disk Encryption.',
        refs: ['MDE01', 'MDE02', 'MDE03', 'MDE04'],
      });
      // No point evaluating individual templates if nothing exists.
    } else if (stateConfigPol === 'scanned') {
      // 2-8. Per-template-family coverage
      for (const fam of Object.keys(TEMPLATE_FAMILIES)) {
        const def = TEMPLATE_FAMILIES[fam];
        if (!byFamily[fam] || byFamily[fam].length === 0) {
          findings.push({
            ruleId: 'missing-' + fam,
            severity: def.severity,
            title: 'No "' + def.label + '" policy configured',
            description: 'No configurationPolicies use the ' + fam + ' template. This category of Defender protection is unconfigured at the MDM layer.',
            remediation: 'Intune → Endpoint Security → ' + def.label + ' → Create policy. Use Microsoft\'s baseline template as a starting point.',
            refs: [],
          });
        }
      }
    }

    // 9. EDR onboarding present but probably audit-mode (best-effort heuristic)
    const edrPolicies = byFamily.endpointSecurityEndpointDetectionAndResponse || [];
    edrPolicies.forEach(p => {
      const name = (p.name || '').toLowerCase();
      if (/audit|monitor|test/.test(name) && !/block|enforce|prod/.test(name)) {
        findings.push({
          ruleId: 'edr-audit-only',
          severity: 'medium',
          title: 'EDR policy may be audit-only: "' + (p.name || p.id) + '"',
          description: 'The policy name suggests audit / monitoring mode. Audit-only EDR detects but does not block — useful during pilot, risky as a steady state.',
          remediation: 'Verify the EDR policy enforces (Block, not Audit). Microsoft recommends Block once tuning is complete.',
          refs: [p.id],
        });
      }
    });

    // 10-N. Secure Score MDE controls that are below 100%
    if (controlScores.length === 0 && scoreSnap == null) {
      findings.push({
        ruleId: 'no-secure-score',
        severity: 'info',
        title: 'Secure Score data not retrieved',
        description: 'Without Secure Score, MDE feature coverage cannot be evaluated against Microsoft\'s own assessment. Grant SecurityEvents.Read.All to the app or sign in as a user who has it.',
        remediation: '',
        refs: [],
      });
    } else {
      for (const cs of controlScores) {
        const id = cs.controlName || cs.id;
        const def = SECURE_SCORE_MDE_CONTROLS[id];
        if (!def) continue;
        const score = cs.score != null ? cs.score : 0;
        const max = cs.maxScore != null ? cs.maxScore : (cs.scoreInPercentage != null ? 100 : null);
        const isImplemented = (cs.implementationStatus === 'Implemented' || (max != null && score >= max));
        if (!isImplemented) {
          findings.push({
            ruleId: 'secure-score-' + id,
            severity: def.severity,
            title: 'Secure Score: ' + def.label + ' not fully implemented',
            description: 'Microsoft\'s own evaluation marks this control as "' + (cs.implementationStatus || 'not implemented') + '"' +
              (max ? ' (' + score + '/' + max + ')' : '') +
              '. ' + (cs.description || ''),
            remediation: 'Open Microsoft Defender → Secure Score and follow the per-control improvement guidance.',
            refs: [],
          });
        }
      }
    }

    // ── Compliance baseline cross-checks ──

    // Find any Windows compliance policies and warn if none enforce Defender requirements
    const winCompliance = compliance.filter(p => /windows/i.test(p['@odata.type'] || ''));
    if (winCompliance.length === 0 && compliance.length > 0) {
      findings.push({
        ruleId: 'no-windows-compliance',
        severity: 'medium',
        title: 'No Windows-specific compliance policy',
        description: 'Compliance policies exist but none are Windows-specific. Windows-only Defender settings (BitLocker, Defender AV active, signature freshness, etc.) need a Windows compliance policy to be enforced.',
        remediation: 'Create a Windows 10/11 Compliance Policy with: BitLocker enabled, antivirus active, antispyware active, real-time protection on, signatures up to date.',
        refs: [],
      });
    }

    // Coverage info line — tell the user what we found.
    const detectedFamilies = Object.keys(byFamily).filter(k => TEMPLATE_FAMILIES[k]);
    if (totalEndpointPolicies > 0) {
      findings.push({
        ruleId: 'mde-coverage-summary',
        severity: 'info',
        title: totalEndpointPolicies + ' Endpoint Security policies across ' + detectedFamilies.length + ' template families',
        description: 'Detected: ' + detectedFamilies.map(f => TEMPLATE_FAMILIES[f].label).join(', '),
        remediation: '',
        refs: [],
      });
    }

    return findings;
  });
})();
