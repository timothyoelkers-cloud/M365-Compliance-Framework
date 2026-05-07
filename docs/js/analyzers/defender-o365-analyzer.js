/* ═══════════════════════════════════════════
   DEFENDER FOR OFFICE 365 ANALYZER

   Sources:
     - secureScores[0].controlScores — Microsoft's own evaluation of MDO
       features (anti-phishing, safe attachments, safe links, anti-malware,
       common attachment filter, ATP for SPO/OneDrive/Teams, etc.)

   We can't query the underlying /adminapi/beta InvokeCommand from the
   browser (CORS), so we lean entirely on Secure Score's pre-computed view.
═══════════════════════════════════════════ */
(function () {
  if (typeof Findings === 'undefined') return;

  // Secure Score control IDs that map to MDO features.
  // (Names taken from Microsoft Secure Score docs; some may have evolved.)
  const MDO_CONTROLS = {
    'AntiPhishingPolicy':           { severity: 'high',     label: 'Anti-Phishing policy' },
    'TargetedAntiPhishing':         { severity: 'high',     label: 'Targeted anti-phishing protection' },
    'EnableSafeLinks':              { severity: 'high',     label: 'Safe Links' },
    'SafeLinksClickTracking':       { severity: 'medium',   label: 'Safe Links click tracking' },
    'EnableSafeAttachments':        { severity: 'high',     label: 'Safe Attachments' },
    'SafeAttachmentsForSPO':        { severity: 'medium',   label: 'Safe Attachments for SharePoint / OneDrive / Teams' },
    'AntiMalwarePolicy':            { severity: 'high',     label: 'Anti-Malware policy' },
    'CommonAttachmentTypesFilter':  { severity: 'medium',   label: 'Common attachment types filter' },
    'OutboundSpam':                 { severity: 'medium',   label: 'Outbound spam policy' },
    'BlockListsExternalSenders':    { severity: 'medium',   label: 'External sender block lists' },
    'EnableMailboxIntelligence':    { severity: 'medium',   label: 'Mailbox intelligence' },
    'PhishingThresholdLevel':       { severity: 'low',      label: 'Phishing threshold level (strictness)' },
    'DKIMSigning':                  { severity: 'medium',   label: 'DKIM signing for accepted domains' },
    'DMARCEnforcement':             { severity: 'medium',   label: 'DMARC enforcement' },
    'PreventDirectMail':            { severity: 'medium',   label: 'Direct-send blocking' },
    'DisableAutoForwarding':        { severity: 'high',     label: 'Block external auto-forwarding' },
    'BlockBasicAuth':               { severity: 'high',     label: 'Block basic authentication (Exchange)' },
  };

  Findings.register('defender-o365', 'Defender for O365', function (data) {
    const H = Findings.helpers;
    const findings = [];
    const scoreSnap = (data.secureScores && data.secureScores[0]) || null;
    const controlScores = (scoreSnap && scoreSnap.controlScores) || [];

    if (!scoreSnap) {
      findings.push({
        ruleId: 'mdo-no-secure-score',
        severity: 'info',
        title: 'Secure Score data not retrieved — Defender for O365 evaluation skipped',
        description: 'MDO policies (anti-phish / safe links / safe attachments / anti-malware / etc.) are exposed by Microsoft mainly via Exchange Online PowerShell, which the browser cannot reach. Secure Score is the only Graph-accessible source, and it returned no data here.',
        remediation: 'Grant SecurityEvents.Read.All to the App Registration. Sign in as Security Reader / Global Reader. After re-scan, this analyzer will surface MDO control gaps.',
        refs: [],
      });
      return findings;
    }

    let mdoMatched = 0;
    for (const cs of controlScores) {
      const id = cs.controlName || cs.id || '';
      // Match either exact ID or name-substring against the catalogue.
      let def = MDO_CONTROLS[id];
      if (!def) {
        for (const k of Object.keys(MDO_CONTROLS)) {
          if (id.toLowerCase().indexOf(k.toLowerCase()) !== -1) { def = MDO_CONTROLS[k]; break; }
        }
      }
      if (!def) continue;
      mdoMatched++;

      const score = cs.score != null ? cs.score : 0;
      const max = cs.maxScore != null ? cs.maxScore : (cs.scoreInPercentage != null ? 100 : null);
      const isImplemented = cs.implementationStatus === 'Implemented' ||
                            cs.state === 'Default' ||
                            (max != null && score >= max);
      if (!isImplemented) {
        findings.push({
          ruleId: 'mdo-' + id,
          severity: def.severity,
          title: 'Defender for O365: ' + def.label + ' not fully implemented',
          description: 'Microsoft Secure Score marks "' + def.label + '" as ' +
            (cs.implementationStatus || 'not implemented') +
            (max ? ' (' + score + '/' + max + ')' : '') + '. ' +
            (cs.description || ''),
          remediation: 'Open Microsoft Defender → Email & collaboration → Policies & rules → Threat policies. Apply the matching framework template (DEF01–DEF08).',
          refs: [],
        });
      }
    }

    // Coverage info line
    findings.push({
      ruleId: 'mdo-coverage-info',
      severity: 'info',
      title: mdoMatched + ' MDO-relevant Secure Score controls evaluated',
      description: mdoMatched === 0
        ? 'No MDO controls were detected in the Secure Score response. The licence may not include MDO Plan 1/2.'
        : 'Microsoft\'s pre-evaluated state for these controls is the basis of the findings above.',
      remediation: '',
      refs: [],
    });

    return findings;
  });
})();
