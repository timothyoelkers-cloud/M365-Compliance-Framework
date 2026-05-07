/* ═══════════════════════════════════════════
   PURVIEW / DATA PROTECTION ANALYZER

   Sources:
     - sensitivityLabels — /beta/security/informationProtection/sensitivityLabels
     - retentionLabels   — /v1.0/security/labels/retentionLabels (optional)
     - dlpPolicies       — /beta/dataLossPrevention/policies (optional, beta)

   Microsoft Graph coverage of Purview is partial. When an endpoint isn't
   licensed in the tenant (returns 404), the scanner already flags it as
   "not available" — we don't generate false-positive findings in that case.
═══════════════════════════════════════════ */
(function () {
  if (typeof Findings === 'undefined') return;

  Findings.register('purview', 'Purview / Data Protection', function (data) {
    const findings = [];
    const sensitivityLabels = Array.isArray(data.sensitivityLabels) ? data.sensitivityLabels : null;
    const retentionLabels   = Array.isArray(data.retentionLabels) ? data.retentionLabels : null;
    const dlpPolicies       = Array.isArray(data.dlpPolicies) ? data.dlpPolicies : null;

    // ── Sensitivity Labels ─────────────────────────────────────────────

    if (sensitivityLabels === null) {
      findings.push({
        ruleId: 'sensitivity-labels-not-scanned',
        severity: 'info',
        title: 'Sensitivity labels could not be scanned',
        description: 'The /beta/security/informationProtection/sensitivityLabels endpoint returned no data. Either the tenant lacks Microsoft Information Protection licensing (E3 + IP add-on, or E5) or the signed-in user lacks InformationProtection.Read permission.',
        remediation: '',
        refs: [],
      });
    } else if (sensitivityLabels.length === 0) {
      findings.push({
        ruleId: 'no-sensitivity-labels',
        severity: 'high',
        title: 'No sensitivity labels published',
        description: 'No sensitivity labels exist in this tenant. Without labels, users have no way to classify data and downstream policies (auto-labelling, DLP-on-label, encryption-on-label) have nothing to bind to.',
        remediation: 'Create a baseline taxonomy in Microsoft Purview → Information Protection: Public / Internal / Confidential / Highly Confidential. Apply to file, email, site, team, and Teams meeting scopes.',
        refs: ['PV10', 'PV14', 'PV15'],
      });
    } else {
      // Detect labels active but with no protection (e.g. Confidential without encryption)
      const sensitiveButUnprotected = sensitivityLabels.filter(l => {
        const name = String(l.displayName || l.name || '').toLowerCase();
        return /confidential|secret|restricted|highly\s*confidential/.test(name) &&
               l.isActive !== false &&
               !l.hasProtection;
      });
      sensitiveButUnprotected.forEach(l => {
        findings.push({
          ruleId: 'sensitive-label-no-protection',
          severity: 'medium',
          title: 'Sensitive label has no encryption: "' + (l.displayName || l.name) + '"',
          description: 'A label named "' + (l.displayName || l.name) + '" is active but has no rights-management / encryption protection attached. Users may classify documents with it and assume they\'re protected when they\'re not.',
          remediation: 'In Purview → Information Protection → Labels, edit this label and add Encryption (Apply) under "Files & emails". Optionally add content marking (watermark / header / footer).',
          refs: ['PV10'],
          policy: l.displayName || l.name,
        });
      });

      // Inactive labels in the tenant
      const inactive = sensitivityLabels.filter(l => l.isActive === false);
      if (inactive.length > 0) {
        findings.push({
          ruleId: 'inactive-sensitivity-labels',
          severity: 'low',
          title: inactive.length + ' inactive sensitivity label' + (inactive.length > 1 ? 's' : ''),
          description: 'Inactive labels can\'t be applied. Often a sign of an in-progress deployment that stalled, or a deprecated taxonomy that should be cleaned up.',
          remediation: 'Either re-activate or delete inactive labels. Don\'t leave them as visual noise in the admin centre.',
          refs: [],
        });
      }
    }

    // ── Retention Labels ───────────────────────────────────────────────

    if (retentionLabels === null) {
      findings.push({
        ruleId: 'retention-labels-not-scanned',
        severity: 'info',
        title: 'Retention labels could not be scanned',
        description: 'The /v1.0/security/labels/retentionLabels endpoint did not return data. Likely needs Compliance E5 or RecordsManagement.Read.All permission. Check the Tenant Inventory for the actual error.',
        remediation: '',
        refs: [],
      });
    } else if (retentionLabels.length === 0) {
      findings.push({
        ruleId: 'no-retention-labels',
        severity: 'high',
        title: 'No retention labels configured',
        description: 'No retention labels exist. Without retention, content is governed only by mailbox / SharePoint defaults and litigation risk increases.',
        remediation: 'Create a baseline retention scheme in Purview → Records Management: at minimum a "General" 7-year retention label aligned with your statutory record-keeping requirements.',
        refs: ['PV22', 'PV24'],
      });
    } else {
      // Labels in use, but only delete-only (no preservation)
      const deleteOnly = retentionLabels.filter(l =>
        l.behaviorDuringRetentionPeriod && l.actionAfterRetentionPeriod === 'delete' &&
        l.behaviorDuringRetentionPeriod === 'doNotRetain'
      );
      if (deleteOnly.length === retentionLabels.length && retentionLabels.length > 0) {
        findings.push({
          ruleId: 'retention-delete-only',
          severity: 'medium',
          title: 'All retention labels are delete-only (no preservation)',
          description: 'Every retention label deletes data without first preserving it. If a user destroys content during the retention period, it\'s gone. For records-management or regulatory holds, preservation is essential.',
          remediation: 'Add at least one label with behaviorDuringRetentionPeriod=retain (or retainAsRecord) for content with statutory retention obligations.',
          refs: ['PV23', 'PV25'],
        });
      }

      // Labels published but never used
      const unused = retentionLabels.filter(l => l.isInUse === false);
      if (unused.length === retentionLabels.length && retentionLabels.length > 1) {
        findings.push({
          ruleId: 'retention-not-applied',
          severity: 'medium',
          title: 'Retention labels exist but none are in use',
          description: retentionLabels.length + ' retention labels are defined but isInUse=false on all of them. Labels without auto-labelling rules or user assignment do nothing.',
          remediation: 'Create auto-labelling rules in Purview → Information Protection → Auto-labelling, or publish the labels via a label policy so users can apply them manually.',
          refs: ['PV13'],
        });
      }
    }

    // ── DLP Policies ───────────────────────────────────────────────────

    if (dlpPolicies === null) {
      findings.push({
        ruleId: 'dlp-not-scanned',
        severity: 'info',
        title: 'DLP policies could not be scanned',
        description: 'The /beta/dataLossPrevention/policies endpoint (Graph beta) did not return data. Note: Graph DLP coverage is partial — the canonical source is Compliance PowerShell which we don\'t call from the browser. The Tenant Inventory shows what was actually retrieved.',
        remediation: 'For an authoritative DLP audit, run Get-DlpCompliancePolicy and Get-DlpComplianceRule in a Connect-IPPSSession PowerShell session.',
        refs: [],
      });
    } else if (dlpPolicies.length === 0) {
      findings.push({
        ruleId: 'no-dlp-policies',
        severity: 'high',
        title: 'No DLP policies detected',
        description: 'No data-loss-prevention policies are configured. Sensitive content (credit cards, PII, financial data, source code) can be sent to external recipients with no detection or block.',
        remediation: 'Deploy baseline DLP for: credit cards (PCI), personally identifiable information (GDPR/UK PII), and financial data. Start in test mode, monitor false positives for 2-4 weeks, then enforce.',
        refs: ['PV01', 'PV02', 'PV04', 'PV06', 'PV07', 'PV08', 'PV16', 'PV17'],
      });
    } else {
      // All DLP in disabled / test mode
      const enforced = dlpPolicies.filter(p =>
        (p.state === 'enabled' || p.state === 'enforced') &&
        (p.policyMode !== 'test' && p.policyMode !== 'audit')
      );
      if (enforced.length === 0 && dlpPolicies.length > 0) {
        findings.push({
          ruleId: 'dlp-all-test-mode',
          severity: 'medium',
          title: 'All DLP policies are in test/disabled mode',
          description: dlpPolicies.length + ' DLP policies are defined but none are actively enforcing. Test mode detects but does not block. After tuning, policies should move to enforced.',
          remediation: 'Review DLP Activity Explorer for false positives, then move tuned policies from "Test" to "Turn on the policy". PV01-PV09 in the framework provide enforced-mode templates.',
          refs: ['PV01', 'PV02', 'PV04', 'PV09'],
        });
      }

      // Detect missing common categories by name match
      const categoryHints = {
        creditCard: /credit\s*card|pci|payment/i,
        pii:        /pii|personal|gdpr|nhs|hipaa/i,
        financial:  /financial|finance|bank|sox|pci/i,
        credentials: /password|credential|secret|api\s*key/i,
      };
      const detectedCategories = {};
      for (const k of Object.keys(categoryHints)) detectedCategories[k] = false;
      dlpPolicies.forEach(p => {
        const text = ((p.displayName || '') + ' ' + (p.description || '')).toLowerCase();
        for (const k of Object.keys(categoryHints)) {
          if (categoryHints[k].test(text)) detectedCategories[k] = true;
        }
      });
      const missingCats = Object.keys(detectedCategories).filter(k => !detectedCategories[k]);
      if (missingCats.length > 0 && dlpPolicies.length > 0) {
        const labels = { creditCard: 'Credit cards / PCI', pii: 'PII / GDPR', financial: 'Financial data', credentials: 'Passwords / credentials' };
        findings.push({
          ruleId: 'dlp-missing-categories',
          severity: 'medium',
          title: 'No DLP coverage detected for: ' + missingCats.map(c => labels[c]).join(', '),
          description: 'DLP exists, but no policy name or description suggests coverage of these baseline categories. (Heuristic — name-based, may miss policies with custom names.)',
          remediation: 'Verify in Purview → DLP whether these categories are covered. If not, deploy the matching framework templates: PV01 (cards), PV02 (PII), PV04 (financial), PV06/PV07 (credentials).',
          refs: ['PV01', 'PV02', 'PV04', 'PV06', 'PV07'],
        });
      }
    }

    // ── Coverage info line ────────────────────────────────────────────
    const counts = [];
    if (sensitivityLabels) counts.push(sensitivityLabels.length + ' sensitivity label' + (sensitivityLabels.length === 1 ? '' : 's'));
    if (retentionLabels) counts.push(retentionLabels.length + ' retention label' + (retentionLabels.length === 1 ? '' : 's'));
    if (dlpPolicies) counts.push(dlpPolicies.length + ' DLP polic' + (dlpPolicies.length === 1 ? 'y' : 'ies'));
    if (counts.length > 0) {
      findings.push({
        ruleId: 'purview-coverage-summary',
        severity: 'info',
        title: 'Detected: ' + counts.join(', '),
        description: 'For a fuller audit (encryption rules, auto-labelling rules, communication compliance, insider risk), use the Purview admin centre — those areas are not yet exposed via Microsoft Graph.',
        remediation: '',
        refs: [],
      });
    }

    return findings;
  });
})();
