/* ═══════════════════════════════════════════
   CA ANALYZER — Findings for Conditional Access policies.
═══════════════════════════════════════════ */
(function () {
  if (typeof Findings === 'undefined') return;
  const H = Findings.helpers;

  Findings.register('conditional-access', 'Conditional Access', function (data) {
    const findings = [];
    const state = H.sourceState(data.conditionalAccess);

    // ── Scan state checks first — never claim "no policies" when the scan errored ──
    if (state === 'scanFailed') {
      return [{
        ruleId: 'ca-scan-failed',
        severity: 'high',
        title: 'Conditional Access could not be scanned',
        description: 'The /v1.0/identity/conditionalAccess/policies request failed (401/403 or similar). Common causes: signed-in user lacks Policy.Read.All, or admin consent has not been granted for the app in this tenant. Check the Tenant Inventory for the exact error.',
        remediation: 'Reconnect Tenant. Verify the signed-in user has Global Reader / Security Reader role and the App Registration has Policy.Read.All admin-consented in this tenant.',
        refs: [],
      }];
    }
    if (state === 'notScanned') {
      return [{
        ruleId: 'ca-not-scanned',
        severity: 'info',
        title: 'Conditional Access scan was not run',
        description: 'No conditionalAccess data in the scan output.',
        remediation: 'Run a tenant scan.',
        refs: [],
      }];
    }

    const policies = data.conditionalAccess;

    // ── Genuine "no policies" only when scan succeeded with [] ──
    if (H.isGenuinelyEmpty(policies)) {
      return [{
        ruleId: 'no-policies',
        severity: 'critical',
        title: 'No Conditional Access policies configured',
        description: 'The tenant has zero Conditional Access policies. Sign-in risk and identity protection rely on these.',
        remediation: 'Deploy a baseline set: block legacy auth, require MFA for all users, require MFA for admins with phishing-resistant strength, sign-in risk block, user risk password change.',
        refs: ['CA01', 'CA02', 'CA03', 'CA04', 'CA05'],
      }];
    }

    const enabled = policies.filter(H.isCAEnabled);
    const reportOnly = policies.filter(H.isCAReportOnly);
    const disabled = policies.filter(p => p.state === 'disabled');

    // 2. Block legacy authentication (CA01)
    const blockLegacy = enabled.find(p =>
      H.isBlockPolicy(p) &&
      ((p.conditions && p.conditions.clientAppTypes) || []).some(c => c === 'exchangeActiveSync' || c === 'other')
    );
    if (!blockLegacy) {
      findings.push({
        ruleId: 'block-legacy-auth',
        severity: 'critical',
        title: 'Legacy authentication is not blocked',
        description: 'No enabled CA policy blocks legacy authentication clients (Exchange ActiveSync, IMAP/POP/SMTP basic auth). Legacy auth bypasses MFA — Microsoft 99% of password-spray attacks target it.',
        remediation: 'Create a block policy targeting clientAppTypes ["exchangeActiveSync","other"] for All users. Test in report-only first.',
        refs: ['CA01'],
      });
    }

    // 3. MFA required for all users (CA02)
    const mfaForAll = enabled.find(p =>
      H.targetsAllUsers(p) &&
      (H.grantControls(p).indexOf('mfa') !== -1 || (p.grantControls && p.grantControls.authenticationStrength))
    );
    if (!mfaForAll) {
      findings.push({
        ruleId: 'mfa-all-users',
        severity: 'critical',
        title: 'No MFA requirement for all users',
        description: 'No enabled CA policy requires MFA (or an authentication strength) for all users. This leaves password-only sign-ins permitted.',
        remediation: 'Enable a policy: All users → All apps → require MFA (or "Phishing-resistant MFA" auth strength). Exclude break-glass.',
        refs: ['CA02'],
      });
    }

    // 4. Phishing-resistant MFA for admins (CA03)
    const adminAuthStrength = enabled.find(p => {
      const roles = (p.conditions && p.conditions.users && p.conditions.users.includeRoles) || [];
      return roles.length > 0 && p.grantControls && p.grantControls.authenticationStrength;
    });
    if (!adminAuthStrength) {
      findings.push({
        ruleId: 'admin-auth-strength',
        severity: 'high',
        title: 'Admins not protected by phishing-resistant MFA',
        description: 'No enabled CA policy targets admin roles with an authenticationStrength (e.g. phishing-resistant MFA). SMS/voice MFA is bypassable.',
        remediation: 'Create a policy targeting privileged roles → all apps → require Phishing-resistant MFA authentication strength.',
        refs: ['CA03'],
      });
    }

    // 5. Sign-in risk: block on high (CA04)
    const blockHighSignInRisk = enabled.find(p =>
      ((p.conditions && p.conditions.signInRiskLevels) || []).indexOf('high') !== -1 &&
      H.isBlockPolicy(p)
    );
    if (!blockHighSignInRisk) {
      findings.push({
        ruleId: 'block-high-signin-risk',
        severity: 'high',
        title: 'High sign-in risk not blocked',
        description: 'No enabled CA policy blocks high sign-in-risk events. Identity Protection requires P2 — without action on detections, real attacks proceed.',
        remediation: 'Create a policy targeting signInRiskLevels=["high"] → block. Requires Microsoft Entra ID P2.',
        refs: ['CA04'],
      });
    }

    // 6. User risk: password change on high (CA05)
    const userRiskPwChange = enabled.find(p =>
      ((p.conditions && p.conditions.userRiskLevels) || []).indexOf('high') !== -1 &&
      H.grantControls(p).indexOf('passwordChange') !== -1
    );
    if (!userRiskPwChange) {
      findings.push({
        ruleId: 'user-risk-pw-change',
        severity: 'high',
        title: 'High user risk does not force password change',
        description: 'No enabled CA policy forces a password change when user risk is high. Compromised credentials remain usable.',
        remediation: 'Create a policy targeting userRiskLevels=["high"] → require password change + MFA. Requires Microsoft Entra ID P2.',
        refs: ['CA05'],
      });
    }

    // ── Per-policy hygiene ──

    for (const p of policies) {
      // 7. Block + All users + All apps + No exclusions = lockout risk
      if (H.isCAEnabled(p) && H.isBlockPolicy(p) && H.targetsAllUsers(p) && H.targetsAllApps(p) && !H.hasUserExclusions(p)) {
        findings.push({
          ruleId: 'block-all-no-exclusions',
          severity: 'critical',
          title: 'Lockout risk: block-all policy with no exclusions',
          description: 'Policy "' + (p.displayName || p.id) + '" blocks all users on all apps with no exclusions — including break-glass accounts. A misconfiguration here can lock the entire tenant out.',
          remediation: 'Add at least one break-glass account / emergency-access security group to excludeUsers / excludeGroups.',
          refs: [p.id],
          policy: p.displayName,
        });
      }

      // 8. Report-only policies older than 30 days (likely forgotten)
      if (H.isCAReportOnly(p) && p.modifiedDateTime) {
        const days = (Date.now() - new Date(p.modifiedDateTime).getTime()) / 86400000;
        if (days > 30) {
          findings.push({
            ruleId: 'stale-report-only',
            severity: 'medium',
            title: 'Stale report-only policy: "' + (p.displayName || p.id) + '"',
            description: 'In report-only mode for ' + Math.round(days) + ' days. Report-only is for evaluation, not steady state.',
            remediation: 'Review the sign-in logs for this policy, then either enable it (state="enabled") or delete it.',
            refs: [p.id],
            policy: p.displayName,
          });
        }
      }

      // 9. Disabled policies (likely abandoned)
      if (p.state === 'disabled') {
        findings.push({
          ruleId: 'disabled-policy',
          severity: 'low',
          title: 'Disabled CA policy: "' + (p.displayName || p.id) + '"',
          description: 'Policy is in "disabled" state — has no effect.',
          remediation: 'Either enable or delete. Disabled policies clutter the register and can hide misconfiguration.',
          refs: [p.id],
          policy: p.displayName,
        });
      }

      // 10. Block policy without break-glass exclusions
      if (H.isCAEnabled(p) && H.isBlockPolicy(p) && H.targetsAllUsers(p) && !H.hasUserExclusions(p)) {
        findings.push({
          ruleId: 'block-policy-no-exclusion',
          severity: 'high',
          title: 'Block policy targeting All users has no exclusions: "' + (p.displayName || p.id) + '"',
          description: 'Block policies should always exclude at least one break-glass / emergency-access account so a misconfiguration cannot lock you out of the tenant.',
          remediation: 'Add break-glass account(s) to excludeUsers, or a "Break Glass" group to excludeGroups.',
          refs: [p.id],
          policy: p.displayName,
        });
      }
    }

    // 11. Coverage: how many enabled vs report-only vs disabled
    findings.push({
      ruleId: 'coverage-summary',
      severity: 'info',
      title: enabled.length + ' enabled / ' + reportOnly.length + ' report-only / ' + disabled.length + ' disabled CA policies',
      description: 'Enabled policies enforce. Report-only evaluates without enforcing. Disabled policies do nothing.',
      remediation: '',
      refs: [],
    });

    // ── Break-glass account analysis ─────────────────────────────────
    // Aggregate every excluded user / group / role across all CA policies.
    // If the entire tenant has zero exclusions, that's a tenant-lockout risk.

    const excludedUsers  = new Set();
    const excludedGroups = new Set();
    const excludedRoles  = new Set();
    for (const p of policies) {
      const u = (p.conditions && p.conditions.users) || {};
      (u.excludeUsers  || []).forEach(x => excludedUsers.add(x));
      (u.excludeGroups || []).forEach(x => excludedGroups.add(x));
      (u.excludeRoles  || []).forEach(x => excludedRoles.add(x));
    }
    const totalExclusions = excludedUsers.size + excludedGroups.size + excludedRoles.size;

    if (enabled.length > 0 && totalExclusions === 0) {
      findings.push({
        ruleId: 'no-break-glass',
        severity: 'critical',
        title: 'No break-glass / emergency-access exclusions across any CA policy',
        description: 'Not a single Conditional Access policy in this tenant excludes any user, group, or role. A misconfigured policy (or a service outage) can lock out every administrator with no recovery path.',
        remediation: 'Create at least two cloud-only break-glass accounts (passwordless preferred). Add them to a "Break Glass Accounts" security group. Exclude that group from every block-and-MFA policy. Document the accounts with monitored-alert sign-in detection.',
        refs: ['CA02', 'CA03'],
      });
    } else if (enabled.length > 0 && totalExclusions < 2) {
      findings.push({
        ruleId: 'thin-break-glass',
        severity: 'high',
        title: 'Only ' + totalExclusions + ' exclusion across all CA policies — limited break-glass coverage',
        description: 'Microsoft\'s recommendation is at least two break-glass accounts (one isolated from the other) excluded from all enforcing CA policies. If your single excluded principal is unavailable, the tenant locks out.',
        remediation: 'Provision a second break-glass account in a separate naming scheme. Include both in a security group excluded from your block / MFA policies.',
        refs: [],
      });
    } else if (enabled.length > 0) {
      // Inventory: surface what we found so the customer can sanity-check.
      const all = []
        .concat(Array.from(excludedUsers).map(x => 'user: ' + x))
        .concat(Array.from(excludedGroups).map(x => 'group: ' + x))
        .concat(Array.from(excludedRoles).map(x => 'role: ' + x));
      findings.push({
        ruleId: 'break-glass-inventory',
        severity: 'info',
        title: totalExclusions + ' principal' + (totalExclusions > 1 ? 's' : '') + ' excluded across CA policies',
        description: 'Aggregated exclusions detected: ' +
          (excludedUsers.size  > 0 ? excludedUsers.size  + ' user' + (excludedUsers.size  > 1 ? 's' : '') + ' / ' : '') +
          (excludedGroups.size > 0 ? excludedGroups.size + ' group' + (excludedGroups.size > 1 ? 's' : '') + ' / ' : '') +
          (excludedRoles.size  > 0 ? excludedRoles.size  + ' role' + (excludedRoles.size  > 1 ? 's' : '') : '').replace(/ \/ $/, '') +
          '. Verify that these include your designated break-glass accounts and that the tenant is monitored for sign-ins from them.',
        remediation: '',
        refs: all.slice(0, 10),
      });
    }

    return findings;
  });
})();
