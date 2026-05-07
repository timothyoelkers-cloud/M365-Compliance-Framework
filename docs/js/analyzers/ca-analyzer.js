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

    // ── Known CA bypass detector ─────────────────────────────────────
    // Checks for documented bypass techniques and Microsoft-published
    // exclusions that should (or should NOT) appear in policies.

    // 1. "All resources / All apps" enforcement rollout (Microsoft is
    //    tightening how includeApplications=['All'] interacts with workload
    //    identities & specific service principals — March-June 2026 rollout).
    //    Flag policies using includeApplications=['All'] for potential review.
    const allAppsBlocking = enabled.filter(p =>
      H.targetsAllApps(p) && H.isBlockPolicy(p) && H.targetsAllUsers(p)
    );
    if (allAppsBlocking.length > 1) {
      findings.push({
        ruleId: 'overlapping-block-all',
        severity: 'medium',
        title: allAppsBlocking.length + ' enabled "block All users + All apps" policies overlap',
        description: 'Microsoft\'s low-privilege scope enforcement (rolling out 2026) changes how multiple "All" policies interact. Overlapping block-all policies risk conflicting evaluations and unintended fall-through. Microsoft recommends consolidating into one policy with focused exclusions.',
        remediation: 'Consolidate the block-all policies. Keep a single canonical "block legacy auth" policy and a single canonical "block high-risk" policy. Move other "All apps" policies to specific app targeting.',
        refs: allAppsBlocking.map(p => p.id),
      });
    }

    // 2. FOCI risk — when a CA policy excludes a specific Microsoft app,
    //    apps in the same Family of Client IDs share refresh tokens and
    //    can therefore inherit the exclusion. Detect any policy that excludes
    //    apps in the well-known FOCI families.
    const FOCI_APPS = {
      // Microsoft Office FOCI family — sharing this token means Outlook,
      // Teams, OneDrive, Word, Excel, PowerPoint can all use it.
      '1fec8e78-bce4-4aaf-ab1b-5451cc387264': 'Microsoft Teams',
      'd3590ed6-52b3-4102-aeff-aad2292ab01c': 'Microsoft Office',
      '00000003-0000-0ff1-ce00-000000000000': 'Microsoft Office',
      'fb78d390-0c51-40cd-8e17-fdbfab77341b': 'Microsoft Exchange REST API',
      '00b41c95-dab0-4487-9791-b9d2c32c80f2': 'Office 365 Management',
    };
    for (const p of enabled) {
      const excludedApps = (p.conditions && p.conditions.applications && p.conditions.applications.excludeApplications) || [];
      const focis = excludedApps.filter(id => FOCI_APPS[id]);
      if (focis.length > 0) {
        findings.push({
          ruleId: 'foci-app-excluded',
          severity: 'medium',
          title: 'FOCI app excluded from CA policy: "' + (p.displayName || p.id) + '"',
          description: 'Excluding ' + focis.map(id => FOCI_APPS[id]).join(', ') + ' allows token sharing across the entire Microsoft Office FOCI family — an attacker compromising one app inherits the exclusion for all of them. Microsoft documents this as a known risk pattern.',
          remediation: 'Remove the FOCI app from excludeApplications. If the user-experience reason for the exclusion is real, narrow the policy by user/group instead of by app.',
          refs: [p.id],
        });
      }
    }

    // 3. MS Learn-documented service principals that should be excluded
    //    Some Microsoft service principals (esp. directory sync) need
    //    exclusion from MFA-blocking policies for the platform to function.
    //    We flag MFA-required-on-all policies that DON'T exclude them.
    const RECOMMENDED_EXCLUSION_SPS = {
      '00000004-0000-0ff1-ce00-000000000000': 'Microsoft Exchange Online',  // for legacy hybrid setups
      // Note: for app-only policies most service principals SHOULD NOT be
      // excluded blanket-fashion — these checks are case-by-case.
    };
    // (Intentionally empty for now — placeholder for the catalogue. Customers
    // can add their own via documentation rather than run unwanted checks.)

    // 4. Report-only that overlaps an enforcing policy on the same scope.
    //    A common mistake: leave a report-only "draft" running alongside its
    //    enforced counterpart, which clutters the sign-in logs.
    for (const ro of reportOnly) {
      const roApps = ((ro.conditions || {}).applications || {}).includeApplications || [];
      const roUsers = ((ro.conditions || {}).users || {}).includeUsers || [];
      const overlap = enabled.find(en => {
        const eApps = ((en.conditions || {}).applications || {}).includeApplications || [];
        const eUsers = ((en.conditions || {}).users || {}).includeUsers || [];
        const sameApps = roApps.length > 0 && eApps.length > 0 &&
          roApps.some(a => eApps.indexOf(a) !== -1);
        const sameUsers = roUsers.length > 0 && eUsers.length > 0 &&
          roUsers.some(u => eUsers.indexOf(u) !== -1);
        return sameApps && sameUsers;
      });
      if (overlap) {
        findings.push({
          ruleId: 'report-only-overlaps-enabled',
          severity: 'low',
          title: 'Report-only policy overlaps an enabled policy: "' + (ro.displayName || ro.id) + '"',
          description: 'This report-only policy targets the same users/apps as the enabled policy "' + (overlap.displayName || overlap.id) + '". Sign-in logs will be cluttered with redundant evaluations.',
          remediation: 'Either retire the report-only policy if its evaluation is complete, or narrow its scope so it tests something different.',
          refs: [ro.id, overlap.id],
        });
      }
    }

    // 5. CA "agents" scope (preview) — Microsoft is still rolling this out.
    //    Detect policies using the experimental Servicw Principal scope/etc.
    for (const p of enabled) {
      const cap = p.conditions || {};
      if (cap.clientApplications && (cap.clientApplications.includeServicePrincipals || []).length > 0) {
        findings.push({
          ruleId: 'workload-id-policy',
          severity: 'info',
          title: 'Workload-identity CA policy active: "' + (p.displayName || p.id) + '"',
          description: 'This policy targets specific service principals (workload identities). Workload Identity Premium licence required. Verify the service principals listed are still appropriate for your environment — orphan SPs accumulate over time.',
          remediation: 'Review the includeServicePrincipals list quarterly. Remove SPs that no longer represent active integrations.',
          refs: [p.id],
        });
      }
    }

    return findings;
  });
})();
