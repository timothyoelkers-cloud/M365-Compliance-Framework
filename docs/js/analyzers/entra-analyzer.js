/* ═══════════════════════════════════════════
   ENTRA ANALYZER — Findings for Entra ID directory + auth settings.
═══════════════════════════════════════════ */
(function () {
  if (typeof Findings === 'undefined') return;

  Findings.register('entra', 'Entra ID', function (data) {
    const H = Findings.helpers;
    const findings = [];

    // Surface scan failures rather than silently skipping checks.
    if (H.sourceState(data.authorizationPolicy) === 'scanFailed') {
      findings.push({
        ruleId: 'authorization-policy-scan-failed',
        severity: 'high',
        title: 'Entra authorization policy could not be scanned',
        description: 'The /v1.0/policies/authorizationPolicy request failed. Likely missing Policy.Read.All consent.',
        remediation: 'Verify Policy.Read.All admin consent for the App Registration in this tenant.',
        refs: [],
      });
    }

    const auth = data.authorizationPolicy || null;
    const consent = data.adminConsentPolicy || null;
    const authMethods = data.authMethodsPolicy || null;
    const orgList = Array.isArray(data.organization) ? data.organization : [];
    const org = orgList[0];

    // 1. Users can consent to apps on their own (risky)
    if (auth && auth.defaultUserRolePermissions) {
      const allowed = auth.defaultUserRolePermissions.permissionGrantPoliciesAssigned || [];
      const userConsentPermitted = allowed.some(p => /user-default/i.test(p));
      if (userConsentPermitted) {
        findings.push({
          ruleId: 'user-consent-allowed',
          severity: 'high',
          title: 'Users can consent to third-party apps without admin review',
          description: 'authorizationPolicy.defaultUserRolePermissions allows users to grant scopes to Entra-registered apps. This is the OAuth phishing risk — attackers register a benign-named app and request Mail.Read, then send a consent link.',
          remediation: 'Set "User consent for applications" to "Do not allow user consent" or "Allow user consent for verified publishers". Configure admin consent requests so users can request, but admin approves.',
          refs: ['ENT01', 'ENT02'],
        });
      }
    }

    // 2. Users can register apps (often unnecessary, broadens attack surface)
    if (auth && auth.defaultUserRolePermissions && auth.defaultUserRolePermissions.allowedToCreateApps) {
      findings.push({
        ruleId: 'users-can-register-apps',
        severity: 'medium',
        title: 'Users can register applications in Entra',
        description: 'allowedToCreateApps=true means any user can create an app registration. Combined with user consent, this is the OAuth attack chain in one tenant.',
        remediation: 'Set authorizationPolicy.defaultUserRolePermissions.allowedToCreateApps to false. Only admins should register apps.',
        refs: ['ENT03'],
      });
    }

    // 3. Guests can invite other guests (uncommonly desirable)
    if (auth && auth.allowInvitesFrom && /everyone|adminsAndGuestInviters|all/i.test(auth.allowInvitesFrom)) {
      findings.push({
        ruleId: 'guests-can-invite',
        severity: 'medium',
        title: 'allowInvitesFrom is "' + auth.allowInvitesFrom + '"',
        description: 'External users / guests can invite further guests. Reduces the boundary on guest sprawl.',
        remediation: 'Set allowInvitesFrom to "adminsAndGuestInviters" or "none".',
        refs: ['ENT04'],
      });
    }

    // 4. Admin consent workflow not enabled
    if (consent && consent.isEnabled === false) {
      findings.push({
        ruleId: 'admin-consent-workflow-off',
        severity: 'low',
        title: 'Admin consent request workflow is disabled',
        description: 'Users can\'t request admin consent for apps they need. They\'ll either bypass policy or pester an admin via email — both worse than a tracked request.',
        remediation: 'Enable adminConsentRequestPolicy with reviewers (Global Admin or Cloud App Admin role).',
        refs: ['ENT05'],
      });
    }

    // 5. Self-service password reset not configured (often via authMethodsPolicy)
    if (authMethods && Array.isArray(authMethods.authenticationMethodConfigurations)) {
      const enabled = authMethods.authenticationMethodConfigurations.filter(m => m.state === 'enabled').map(m => m.id);
      if (enabled.indexOf('MicrosoftAuthenticator') === -1) {
        findings.push({
          ruleId: 'authenticator-app-not-enabled',
          severity: 'medium',
          title: 'Microsoft Authenticator method is not enabled',
          description: 'The authenticator app is the most secure of the standard MFA options. If only SMS or voice is enabled, MFA is bypassable via SIM-swap.',
          remediation: 'Enable Microsoft Authenticator in the authentication-methods policy. Disable SMS / voice except for break-glass.',
          refs: ['ENT06'],
        });
      }
    }

    // 6. On-prem sync (security-relevant context)
    if (org && org.onPremisesSyncEnabled) {
      findings.push({
        ruleId: 'on-prem-sync-active',
        severity: 'info',
        title: 'On-premises directory sync is active',
        description: 'Entra Connect is syncing from on-premises AD. Make sure the AD environment has the same security baselines (LAPS, tier-0 protection, etc.) — the cloud is only as secure as the source.',
        remediation: '',
        refs: [],
      });
    }

    return findings;
  });
})();
