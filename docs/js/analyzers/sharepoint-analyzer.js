/* ═══════════════════════════════════════════
   SHAREPOINT ANALYZER — Findings for SharePoint admin tenant settings.
═══════════════════════════════════════════ */
(function () {
  if (typeof Findings === 'undefined') return;

  Findings.register('sharepoint', 'SharePoint / OneDrive', function (data) {
    const H = Findings.helpers;
    const findings = [];
    const state = H.sourceState(data.sharepointSettings);

    if (state === 'scanFailed') {
      return [{
        ruleId: 'spo-scan-failed',
        severity: 'high',
        title: 'SharePoint admin settings could not be scanned',
        description: 'The /v1.0/admin/sharepoint/settings request failed. Most often the App Registration is missing SharePointTenantSettings.Read.All admin consent in this tenant.',
        remediation: 'Add SharePointTenantSettings.Read.All to the App Registration\'s Microsoft Graph permissions and grant admin consent. Reconnect Tenant.',
        refs: [],
      }];
    }
    if (state === 'notScanned' || data.sharepointSettings === undefined) {
      return [{
        ruleId: 'no-spo-settings',
        severity: 'info',
        title: 'SharePoint admin settings not retrieved',
        description: 'No data returned for /admin/sharepoint/settings.',
        remediation: '',
        refs: [],
      }];
    }
    const s = data.sharepointSettings;

    // 1. Anyone-with-the-link sharing
    if (s.sharingCapability === 'externalUserAndGuestSharing') {
      findings.push({
        ruleId: 'anyone-link-allowed',
        severity: 'high',
        title: 'External sharing allows "Anyone with the link"',
        description: 'sharingCapability=externalUserAndGuestSharing permits anonymous links — a frequent source of unintended data exposure.',
        remediation: 'Set sharingCapability to "externalUserSharingOnly" (require sign-in) or "existingExternalUserSharingOnly" (only existing guests).',
        refs: ['SPO01', 'SPO07'],
      });
    }

    // 2. Default link type is anonymous
    if (s.defaultSharingLinkType === 'anonymousAccess') {
      findings.push({
        ruleId: 'default-link-anonymous',
        severity: 'medium',
        title: 'Default sharing link type is "Anyone"',
        description: 'When a user clicks Share, the default option is an anonymous link. Even with anonymous sharing technically allowed, this primes accidental oversharing.',
        remediation: 'Set defaultSharingLinkType to "internal" or "direct".',
        refs: ['SPO02'],
      });
    }

    // 3. Anonymous links never expire
    if (s.sharingCapability !== 'disabled' && s.sharingCapability !== 'existingExternalUserSharingOnly') {
      const exp = s.anonymousLinkExpirationRestrictionDays;
      if (!exp || exp <= 0) {
        findings.push({
          ruleId: 'anonymous-link-no-expiry',
          severity: 'medium',
          title: 'Anonymous sharing links do not expire',
          description: 'Without expiry, an anonymous link shared once persists forever (or until manually revoked).',
          remediation: 'Set anonymousLinkExpirationRestrictionDays to 30 (or shorter for sensitive data).',
          refs: ['SPO03'],
        });
      }
    }

    // 4. Legacy auth allowed
    if (s.isLegacyAuthProtocolsEnabled === true) {
      findings.push({
        ruleId: 'legacy-auth-on',
        severity: 'high',
        title: 'Legacy authentication protocols are allowed in SharePoint',
        description: 'isLegacyAuthProtocolsEnabled=true permits non-modern auth clients (which can\'t be MFA-protected).',
        remediation: 'Set isLegacyAuthProtocolsEnabled to false.',
        refs: ['SPO09'],
      });
    }

    // 5. Unmanaged sync clients not restricted
    if (s.isUnmanagedSyncAppForTenantRestricted !== true) {
      findings.push({
        ruleId: 'unmanaged-sync-allowed',
        severity: 'medium',
        title: 'OneDrive sync allowed on unmanaged devices',
        description: 'OneDrive can sync to any device, including unmanaged personal computers — corporate data leaves the management boundary.',
        remediation: 'Set isUnmanagedSyncAppForTenantRestricted to true. Optionally add allowedDomainGuidsForSyncApp for AD-joined devices.',
        refs: ['SPO14'],
      });
    }

    // 6. Re-sharing by guests permitted
    if (s.isResharingByExternalUsersEnabled === true) {
      findings.push({
        ruleId: 'guest-resharing-on',
        severity: 'medium',
        title: 'Guests can re-share content with other guests',
        description: 'isResharingByExternalUsersEnabled=true means a guest you share a doc with can forward access to other guests, who you didn\'t invite.',
        remediation: 'Set isResharingByExternalUsersEnabled to false.',
        refs: ['SPO19'],
      });
    }

    // 7. Idle session sign-out not configured
    if (!s.idleSessionSignOut || !s.idleSessionSignOut.isEnabled) {
      findings.push({
        ruleId: 'idle-session-not-enforced',
        severity: 'low',
        title: 'No idle-session sign-out for SharePoint',
        description: 'On unmanaged devices, an idle SharePoint tab stays signed in indefinitely. Idle sign-out forces re-auth after inactivity.',
        remediation: 'Enable idleSessionSignOut with a reasonable warnAfter / signOutAfter (e.g. 55min / 60min).',
        refs: ['SPO15'],
      });
    }

    return findings;
  });
})();
