/* ═══════════════════════════════════════════
   INTUNE ANALYZER — Findings for Intune device management.
═══════════════════════════════════════════ */
(function () {
  if (typeof Findings === 'undefined') return;

  Findings.register('intune', 'Intune / Device Management', function (data) {
    const H = Findings.helpers;
    const findings = [];

    // Surface scan failures explicitly — don't silently report "tenant has no Intune".
    const stateCompliance = H.sourceState(data.compliancePolicies);
    const stateDevice     = H.sourceState(data.deviceConfigurations);
    const stateConfig     = H.sourceState(data.configurationPolicies);
    const allFailed = stateCompliance === 'scanFailed' && stateDevice === 'scanFailed' && stateConfig === 'scanFailed';
    if (allFailed) {
      return [{
        ruleId: 'intune-scan-failed',
        severity: 'high',
        title: 'Intune endpoints could not be scanned',
        description: 'All Intune Graph endpoints (compliance, device-configuration, configuration-policies) returned errors. Likely an auth/permissions issue rather than a tenant with no Intune.',
        remediation: 'Verify the App Registration has DeviceManagementConfiguration.Read.All and DeviceManagementManagedDevices.Read.All admin-consented. Reconnect Tenant.',
        refs: [],
      }];
    }

    const compliance = stateCompliance === 'scanned' ? data.compliancePolicies : [];
    const config     = stateDevice === 'scanned' ? data.deviceConfigurations : [];
    const policies   = stateConfig === 'scanned' ? data.configurationPolicies : [];

    // 1. No compliance policies at all (only when we actually retrieved the endpoint)
    if (stateCompliance === 'scanned' && H.isGenuinelyEmpty(data.compliancePolicies)) {
      findings.push({
        ruleId: 'no-compliance-policies',
        severity: 'critical',
        title: 'No Intune device-compliance policies',
        description: 'Without compliance policies, Conditional Access "require compliant device" cannot enforce anything. Devices report as unknown and may be allowed by default.',
        remediation: 'Create compliance policies for each device platform you support: Windows, macOS, iOS, Android. At minimum require encryption, OS minimum version, and password complexity.',
        refs: ['IN01', 'IN02', 'IN03'],
      });
    } else if (stateCompliance === 'scanFailed') {
      findings.push({
        ruleId: 'compliance-scan-failed',
        severity: 'high',
        title: 'Intune compliance policies could not be scanned',
        description: 'The /v1.0/deviceManagement/deviceCompliancePolicies endpoint errored. The tenant may have policies — we just can\'t see them.',
        remediation: 'Verify DeviceManagementConfiguration.Read.All admin consent. Reconnect Tenant.',
        refs: [],
      });
    }
    if (compliance.length > 0) {
      // 2. Coverage gaps by platform
      const platforms = ['windows10', 'macOS', 'iOS', 'androidWorkProfile', 'android'];
      const detectedPlatforms = new Set();
      compliance.forEach(p => {
        const t = (p['@odata.type'] || '').toLowerCase();
        if (t.indexOf('windows') !== -1) detectedPlatforms.add('Windows');
        else if (t.indexOf('macos') !== -1) detectedPlatforms.add('macOS');
        else if (t.indexOf('ios') !== -1) detectedPlatforms.add('iOS');
        else if (t.indexOf('android') !== -1) detectedPlatforms.add('Android');
      });
      const missingPlatforms = ['Windows', 'macOS', 'iOS', 'Android'].filter(p => !detectedPlatforms.has(p));
      if (missingPlatforms.length) {
        findings.push({
          ruleId: 'compliance-platform-gaps',
          severity: 'medium',
          title: 'Compliance policies missing for: ' + missingPlatforms.join(', '),
          description: 'Each device platform that signs into M365 needs its own compliance policy. Otherwise CA "require compliant device" allows unmanaged devices on those platforms.',
          remediation: 'Create one compliance policy per missing platform with a baseline of: encryption required, OS minimum version, password/PIN required.',
          refs: ['IN01', 'IN02', 'IN03'],
        });
      }
    }

    // 3. No device configurations — only when we actually retrieved both endpoints
    const bothConfigsScanned = stateDevice === 'scanned' && stateConfig === 'scanned';
    if (bothConfigsScanned && !config.length && !policies.length) {
      findings.push({
        ruleId: 'no-device-config',
        severity: 'high',
        title: 'No device-configuration profiles',
        description: 'No baseline configuration is enforced on managed devices. Disk encryption, Defender, BitLocker, firewall, etc. are only as configured as their default state.',
        remediation: 'Apply Microsoft\'s baseline templates (Windows security baseline, macOS, iOS) via Endpoint Security or Settings Catalog.',
        refs: [],
      });
    }

    // 4. Compliance policies that don't actually mark non-compliant
    compliance.forEach(p => {
      if (!p.scheduledActionsForRule || !p.scheduledActionsForRule.length) {
        findings.push({
          ruleId: 'compliance-no-actions',
          severity: 'medium',
          title: 'Compliance policy has no scheduled actions: "' + (p.displayName || p.id) + '"',
          description: 'Without actions (e.g. mark non-compliant after grace period), the policy detects but never enforces. Devices stay "unknown" instead of being blocked.',
          remediation: 'Add a default scheduledActionsForRule: { actionType: "block", gracePeriodHours: 0 }.',
          refs: [p.id],
        });
      }
    });

    return findings;
  });
})();
