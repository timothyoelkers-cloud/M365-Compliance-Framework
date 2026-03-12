/* ═══════════════════════════════════════════
   TEST FIXTURES — Mock scan data for every
   scannable policy rule in MATCH_RULES.
   Each rule has a "configured" fixture (should match)
   and a "missing" fixture (should NOT match).
═══════════════════════════════════════════ */
window.TEST_FIXTURES = {

  // ─────────────────────────────────────────────────────────
  //  CONDITIONAL ACCESS (CA01–CA18)
  //  scanSource: 'conditionalAccess', matchMode: 'any'
  //  Each item in the array is a CA policy object.
  //  ALL conditions in a rule must match on a SINGLE item.
  // ─────────────────────────────────────────────────────────

  CA01: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Block Legacy Authentication',
        conditions: { clientAppTypes: ['exchangeActiveSync', 'other'] },
        grantControls: { builtInControls: ['block'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { clientAppTypes: ['browser'] },
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA02: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require MFA for All Users',
        conditions: { users: { includeUsers: ['All'] } },
        grantControls: { builtInControls: ['mfa'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { users: { includeUsers: ['user1@contoso.com'] } },
        grantControls: { builtInControls: ['block'] }
      }]
    }
  },

  CA03: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require Phishing-Resistant MFA for Admins',
        conditions: { users: { includeRoles: ['62e90394-69f5-4237-9190-012177145e10'] } },
        grantControls: { authenticationStrength: { id: 'phishing-resistant' } }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { users: { includeRoles: [] } },
        grantControls: {}
      }]
    }
  },

  CA04: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Block High Sign-In Risk',
        conditions: { signInRiskLevels: ['high'] },
        grantControls: { builtInControls: ['block'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { signInRiskLevels: ['low'] },
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA05: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require Password Change for High User Risk',
        conditions: { userRiskLevels: ['high'] },
        grantControls: { builtInControls: ['passwordChange'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { userRiskLevels: ['low'] },
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA06: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require Compliant Device',
        conditions: {},
        grantControls: { builtInControls: ['compliantDevice'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {},
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA07: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Block Untrusted Locations',
        conditions: { locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } },
        grantControls: { builtInControls: ['block'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {},
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA08: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require MFA for Azure Management',
        conditions: { applications: { includeApplications: ['797f4846-ba00-4fd7-ba43-dac1f8f63013'] } },
        grantControls: { builtInControls: ['mfa'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { applications: { includeApplications: ['00000003-0000-0000-c000-000000000000'] } },
        grantControls: { builtInControls: ['block'] }
      }]
    }
  },

  CA09: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require Approved Client App',
        conditions: {},
        grantControls: { builtInControls: ['approvedApplication'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {},
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA10: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Block All Apps Except Exclusions',
        conditions: {
          applications: {
            includeApplications: ['All'],
            excludeApplications: ['00000003-0000-0000-c000-000000000000']
          }
        },
        grantControls: { builtInControls: ['block'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {
          applications: {
            includeApplications: ['some-app'],
            excludeApplications: []
          }
        },
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA11: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Block Specific Applications',
        conditions: { applications: { includeApplications: ['app1'] } },
        grantControls: { builtInControls: ['block'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {},
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA12: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require MFA for Guest Users',
        conditions: { users: { includeGuestsOrExternalUsers: { guestOrExternalUserTypes: 'b2bCollaborationGuest' } } },
        grantControls: { builtInControls: ['mfa'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { users: {} },
        grantControls: { builtInControls: ['block'] }
      }]
    }
  },

  CA13: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Sign-In Frequency Policy',
        conditions: {},
        sessionControls: { signInFrequency: { value: 4, type: 'hours', isEnabled: true } },
        grantControls: {}
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {},
        sessionControls: {},
        grantControls: {}
      }]
    }
  },

  CA14: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require MFA for Admin Roles',
        conditions: { users: { includeRoles: ['62e90394-69f5-4237-9190-012177145e10'] } },
        grantControls: { builtInControls: ['mfa'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { users: { includeRoles: [] } },
        grantControls: { builtInControls: ['block'] }
      }]
    }
  },

  CA15: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Persistent Browser Session Control',
        conditions: {},
        sessionControls: { persistentBrowser: { mode: 'never', isEnabled: true } },
        grantControls: {}
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {},
        sessionControls: {},
        grantControls: {}
      }]
    }
  },

  CA16: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Block Unsupported Platforms',
        conditions: {
          platforms: { includePlatforms: ['all'], excludePlatforms: ['windows', 'iOS'] },
          clientAppTypes: ['mobileAppsAndDesktopClients']
        },
        grantControls: { builtInControls: ['block'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {
          clientAppTypes: ['browser']
        },
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  CA17: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Require MFA for Medium Sign-In Risk',
        conditions: { signInRiskLevels: ['medium'] },
        grantControls: { builtInControls: ['mfa'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: { signInRiskLevels: ['low'] },
        grantControls: { builtInControls: ['block'] }
      }]
    }
  },

  CA18: {
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Block Exchange ActiveSync',
        conditions: {
          clientAppTypes: ['exchangeActiveSync'],
          applications: { includeApplications: ['All'] }
        },
        grantControls: { builtInControls: ['block'] }
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        conditions: {
          clientAppTypes: ['browser'],
        },
        grantControls: { builtInControls: ['mfa'] }
      }]
    }
  },

  // ─────────────────────────────────────────────────────────
  //  ENTRA ID (ENT01–ENT10)
  //  Various singleton scan sources, matchMode: 'direct' or 'any'
  // ─────────────────────────────────────────────────────────

  ENT01: {
    // scanSource: 'authorizationPolicy', matchMode: 'direct'
    // condition: defaultUserRolePermissions.permissionGrantPoliciesAssigned isEmpty
    configured: {
      authorizationPolicy: {
        displayName: 'Authorization Policy',
        defaultUserRolePermissions: {
          permissionGrantPoliciesAssigned: []
        }
      }
    },
    missing: {
      authorizationPolicy: {
        displayName: 'Authorization Policy',
        defaultUserRolePermissions: {
          permissionGrantPoliciesAssigned: ['ManagePermissionGrantsForSelf.microsoft-user-default-low']
        }
      }
    }
  },

  ENT02: {
    // scanSource: 'adminConsentPolicy', matchMode: 'direct'
    // condition: isEnabled equals true
    configured: {
      adminConsentPolicy: {
        displayName: 'Admin Consent Policy',
        isEnabled: true
      }
    },
    missing: {
      adminConsentPolicy: {
        displayName: 'Admin Consent Policy',
        isEnabled: false
      }
    }
  },

  ENT03: {
    // scanSource: 'authorizationPolicy', matchMode: 'direct'
    // condition: defaultUserRolePermissions.allowedToCreateApps equals false
    configured: {
      authorizationPolicy: {
        displayName: 'Authorization Policy',
        defaultUserRolePermissions: {
          allowedToCreateApps: false
        }
      }
    },
    missing: {
      authorizationPolicy: {
        displayName: 'Authorization Policy',
        defaultUserRolePermissions: {
          allowedToCreateApps: true
        }
      }
    }
  },

  ENT04: {
    // scanSource: 'groupSettings', matchMode: 'any'
    // condition: displayName equals 'Password Rule Settings'
    configured: {
      groupSettings: [
        { displayName: 'Password Rule Settings', id: 'gs-001' }
      ]
    },
    missing: {
      groupSettings: [
        { displayName: 'Group.Unified.Guest', id: 'gs-002' }
      ]
    }
  },

  ENT05: {
    // scanSource: 'deviceRegistrationPolicy', matchMode: 'direct'
    // condition: userDeviceQuota exists
    configured: {
      deviceRegistrationPolicy: {
        displayName: 'Device Registration Policy',
        userDeviceQuota: 50
      }
    },
    missing: {
      deviceRegistrationPolicy: {
        displayName: 'Device Registration Policy'
      }
    }
  },

  ENT06: {
    // scanSource: 'authorizationPolicy', matchMode: 'direct'
    // condition: allowInvitesFrom equals 'adminsAndGuestInviters'
    configured: {
      authorizationPolicy: {
        displayName: 'Authorization Policy',
        allowInvitesFrom: 'adminsAndGuestInviters'
      }
    },
    missing: {
      authorizationPolicy: {
        displayName: 'Authorization Policy',
        allowInvitesFrom: 'everyone'
      }
    }
  },

  ENT07: {
    // scanSource: 'authMethodsPolicy', matchMode: 'direct'
    // condition: registrationEnforcement.authenticationMethodsRegistrationCampaign exists
    configured: {
      authMethodsPolicy: {
        displayName: 'Auth Methods Policy',
        registrationEnforcement: {
          authenticationMethodsRegistrationCampaign: {
            state: 'enabled',
            snoozeDurationInDays: 0
          }
        }
      }
    },
    missing: {
      authMethodsPolicy: {
        displayName: 'Auth Methods Policy',
        registrationEnforcement: {}
      }
    }
  },

  ENT08: {
    // scanSource: 'groupSettings', matchMode: 'any'
    // condition: displayName equals 'Group.Unified'
    configured: {
      groupSettings: [
        { displayName: 'Group.Unified', id: 'gs-003' }
      ]
    },
    missing: {
      groupSettings: [
        { displayName: 'Password Rule Settings', id: 'gs-001' }
      ]
    }
  },

  ENT09: {
    // scanSource: 'organization', matchMode: 'any'
    // condition: id exists
    configured: {
      organization: [
        { id: 'org-12345', displayName: 'Contoso' }
      ]
    },
    missing: {
      organization: [
        { displayName: 'Contoso' }
      ]
    }
  },

  ENT10: {
    // scanSource: 'authenticatorConfig', matchMode: 'direct'
    // condition: featureSettings.numberMatchingRequiredState.state equals 'enabled'
    configured: {
      authenticatorConfig: {
        displayName: 'Microsoft Authenticator',
        featureSettings: {
          numberMatchingRequiredState: { state: 'enabled' }
        }
      }
    },
    missing: {
      authenticatorConfig: {
        displayName: 'Microsoft Authenticator',
        featureSettings: {
          numberMatchingRequiredState: { state: 'disabled' }
        }
      }
    }
  },

  // ─────────────────────────────────────────────────────────
  //  INTUNE — Compliance Policies (INT01–INT04)
  //  scanSource: 'compliancePolicies', matchMode: 'any'
  // ─────────────────────────────────────────────────────────

  'INT01-Device-Compliance-Windows-Baseline': {
    configured: {
      compliancePolicies: [{
        '@odata.type': '#microsoft.graph.windows10CompliancePolicy',
        displayName: 'Windows 10 Compliance Baseline',
        id: 'cp-win10'
      }]
    },
    missing: {
      compliancePolicies: [{
        '@odata.type': '#microsoft.graph.iosCompliancePolicy',
        displayName: 'iOS Compliance Baseline',
        id: 'cp-ios'
      }]
    }
  },

  'INT02-Device-Compliance-iOS-Baseline': {
    configured: {
      compliancePolicies: [{
        '@odata.type': '#microsoft.graph.iosCompliancePolicy',
        displayName: 'iOS Compliance Baseline',
        id: 'cp-ios'
      }]
    },
    missing: {
      compliancePolicies: [{
        '@odata.type': '#microsoft.graph.windows10CompliancePolicy',
        displayName: 'Windows 10 Compliance',
        id: 'cp-win10'
      }]
    }
  },

  'INT03-Device-Compliance-Android-Baseline': {
    configured: {
      compliancePolicies: [{
        '@odata.type': '#microsoft.graph.androidWorkProfileCompliancePolicy',
        displayName: 'Android Work Profile Compliance',
        id: 'cp-android'
      }]
    },
    missing: {
      compliancePolicies: [{
        '@odata.type': '#microsoft.graph.windows10CompliancePolicy',
        displayName: 'Windows 10 Compliance',
        id: 'cp-win10'
      }]
    }
  },

  'INT04-Device-Compliance-macOS-Baseline': {
    configured: {
      compliancePolicies: [{
        '@odata.type': '#microsoft.graph.macOSCompliancePolicy',
        displayName: 'macOS Compliance Baseline',
        id: 'cp-macos'
      }]
    },
    missing: {
      compliancePolicies: [{
        '@odata.type': '#microsoft.graph.windows10CompliancePolicy',
        displayName: 'Windows 10 Compliance',
        id: 'cp-win10'
      }]
    }
  },

  // ─────────────────────────────────────────────────────────
  //  INTUNE — Device Configuration Policies (INT05–INT20)
  //  scanSource: 'deviceConfigurations', matchMode: 'any'
  // ─────────────────────────────────────────────────────────

  'INT05-BitLocker-Encryption-Policy': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'BitLocker Encryption',
        id: 'dc-bitlocker',
        bitLockerEncryptDevice: true
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Some Windows Config',
        id: 'dc-other',
        bitLockerEncryptDevice: false
      }]
    }
  },

  'INT06-Windows-LAPS-Local-Admin-Password': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10CustomConfiguration',
        displayName: 'Windows LAPS Configuration',
        id: 'dc-laps'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10CustomConfiguration',
        displayName: 'Windows Firewall Settings',
        id: 'dc-fw'
      }]
    }
  },

  'INT07-Defender-AV-Configuration-Windows': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'Defender AV Config',
        id: 'dc-av',
        defenderMonitorFileActions: true
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'General Config',
        id: 'dc-gen'
      }]
    }
  },

  'INT08-Windows-Update-Ring-Policy': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windowsUpdateForBusinessConfiguration',
        displayName: 'Windows Update Ring - Production',
        id: 'dc-wufb'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'General Config',
        id: 'dc-gen'
      }]
    }
  },

  'INT09-App-Protection-Policy-iOS-Android': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.iosManagedAppProtection',
        displayName: 'iOS App Protection Policy',
        id: 'dc-mam-ios'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'General Config',
        id: 'dc-gen'
      }]
    }
  },

  'INT10-Device-Enrollment-Restrictions': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration',
        displayName: 'Enrollment Platform Restrictions',
        id: 'dc-enroll'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'General Config',
        id: 'dc-gen'
      }]
    }
  },

  'INT11-Windows-Security-Baseline-CIS': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'Windows 11 Security Baseline (CIS)',
        id: 'dc-cis'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'Windows General Configuration',
        id: 'dc-gen'
      }]
    }
  },

  'INT12-Microsoft-Edge-Security-Baseline': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'Microsoft Edge Security Baseline',
        id: 'dc-edge'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'Windows Firewall Config',
        id: 'dc-fw'
      }]
    }
  },

  'INT13-Windows-Hello-For-Business': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windowsIdentityProtectionConfiguration',
        displayName: 'Windows Hello for Business',
        id: 'dc-whfb'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'General Config',
        id: 'dc-gen'
      }]
    }
  },

  'INT14-Firewall-Policy-Windows': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Windows Firewall Policy',
        id: 'dc-fw',
        firewallBlockAllIncoming: true
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Windows Endpoint Protection',
        id: 'dc-ep'
      }]
    }
  },

  'INT15-Attack-Surface-Reduction-Rules': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'ASR Rules',
        id: 'dc-asr',
        defenderAttackSurfaceReductionRules: [{ id: 'rule1', state: 'block' }]
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Endpoint Protection',
        id: 'dc-ep'
      }]
    }
  },

  'INT16-Credential-Guard-Windows': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Credential Guard',
        id: 'dc-cg',
        deviceGuardEnableVirtualizationBasedSecurity: true
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Endpoint Protection',
        id: 'dc-ep'
      }]
    }
  },

  'INT17-Removable-Storage-Control': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'Removable Storage Block',
        id: 'dc-usb',
        storageBlockRemovableStorage: true
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'General Config',
        id: 'dc-gen'
      }]
    }
  },

  'INT18-Windows-Diagnostic-Data-Limit': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'Diagnostic Data Restriction',
        id: 'dc-diag',
        diagnosticsDataSubmissionMode: 'basic'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10GeneralConfiguration',
        displayName: 'General Config',
        id: 'dc-gen'
      }]
    }
  },

  'INT19-Exploit-Protection-Policy': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Exploit Protection',
        id: 'dc-exploit',
        defenderExploitProtectionXml: '<ExploitProtection />'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Endpoint Protection',
        id: 'dc-ep'
      }]
    }
  },

  'INT20-Controlled-Folder-Access': {
    configured: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Controlled Folder Access',
        id: 'dc-cfa',
        defenderGuardedFoldersEnableControlledFolderAccess: 'enable'
      }]
    },
    missing: {
      deviceConfigurations: [{
        '@odata.type': '#microsoft.graph.windows10EndpointProtectionConfiguration',
        displayName: 'Endpoint Protection',
        id: 'dc-ep'
      }]
    }
  },

  // ─────────────────────────────────────────────────────────
  //  DEFENDER FOR ENDPOINT (MDE01–MDE12)
  //  scanSource: 'configurationPolicies', matchMode: 'any'
  // ─────────────────────────────────────────────────────────

  MDE01: {
    configured: {
      configurationPolicies: [{
        name: 'Endpoint Security Antivirus',
        id: 'cp-av',
        templateReference: { templateFamily: 'endpointSecurityAntivirus' }
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'General Configuration',
        id: 'cp-gen',
        templateReference: { templateFamily: 'deviceConfiguration' }
      }]
    }
  },

  MDE02: {
    configured: {
      configurationPolicies: [{
        name: 'macOS Endpoint Protection',
        id: 'cp-macos'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Windows Endpoint Protection',
        id: 'cp-win'
      }]
    }
  },

  MDE03: {
    configured: {
      configurationPolicies: [{
        name: 'iOS Mobile Threat Defense',
        id: 'cp-ios'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Windows Endpoint Protection',
        id: 'cp-win'
      }]
    }
  },

  MDE04: {
    configured: {
      configurationPolicies: [{
        name: 'EDR Block Mode Configuration',
        id: 'cp-edr'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  MDE05: {
    configured: {
      configurationPolicies: [{
        name: 'Automated Investigation and Response (AIR)',
        id: 'cp-air'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  MDE06: {
    configured: {
      configurationPolicies: [{
        name: 'Threat and Vulnerability Management (TVM)',
        id: 'cp-tvm'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  MDE07: {
    configured: {
      configurationPolicies: [{
        name: 'Network Protection Policy',
        id: 'cp-np'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  MDE08: {
    configured: {
      configurationPolicies: [{
        name: 'Web Content Filtering',
        id: 'cp-wcf'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  MDE09: {
    configured: {
      configurationPolicies: [{
        name: 'Tamper Protection Configuration',
        id: 'cp-tamper'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  MDE10: {
    configured: {
      configurationPolicies: [{
        name: 'Alert Notification Rules',
        id: 'cp-alert'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  MDE11: {
    configured: {
      configurationPolicies: [{
        name: 'Deception Rules Configuration',
        id: 'cp-deception'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  MDE12: {
    configured: {
      configurationPolicies: [{
        name: 'Threat Intelligence TAXII Feed',
        id: 'cp-ti'
      }]
    },
    missing: {
      configurationPolicies: [{
        name: 'Antivirus Configuration',
        id: 'cp-av'
      }]
    }
  },

  // ─────────────────────────────────────────────────────────
  //  SHAREPOINT ONLINE — Scannable rules (SPO01, SPO07–SPO09, SPO13, SPO15, SPO19)
  //  scanSource: 'sharepointSettings', matchMode: 'direct'
  // ─────────────────────────────────────────────────────────

  SPO01: {
    configured: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        sharingCapability: 'existingExternalUserSharingOnly'
      }
    },
    missing: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        sharingCapability: 'externalUserAndGuestSharing'
      }
    }
  },

  SPO07: {
    // conditions: sharingCapability containsAny [...], isRequireAcceptingUserToMatchInvitedUserEnabled equals true
    configured: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        sharingCapability: 'existingExternalUserSharingOnly',
        isRequireAcceptingUserToMatchInvitedUserEnabled: true
      }
    },
    missing: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        sharingCapability: 'externalUserAndGuestSharing',
        isRequireAcceptingUserToMatchInvitedUserEnabled: false
      }
    }
  },

  SPO08: {
    // condition: isUnmanagedSyncAppForTenantRestricted equals true
    configured: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        isUnmanagedSyncAppForTenantRestricted: true
      }
    },
    missing: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        isUnmanagedSyncAppForTenantRestricted: false
      }
    }
  },

  SPO09: {
    // condition: isLegacyAuthProtocolsEnabled equals false
    configured: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        isLegacyAuthProtocolsEnabled: false
      }
    },
    missing: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        isLegacyAuthProtocolsEnabled: true
      }
    }
  },

  SPO13: {
    // conditions: sharingDomainRestrictionMode equals 'allowList', sharingAllowedDomainList isNotEmpty
    configured: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        sharingDomainRestrictionMode: 'allowList',
        sharingAllowedDomainList: 'contoso.com fabrikam.com'
      }
    },
    missing: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        sharingDomainRestrictionMode: 'none',
        sharingAllowedDomainList: ''
      }
    }
  },

  SPO15: {
    // condition: idleSessionSignOut.isEnabled equals true
    configured: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        idleSessionSignOut: { isEnabled: true, warnAfterInSeconds: 2700, signOutAfterInSeconds: 3600 }
      }
    },
    missing: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        idleSessionSignOut: { isEnabled: false }
      }
    }
  },

  SPO19: {
    // condition: isResharingByExternalUsersEnabled equals false
    configured: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        isResharingByExternalUsersEnabled: false
      }
    },
    missing: {
      sharepointSettings: {
        displayName: 'SharePoint Settings',
        isResharingByExternalUsersEnabled: true
      }
    }
  },

  // ─────────────────────────────────────────────────────────
  //  PURVIEW — Scannable rules (PV10, PV14)
  //  scanSource: 'sensitivityLabels', matchMode: 'any'
  // ─────────────────────────────────────────────────────────

  PV10: {
    // condition: name exists
    configured: {
      sensitivityLabels: [
        { name: 'Confidential', id: 'sl-001', displayName: 'Confidential' }
      ]
    },
    missing: {
      sensitivityLabels: [
        { id: 'sl-002', displayName: 'Unnamed Label' }
      ]
    }
  },

  PV14: {
    // condition: contentFormats containsAny ['site', 'unifiedGroup', 'group']
    configured: {
      sensitivityLabels: [
        { name: 'Groups and Sites', id: 'sl-003', contentFormats: ['site', 'unifiedGroup'] }
      ]
    },
    missing: {
      sensitivityLabels: [
        { name: 'File Only Label', id: 'sl-004', contentFormats: ['file', 'email'] }
      ]
    }
  },

  // ─────────────────────────────────────────────────────────
  //  GOVERNANCE — Scannable rules (GOV03, GOV04)
  // ─────────────────────────────────────────────────────────

  GOV03: {
    // scanSource: 'conditionalAccess', matchMode: 'any'
    // conditions: persistentBrowser.isEnabled true, persistentBrowser.mode 'never', state 'enabled'
    configured: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Block Persistent Browser on Unmanaged Devices',
        sessionControls: {
          persistentBrowser: { isEnabled: true, mode: 'never' }
        },
        conditions: {},
        grantControls: {}
      }]
    },
    missing: {
      conditionalAccess: [{
        state: 'enabled',
        displayName: 'Some Policy',
        sessionControls: {
          persistentBrowser: { isEnabled: false, mode: 'always' }
        },
        conditions: {},
        grantControls: {}
      }]
    }
  },

  GOV04: {
    // scanSource: 'authorizationPolicy', matchMode: 'all'
    // condition: allowInvitesFrom equalsAny ['adminsAndGuestInviters', 'none']
    // NOTE: 'equalsAny' operator is not defined in OPERATORS, so this rule
    // will always fail to match. We test that it returns 'missing' in both cases.
    configured: {
      authorizationPolicy: {
        displayName: 'Authorization Policy',
        allowInvitesFrom: 'adminsAndGuestInviters'
      }
    },
    missing: {
      authorizationPolicy: {
        displayName: 'Authorization Policy',
        allowInvitesFrom: 'everyone'
      }
    }
  },
};

// ─────────────────────────────────────────────────────────
//  MANUAL POLICY IDS — policies with status:'manual' in MATCH_RULES
//  These are tested separately (no fixture data needed).
// ─────────────────────────────────────────────────────────
window.MANUAL_POLICY_IDS = [
  'DEF01', 'DEF02', 'DEF03', 'DEF04', 'DEF05', 'DEF06', 'DEF07', 'DEF08',
  'EXO01', 'EXO02', 'EXO03', 'EXO04', 'EXO05', 'EXO06', 'EXO07', 'EXO08', 'EXO09', 'EXO10',
  'SPO02', 'SPO03', 'SPO04', 'SPO05', 'SPO06', 'SPO10', 'SPO11', 'SPO12', 'SPO14', 'SPO16', 'SPO17', 'SPO18', 'SPO20',
  'TEA01', 'TEA02', 'TEA03', 'TEA04', 'TEA05', 'TEA06', 'TEA07', 'TEA08', 'TEA09', 'TEA10',
  'PV01', 'PV02', 'PV03', 'PV04', 'PV05', 'PV06', 'PV07', 'PV08', 'PV09',
  'PV11', 'PV12', 'PV13', 'PV15', 'PV16', 'PV17', 'PV18', 'PV19', 'PV20',
  'PV21', 'PV22', 'PV23', 'PV24', 'PV25', 'PV26', 'PV27', 'PV28', 'PV29', 'PV30',
  'GOV01', 'GOV02', 'GOV05',
];

// Exhaustive list of all rule IDs in MATCH_RULES for completeness checks
window.ALL_MATCH_RULE_IDS = [
  'CA01', 'CA02', 'CA03', 'CA04', 'CA05', 'CA06', 'CA07', 'CA08', 'CA09',
  'CA10', 'CA11', 'CA12', 'CA13', 'CA14', 'CA15', 'CA16', 'CA17', 'CA18',
  'ENT01', 'ENT02', 'ENT03', 'ENT04', 'ENT05', 'ENT06', 'ENT07', 'ENT08', 'ENT09', 'ENT10',
  'INT01-Device-Compliance-Windows-Baseline', 'INT02-Device-Compliance-iOS-Baseline',
  'INT03-Device-Compliance-Android-Baseline', 'INT04-Device-Compliance-macOS-Baseline',
  'INT05-BitLocker-Encryption-Policy', 'INT06-Windows-LAPS-Local-Admin-Password',
  'INT07-Defender-AV-Configuration-Windows', 'INT08-Windows-Update-Ring-Policy',
  'INT09-App-Protection-Policy-iOS-Android', 'INT10-Device-Enrollment-Restrictions',
  'INT11-Windows-Security-Baseline-CIS', 'INT12-Microsoft-Edge-Security-Baseline',
  'INT13-Windows-Hello-For-Business', 'INT14-Firewall-Policy-Windows',
  'INT15-Attack-Surface-Reduction-Rules', 'INT16-Credential-Guard-Windows',
  'INT17-Removable-Storage-Control', 'INT18-Windows-Diagnostic-Data-Limit',
  'INT19-Exploit-Protection-Policy', 'INT20-Controlled-Folder-Access',
  'MDE01', 'MDE02', 'MDE03', 'MDE04', 'MDE05', 'MDE06', 'MDE07', 'MDE08',
  'MDE09', 'MDE10', 'MDE11', 'MDE12',
  'DEF01', 'DEF02', 'DEF03', 'DEF04', 'DEF05', 'DEF06', 'DEF07', 'DEF08',
  'EXO01', 'EXO02', 'EXO03', 'EXO04', 'EXO05', 'EXO06', 'EXO07', 'EXO08', 'EXO09', 'EXO10',
  'SPO01', 'SPO02', 'SPO03', 'SPO04', 'SPO05', 'SPO06', 'SPO07', 'SPO08', 'SPO09', 'SPO10',
  'SPO11', 'SPO12', 'SPO13', 'SPO14', 'SPO15', 'SPO16', 'SPO17', 'SPO18', 'SPO19', 'SPO20',
  'TEA01', 'TEA02', 'TEA03', 'TEA04', 'TEA05', 'TEA06', 'TEA07', 'TEA08', 'TEA09', 'TEA10',
  'PV01', 'PV02', 'PV03', 'PV04', 'PV05', 'PV06', 'PV07', 'PV08', 'PV09', 'PV10',
  'PV11', 'PV12', 'PV13', 'PV14', 'PV15', 'PV16', 'PV17', 'PV18', 'PV19', 'PV20',
  'PV21', 'PV22', 'PV23', 'PV24', 'PV25', 'PV26', 'PV27', 'PV28', 'PV29', 'PV30',
  'GOV01', 'GOV02', 'GOV03', 'GOV04', 'GOV05',
];
