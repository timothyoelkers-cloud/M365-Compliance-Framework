/* ═══════════════════════════════════════════
   POLICY MATCHER — Data-driven rules engine
   Compares scanned tenant data against framework
   policies to determine configuration status.
═══════════════════════════════════════════ */
const PolicyMatcher = (() => {

  // ─── Operators ───────────────────────────────────────────

  const OPERATORS = {
    equals(actual, expected) {
      return actual === expected;
    },
    notEquals(actual, expected) {
      return actual !== expected;
    },
    contains(actual, expected) {
      if (Array.isArray(actual)) return actual.includes(expected);
      if (typeof actual === 'string') return actual.indexOf(expected) !== -1;
      return false;
    },
    containsAny(actual, expected) {
      if (!Array.isArray(expected)) return false;
      if (Array.isArray(actual)) return expected.some(v => actual.includes(v));
      if (typeof actual === 'string') return expected.some(v => actual.indexOf(v) !== -1);
      return false;
    },
    containsAll(actual, expected) {
      if (!Array.isArray(expected)) return false;
      if (Array.isArray(actual)) return expected.every(v => actual.includes(v));
      return false;
    },
    isEmpty(actual) {
      if (actual === null || actual === undefined) return true;
      if (Array.isArray(actual)) return actual.length === 0;
      if (typeof actual === 'string') return actual.length === 0;
      return false;
    },
    isNotEmpty(actual) {
      return !OPERATORS.isEmpty(actual);
    },
    exists(actual) {
      return actual !== null && actual !== undefined;
    },
    notExists(actual) {
      return actual === null || actual === undefined;
    },
    includes(actual, expected) {
      return OPERATORS.contains(actual, expected);
    },
  };

  // ─── Utility ─────────────────────────────────────────────

  /**
   * Safely traverse a dot-separated path on an object.
   * Returns undefined if any segment is missing.
   */
  function getNestedValue(obj, path) {
    if (obj === null || obj === undefined) return undefined;
    const parts = path.split('.');
    let current = obj;
    for (const part of parts) {
      if (current === null || current === undefined) return undefined;
      if (typeof current !== 'object') return undefined;
      current = current[part];
    }
    return current;
  }

  /**
   * Case-insensitive substring check for keyword matching.
   */
  function containsKeyword(str, keyword) {
    if (typeof str !== 'string') return false;
    return str.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
  }

  // ─── Condition Evaluation ────────────────────────────────

  /**
   * Evaluate a single condition object against a data item.
   * Gracefully returns false on any missing path or type mismatch.
   */
  function evaluateCondition(data, condition) {
    try {
      const { path, op, value, values } = condition;
      const actual = getNestedValue(data, path);
      const operatorFn = OPERATORS[op];
      if (!operatorFn) {
        console.warn('[PolicyMatcher] Unknown operator:', op);
        return false;
      }
      // Operators that take no value argument
      if (op === 'isEmpty' || op === 'isNotEmpty' || op === 'exists' || op === 'notExists') {
        return operatorFn(actual);
      }
      // Use 'values' for array-expecting operators, otherwise 'value'
      const expected = (op === 'containsAny' || op === 'containsAll') ? (values || value) : value;
      return operatorFn(actual, expected);
    } catch (e) {
      return false;
    }
  }

  /**
   * Evaluate a complete rule against the scan data.
   * Returns a match result object.
   */
  function evaluateRule(scanData, rule) {
    const { scanSource, matchMode, conditions } = rule;

    // Manual / PowerShell-only rules bypass scanning
    if (rule.status === 'manual') {
      return {
        status: 'manual',
        confidence: 'medium',
        matchedItem: null,
        detail: rule.detail || 'Requires PowerShell verification',
        verifyCommand: rule.verifyCommand || null,
      };
    }

    // Check that scan data exists for this source
    const sourceData = scanData[scanSource];
    if (sourceData === undefined || sourceData === null) {
      return {
        status: 'not_scanned',
        confidence: 'medium',
        matchedItem: null,
        detail: 'Scan data not available for: ' + scanSource,
      };
    }

    try {
      if (matchMode === 'any') {
        // sourceData is expected to be an array; find any item where ALL conditions pass
        if (!Array.isArray(sourceData)) {
          return {
            status: 'error',
            confidence: 'medium',
            matchedItem: null,
            detail: 'Expected array for scan source: ' + scanSource,
          };
        }
        for (const item of sourceData) {
          const allMatch = conditions.every(cond => evaluateCondition(item, cond));
          if (allMatch) {
            return {
              status: 'configured',
              confidence: 'high',
              matchedItem: {
                displayName: item.displayName || item.name || item.id || '(unnamed)',
                id: item.id || null,
              },
              detail: 'Matched existing tenant policy',
            };
          }
        }
        return {
          status: 'missing',
          confidence: 'high',
          matchedItem: null,
          detail: 'No matching policy found in ' + scanSource,
        };
      }

      if (matchMode === 'all' || matchMode === 'direct') {
        // sourceData is a singleton object; ALL conditions must pass
        const allMatch = conditions.every(cond => evaluateCondition(sourceData, cond));
        if (allMatch) {
          return {
            status: 'configured',
            confidence: 'high',
            matchedItem: {
              displayName: sourceData.displayName || sourceData.name || scanSource,
              id: sourceData.id || null,
            },
            detail: 'Setting is configured as expected',
          };
        }
        return {
          status: 'missing',
          confidence: 'high',
          matchedItem: null,
          detail: 'Setting does not match expected configuration',
        };
      }

      return {
        status: 'error',
        confidence: 'medium',
        matchedItem: null,
        detail: 'Unknown matchMode: ' + matchMode,
      };
    } catch (e) {
      return {
        status: 'error',
        confidence: 'medium',
        matchedItem: null,
        detail: 'Evaluation error: ' + e.message,
      };
    }
  }

  // ═══════════════════════════════════════════════════════════
  //  MATCH RULES — per-policy definitions
  //  Every one of the 138 policies MUST have an entry.
  // ═══════════════════════════════════════════════════════════

  const MATCH_RULES = {

    // ─────────────────────────────────────────────────────────
    //  CONDITIONAL ACCESS (18 policies)
    //  scanSource: 'conditionalAccess', matchMode: 'any'
    // ─────────────────────────────────────────────────────────

    CA01: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.clientAppTypes', op: 'containsAny', values: ['exchangeActiveSync', 'other'] },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'block' },
      ],
    },

    CA02: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.users.includeUsers', op: 'contains', value: 'All' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'mfa' },
      ],
    },

    CA03: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.users.includeRoles', op: 'isNotEmpty' },
        { path: 'grantControls.authenticationStrength', op: 'exists' },
      ],
    },

    CA04: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.signInRiskLevels', op: 'contains', value: 'high' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'block' },
      ],
    },

    CA05: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.userRiskLevels', op: 'contains', value: 'high' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'passwordChange' },
      ],
    },

    CA06: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'grantControls.builtInControls', op: 'contains', value: 'compliantDevice' },
      ],
    },

    CA07: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.locations', op: 'exists' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'block' },
      ],
    },

    CA08: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.applications.includeApplications', op: 'containsAny', values: ['797f4846-ba00-4fd7-ba43-dac1f8f63013'] },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'mfa' },
      ],
    },

    CA09: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'grantControls.builtInControls', op: 'contains', value: 'approvedApplication' },
      ],
    },

    CA10: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.applications.includeApplications', op: 'contains', value: 'All' },
        { path: 'conditions.applications.excludeApplications', op: 'isNotEmpty' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'block' },
      ],
    },

    CA11: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.applications', op: 'exists' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'block' },
      ],
    },

    CA12: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.users.includeGuestsOrExternalUsers', op: 'exists' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'mfa' },
      ],
    },

    CA13: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'sessionControls.signInFrequency', op: 'exists' },
      ],
    },

    CA14: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.users.includeRoles', op: 'isNotEmpty' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'mfa' },
      ],
    },

    CA15: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'sessionControls.persistentBrowser', op: 'exists' },
      ],
    },

    CA16: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.platforms', op: 'exists' },
        { path: 'conditions.clientAppTypes', op: 'containsAny', values: ['mobileAppsAndDesktopClients'] },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'block' },
      ],
    },

    CA17: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.signInRiskLevels', op: 'contains', value: 'medium' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'mfa' },
      ],
    },

    CA18: {
      scanSource: 'conditionalAccess',
      matchMode: 'any',
      conditions: [
        { path: 'conditions.clientAppTypes', op: 'containsAny', values: ['exchangeActiveSync'] },
        { path: 'conditions.applications', op: 'exists' },
        { path: 'grantControls.builtInControls', op: 'contains', value: 'block' },
      ],
    },

    // ─────────────────────────────────────────────────────────
    //  ENTRA ID SETTINGS (10 policies)
    //  Each uses a different singleton scan source
    // ─────────────────────────────────────────────────────────

    ENT01: {
      scanSource: 'authorizationPolicy',
      matchMode: 'direct',
      conditions: [
        { path: 'defaultUserRolePermissions.permissionGrantPoliciesAssigned', op: 'isEmpty' },
      ],
    },

    ENT02: {
      scanSource: 'adminConsentPolicy',
      matchMode: 'direct',
      conditions: [
        { path: 'isEnabled', op: 'equals', value: true },
      ],
    },

    ENT03: {
      scanSource: 'authorizationPolicy',
      matchMode: 'direct',
      conditions: [
        { path: 'defaultUserRolePermissions.allowedToCreateApps', op: 'equals', value: false },
      ],
    },

    ENT04: {
      scanSource: 'groupSettings',
      matchMode: 'any',
      conditions: [
        { path: 'displayName', op: 'equals', value: 'Password Rule Settings' },
      ],
    },

    ENT05: {
      scanSource: 'deviceRegistrationPolicy',
      matchMode: 'direct',
      conditions: [
        { path: 'userDeviceQuota', op: 'exists' },
      ],
    },

    ENT06: {
      scanSource: 'authorizationPolicy',
      matchMode: 'direct',
      conditions: [
        { path: 'allowInvitesFrom', op: 'equals', value: 'adminsAndGuestInviters' },
      ],
    },

    ENT07: {
      scanSource: 'authMethodsPolicy',
      matchMode: 'direct',
      conditions: [
        { path: 'registrationEnforcement.authenticationMethodsRegistrationCampaign', op: 'exists' },
      ],
    },

    ENT08: {
      scanSource: 'groupSettings',
      matchMode: 'any',
      conditions: [
        { path: 'displayName', op: 'equals', value: 'Group.Unified' },
      ],
    },

    ENT09: {
      scanSource: 'organization',
      matchMode: 'any',
      conditions: [
        { path: 'id', op: 'exists' },
      ],
    },

    ENT10: {
      scanSource: 'authenticatorConfig',
      matchMode: 'direct',
      conditions: [
        { path: 'featureSettings.numberMatchingRequiredState.state', op: 'equals', value: 'enabled' },
      ],
    },

    // ─────────────────────────────────────────────────────────
    //  INTUNE — Device Compliance Policies (INT01-INT04)
    //  scanSource: 'compliancePolicies', matchMode: 'any'
    // ─────────────────────────────────────────────────────────

    'INT01-Device-Compliance-Windows-Baseline': {
      scanSource: 'compliancePolicies',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'equals', value: '#microsoft.graph.windows10CompliancePolicy' },
      ],
    },

    'INT02-Device-Compliance-iOS-Baseline': {
      scanSource: 'compliancePolicies',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'equals', value: '#microsoft.graph.iosCompliancePolicy' },
      ],
    },

    'INT03-Device-Compliance-Android-Baseline': {
      scanSource: 'compliancePolicies',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'containsAny', values: [
          '#microsoft.graph.androidCompliancePolicy',
          '#microsoft.graph.androidWorkProfileCompliancePolicy',
          '#microsoft.graph.androidDeviceOwnerCompliancePolicy',
        ] },
      ],
    },

    'INT04-Device-Compliance-macOS-Baseline': {
      scanSource: 'compliancePolicies',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'equals', value: '#microsoft.graph.macOSCompliancePolicy' },
      ],
    },

    // ─────────────────────────────────────────────────────────
    //  INTUNE — Device Configuration Policies (INT05-INT20)
    //  scanSource: 'deviceConfigurations', matchMode: 'any'
    //  Broad platform-keyword matching via @odata.type
    // ─────────────────────────────────────────────────────────

    'INT05-BitLocker-Encryption-Policy': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
        { path: 'bitLockerEncryptDevice', op: 'equals', value: true },
      ],
    },

    'INT06-Windows-LAPS-Local-Admin-Password': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT07-Defender-AV-Configuration-Windows': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT08-Windows-Update-Ring-Policy': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windowsUpdateForBusiness' },
      ],
    },

    'INT09-App-Protection-Policy-iOS-Android': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'containsAny', values: ['ios', 'android'] },
      ],
    },

    'INT10-Device-Enrollment-Restrictions': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'deviceEnrollment' },
      ],
    },

    'INT11-Windows-Security-Baseline-CIS': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT12-Microsoft-Edge-Security-Baseline': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT13-Windows-Hello-For-Business': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windowsIdentityProtection' },
      ],
    },

    'INT14-Firewall-Policy-Windows': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT15-Attack-Surface-Reduction-Rules': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT16-Credential-Guard-Windows': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT17-Removable-Storage-Control': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT18-Windows-Diagnostic-Data-Limit': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT19-Exploit-Protection-Policy': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    'INT20-Controlled-Folder-Access': {
      scanSource: 'deviceConfigurations',
      matchMode: 'any',
      conditions: [
        { path: '@odata.type', op: 'contains', value: 'windows10' },
      ],
    },

    // ─────────────────────────────────────────────────────────
    //  DEFENDER FOR ENDPOINT (12 policies)
    //  scanSource: 'configurationPolicies', matchMode: 'any'
    //  Keyword matching on name / templateReference fields
    // ─────────────────────────────────────────────────────────

    MDE01: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'templateReference.templateFamily', op: 'contains', value: 'endpointSecurity' },
      ],
    },

    MDE02: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'contains', value: 'macOS' },
      ],
    },

    MDE03: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['iOS', 'Android', 'mobile'] },
      ],
    },

    MDE04: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['EDR', 'endpointDetection', 'Endpoint detection'] },
      ],
    },

    MDE05: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['automated investigation', 'auto remediation', 'AIR'] },
      ],
    },

    MDE06: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['vulnerability', 'TVM', 'threat and vulnerability'] },
      ],
    },

    MDE07: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['network protection', 'networkProtection'] },
      ],
    },

    MDE08: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['web content', 'webContentFilter', 'web filter'] },
      ],
    },

    MDE09: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['tamper protection', 'tamperProtection'] },
      ],
    },

    MDE10: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['alert notification', 'email notification', 'alert rule'] },
      ],
    },

    MDE11: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['deception', 'honeypot', 'lure'] },
      ],
    },

    MDE12: {
      scanSource: 'configurationPolicies',
      matchMode: 'any',
      conditions: [
        { path: 'name', op: 'containsAny', values: ['threat intelligence', 'TI integration', 'TAXII'] },
      ],
    },

    // ─────────────────────────────────────────────────────────
    //  DEFENDER FOR OFFICE 365 (8 policies)
    //  PowerShell-only — manual verification
    // ─────────────────────────────────────────────────────────

    DEF01: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-AntiPhishPolicy | Format-List Name, Enabled, PhishThresholdLevel',
    },

    DEF02: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-SafeLinksPolicy | Format-List Name, IsEnabled, ScanUrls',
    },

    DEF03: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-SafeAttachmentPolicy | Format-List Name, Enable, Action',
    },

    DEF04: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-MalwareFilterPolicy | Format-List Name, EnableFileFilter',
    },

    DEF05: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-HostedContentFilterPolicy | Format-List Name, SpamAction, HighConfidenceSpamAction',
    },

    DEF06: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-HostedOutboundSpamFilterPolicy | Format-List Name, RecipientLimitExternalPerHour',
    },

    DEF07: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-AtpPolicyForO365 | Format-List EnableATPForSPOTeamsODB',
    },

    DEF08: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-MalwareFilterPolicy | Format-List Name, FileTypes',
    },

    // ─────────────────────────────────────────────────────────
    //  EXCHANGE ONLINE (10 policies)
    //  PowerShell-only — manual verification
    // ─────────────────────────────────────────────────────────

    EXO01: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-DkimSigningConfig | Format-List Domain, Enabled',
    },

    EXO02: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Resolve-DnsName -Name _dmarc.yourdomain.com -Type TXT',
    },

    EXO03: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-TransportRule | Where-Object {$_.Name -like "*forward*"} | Format-List Name, State',
    },

    EXO04: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-AuthenticationPolicy | Format-List Name, AllowBasicAuth*',
    },

    EXO05: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-OrganizationConfig | Format-List OAuth2ClientProfileEnabled',
    },

    EXO06: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-TransportRule | Where-Object {$_.SetSCL -eq -1} | Format-List Name',
    },

    EXO07: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-SharingPolicy | Format-List Name, Domains, Enabled',
    },

    EXO08: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-HostedConnectionFilterPolicy | Format-List Name, IPAllowList, EnableSafeList',
    },

    EXO09: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-App -OrganizationApp | Where-Object {$_.DisplayName -like "*Report Message*"} | Format-List DisplayName, Enabled',
    },

    EXO10: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-ExchangeOnline; Get-PublicFolder -GetChildren | Format-List Name, MailEnabled',
    },

    // ─────────────────────────────────────────────────────────
    //  SHAREPOINT ONLINE (20 policies)
    //  PowerShell-only — manual verification
    // ─────────────────────────────────────────────────────────

    SPO01: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List SharingCapability',
    },

    SPO02: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List DefaultSharingLinkType',
    },

    SPO03: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List RequireAnonymousLinksExpireInDays',
    },

    SPO04: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List ConditionalAccessPolicy',
    },

    SPO05: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List DisallowInfectedFileDownload',
    },

    SPO06: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List EnableAzureADB2BIntegration',
    },

    SPO07: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List SharingCapability, SharingDomainRestrictionMode',
    },

    SPO08: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List AllowedDomainListForSyncClient, IsUnmanagedSyncClientForTenantRestricted',
    },

    SPO09: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List LegacyAuthProtocolsEnabled',
    },

    SPO10: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List IPAddressAllowList, IPAddressEnforcement',
    },

    SPO11: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPSiteClassification',
    },

    SPO12: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List EnableAutoExpirationVersionTrim, MajorVersionLimit',
    },

    SPO13: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List SharingAllowedDomainList, SharingDomainRestrictionMode',
    },

    SPO14: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List ConditionalAccessPolicy',
    },

    SPO15: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List BrowserIdleSignout, BrowserIdleSignoutMinutes',
    },

    SPO16: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List DenyAddAndCustomizePages',
    },

    SPO17: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.SharePointLocation -ne $null} | Format-List Name',
    },

    SPO18: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List ConditionalAccessPolicy, AllowDownloadingNonWebViewableFiles',
    },

    SPO19: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-PnPOnline -Url https://<tenant>-admin.sharepoint.com -Interactive; Get-PnPTenant | Format-List PreventExternalUsersFromResharing',
    },

    SPO20: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -RecordType SharePoint -ResultSize 1',
    },

    // ─────────────────────────────────────────────────────────
    //  MICROSOFT TEAMS (10 policies)
    //  PowerShell-only — manual verification
    // ─────────────────────────────────────────────────────────

    TEA01: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTeamsMeetingPolicy -Identity Global | Format-List AllowAnonymousUsersToJoinMeeting',
    },

    TEA02: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTeamsMeetingPolicy -Identity Global | Format-List AutoAdmittedUsers',
    },

    TEA03: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTeamsMeetingPolicy -Identity Global | Format-List AutoAdmittedUsers, AllowPSTNUsersToBypassLobby',
    },

    TEA04: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTeamsMeetingPolicy -Identity Global | Format-List AllowDropBox, AllowBox, AllowGoogleDrive, AllowShareFile, AllowEgnyte',
    },

    TEA05: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsExternalAccessPolicy -Identity Global | Format-List EnableFederationAccess, EnableTeamsConsumerAccess',
    },

    TEA06: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTenantFederationConfiguration | Format-List AllowFederatedUsers, AllowedDomains',
    },

    TEA07: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTeamsGuestMeetingConfiguration | Format-List AllowIPVideo, ScreenSharingMode',
    },

    TEA08: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTeamsMeetingPolicy -Identity Global | Format-List DesignatedPresenterRoleMode',
    },

    TEA09: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTeamsMeetingPolicy -Identity Global | Format-List AllowCloudRecording, AllowRecordingStorageOutsideRegion',
    },

    TEA10: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-MicrosoftTeams; Get-CsTeamsChannelsPolicy -Identity Global | Format-List AllowChannelEmailAddresses',
    },

    // ─────────────────────────────────────────────────────────
    //  PURVIEW / COMPLIANCE (30 policies)
    //  PowerShell-only — manual verification
    // ─────────────────────────────────────────────────────────

    PV01: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*credit card*"} | Format-List Name, Mode',
    },

    PV02: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*PII*"} | Format-List Name, Mode',
    },

    PV03: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*PHI*" -or $_.Name -like "*HIPAA*"} | Format-List Name, Mode',
    },

    PV04: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*financial*" -or $_.Name -like "*PCI*"} | Format-List Name, Mode',
    },

    PV05: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*insider*" -or $_.Name -like "*bulk download*"} | Format-List Name, Mode',
    },

    PV06: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*source code*" -or $_.Name -like "*credential*"} | Format-List Name, Mode',
    },

    PV07: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*password*"} | Format-List Name, Mode',
    },

    PV08: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*GDPR*"} | Format-List Name, Mode',
    },

    PV09: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*Teams*"} | Format-List Name, Mode',
    },

    PV10: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-Label | Format-List Name, DisplayName, IsActive',
    },

    PV11: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -ResultSize 1',
    },

    PV12: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-InsiderRiskPolicy | Format-List Name, InsiderRiskScenario, IsEnabled',
    },

    PV13: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-AutoSensitivityLabelPolicy | Format-List Name, Mode',
    },

    PV14: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-Label | Where-Object {$_.ContentType -like "*Site*" -or $_.ContentType -like "*UnifiedGroup*"} | Format-List Name',
    },

    PV15: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-LabelPolicy | Format-List Name, Labels, Settings',
    },

    PV16: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*Australian*"} | Format-List Name, Mode',
    },

    PV17: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*SSN*" -or $_.Name -like "*Social Security*"} | Format-List Name, Mode',
    },

    PV18: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*endpoint*"} | Format-List Name, Mode, EndpointDlpLocation',
    },

    PV19: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-DlpCompliancePolicy | Where-Object {$_.Name -like "*Power BI*"} | Format-List Name, Mode',
    },

    PV20: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-InformationBarrierPolicy | Format-List Name, State, Segments',
    },

    PV21: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-InformationBarrierPolicy | Format-List Name, State, AssignedSegment',
    },

    PV22: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-RetentionCompliancePolicy | Format-List Name, Mode, Enabled',
    },

    PV23: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-RetentionCompliancePolicy | Where-Object {$_.Name -like "*regulatory*" -or $_.Name -like "*financial*"} | Format-List Name, Mode',
    },

    PV24: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-ComplianceTag | Format-List Name, RetentionAction, RetentionDuration',
    },

    PV25: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-ComplianceTag | Where-Object {$_.IsRecordLabel -eq $true} | Format-List Name, IsRecordLabel, IsRegulatoryLabel',
    },

    PV26: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-ComplianceTag | Where-Object {$_.ReviewerEmail -ne $null} | Format-List Name, ReviewerEmail',
    },

    PV27: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-SupervisoryReviewPolicy | Format-List Name, IsActive',
    },

    PV28: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-SupervisoryReviewPolicy | Format-List Name, IsActive, ReviewCondition',
    },

    PV29: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-InsiderRiskPolicy | Where-Object {$_.Name -like "*adaptive*"} | Format-List Name, IsEnabled',
    },

    PV30: {
      status: 'manual',
      detail: 'Requires PowerShell verification',
      verifyCommand: 'Connect-IPPSSession; Get-ComplianceCase | Format-List Name, Status, CaseType',
    },
  };

  // ─── Main Matching Functions ─────────────────────────────

  /**
   * Match a single policy against scan data.
   * @param {Object} policy  — policy object with at minimum { id, type }
   * @param {Object} scanData — full scan results from TenantScanner
   * @returns {Object} match result
   */
  function matchPolicy(policy, scanData) {
    if (!policy || !policy.id) {
      return {
        status: 'error',
        confidence: 'medium',
        matchedItem: null,
        detail: 'Invalid policy object',
      };
    }

    // Look up the rule by policy id
    const rule = MATCH_RULES[policy.id];

    // If no rule defined, determine status from policy type
    if (!rule) {
      if (DeployEngine.isPowerShellOnly(policy.type)) {
        return {
          status: 'manual',
          confidence: 'medium',
          matchedItem: null,
          detail: 'Requires PowerShell verification',
          verifyCommand: null,
        };
      }
      return {
        status: 'error',
        confidence: 'medium',
        matchedItem: null,
        detail: 'No match rule defined for policy: ' + policy.id,
      };
    }

    // Manual rules short-circuit immediately
    if (rule.status === 'manual') {
      return evaluateRule(scanData, rule);
    }

    // Validate that scan data is present
    if (!scanData || typeof scanData !== 'object') {
      return {
        status: 'not_scanned',
        confidence: 'medium',
        matchedItem: null,
        detail: 'No scan data available',
      };
    }

    return evaluateRule(scanData, rule);
  }

  /**
   * Match ALL policies against current scan data.
   * Stores results in AppState and returns them.
   * @param {Array} policies — array of policy objects
   * @returns {Object} map of policyId -> match result
   */
  function matchAll(policies) {
    const scanData = typeof TenantScanner !== 'undefined' ? TenantScanner.getScanResults() : null;

    if (!scanData) {
      // If no scan data, mark Graph-deployable policies as not_scanned and PS-only as manual
      const results = {};
      for (const pol of policies) {
        const rule = MATCH_RULES[pol.id];
        if (rule && rule.status === 'manual') {
          results[pol.id] = {
            status: 'manual',
            confidence: 'medium',
            matchedItem: null,
            detail: rule.detail || 'Requires PowerShell verification',
            verifyCommand: rule.verifyCommand || null,
          };
        } else if (DeployEngine.isPowerShellOnly(pol.type)) {
          results[pol.id] = {
            status: 'manual',
            confidence: 'medium',
            matchedItem: null,
            detail: 'Requires PowerShell verification',
          };
        } else {
          results[pol.id] = {
            status: 'not_scanned',
            confidence: 'medium',
            matchedItem: null,
            detail: 'Tenant not scanned — connect and scan to check status',
          };
        }
      }
      AppState.set('tenantScanResults', results);
      return results;
    }

    const results = {};
    for (const pol of policies) {
      results[pol.id] = matchPolicy(pol, scanData);
    }
    AppState.set('tenantScanResults', results);
    return results;
  }

  /**
   * Retrieve the cached match result for a single policy.
   * @param {string} policyId
   * @returns {Object|null} match result or null
   */
  function getMatchResult(policyId) {
    const results = AppState.get('tenantScanResults') || {};
    return results[policyId] || null;
  }

  /**
   * Get summary statistics from the latest match results.
   * @returns {Object} { configured, missing, manual, error, not_scanned, total }
   */
  function getSummary() {
    const results = AppState.get('tenantScanResults') || {};
    const summary = { configured: 0, missing: 0, manual: 0, error: 0, not_scanned: 0, total: 0 };
    for (const id of Object.keys(results)) {
      summary.total++;
      const s = results[id].status;
      if (s === 'configured') summary.configured++;
      else if (s === 'missing') summary.missing++;
      else if (s === 'manual') summary.manual++;
      else if (s === 'error') summary.error++;
      else if (s === 'not_scanned') summary.not_scanned++;
    }
    return summary;
  }

  // ─── Public API ──────────────────────────────────────────

  return {
    matchAll,
    matchPolicy,
    getMatchResult,
    getSummary,
    MATCH_RULES,
    // Exposed for testing
    _evaluateCondition: evaluateCondition,
    _evaluateRule: evaluateRule,
    _getNestedValue: getNestedValue,
  };
})();
