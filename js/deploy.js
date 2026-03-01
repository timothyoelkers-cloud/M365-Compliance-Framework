/* ═══════════════════════════════════════════
   DEPLOY ENGINE — Graph API + InvokeCommand REST + PowerShell generation
═══════════════════════════════════════════ */
const DeployEngine = (() => {

  // ─── Deployment Method Registry ───

  const DEPLOY_METHOD = {
    GRAPH: 'graph',
    EXO_INVOKE: 'exo-invoke',
    COMPLIANCE_INVOKE: 'cc-invoke',
    SPO_GRAPH: 'spo-graph',
    PS_ONLY: 'ps-only',
  };

  // Backward-compat arrays
  const GRAPH_TYPES = ['conditional-access', 'intune', 'entra', 'defender-endpoint'];
  const PS_TYPES = ['defender', 'exchange', 'sharepoint', 'teams', 'purview'];

  // Type → default deployment method
  const TYPE_DEPLOY_MAP = {
    'conditional-access': DEPLOY_METHOD.GRAPH,
    'intune':             DEPLOY_METHOD.GRAPH,
    'entra':              DEPLOY_METHOD.GRAPH,
    'defender-endpoint':  DEPLOY_METHOD.GRAPH,
    'defender':           DEPLOY_METHOD.EXO_INVOKE,
    'exchange':           DEPLOY_METHOD.EXO_INVOKE,
    'purview':            DEPLOY_METHOD.COMPLIANCE_INVOKE,
    'sharepoint':         DEPLOY_METHOD.PS_ONLY,
    'teams':              DEPLOY_METHOD.PS_ONLY,
  };

  // Per-policy overrides (SPO Graph subset + EXO02 DNS-only)
  const POLICY_DEPLOY_OVERRIDE = {
    'EXO02': DEPLOY_METHOD.PS_ONLY,
    'SPO07': DEPLOY_METHOD.SPO_GRAPH,
    'SPO09': DEPLOY_METHOD.SPO_GRAPH,
    'SPO13': DEPLOY_METHOD.SPO_GRAPH,
    'SPO15': DEPLOY_METHOD.SPO_GRAPH,
    'SPO19': DEPLOY_METHOD.SPO_GRAPH,
  };

  function getDeployMethod(type, policyId) {
    if (policyId && POLICY_DEPLOY_OVERRIDE[policyId]) return POLICY_DEPLOY_OVERRIDE[policyId];
    return TYPE_DEPLOY_MAP[type] || DEPLOY_METHOD.PS_ONLY;
  }

  function isDeployable(type, policyId) {
    return getDeployMethod(type, policyId) !== DEPLOY_METHOD.PS_ONLY;
  }

  function hasScript(type) {
    return PS_TYPES.includes(type);
  }

  // Backward compat
  function isGraphDeployable(type) { return GRAPH_TYPES.includes(type); }
  function isPowerShellOnly(type) { return PS_TYPES.includes(type); }

  // ─── Graph API Payload Extraction (existing) ───

  function stripMeta(obj) {
    const clone = JSON.parse(JSON.stringify(obj));
    const metaKeys = ['_metadata', '_notes', '_explanation', '_note', '_modeOptions'];
    metaKeys.forEach(k => delete clone[k]);
    return clone;
  }

  function cleanPayload(obj) {
    if (Array.isArray(obj)) return obj.map(cleanPayload);
    if (obj && typeof obj === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        if (v === null || v === undefined) continue;
        if (Array.isArray(v) && v.length === 0) continue;
        if (typeof v === 'object' && !Array.isArray(v)) {
          const cleaned = cleanPayload(v);
          if (Object.keys(cleaned).length > 0) out[k] = cleaned;
        } else {
          out[k] = cleanPayload(v);
        }
      }
      return out;
    }
    return obj;
  }

  function extractConditionalAccessPayload(raw) {
    const body = cleanPayload(stripMeta(raw));
    return {
      calls: [{
        endpoint: '/v1.0/identity/conditionalAccess/policies',
        method: 'POST',
        body: body,
        description: 'Create CA policy: ' + (body.displayName || ''),
      }],
    };
  }

  function extractIntunePayload(raw) {
    const body = stripMeta(raw);
    const odata = body['@odata.type'] || '';
    let endpoint;
    if (odata.toLowerCase().includes('compliancepolicy')) {
      endpoint = '/v1.0/deviceManagement/deviceCompliancePolicies';
      if (!body.scheduledActionsForRule || body.scheduledActionsForRule.length === 0) {
        body.scheduledActionsForRule = [{
          ruleName: 'DefaultRule',
          scheduledActionConfigurations: [{
            actionType: 'block',
            gracePeriodHours: 0,
            notificationTemplateId: '',
            notificationMessageCCList: [],
          }],
        }];
      }
    } else {
      endpoint = '/v1.0/deviceManagement/deviceConfigurations';
    }
    return {
      calls: [{
        endpoint: endpoint,
        method: 'POST',
        body: body,
        description: 'Create Intune policy: ' + (body.displayName || ''),
      }],
    };
  }

  function extractEntraPayload(raw) {
    const calls = [];
    const apiCalls = raw.graphApiCalls || [];
    for (const apiCall of apiCalls) {
      if ((apiCall.method || '').toUpperCase() === 'GET') continue;
      let endpoint = apiCall.endpoint || '';
      endpoint = endpoint.replace('https://graph.microsoft.com', '');
      const acct = TenantAuth.getAccount();
      if (acct && acct.tenantId) {
        endpoint = endpoint.replace('<TENANT-ID>', acct.tenantId);
      }
      const body = apiCall.body ? JSON.parse(JSON.stringify(apiCall.body)) : undefined;
      calls.push({
        endpoint: endpoint,
        method: apiCall.method || 'PATCH',
        body: body,
        description: apiCall.description || '',
        stepOrder: apiCall.stepOrder || 0,
      });
    }
    calls.sort((a, b) => a.stepOrder - b.stepOrder);
    return { calls };
  }

  function extractDefenderEndpointPayload(raw) {
    const calls = [];
    if (raw.endpointSecurityPolicy) {
      const body = JSON.parse(JSON.stringify(raw.endpointSecurityPolicy));
      calls.push({
        endpoint: '/beta/deviceManagement/configurationPolicies',
        method: 'POST',
        body: body,
        description: 'Create endpoint security policy: ' + (body.name || body.displayName || ''),
      });
    } else if (raw.intuneProfile) {
      const body = JSON.parse(JSON.stringify(raw.intuneProfile));
      calls.push({
        endpoint: '/v1.0/deviceManagement/deviceConfigurations',
        method: 'POST',
        body: body,
        description: 'Create device config: ' + (body.displayName || ''),
      });
    } else if (raw.intuneOmaUriPolicy) {
      const body = JSON.parse(JSON.stringify(raw.intuneOmaUriPolicy));
      calls.push({
        endpoint: '/v1.0/deviceManagement/deviceConfigurations',
        method: 'POST',
        body: body,
        description: 'Create OMA-URI config: ' + (body.displayName || ''),
      });
    } else if (raw.intuneEndpointSecurityPolicy) {
      const body = JSON.parse(JSON.stringify(raw.intuneEndpointSecurityPolicy));
      calls.push({
        endpoint: '/beta/deviceManagement/configurationPolicies',
        method: 'POST',
        body: body,
        description: 'Create endpoint security policy: ' + (body.name || ''),
      });
    }
    return { calls };
  }

  function extractPayload(rawPolicy, policyType) {
    switch (policyType) {
      case 'conditional-access': return extractConditionalAccessPayload(rawPolicy);
      case 'intune': return extractIntunePayload(rawPolicy);
      case 'entra': return extractEntraPayload(rawPolicy);
      case 'defender-endpoint': return extractDefenderEndpointPayload(rawPolicy);
      default: return { calls: [] };
    }
  }

  // ─── InvokeCommand Payload Extraction (new) ───

  /** Strip _-prefixed keys from parameter objects */
  function cleanInvokeParams(params) {
    if (!params) return {};
    const cleaned = {};
    for (const [k, v] of Object.entries(params)) {
      if (k.startsWith('_')) continue;
      cleaned[k] = v;
    }
    return cleaned;
  }

  /**
   * Extract InvokeCommand calls from Defender for O365 policies.
   * DEF01-DEF06: steps[] array with Policy+Rule pattern
   * DEF07-DEF08: flat root-level cmdlet + parameters
   */
  function extractDefenderInvokePayload(raw) {
    const commands = [];
    if (raw.steps && raw.steps.length > 0) {
      for (const step of raw.steps) {
        if (!step.cmdlet) continue;
        commands.push({
          cmdletName: step.cmdlet,
          parameters: cleanInvokeParams(step.parameters),
          description: step.cmdlet,
        });
      }
    } else if (raw.cmdlet && raw.parameters) {
      commands.push({
        cmdletName: raw.cmdlet,
        parameters: cleanInvokeParams(raw.parameters),
        description: raw.cmdlet,
      });
    }
    return { commands, method: DEPLOY_METHOD.EXO_INVOKE };
  }

  /**
   * Extract InvokeCommand calls from Exchange Online policies.
   * Same dual-format as Defender. EXO02 is DNS-only (returns empty).
   */
  function extractExchangeInvokePayload(raw, policyId) {
    if (policyId === 'EXO02') return { commands: [], method: DEPLOY_METHOD.PS_ONLY };
    const commands = [];
    if (raw.steps && raw.steps.length > 0) {
      for (const step of raw.steps) {
        if (!step.cmdlet) continue;
        commands.push({
          cmdletName: step.cmdlet,
          parameters: cleanInvokeParams(step.parameters),
          description: step._notes || step.cmdlet,
        });
      }
    } else if (raw.cmdlet && raw.parameters) {
      commands.push({
        cmdletName: raw.cmdlet,
        parameters: cleanInvokeParams(raw.parameters),
        description: raw.cmdlet,
      });
    }
    return { commands, method: DEPLOY_METHOD.EXO_INVOKE };
  }

  /**
   * Extract InvokeCommand calls from Purview policies.
   * Uses powershellCommands{} object with semantic keys.
   * Values can be single {cmdlet, parameters} objects or arrays thereof.
   * Also processes steps[] if present.
   */
  function extractPurviewInvokePayload(raw) {
    const commands = [];
    const cmds = raw.powershellCommands || {};

    for (const [key, cmd] of Object.entries(cmds)) {
      if (!cmd) continue;
      if (Array.isArray(cmd)) {
        for (const item of cmd) {
          if (!item || !item.cmdlet) continue;
          commands.push({
            cmdletName: item.cmdlet,
            parameters: cleanInvokeParams(item.parameters),
            description: key + ': ' + item.cmdlet,
          });
        }
        continue;
      }
      if (!cmd.cmdlet) continue;
      commands.push({
        cmdletName: cmd.cmdlet,
        parameters: cleanInvokeParams(cmd.parameters),
        description: key + ': ' + cmd.cmdlet,
      });
    }

    // Also handle steps[] if present
    if (raw.steps && raw.steps.length > 0) {
      for (const step of raw.steps) {
        if (!step.cmdlet) continue;
        commands.push({
          cmdletName: step.cmdlet,
          parameters: cleanInvokeParams(step.parameters),
          description: step.cmdlet,
        });
      }
    }

    return { commands, method: DEPLOY_METHOD.COMPLIANCE_INVOKE };
  }

  // ─── SharePoint Graph API Mapping ───

  function parseTimeSpanToSeconds(ts) {
    if (!ts) return 0;
    const parts = String(ts).split(':').map(Number);
    return (parts[0] || 0) * 3600 + (parts[1] || 0) * 60 + (parts[2] || 0);
  }

  const SPO_GRAPH_MAP = {
    'SPO07': function () {
      return {
        sharingCapability: 'externalUserSharingOnly',
        isRequireAcceptingUserToMatchInvitedUserEnabled: true,
      };
    },
    'SPO09': function () {
      return { isLegacyAuthProtocolsEnabled: false };
    },
    'SPO13': function (raw) {
      var params = (raw.steps && raw.steps[0] && raw.steps[0].parameters) || raw.parameters || {};
      var domainStr = params.SharingAllowedDomainList || 'partner1.com partner2.com';
      var domains = domainStr.split(/[\s,]+/).filter(Boolean);
      return {
        sharingDomainRestrictionMode: 'allowList',
        sharingAllowedDomainList: domains,
      };
    },
    'SPO15': function (raw) {
      var params = (raw.steps && raw.steps[0] && raw.steps[0].parameters) || raw.parameters || {};
      return {
        idleSessionSignOut: {
          isEnabled: true,
          warnAfterInSeconds: parseTimeSpanToSeconds(params.WarnAfter || '00:55:00'),
          signOutAfterInSeconds: parseTimeSpanToSeconds(params.SignOutAfter || '01:00:00'),
        },
      };
    },
    'SPO19': function () {
      return { isResharingByExternalUsersEnabled: false };
    },
  };

  function extractSpoGraphPayload(raw, policyId) {
    var transform = SPO_GRAPH_MAP[policyId];
    if (!transform) return { calls: [] };
    var body = transform(raw);
    return {
      calls: [{
        endpoint: '/v1.0/admin/sharepoint/settings',
        method: 'PATCH',
        body: body,
        description: 'Update SharePoint tenant settings for ' + policyId,
      }],
    };
  }

  // ─── Graph API Execution ───

  const GRAPH_BASE = 'https://graph.microsoft.com';

  function decodeTokenScopes(token) {
    try {
      const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
      return { scp: payload.scp || '(none)', roles: payload.roles || [], aud: payload.aud || '', appid: payload.appid || payload.azp || '' };
    } catch (e) { return { scp: '(decode error)', roles: [], aud: '', appid: '' }; }
  }

  async function callGraphApi(endpoint, method, body) {
    const token = await TenantAuth.getGraphToken();
    if (!token) return { success: false, status: 0, error: 'No access token — please sign in' };

    const url = endpoint.startsWith('http') ? endpoint : GRAPH_BASE + endpoint;
    const opts = {
      method: method,
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
      },
    };
    if (body && method !== 'GET') opts.body = JSON.stringify(body);

    try {
      const res = await fetch(url, opts);
      const text = await res.text();
      let data = null;
      try { data = JSON.parse(text); } catch (e) { /* non-JSON */ }

      if (res.ok) {
        return { success: true, status: res.status, data: data };
      } else if (res.status === 409 || (data && data.error && data.error.code === 'ConditionalAccessPolicyAlreadyExists')) {
        return { success: false, status: 409, error: 'Policy already exists', data: data };
      } else if (res.status === 429) {
        return { success: false, status: 429, error: 'Rate limited — try again shortly', data: data };
      } else {
        const msg = (data && data.error && data.error.message) || text || res.statusText;
        if (res.status === 401 || res.status === 403 || msg.toLowerCase().includes('scope')) {
          const tokenInfo = decodeTokenScopes(token);
          console.error('[Deploy Debug] Token scopes:', tokenInfo.scp);
          console.error('[Deploy Debug] Token audience:', tokenInfo.aud);
          console.error('[Deploy Debug] Token appId:', tokenInfo.appid);
          console.error('[Deploy Debug] Endpoint:', method, url);
          return { success: false, status: res.status, error: msg + ' [aud: ' + tokenInfo.aud + ' | scp: ' + tokenInfo.scp + ']', data: data };
        }
        return { success: false, status: res.status, error: msg, data: data };
      }
    } catch (err) {
      return { success: false, status: 0, error: err.message };
    }
  }

  // ─── InvokeCommand REST Execution (new) ───

  const EXO_INVOKE_BASE = 'https://outlook.office365.com/adminapi/beta/';
  const COMPLIANCE_INVOKE_BASE = 'https://ps.compliance.protection.outlook.com/adminapi/beta/';

  /**
   * Call the InvokeCommand REST API (Exchange or Compliance).
   * This is the same REST backend that the EXO V3 PowerShell module uses.
   */
  async function callInvokeCommand(cmdletName, parameters, method) {
    const isCompliance = (method === DEPLOY_METHOD.COMPLIANCE_INVOKE);

    // Get the right token
    const token = isCompliance
      ? await TenantAuth.getComplianceToken()
      : await TenantAuth.getExchangeToken();

    if (!token) {
      return {
        success: false, status: 0,
        error: 'No ' + (isCompliance ? 'Compliance' : 'Exchange') + ' token — ensure permissions are granted and re-sign in',
      };
    }

    const acct = TenantAuth.getAccount();
    if (!acct || !acct.tenantId) {
      return { success: false, status: 0, error: 'No tenant ID — please sign in' };
    }

    const base = isCompliance ? COMPLIANCE_INVOKE_BASE : EXO_INVOKE_BASE;
    const url = base + acct.tenantId + '/InvokeCommand';

    const body = {
      CmdletInput: {
        CmdletName: cmdletName,
        Parameters: parameters || {},
      },
    };

    const opts = {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json;odata.metadata=minimal',
        'X-ResponseFormat': 'json',
      },
      body: JSON.stringify(body),
    };

    try {
      const res = await fetch(url, opts);
      const text = await res.text();
      let data = null;
      try { data = JSON.parse(text); } catch (e) { /* non-JSON */ }

      if (res.ok) {
        // InvokeCommand returns HTTP 200 even on cmdlet errors;
        // check for ErrorRecords in the response
        if (data && data.ErrorRecords && data.ErrorRecords.length > 0) {
          var errMsg = '';
          var rec = data.ErrorRecords[0];
          if (rec.ErrorRecord && rec.ErrorRecord.Exception && rec.ErrorRecord.Exception.Message) {
            errMsg = rec.ErrorRecord.Exception.Message;
          } else if (rec.Message) {
            errMsg = rec.Message;
          } else {
            errMsg = JSON.stringify(rec).substring(0, 200);
          }
          return { success: false, status: res.status, error: errMsg, data: data };
        }
        // Check for @odata error format
        if (data && data.error && data.error.message) {
          return { success: false, status: res.status, error: data.error.message, data: data };
        }
        return { success: true, status: res.status, data: data };
      } else if (res.status === 401 || res.status === 403) {
        const tokenInfo = decodeTokenScopes(token);
        const msg = (data && data.error && data.error.message) || text || res.statusText;
        console.error('[InvokeCommand] Auth error:', {
          status: res.status,
          audience: tokenInfo.aud,
          scopes: tokenInfo.scp,
          cmdlet: cmdletName,
        });
        return {
          success: false, status: res.status,
          error: msg + ' [aud: ' + tokenInfo.aud + ' | scp: ' + tokenInfo.scp + ']',
        };
      } else {
        const msg = (data && data.error && data.error.message) || text || res.statusText;
        return { success: false, status: res.status, error: msg, data: data };
      }
    } catch (err) {
      // CORS errors surface as TypeError with no status
      const errMsg = err.name === 'TypeError'
        ? 'Network/CORS error — the InvokeCommand endpoint may not allow browser requests. Error: ' + err.message
        : 'Network error: ' + err.message;
      return { success: false, status: 0, error: errMsg };
    }
  }

  // ─── Preflight Checks ───

  let preflightResults = { graph: false, exo: false, compliance: false };

  async function runPreflight(method) {
    method = method || DEPLOY_METHOD.GRAPH;

    if (method === DEPLOY_METHOD.GRAPH || method === DEPLOY_METHOD.SPO_GRAPH) {
      if (preflightResults.graph) return true;
      const token = await TenantAuth.getGraphToken();
      if (!token) {
        showToast('No Graph token — please sign in first');
        return false;
      }
      const info = decodeTokenScopes(token);
      console.log('[Preflight] Graph — aud:', info.aud, '| scp:', info.scp);
      const me = await callGraphApi('/v1.0/me', 'GET', null);
      if (!me.success) {
        showToast('Graph preflight failed: ' + me.error);
        return false;
      }
      console.log('[Preflight] Graph OK:', me.data && me.data.displayName);
      preflightResults.graph = true;
      return true;
    }

    if (method === DEPLOY_METHOD.EXO_INVOKE) {
      if (preflightResults.exo) return true;
      const token = await TenantAuth.getExchangeToken();
      if (!token) {
        showToast('No Exchange token — add Exchange.Manage permission and re-sign in');
        return false;
      }
      const info = decodeTokenScopes(token);
      console.log('[Preflight] Exchange — aud:', info.aud, '| scp:', info.scp);
      // Test with a read-only cmdlet
      const test = await callInvokeCommand('Get-OrganizationConfig', {}, DEPLOY_METHOD.EXO_INVOKE);
      if (!test.success) {
        showToast('Exchange preflight failed: ' + test.error);
        return false;
      }
      console.log('[Preflight] Exchange InvokeCommand OK');
      preflightResults.exo = true;
      return true;
    }

    if (method === DEPLOY_METHOD.COMPLIANCE_INVOKE) {
      if (preflightResults.compliance) return true;
      const token = await TenantAuth.getComplianceToken();
      if (!token) {
        showToast('No Compliance token — add Security & Compliance permission and re-sign in');
        return false;
      }
      const info = decodeTokenScopes(token);
      console.log('[Preflight] Compliance — aud:', info.aud, '| scp:', info.scp);
      const test = await callInvokeCommand('Get-DlpCompliancePolicy', {}, DEPLOY_METHOD.COMPLIANCE_INVOKE);
      if (!test.success) {
        showToast('Compliance preflight failed: ' + test.error);
        return false;
      }
      console.log('[Preflight] Compliance InvokeCommand OK');
      preflightResults.compliance = true;
      return true;
    }

    return false;
  }

  // ─── Deployment Execution ───

  async function deploySinglePolicy(id) {
    const pol = AppState.get('policies').find(function (p) { return p.id === id; });
    if (!pol) return { success: false, error: 'Policy not found' };

    const method = getDeployMethod(pol.type, pol.id);
    if (method === DEPLOY_METHOD.PS_ONLY) {
      return { success: false, error: 'PowerShell-only policy — use Generate Script' };
    }

    // Run preflight for this deployment method
    if (!await runPreflight(method)) {
      setDeploymentStatus(id, 'failed', 'Preflight failed for ' + method);
      return { success: false, error: 'Preflight failed' };
    }

    setDeploymentStatus(id, 'deploying', 'Deploying...');

    try {
      const rawPolicy = await DataStore.loadPolicy(pol.type, pol.file);

      // ── Route by deployment method ──

      if (method === DEPLOY_METHOD.GRAPH) {
        // Existing Graph API deployment
        var payload = extractPayload(rawPolicy, pol.type);
        if (payload.calls.length === 0) {
          setDeploymentStatus(id, 'failed', 'No deployable payload found');
          return { success: false, error: 'No deployable payload' };
        }
        for (var i = 0; i < payload.calls.length; i++) {
          var call = payload.calls[i];
          var result = await callGraphApi(call.endpoint, call.method, call.body);
          if (!result.success) {
            if (result.status === 409) {
              setDeploymentStatus(id, 'exists', 'Already exists in tenant');
              showToast(pol.id + ': already exists');
              return { success: false, status: 'exists', error: result.error };
            }
            setDeploymentStatus(id, 'failed', result.error);
            showToast(pol.id + ' failed: ' + result.error);
            return { success: false, error: result.error };
          }
        }
      }

      else if (method === DEPLOY_METHOD.SPO_GRAPH) {
        // SharePoint Graph API (PATCH /admin/sharepoint/settings)
        var spoPayload = extractSpoGraphPayload(rawPolicy, pol.id);
        if (spoPayload.calls.length === 0) {
          setDeploymentStatus(id, 'failed', 'No SPO Graph payload for ' + pol.id);
          return { success: false, error: 'No SPO Graph payload' };
        }
        for (var si = 0; si < spoPayload.calls.length; si++) {
          var spoCall = spoPayload.calls[si];
          var spoResult = await callGraphApi(spoCall.endpoint, spoCall.method, spoCall.body);
          if (!spoResult.success) {
            setDeploymentStatus(id, 'failed', spoResult.error);
            showToast(pol.id + ' failed: ' + spoResult.error);
            return { success: false, error: spoResult.error };
          }
        }
      }

      else if (method === DEPLOY_METHOD.EXO_INVOKE) {
        // Exchange InvokeCommand (DEF + EXO policies)
        var exoExtractor = pol.type === 'defender'
          ? extractDefenderInvokePayload(rawPolicy)
          : extractExchangeInvokePayload(rawPolicy, pol.id);

        if (exoExtractor.commands.length === 0) {
          setDeploymentStatus(id, 'failed', 'No deployable commands');
          return { success: false, error: 'No deployable commands' };
        }

        for (var ei = 0; ei < exoExtractor.commands.length; ei++) {
          var cmd = exoExtractor.commands[ei];
          var exoResult = await callInvokeCommand(cmd.cmdletName, cmd.parameters, DEPLOY_METHOD.EXO_INVOKE);
          if (!exoResult.success) {
            setDeploymentStatus(id, 'failed', cmd.cmdletName + ': ' + exoResult.error);
            showToast(pol.id + ' failed at ' + cmd.cmdletName + ': ' + exoResult.error);
            return { success: false, error: exoResult.error };
          }
          // Delay between multi-step commands (Policy+Rule pattern)
          if (exoExtractor.commands.length > 1 && ei < exoExtractor.commands.length - 1) {
            await new Promise(function (r) { setTimeout(r, 500); });
          }
        }
      }

      else if (method === DEPLOY_METHOD.COMPLIANCE_INVOKE) {
        // Compliance InvokeCommand (PV policies)
        var pvExtractor = extractPurviewInvokePayload(rawPolicy);

        if (pvExtractor.commands.length === 0) {
          setDeploymentStatus(id, 'failed', 'No deployable commands');
          return { success: false, error: 'No deployable commands' };
        }

        for (var pi = 0; pi < pvExtractor.commands.length; pi++) {
          var pvCmd = pvExtractor.commands[pi];
          var pvResult = await callInvokeCommand(pvCmd.cmdletName, pvCmd.parameters, DEPLOY_METHOD.COMPLIANCE_INVOKE);
          if (!pvResult.success) {
            setDeploymentStatus(id, 'failed', pvCmd.cmdletName + ': ' + pvResult.error);
            showToast(pol.id + ' failed at ' + pvCmd.cmdletName + ': ' + pvResult.error);
            return { success: false, error: pvResult.error };
          }
          if (pvExtractor.commands.length > 1 && pi < pvExtractor.commands.length - 1) {
            await new Promise(function (r) { setTimeout(r, 500); });
          }
        }
      }

      setDeploymentStatus(id, 'success', 'Deployed successfully');
      showToast(pol.id + ' deployed successfully');
      return { success: true };
    } catch (err) {
      setDeploymentStatus(id, 'failed', err.message);
      showToast(pol.id + ' error: ' + err.message);
      return { success: false, error: err.message };
    }
  }

  async function deployBulk(policyIds) {
    const results = { total: policyIds.length, succeeded: 0, failed: 0, exists: 0 };
    AppState.set('deploymentProgress', { ...results, completed: 0 });

    for (let i = 0; i < policyIds.length; i++) {
      const result = await deploySinglePolicy(policyIds[i]);
      if (result.success) results.succeeded++;
      else if (result.status === 'exists') results.exists++;
      else results.failed++;

      AppState.set('deploymentProgress', { ...results, completed: i + 1 });

      if (i < policyIds.length - 1) {
        await new Promise(r => setTimeout(r, 300));
      }
    }

    AppState.set('deploymentProgress', null);
    showToast(`Deployed: ${results.succeeded} success, ${results.exists} existing, ${results.failed} failed`);
    return results;
  }

  // ─── Deployment Status ───

  function getDeploymentStatus(id) {
    const statuses = AppState.get('deploymentStatus') || {};
    return statuses[id] || null;
  }

  function setDeploymentStatus(id, status, detail) {
    const statuses = { ...(AppState.get('deploymentStatus') || {}) };
    statuses[id] = { status, detail, timestamp: Date.now() };
    AppState.set('deploymentStatus', statuses);
  }

  function clearDeploymentStatus() {
    AppState.set('deploymentStatus', {});
    preflightResults = { graph: false, exo: false, compliance: false };
  }

  // ─── Permissions Info ───

  function getRequiredPermissions(type, policyId) {
    var method = getDeployMethod(type, policyId);
    switch (method) {
      case DEPLOY_METHOD.GRAPH:
        switch (type) {
          case 'conditional-access': return ['Policy.ReadWrite.ConditionalAccess'];
          case 'intune': return ['DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All'];
          case 'entra': return ['Policy.ReadWrite.Authorization', 'Directory.ReadWrite.All', 'Policy.ReadWrite.AuthenticationMethod'];
          case 'defender-endpoint': return ['DeviceManagementConfiguration.ReadWrite.All'];
          default: return [];
        }
      case DEPLOY_METHOD.EXO_INVOKE:
        return ['Exchange.Manage (delegated)'];
      case DEPLOY_METHOD.COMPLIANCE_INVOKE:
        return ['Compliance Center (delegated)'];
      case DEPLOY_METHOD.SPO_GRAPH:
        return ['SharePointTenantSettings.ReadWrite.All'];
      default:
        return [];
    }
  }

  function getRequiredRoles(type) {
    switch (type) {
      case 'conditional-access': return ['Conditional Access Administrator', 'Security Administrator'];
      case 'intune': return ['Intune Administrator'];
      case 'entra': return ['Global Administrator'];
      case 'defender-endpoint': return ['Security Administrator', 'Intune Administrator'];
      case 'defender': return ['Security Administrator'];
      case 'exchange': return ['Exchange Administrator'];
      case 'sharepoint': return ['SharePoint Administrator'];
      case 'teams': return ['Teams Administrator'];
      case 'purview': return ['Compliance Administrator'];
      default: return ['Global Administrator'];
    }
  }

  // ─── PowerShell Script Generation (unchanged) ───

  function formatPsValue(value) {
    if (value === null || value === undefined) return '$null';
    if (typeof value === 'boolean') return value ? '$true' : '$false';
    if (typeof value === 'number') return String(value);
    if (Array.isArray(value)) {
      if (value.length === 0) return '@()';
      return '@(' + value.map(v => formatPsValue(v)).join(', ') + ')';
    }
    if (typeof value === 'object') {
      const entries = Object.entries(value).map(([k, v]) => `    ${k} = ${formatPsValue(v)}`);
      return '@{\n' + entries.join('\n') + '\n}';
    }
    return '"' + String(value).replace(/"/g, '`"') + '"';
  }

  function scriptHeader(meta, module) {
    const id = meta.id || meta.policyNumber || '';
    const title = meta.title || meta.displayName || '';
    const desc = meta.description || '';
    let s = '#' + '='.repeat(60) + '\n';
    s += `# ${id} - ${title}\n`;
    if (desc) s += `# ${desc.substring(0, 120)}${desc.length > 120 ? '...' : ''}\n`;
    s += '# Generated by M365 Compliance Framework\n';
    s += '# ' + new Date().toISOString().split('T')[0] + '\n';
    s += '#' + '='.repeat(60) + '\n\n';
    if (module) s += `#Requires -Module ${module}\n\n`;
    return s;
  }

  function generateDefenderScript(raw) {
    const meta = raw._metadata || {};
    let s = scriptHeader(meta, 'ExchangeOnlineManagement');
    s += '# Connect to Exchange Online (required for Defender for O365 cmdlets)\n';
    s += 'Connect-ExchangeOnline\n\n';
    for (const step of (raw.steps || [])) {
      s += `# ${step.cmdlet}\n`;
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(step.parameters || {})) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${step.cmdlet} @params\n\n`;
    }
    if (raw.cmdlet && raw.parameters && !(raw.steps && raw.steps.length > 0)) {
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(raw.parameters || {})) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${raw.cmdlet} @params\n\n`;
    }
    if (raw.postDeployment) {
      s += '# --- Post-Deployment Verification ---\n';
      for (const cmd of raw.postDeployment) {
        s += `${cmd}\n`;
      }
    }
    return s;
  }

  function generateExchangeScript(raw) {
    const meta = raw._metadata || {};
    let s = scriptHeader(meta, 'ExchangeOnlineManagement');
    s += '# Connect to Exchange Online\n';
    s += 'Connect-ExchangeOnline\n\n';
    for (const step of (raw.steps || [])) {
      if (step._notes) s += `# ${step._notes.substring(0, 120)}\n`;
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(step.parameters || {})) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${step.cmdlet} @params\n\n`;
    }
    if (raw.cmdlet && raw.parameters && !(raw.steps && raw.steps.length > 0)) {
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(raw.parameters || {})) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${raw.cmdlet} @params\n\n`;
    }
    if (raw.postDeployment) {
      s += '# --- Post-Deployment Verification ---\n';
      for (const cmd of raw.postDeployment) {
        s += `${cmd}\n`;
      }
    }
    return s;
  }

  function generateSharePointScript(raw) {
    const meta = raw._metadata || {};
    let s = scriptHeader(meta, 'PnP.PowerShell');
    s += '# Connect to SharePoint Online Admin\n';
    s += '# Replace <tenant> with your tenant name\n';
    s += 'Connect-PnPOnline -Url "https://<tenant>-admin.sharepoint.com" -Interactive\n\n';
    if (raw.cmdlet && raw.parameters) {
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(raw.parameters)) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${raw.cmdlet} @params\n\n`;
    }
    for (const step of (raw.steps || [])) {
      if (step._notes) s += `# ${step._notes.substring(0, 120)}\n`;
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(step.parameters || {})) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${step.cmdlet} @params\n\n`;
    }
    if (raw.postDeployment) {
      s += '# --- Post-Deployment Verification ---\n';
      for (const cmd of raw.postDeployment) {
        s += `${cmd}\n`;
      }
    }
    return s;
  }

  function generateTeamsScript(raw) {
    const meta = raw._metadata || {};
    let s = scriptHeader(meta, 'MicrosoftTeams');
    s += '# Connect to Microsoft Teams\n';
    s += 'Connect-MicrosoftTeams\n\n';
    if (raw.cmdlet && raw.parameters) {
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(raw.parameters)) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${raw.cmdlet} @params\n\n`;
    }
    for (const step of (raw.steps || [])) {
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(step.parameters || {})) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${step.cmdlet} @params\n\n`;
    }
    if (raw.postDeployment) {
      s += '# --- Post-Deployment Verification ---\n';
      for (const cmd of raw.postDeployment) {
        s += `${cmd}\n`;
      }
    }
    return s;
  }

  function generatePurviewScript(raw) {
    const meta = raw._metadata || {};
    let s = scriptHeader(meta, 'ExchangeOnlineManagement');
    s += '# Connect to Security & Compliance Center\n';
    s += 'Connect-IPPSSession\n\n';
    const cmds = raw.powershellCommands || {};
    for (const [key, cmd] of Object.entries(cmds)) {
      if (!cmd) continue;
      if (Array.isArray(cmd)) {
        s += `# --- ${key} ---\n`;
        for (const item of cmd) {
          if (!item || !item.cmdlet) continue;
          s += `# ${item.cmdlet}\n`;
          s += '$params = @{\n';
          for (const [k, v] of Object.entries(item.parameters || {})) {
            if (k.startsWith('_')) continue;
            s += `    ${k} = ${formatPsValue(v)}\n`;
          }
          s += '}\n';
          s += `${item.cmdlet} @params\n\n`;
        }
        continue;
      }
      if (!cmd.cmdlet) continue;
      s += `# ${key}\n`;
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(cmd.parameters || {})) {
        if (k.startsWith('_')) continue;
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${cmd.cmdlet} @params\n\n`;
    }
    for (const step of (raw.steps || [])) {
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(step.parameters || {})) {
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${step.cmdlet} @params\n\n`;
    }
    if (raw.postDeployment) {
      s += '# --- Post-Deployment Verification ---\n';
      for (const cmd of raw.postDeployment) {
        s += `${cmd}\n`;
      }
    }
    return s;
  }

  function generateScript(rawPolicy, policyType) {
    switch (policyType) {
      case 'defender': return generateDefenderScript(rawPolicy);
      case 'exchange': return generateExchangeScript(rawPolicy);
      case 'sharepoint': return generateSharePointScript(rawPolicy);
      case 'teams': return generateTeamsScript(rawPolicy);
      case 'purview': return generatePurviewScript(rawPolicy);
      default: return '# No PowerShell script available for this policy type\n';
    }
  }

  // ─── Public API ───

  return {
    // Classification
    isGraphDeployable, isPowerShellOnly,
    isDeployable, hasScript, getDeployMethod,
    DEPLOY_METHOD, GRAPH_TYPES, PS_TYPES,
    // Extraction
    extractPayload,
    // Execution
    deploySinglePolicy, deployBulk,
    callGraphApi, callInvokeCommand,
    // Script generation
    generateScript,
    // Status
    getDeploymentStatus, setDeploymentStatus, clearDeploymentStatus,
    // Info
    getRequiredPermissions, getRequiredRoles,
  };
})();
