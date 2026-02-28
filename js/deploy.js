/* ═══════════════════════════════════════════
   DEPLOY ENGINE — Graph API + PowerShell generation
═══════════════════════════════════════════ */
const DeployEngine = (() => {

  const GRAPH_TYPES = ['conditional-access', 'intune', 'entra', 'defender-endpoint'];
  const PS_TYPES = ['defender', 'exchange', 'sharepoint', 'teams', 'purview'];

  function isGraphDeployable(type) { return GRAPH_TYPES.includes(type); }
  function isPowerShellOnly(type) { return PS_TYPES.includes(type); }

  // ─── Payload Extraction ───

  function stripMeta(obj) {
    const clone = JSON.parse(JSON.stringify(obj));
    const metaKeys = ['_metadata', '_notes', '_explanation', '_note', '_modeOptions'];
    metaKeys.forEach(k => delete clone[k]);
    return clone;
  }

  // Remove empty arrays/objects and null values to prevent Graph from
  // checking permissions for fields that aren't actually used
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
      // Graph API requires scheduledActionsForRule with a block action
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
      const body = apiCall.body ? JSON.parse(JSON.stringify(apiCall.body)) : undefined;
      calls.push({
        endpoint: endpoint,
        method: apiCall.method || 'PATCH',
        body: body,
        description: apiCall.description || '',
        stepOrder: apiCall.stepOrder || 0,
      });
    }
    // Sort by stepOrder
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
      try { data = JSON.parse(text); } catch (e) { /* non-JSON response */ }

      if (res.ok) {
        return { success: true, status: res.status, data: data };
      } else if (res.status === 409 || (data && data.error && data.error.code === 'ConditionalAccessPolicyAlreadyExists')) {
        return { success: false, status: 409, error: 'Policy already exists', data: data };
      } else if (res.status === 429) {
        return { success: false, status: 429, error: 'Rate limited — try again shortly', data: data };
      } else {
        const msg = (data && data.error && data.error.message) || text || res.statusText;
        // Log token debug info on permission errors
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

  // Pre-flight: verify Graph token works before attempting deployment
  let preflightPassed = false;
  async function runPreflight() {
    if (preflightPassed) return true;
    const token = await TenantAuth.getGraphToken();
    if (!token) {
      showToast('No Graph token — please sign in first');
      return false;
    }
    const info = decodeTokenScopes(token);
    console.log('[Preflight] Token aud:', info.aud, '| appid:', info.appid, '| scp:', info.scp);

    // Test basic Graph access
    const me = await callGraphApi('/v1.0/me', 'GET', null);
    if (!me.success) {
      showToast('Graph preflight failed: GET /me returned ' + me.status + ' — ' + me.error);
      console.error('[Preflight] GET /me failed:', me);
      return false;
    }
    console.log('[Preflight] GET /me OK:', me.data && me.data.displayName);
    preflightPassed = true;
    return true;
  }

  async function deploySinglePolicy(id) {
    const pol = AppState.get('policies').find(p => p.id === id);
    if (!pol) return { success: false, error: 'Policy not found' };
    if (!isGraphDeployable(pol.type)) return { success: false, error: 'PowerShell-only policy' };

    // Run preflight on first deployment
    if (!await runPreflight()) {
      setDeploymentStatus(id, 'failed', 'Graph API preflight failed — check token');
      return { success: false, error: 'Preflight failed' };
    }

    setDeploymentStatus(id, 'deploying', 'Deploying...');

    try {
      const rawPolicy = await DataStore.loadPolicy(pol.type, pol.file);
      const payload = extractPayload(rawPolicy, pol.type);

      if (payload.calls.length === 0) {
        setDeploymentStatus(id, 'failed', 'No deployable payload found');
        return { success: false, error: 'No deployable payload' };
      }

      // Execute calls sequentially
      for (const call of payload.calls) {
        const result = await callGraphApi(call.endpoint, call.method, call.body);
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

      // Small delay to avoid rate limiting
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
  }

  // ─── Permissions Info ───

  function getRequiredPermissions(type) {
    switch (type) {
      case 'conditional-access': return ['Policy.ReadWrite.ConditionalAccess'];
      case 'intune': return ['DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementConfiguration.ReadWrite.All'];
      case 'entra': return ['Policy.ReadWrite.Authorization', 'Directory.ReadWrite.All', 'Policy.ReadWrite.AuthenticationMethod'];
      case 'defender-endpoint': return ['DeviceManagementConfiguration.ReadWrite.All'];
      default: return [];
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

  // ─── PowerShell Script Generation ───

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

    // Teams policies can be flat (cmdlet + parameters) or steps[]
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

    // Purview uses powershellCommands: { createPolicy: {cmdlet, parameters}, createRule: {cmdlet, parameters} }
    const cmds = raw.powershellCommands || {};
    for (const [key, cmd] of Object.entries(cmds)) {
      if (!cmd || !cmd.cmdlet) continue;
      s += `# ${key}\n`;
      s += '$params = @{\n';
      for (const [k, v] of Object.entries(cmd.parameters || {})) {
        if (k.startsWith('_')) continue;
        s += `    ${k} = ${formatPsValue(v)}\n`;
      }
      s += '}\n';
      s += `${cmd.cmdlet} @params\n\n`;
    }

    // Also handle steps[] if present
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

  return {
    isGraphDeployable, isPowerShellOnly,
    extractPayload, deploySinglePolicy, deployBulk,
    callGraphApi,
    generateScript,
    getDeploymentStatus, setDeploymentStatus, clearDeploymentStatus,
    getRequiredPermissions, getRequiredRoles,
    GRAPH_TYPES, PS_TYPES,
  };
})();
