/**
 * M365 Compliance Framework — Deployment Proxy (App-Only mode)
 *
 * Server-side OAuth client_credentials flow. The SPA only signs the user
 * in for identity (user clicks Connect Tenant in the browser), but every
 * Defender/Exchange/Purview deploy is performed by THIS proxy authenticating
 * AS THE APP using a client secret. The user's bearer token is no longer
 * forwarded for those workloads.
 *
 * Trust model:
 *   - APP_CLIENT_SECRET is held only on the Function App (encrypted-at-rest).
 *   - For each customer tenant, we acquire a tenant-scoped app token via
 *     /token endpoint with grant_type=client_credentials.
 *   - That token is sent to outlook.office365.com / ps.compliance...
 *     /adminapi/beta/{tenantId}/InvokeCommand.
 *   - Customer tenant must have the app SP and a role assignment
 *     (Organization Management / Compliance Admin) — see /onboarding doc.
 *
 * Endpoints:
 *   GET  /health     → 200 OK
 *   GET  /diag       → upstream connectivity probe (anonymous)
 *   POST /invoke     → forwards { target, tenantId, cmdlet } to MS using app-only auth
 */

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const APP_CLIENT_ID  = process.env.APP_CLIENT_ID  || '';
const APP_CLIENT_SECRET = process.env.APP_CLIENT_SECRET || '';

const TARGETS = {
  exchange:   'https://outlook.office365.com/adminapi/beta/',
  compliance: 'https://ps.compliance.protection.outlook.com/adminapi/beta/',
};
// Both Exchange and Compliance endpoints accept tokens with this audience
// when the app has Exchange.ManageAsApp application permission.
const TOKEN_RESOURCE_SCOPE = 'https://outlook.office365.com/.default';

// ── Per-tenant app token cache ────────────────────────────────────────────
// Tokens last ~60 min; cache for 55 min to give a safety margin.
const tokenCache = new Map();  // key: tenantId → { token, expiresAt }
const TOKEN_TTL_MS = 55 * 60 * 1000;

async function getAppTokenForTenant(tenantId) {
  const now = Date.now();
  const cached = tokenCache.get(tenantId);
  if (cached && cached.expiresAt > now) return cached.token;

  if (!APP_CLIENT_ID || !APP_CLIENT_SECRET) {
    throw new Error('Proxy not configured: APP_CLIENT_ID / APP_CLIENT_SECRET missing');
  }

  const url = 'https://login.microsoftonline.com/' + encodeURIComponent(tenantId) + '/oauth2/v2.0/token';
  const body = new URLSearchParams({
    client_id:     APP_CLIENT_ID,
    client_secret: APP_CLIENT_SECRET,
    scope:         TOKEN_RESOURCE_SCOPE,
    grant_type:    'client_credentials',
  });

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch (_) { data = null; }

  if (!res.ok || !data || !data.access_token) {
    const err = (data && data.error_description) || (data && data.error) || text || res.statusText;
    const e = new Error('Failed to acquire app token for tenant ' + tenantId + ': ' + err);
    e.aadError = data || { raw: text };
    e.status = res.status;
    throw e;
  }

  tokenCache.set(tenantId, { token: data.access_token, expiresAt: now + TOKEN_TTL_MS });
  return data.access_token;
}

// ── CORS / response helpers ──
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin':  ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age':       '600',
  };
}
function json(status, body) {
  return {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
    body: JSON.stringify(body),
  };
}

// ── /invoke handler ─────────────────────────────────────────────────────
async function handleInvoke(payload) {
  const { target, tenantId, cmdlet, userToken } = payload || {};
  if (!target || !tenantId || !cmdlet || !cmdlet.CmdletInput) {
    return json(400, { error: 'Missing required fields: target, tenantId, cmdlet.CmdletInput' });
  }
  const base = TARGETS[target];
  if (!base) return json(400, { error: 'Unknown target. Use "exchange" or "compliance".' });
  if (!/^[0-9a-fA-F-]{32,40}$/.test(tenantId)) {
    return json(400, { error: 'tenantId must be a GUID.' });
  }

  // 1) Get a token: either use the caller-supplied delegated token (used
  //    during onboarding to register the EXO/IPPS service principal under
  //    the user's identity), or acquire an app-only token via client_credentials.
  let token;
  if (userToken) {
    token = userToken;
  } else {
    try {
      token = await getAppTokenForTenant(tenantId);
    } catch (err) {
      return json(401, {
        error: 'App-only token acquisition failed',
        message: err.message,
        hint: 'Has the customer admin granted consent for Exchange.ManageAsApp and assigned the app to a role? See /api/onboarding for instructions.',
        aadError: err.aadError || null,
      });
    }
  }

  // 2) Call the InvokeCommand endpoint with the app token.
  // Retry once on connect-level errors (cold-start outbound networking).
  const RETRYABLE_CODES = new Set(['ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_SOCKET']);
  const attempts = [0, 1500];
  let lastErr = null;
  const url = base + tenantId + '/InvokeCommand';

  for (let i = 0; i < attempts.length; i++) {
    if (attempts[i] > 0) await new Promise(r => setTimeout(r, attempts[i]));

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + token,
          'Content-Type':  'application/json;odata.metadata=minimal',
          'X-ResponseFormat': 'json',
        },
        body: JSON.stringify(cmdlet),
        signal: controller.signal,
      });
      clearTimeout(timer);
      const text = await res.text();
      return {
        status: res.status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
        body: text,
      };
    } catch (err) {
      clearTimeout(timer);
      lastErr = err;
      const cause = err && err.cause ? err.cause : {};
      const code = cause.code || (err.name === 'AbortError' ? 'TIMEOUT' : null);
      if (!RETRYABLE_CODES.has(code) && err.name !== 'AbortError') break;
    }
  }

  const cause = lastErr && lastErr.cause ? lastErr.cause : {};
  const code = cause.code || (lastErr && lastErr.name === 'AbortError' ? 'TIMEOUT' : null);
  let hint = null;
  if (code === 'ETIMEDOUT' || code === 'TIMEOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') {
    if (target === 'compliance') {
      hint = 'Microsoft compliance endpoint did not respond. The most common cause now is the app SP has not been assigned a role in this tenant. See /api/onboarding.';
    } else {
      hint = 'Microsoft Exchange endpoint did not respond. Check the app SP role assignment.';
    }
  }
  return json(502, {
    error: 'Upstream fetch failed after retry',
    target: target,
    message: lastErr ? (lastErr.message || String(lastErr)) : 'unknown',
    causeMessage: cause.message || null,
    causeCode: code,
    causeErrno: cause.errno || null,
    url: url,
    hint: hint,
  });
}

// ── Diagnostic ──
async function handleDiag() {
  const probes = [
    { target: 'compliance', url: 'https://ps.compliance.protection.outlook.com/' },
    { target: 'exchange',   url: 'https://outlook.office365.com/' },
    { target: 'graph',      url: 'https://graph.microsoft.com/v1.0/$metadata' },
  ];
  const results = [];
  for (const p of probes) {
    const start = Date.now();
    let result = { target: p.target, url: p.url, ok: false };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const res = await fetch(p.url, { method: 'GET', signal: controller.signal });
      result.ok = true; result.status = res.status; result.elapsedMs = Date.now() - start;
    } catch (err) {
      const cause = err && err.cause ? err.cause : {};
      result.error = err.message || String(err);
      result.causeCode = cause.code || null;
      result.elapsedMs = Date.now() - start;
    } finally {
      clearTimeout(timer);
    }
    results.push(result);
  }
  return json(200, {
    service: 'm365-deploy-proxy-diag',
    node: process.version,
    region: process.env.REGION_NAME || null,
    appConfigured: !!(APP_CLIENT_ID && APP_CLIENT_SECRET),
    cachedTenants: tokenCache.size,
    results,
  });
}

// ── Onboarding instructions ──
function handleOnboarding() {
  const appId = APP_CLIENT_ID || 'c9bcd329-2658-493b-ab75-6afc6d98adc4';
  const consentUrl = 'https://login.microsoftonline.com/common/v2.0/adminconsent' +
    '?client_id=' + appId +
    '&scope=' + encodeURIComponent('https://outlook.office365.com/.default') +
    '&redirect_uri=' + encodeURIComponent('https://timothyoelkers-cloud.github.io/M365-Compliance-Framework/');

  return json(200, {
    appId: appId,
    consentUrl: consentUrl,
    steps: [
      'Step 1 — Customer admin opens the consentUrl in a browser, signs in as Global Admin, accepts the permissions. This creates the app SP in the tenant.',
      'Step 2 — Customer admin runs the PowerShell snippet below to assign roles to the app SP. Required to use Exchange.ManageAsApp at runtime.',
      'Step 3 — Done. The deploy framework can now invoke Exchange/Compliance/Defender cmdlets in this tenant.',
    ],
    powershell:
      '$appId = "' + appId + '"\n' +
      '# Connect as Global Admin or Exchange Admin\n' +
      'Connect-ExchangeOnline\n' +
      'Connect-IPPSSession\n' +
      '\n' +
      '# Look up the AAD service principal object id\n' +
      'Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome\n' +
      '$aadSp = Get-MgServicePrincipal -Filter "appId eq \'$appId\'"\n' +
      'if (-not $aadSp) { throw "AAD service principal not found. Has the consent step been completed?" }\n' +
      '\n' +
      '# Create the Exchange Online service principal entry (if not present)\n' +
      '$exoSp = Get-ServicePrincipal -ErrorAction SilentlyContinue | Where-Object { $_.AppId -eq $appId }\n' +
      'if (-not $exoSp) {\n' +
      '    $exoSp = New-ServicePrincipal -AppId $appId -ServiceId $aadSp.Id -DisplayName "M365 Compliance Framework Deploy"\n' +
      '}\n' +
      '\n' +
      '# Assign the role groups required for the cmdlets the framework invokes\n' +
      'Add-RoleGroupMember -Identity "Organization Management" -Member $exoSp.Identity\n' +
      'Add-RoleGroupMember -Identity "Compliance Administrator" -Member $exoSp.Identity\n' +
      '\n' +
      '# Verify\n' +
      'Get-RoleGroupMember "Organization Management" | Where-Object { $_.Name -eq $exoSp.Identity }\n',
  });
}

// ── Azure Functions v4 entry ──
module.exports = async function (context, req) {
  const path = (req.params && req.params.restOfPath) || '';

  if (req.method === 'OPTIONS') {
    context.res = { status: 204, headers: corsHeaders() };
    return;
  }
  if (req.method === 'GET' && (path === 'health' || path === '')) {
    context.res = json(200, { ok: true, service: 'm365-deploy-proxy', mode: 'app-only', appConfigured: !!(APP_CLIENT_ID && APP_CLIENT_SECRET) });
    return;
  }
  if (req.method === 'GET' && path === 'diag') {
    context.res = await handleDiag();
    return;
  }
  if (req.method === 'GET' && path === 'onboarding') {
    context.res = handleOnboarding();
    return;
  }
  if (req.method === 'POST' && path === 'invoke') {
    try {
      context.res = await handleInvoke(req.body);
    } catch (err) {
      context.res = json(500, { error: err.message || String(err) });
    }
    return;
  }
  context.res = json(404, { error: 'Not found', receivedPath: path, method: req.method });
};
