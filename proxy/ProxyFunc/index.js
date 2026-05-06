/**
 * M365 Compliance Framework — Deployment Proxy
 *
 * The Exchange Online and Security/Compliance Center REST endpoints
 * (outlook.office365.com, ps.compliance.protection.outlook.com) do not allow
 * browser CORS. This proxy forwards InvokeCommand calls server-side so the
 * SPA can deploy Defender for O365, Exchange Online, and Purview policies
 * with one click.
 *
 * Trust model:
 *   - The SPA acquires the user's delegated token via MSAL and sends it here.
 *   - This proxy does NOT mint tokens; it only forwards the user's bearer
 *     token to the target Microsoft endpoint. All authentication and
 *     authorisation happens at the Microsoft side.
 *   - CORS is restricted to the configured allow-list.
 *   - Set ALLOWED_ORIGIN to your SPA origin (e.g. https://yourorg.github.io).
 *
 * Deploy as Azure Functions (Node 18+), Cloudflare Worker, or any Node host.
 *
 * Endpoints:
 *   GET  /health     → 200 OK (used by the SPA to test connectivity)
 *   POST /invoke     → forwards { target, tenantId, token, cmdlet } to MS
 */

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

const TARGETS = {
  exchange:   'https://outlook.office365.com/adminapi/beta/',
  compliance: 'https://ps.compliance.protection.outlook.com/adminapi/beta/',
};

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

async function handleInvoke(payload) {
  const { target, tenantId, token, cmdlet } = payload || {};
  if (!target || !tenantId || !token || !cmdlet || !cmdlet.CmdletInput) {
    return json(400, { error: 'Missing required fields: target, tenantId, token, cmdlet.CmdletInput' });
  }
  const base = TARGETS[target];
  if (!base) return json(400, { error: 'Unknown target. Use "exchange" or "compliance".' });

  // Basic tenant ID sanity check.
  if (!/^[0-9a-fA-F-]{32,40}$/.test(tenantId)) {
    return json(400, { error: 'tenantId must be a GUID.' });
  }

  const url = base + tenantId + '/InvokeCommand';
  const body = JSON.stringify(cmdlet);

  // One-shot retry on transient connect-level errors. Linux Consumption can
  // have a slow first outbound after idle (ETIMEDOUT / ECONNRESET / EAI_AGAIN);
  // a single retry after a short pause heals it without bubbling to the user.
  const RETRYABLE_CODES = new Set(['ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_SOCKET']);
  const attempts = [0, 1500];  // immediate, then +1.5s
  let lastErr = null;

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
        body: body,
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
      // Retry only on connect-level errors. Otherwise bail immediately.
      if (!RETRYABLE_CODES.has(code) && err.name !== 'AbortError') break;
    }
  }

  // All attempts failed — surface the underlying cause + a hypothesis hint.
  const cause = lastErr && lastErr.cause ? lastErr.cause : {};
  const code = cause.code || (lastErr && lastErr.name === 'AbortError' ? 'TIMEOUT' : null);
  let hint = null;
  if (code === 'ETIMEDOUT' || code === 'TIMEOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') {
    if (target === 'compliance') {
      hint = 'Microsoft\'s compliance endpoint silently dropped the request. Most common cause: this tenant does not have a Microsoft Purview / Security & Compliance workload provisioned (requires M365 E5, E3+Compliance add-on, or Compliance E5).';
    } else {
      hint = 'Microsoft\'s Exchange endpoint did not respond. Check that the signed-in user has an Exchange Online admin role assigned.';
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

// Diagnostic — probe outbound networking to the compliance/exchange endpoints.
// Reports DNS, TCP, TLS, and first-byte timings without needing a real token.
async function handleDiag() {
  const tid = 'e4fcc63f-a000-456e-a120-3984af8367ce';
  const probes = [
    { target: 'compliance', url: 'https://ps.compliance.protection.outlook.com/' },
    { target: 'exchange',   url: 'https://outlook.office365.com/' },
    { target: 'graph',      url: 'https://graph.microsoft.com/v1.0/$metadata' },
    { target: 'compliance-invokecommand-post', url: 'https://ps.compliance.protection.outlook.com/adminapi/beta/' + tid + '/InvokeCommand', method: 'POST',
      body: JSON.stringify({ CmdletInput: { CmdletName: 'Get-DlpCompliancePolicy', Parameters: {} } }),
      headers: { 'Authorization': 'Bearer fake.token.for.diag', 'Content-Type': 'application/json;odata.metadata=minimal', 'X-ResponseFormat': 'json' } },
    { target: 'exchange-invokecommand-post', url: 'https://outlook.office365.com/adminapi/beta/' + tid + '/InvokeCommand', method: 'POST',
      body: JSON.stringify({ CmdletInput: { CmdletName: 'Get-OrganizationConfig', Parameters: {} } }),
      headers: { 'Authorization': 'Bearer fake.token.for.diag', 'Content-Type': 'application/json;odata.metadata=minimal', 'X-ResponseFormat': 'json' } },
  ];
  const results = [];
  for (const p of probes) {
    const start = Date.now();
    let result = { target: p.target, url: p.url, ok: false };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const res = await fetch(p.url, {
        method: p.method || 'GET',
        signal: controller.signal,
        headers: p.headers,
        body: p.body,
      });
      result.ok = true;
      result.status = res.status;
      result.elapsedMs = Date.now() - start;
    } catch (err) {
      const cause = err && err.cause ? err.cause : {};
      result.error = err.message || String(err);
      result.causeCode = cause.code || null;
      result.causeMessage = cause.message || null;
      result.elapsedMs = Date.now() - start;
    } finally {
      clearTimeout(timer);
    }
    results.push(result);
  }
  return json(200, { service: 'm365-deploy-proxy-diag', node: process.version, region: process.env.REGION_NAME || null, results });
}

// ── Azure Functions v4 (Node) entrypoint ──
// function.json uses route "{*restOfPath}" so req.params.restOfPath captures
// the path beyond /api/. We accept either /api/health or just /health.
module.exports = async function (context, req) {
  const path = (req.params && req.params.restOfPath) || '';

  if (req.method === 'OPTIONS') {
    context.res = { status: 204, headers: corsHeaders() };
    return;
  }
  if (req.method === 'GET' && (path === 'health' || path === '')) {
    context.res = json(200, { ok: true, service: 'm365-deploy-proxy' });
    return;
  }
  if (req.method === 'GET' && path === 'diag') {
    context.res = await handleDiag();
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
