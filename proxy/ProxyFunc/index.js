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
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token,
      'Content-Type':  'application/json;odata.metadata=minimal',
      'X-ResponseFormat': 'json',
    },
    body: JSON.stringify(cmdlet),
  });
  const text = await res.text();
  return {
    status: res.status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
    body: text,
  };
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
