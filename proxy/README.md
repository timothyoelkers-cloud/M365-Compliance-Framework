# M365 Deployment Proxy

A tiny stateless forwarder that lets the M365 Compliance Framework SPA deploy
Defender for O365, Exchange Online, and Purview policies — endpoints that
otherwise block browser CORS.

> **Hosted instance:** `https://m365-deploy-proxy-inforcer.azurewebsites.net/api`
> Hosted in Inforcer Ltd's Azure subscription, CORS-locked to
> `https://timothyoelkers-cloud.github.io`. The SPA uses this by default —
> you only need to deploy your own if you want to host the proxy yourself.

## Why this exists

`outlook.office365.com` and `ps.compliance.protection.outlook.com` host the
REST `InvokeCommand` API used by the EXO V3 PowerShell module. They do not
return CORS headers for browser callers, so a static SPA cannot reach them
directly. This proxy receives the call server-side and forwards the user's
bearer token unchanged.

## Trust model

- The proxy never mints tokens. The SPA acquires a delegated token via MSAL
  for the user, and the proxy passes it through to Microsoft.
- CORS is locked to your SPA origin via `ALLOWED_ORIGIN`.
- Tenant ID is validated as a GUID before forwarding.

## Endpoints

```
GET  /health   → { ok: true } — the SPA "Test" button hits this
POST /invoke   → forwards { target, tenantId, token, cmdlet } to Microsoft
```

`target` is `"exchange"` or `"compliance"`.

## Deploy as an Azure Function (recommended)

```bash
# Prereqs: Azure Functions Core Tools v4, Node 18+
cd proxy
func init . --javascript
# Replace the generated function with the files in this directory.
func azure functionapp publish <YOUR_FUNCTION_APP_NAME>
```

Then set the app setting:

```
ALLOWED_ORIGIN = https://yourorg.github.io
```

Copy the function URL (e.g. `https://m365-deploy.azurewebsites.net/api`) and
paste it into the Connect Tenant modal in the SPA.

## Deploy as a Cloudflare Worker

`index.js` is plain Node. Replace the Azure Functions entrypoint at the bottom
with a `fetch` handler:

```js
export default {
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });
    if (req.method === 'GET' && url.pathname.endsWith('/health')) return jsonResp(200, { ok: true });
    if (req.method === 'POST' && url.pathname.endsWith('/invoke')) {
      const payload = await req.json();
      return await handleInvokeWorker(payload);
    }
    return jsonResp(404, { error: 'Not found' });
  },
};
```

## Security checklist

- Lock `ALLOWED_ORIGIN` to your SPA host. Do not leave it as `*` in production.
- Front the proxy with Azure WAF or Cloudflare if you expect public exposure.
- Consider adding a shared-secret header that the SPA sends and the proxy
  validates if you want a second factor beyond the user's bearer token.
- The proxy logs nothing by default. Add structured logging only if you can
  guarantee tokens are not written to logs.
