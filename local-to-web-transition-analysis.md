# CA Policy Analyzer — Local → Web Hosting Transition

**Source:** chat-export-2026-02-26.md
**Analysis Date:** February 27, 2026

This document highlights the key exchanges where the app transitioned from requiring local hosting with manual app secret configuration to being web-hosted on GitHub Pages where users just approve Graph permissions.

---

## Phase 1: Local Hosting + Manual Secret Setup (Exchanges 10–13)

### Exchange 10 — 08:37 (Line 886)
**The pain point begins** — clicking "Connect Tenant" fails because no `.env.local` exists with the Client ID. Copilot discovers MSAL has no configured client ID and offers to register an Entra ID app automatically.

### Exchange 11 — 08:38 (Line 905)
**App registration via PowerShell** — uses `Connect-MgGraph` + `New-MgApplication` to register the Entra ID app, but it registers in the wrong tenant (Contoso instead of inforcer2M365).

### Exchange 12 — 08:41 (Line 926)
**Re-registers in the correct tenant** — reconnects to inforcer2M365, registers the app (Client ID `b8fe9cbf-f32d-4af7-87ae-0781bc0126c7`), grants admin consent for `Policy.Read.All` / `Application.Read.All` / `Directory.Read.All`, writes `.env.local` manually, and restarts the dev server.

### Exchange 13 — 08:52 (Line 966)
**Local auth working** — confirms everything is configured, dev server picks up `.env.local`, user authenticates via passkey/FIDO2 flow.

---

## Phase 2: Auth Flow Fixes (Exchanges 14–22)

### Exchange 14–15 — 08:53–08:58 (Lines 991–1011)
**Popup → Redirect flow** — MSAL's `loginPopup()` times out in VS Code's Simple Browser (blocks popups). Switched to `loginRedirect()` which navigates the full page to Microsoft login and back.

### Exchange 19 — 09:18 (Line 1136)
**SSR fix** — `PublicClientApplication` was created at module scope, which Next.js evaluates during server-side rendering where `window` doesn't exist. Moved to a lazy getter that only runs in the browser.

### Exchange 22 — 09:28 (Line 1226)
**Committed and pushed** — all auth fixes (popup→redirect, SSR guard) committed. App works locally in Edge with redirect flow.

---

## ⭐ Phase 3: The Key Pivot — "Can I host this on GitHub Pages?" (Exchange 23)

### Exchange 23 — 11:53 (Line 1238)
> **THIS IS THE TURNING POINT**

User asks about hosting on GitHub Pages. Copilot explains the app is 100% client-side (MSAL authenticates in the browser, Graph API calls go direct from browser to Microsoft, no backend needed) and GitHub Pages is a perfect fit.

**What needs to change:**

| Aspect | Before | After |
|--------|--------|-------|
| Hosting | `npm run dev` on localhost | Static files at `jhope188.github.io/ca-policy-analyzer` |
| Next.js output | Server mode | Static export (`output: 'export'`) |
| Base path | `/` | `/ca-policy-analyzer/` |
| Redirect URI | `http://localhost:3000` only | Add GitHub Pages URL to Entra ID app |
| Client ID | `.env.local` (gitignored, manual) | Baked into the build |

---

## Phase 4: Implementation — Web Hosting + Public Client ID (Exchanges 24–26)

### Exchange 24 — 11:55 (Line 1305)
**Full implementation** — updates `next.config` for static export with `basePath`, updates `msal-config.ts` with GitHub Pages redirect URI, creates GitHub Actions workflow (`.github/workflows/deploy.yml`) for auto-deploy on push to `main`.

### Exchange 25 — 12:11 (Line 1350)
> **THE SECURITY DECISION** — "Is hardcoding the Client ID safe?"

Copilot explains:
- It's a **public SPA client** — no client secret exists
- The Client ID is just an **identifier**, not a credential
- Even injected via GitHub secret, it still ends up in the JS bundle every visitor downloads
- Microsoft's own MSAL samples hardcode Client IDs
- **Real protection comes from:** redirect URI whitelist, user authentication, admin consent, delegated permissions

### Exchange 26 — 12:11 (Line 1408)
**Final switch** — hardcodes Client ID as fallback in `msal-config.ts`, removes GitHub Actions secret reference from workflow, builds, commits, and pushes. Instructions to enable GitHub Pages in repo settings (`Settings → Pages → Source: GitHub Actions`).

---

## Before vs. After Summary

| Aspect | Before (Exchanges 10–13) | After (Exchanges 23–26) |
|--------|--------------------------|------------------------|
| **Hosting** | `npm run dev` on localhost | GitHub Pages at `jhope188.github.io/ca-policy-analyzer` |
| **Client ID** | Stored in gitignored `.env.local`, manually created per machine | Hardcoded in source — public SPA client, not a secret |
| **User setup** | Clone repo → `npm install` → create `.env.local` → register app → grant consent → `npm run dev` | Visit URL → click "Connect Tenant" → approve Graph permissions → done |
| **Deployment** | Manual (developer runs locally) | Auto-deploy via GitHub Actions on push to `main` |
| **Audience** | Developer on their own machine | Anyone with a browser and Entra ID credentials |

---

## Key Takeaway

The entire architecture shift — from "developer must configure a local environment with secrets" to "anyone with a browser can use it by approving Graph permissions" — was triggered by a single question in **Exchange 23** about GitHub Pages. The realization that the app is 100% client-side (no backend, no secrets, just static files + browser-based MSAL auth) made web hosting not just possible but trivially simple.
