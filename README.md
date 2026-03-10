# M365 Compliance Framework

Open-source Microsoft 365 compliance toolkit that maps **46 global regulatory frameworks** to **140+ CIS Microsoft 365 Benchmark v3 controls**, with **110 deployment-ready JSON policies** across 10 policy types.

Built as a single-page application (SPA) — no build tools, no frameworks, pure vanilla JavaScript.

---

## Features

### Core Platform
- **Compliance Assessment Wizard** — Step-by-step workflow: select frameworks, review applicable CIS controls, mark compliance status, generate score
- **Compliance Dashboard** — Real-time score, framework coverage bars, gap register with prioritisation, executive summary KPIs
- **Policy Library** — 110 policies across 10 types (Conditional Access, Defender, Intune, Entra, Exchange, SharePoint, Teams, Purview, Governance, Defender for Endpoint), filterable and downloadable
- **Report Generator** — Branded PDF/HTML/Excel compliance reports with configurable sections, cover page, and framework breakdown

### Tenant Integration (Microsoft Graph API)
- **Live Tenant Scanning** — Authenticate via MSAL.js, scan 15+ Graph API endpoints to detect current policy configuration
- **Batch Graph API** — Uses `$batch` endpoint to scan up to 20 endpoints per request for faster scanning
- **Policy Matching** — 138+ match rules that compare live tenant config against expected policy state (configured / missing / partial / manual)
- **One-Click Deploy** — Deploy policies directly to your tenant via Graph API from the policy library or remediation cards
- **Pre-Deploy Configuration** — Interactive config forms for policies that require tenant-specific values before deployment
- **PowerShell Deploy & Verify** — Generated PS scripts for Exchange, Purview, and other endpoints not available via Graph
- **Bulk Deploy** — Deploy all policies of a type, or deploy an entire organisation profile at once
- **Dependency Graph** — Automatic dependency resolution ensuring policies deploy in the correct order

### Analytics & Monitoring
- **Score Forecasting** — Linear regression trend analysis with 95% confidence intervals projecting your compliance score forward
- **Framework Overlap Matrix** — Interactive NxN heatmap showing shared CIS controls between selected frameworks
- **Policy Change Tracking** — Field-level diff detection between consecutive scans highlighting unexpected configuration changes
- **Dependency Graph Visualization** — Interactive SVG showing policy dependency relationships with deploy status colouring
- **Scan History** — IndexedDB-backed timeline of all scans with score trends and sparkline charts
- **Drift Detection** — Compares current scan against previous results to detect configuration drift

### Operations & Integrations
- **Audit Trail** — Every significant action (scans, deploys, exports, logins) logged to IndexedDB with searchable viewer
- **Scheduled Scans** — Configurable auto-scan intervals (hourly, daily, weekly)
- **Webhook Notifications** — Microsoft Teams, Splunk HEC, Microsoft Sentinel, and CEF (syslog) format support
- **GitHub / Azure DevOps Integration** — Create work items from gap register entries directly in your issue tracker
- **Power BI Export** — Structured dataset export (JSON/CSV) with 5 tables for Power BI consumption
- **Evidence Collector** — ZIP package with scan results, match data, gap register, assessment state, and reports
- **Multi-Tenant Management** — Switch between multiple tenants, each with isolated scan data and state

### User Experience
- **Dark / Light Theme** — Toggle with system preference detection and localStorage persistence
- **Keyboard Shortcuts** — `Ctrl+S` scan, `Ctrl+E` export, `1`–`5` navigate, `/` search, `?` help, `T` theme
- **Accessibility** — ARIA landmarks, skip link, focus management, screen reader announcements
- **Offline Mode** — Service worker + cache for offline access to assessment data
- **Progressive Web App** — Installable PWA with manifest and service worker
- **RBAC** — Role-based access control checking Entra ID directory roles

---

## Access Gate

The application is protected by a client-side access gate. Users must enter the correct access code to unlock the application. The code is validated against a SHA-256 hash — once authenticated, a token is stored in `localStorage` so users don't need to re-enter it on subsequent visits.

To request access, use the link on the gate screen.

---

## Architecture

```
site/
├── index.html              # SPA shell — all pages, modals, bootstrap
├── manifest.json           # PWA manifest
├── sw.js                   # Service worker
├── css/
│   ├── design-system.css   # CSS custom properties, dark theme, typography
│   ├── layout.css          # Grid layout, topbar, sidebar, responsive
│   └── components.css      # Cards, tables, modals, badges, buttons
├── js/                     # 35 vanilla JS modules (IIFE pattern)
│   ├── data.js             # Data loader (checks, frameworks, policies)
│   ├── state.js            # Reactive AppState store (get/set/on/notify)
│   ├── auth.js             # MSAL.js 2.x authentication (Graph, Exchange, Compliance tokens)
│   ├── router.js           # Hash-based SPA router
│   ├── tenant-scanner.js   # Graph API scanner with $batch support
│   ├── policy-matcher.js   # 138+ match rules engine
│   ├── deploy.js           # Graph API policy deployment
│   ├── dashboard.js        # Dashboard page renderer
│   ├── assessment.js       # Assessment wizard
│   ├── policies.js         # Policy library page
│   ├── reports.js          # Report generator (PDF/HTML/Excel)
│   └── ...                 # 24 more modules (see below)
└── data/
    ├── checks.json         # 140+ CIS Benchmark v3 checks
    ├── frameworks.json     # 46 frameworks, groups, org profiles
    ├── policies-all.json   # All 110 policies combined
    └── policies/           # Individual policy JSON files
        ├── conditional-access/
        ├── defender/
        ├── intune/
        ├── entra/
        ├── exchange/
        ├── sharepoint/
        ├── teams/
        ├── purview/
        ├── governance/
        └── defender-endpoint/
```

### Module Overview (35 files, ~12,400 lines)

| Module | Purpose |
|--------|---------|
| `state.js` | Reactive store with localStorage persistence |
| `auth.js` | MSAL.js 2.x — Graph, Exchange, Compliance tokens |
| `router.js` | Hash-based SPA routing with page registration |
| `data.js` | Fetches checks, frameworks, policies from `/data/` |
| `tenant-scanner.js` | Graph API scanning with `$batch` support |
| `policy-matcher.js` | 138+ rules matching live config to expected state |
| `deploy.js` | Graph API PUT/POST/PATCH policy deployment |
| `pre-deploy-config.js` | Interactive config forms for deployment |
| `dependency-graph.js` | Policy dependency resolution and ordering |
| `bulk-config.js` | Bulk deployment orchestration |
| `profile-deploy.js` | Organisation profile deployment |
| `ps-deploy.js` | PowerShell script generation for non-Graph endpoints |
| `ps-verify.js` | PowerShell verification script generation |
| `remediation.js` | Remediation cards with deploy-from-card support |
| `scan-diff.js` | Scan-to-scan comparison and drift detection |
| `scan-history.js` | IndexedDB (v2) — scans, cache, evidence, audit |
| `change-tracker.js` | Field-level policy change detection |
| `forecasting.js` | OLS linear regression score forecasting |
| `overlap-matrix.js` | NxN framework overlap heatmap |
| `dep-viz.js` | Interactive SVG dependency graph |
| `audit-trail.js` | Action logging with viewer, export, prune |
| `notifications.js` | Webhooks — Teams, Splunk, Sentinel, CEF |
| `integrations.js` | GitHub/AzDO work items + Power BI export |
| `evidence.js` | ZIP evidence package generator |
| `scheduler.js` | Scheduled scan intervals |
| `rbac.js` | Entra ID role-based access checks |
| `tenant-manager.js` | Multi-tenant switching and isolation |
| `offline.js` | Offline detection and cache management |
| `theme-toggle.js` | Dark/light theme with system preference |
| `keyboard-shortcuts.js` | Global keyboard shortcuts + help modal |
| `assessment.js` | Assessment wizard page |
| `dashboard.js` | Dashboard page with all analytics widgets |
| `policies.js` | Policy library page |
| `reports.js` | Report generator page |
| `test-runner.js` | Built-in test suite |

### Data Storage

- **localStorage** — Assessment state, selected frameworks, check status, theme preference, webhook settings
- **IndexedDB** (`m365-compliance`, v2) — 5 object stores:
  - `scans` — Scan results with match data, keyed by tenant+timestamp
  - `policyCache` — Cached policy configurations
  - `evidence` — Evidence export records
  - `tenantState` — Per-tenant state isolation
  - `auditLog` — Action audit trail with timestamp/action/user indexes

### Authentication

Uses **MSAL.js 2.x** with a registered Azure AD application (`Framework-Assessment-Deployment`). Supports three token audiences:

| Resource | Scope | Used For |
|----------|-------|----------|
| Microsoft Graph | `https://graph.microsoft.com/.default` | Tenant scanning, policy deployment |
| Exchange Online | `https://outlook.office365.com/.default` | Exchange/Defender PowerShell |
| Compliance Center | `https://ps.compliance.protection.outlook.com/.default` | Purview PowerShell |

Authentication flow: `loginPopup` → silent token acquisition → popup fallback on `InteractionRequiredAuthError`.

---

## Getting Started

### Prerequisites
- A modern web browser (Chrome, Edge, Firefox, Safari)
- A local HTTP server (the app won't work from `file://`)
- For tenant features: an Azure AD app registration with appropriate delegated permissions

### Running Locally

```bash
# Clone the repository
git clone https://github.com/timothyoelkers-cloud/M365-Compliance-Framework.git
cd M365-Compliance-Framework

# Serve with any static server
npx serve site
# or
python -m http.server 8000 --directory site
# or
php -S localhost:8000 -t site
```

Then open `http://localhost:8000` and enter the access code.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `1` – `5` | Navigate to Home / Assessment / Dashboard / Policies / Reports |
| `Ctrl+S` | Start tenant scan |
| `Ctrl+E` | Export evidence package |
| `/` | Focus search input |
| `Escape` | Close modal |
| `T` | Toggle dark/light theme |
| `Shift+?` | Show shortcuts help |

---

## Frameworks Supported (46)

Organised into 9 groups covering EU Regulatory, ISO Standards, NIST/US Federal, US Sector, UK & Ireland, APAC & Other, Regional, Sector Specific, and Cloud & Tech frameworks. Includes GDPR, ISO 27001, NIST 800-53, HIPAA, SOX, PCI DSS, Essential Eight, POPIA, and many more.

---

## Policy Types (10)

| Type | Count | Description |
|------|-------|-------------|
| Conditional Access | ~15 | MFA, sign-in risk, device compliance, session controls |
| Defender for Office 365 | ~12 | Anti-phishing, safe links, safe attachments |
| Intune | ~20 | Device compliance, configuration profiles |
| Entra ID | ~10 | Authentication methods, password policies |
| Exchange Online | ~15 | Transport rules, mailbox auditing, OWA policies |
| SharePoint Online | ~8 | Sharing settings, access controls |
| Teams | ~8 | Meeting policies, messaging, external access |
| Purview | ~10 | DLP, sensitivity labels, retention |
| Governance | ~5 | Access reviews, entitlement management |
| Defender for Endpoint | ~7 | Security baselines, attack surface reduction |

---

## License

Open source. See repository for details.

---

## Contact

For access requests or questions: [timothy.oelkers@outlook.com](mailto:timothy.oelkers@outlook.com)
