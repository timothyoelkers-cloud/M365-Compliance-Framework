# M365 Compliance Framework

Open-source Microsoft 365 compliance toolkit mapping **46 global regulatory frameworks** to **140 CIS Microsoft 365 Benchmark v6.0.0 controls**, with **143 deployment-ready JSON policies** across 10 policy types and **11 strategy/maturity models** aligned to official framework structures.

Built as a single-page application (SPA) — no build tools, no frameworks, pure vanilla JavaScript.

---

## Data Accuracy & Validation

This platform is engineered for accuracy at every layer. Customers can trust that what they see maps directly to the authoritative source.

### Strategy & Maturity Mappings

11 frameworks include full **strategy/maturity tier mappings** based on how each governing organisation officially structures their framework:

| Framework | Strategies | Structure | Maturity Levels | Source |
|-----------|-----------|-----------|----------------|--------|
| ASD Essential Eight | 8 | Mitigation Strategies | ML1 / ML2 / ML3 | [cyber.gov.au](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight/essential-eight-maturity-model) |
| NIS2 | 10 | Article 21(2) Measures (a–j) | Essential / Enhanced / Advanced | [EUR-Lex 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555) |
| NIST CSF 2.0 | 6 | Core Functions (GV/ID/PR/DE/RS/RC) | Tier 1 (Partial) / Tier 2 (Risk Informed) / Tier 3 (Repeatable) | [nist.gov/cyberframework](https://www.nist.gov/cyberframework) |
| ISO 27001:2022 | 4 | Annex A Themes (A.5–A.8) | Documented / Implemented / Optimised | [iso.org/standard/27001](https://www.iso.org/standard/27001) |
| CMMC v2.0 | 8 | Consolidated Domains | Level 1 (Foundational) / Level 2 (Advanced) / Level 3 (Expert) | [dodcio.defense.gov/CMMC](https://dodcio.defense.gov/CMMC/) |
| SOC 2 | 5 | Trust Service Criteria (CC/A1/PI/C1/P) | Foundational / Operational / Advanced | [AICPA TSP 100](https://www.aicpa-cima.com/topic/system-and-organization-controls-soc) |
| PCI DSS v4.0 | 6 | Goals (Req 1–12) | Defined / Implemented / Managed | [pcisecuritystandards.org](https://www.pcisecuritystandards.org/document_library/) |
| DORA | 5 | Pillars (Art. 5–45) | Basic / Intermediate / Advanced | [EUR-Lex 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554) |
| GDPR | 6 | Key Articles (Art. 5–49) | Essential / Enhanced / Comprehensive | [EUR-Lex 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj) |
| HIPAA | 4 | Safeguard Types (§164.308–414) | Required / Addressable / Advanced | [hhs.gov/hipaa](https://www.hhs.gov/hipaa/for-professionals/security/index.html) |
| UK NCSC CAF v3.2 | 4 | Objectives (A–D) | Initial / Achieved / Enhanced | [ncsc.gov.uk/caf](https://www.ncsc.gov.uk/collection/cyber-assessment-framework) |

**Integrity guarantees:**
- Every policy in each framework appears in exactly one strategy at exactly one maturity level — no orphans, no duplicates
- Each framework JSON includes a `source` object with the official URL, publication date, and legal reference
- Strategy structures match the official organisational breakdown (e.g., NIS2 uses the 10 measures from Article 21(2)(a)–(j), not an arbitrary grouping)

### Policy Matching Engine

143 match rules evaluate live tenant configuration against expected policy state:

- **Data-driven rules** — each rule specifies a scan source, match mode, and conditions with typed operators (`equals`, `contains`, `containsAny`, `exists`, etc.)
- **Case-insensitive string matching** — operators handle mixed-case Graph API responses correctly
- **OData-aware** — property paths like `@odata.type` are resolved as literal keys, not dot-separated paths
- **Four match statuses:** `configured` (policy detected), `missing` (not found), `manual` (requires PowerShell verification), `not_scanned` (data unavailable)

### Check-to-Policy Mapping

140 CIS Microsoft 365 Benchmark v6.0.0 checks are mapped to 143 M365 policies:

- **Curated mapping** in `check-policy-map.json` — every check has at least one policy recommendation
- **Fallback derivation** — if the curated map is unavailable, mappings are derived from each policy's `cisChecks` field
- **Bidirectional traceability** — from any CIS check you can find the relevant policies, and from any policy you can find which CIS checks it satisfies

### Control-Level Traceability

102 of 143 policies include a `controlMappings` object linking to specific controls within each framework:

```json
{
  "controlMappings": {
    "NIST SP 800-53 Rev.5": ["IA-2", "IA-5", "AC-17(2)"],
    "ISO 27001:2022": ["A.8.5"],
    "MITRE ATT&CK": ["T1078", "T1110"],
    "ASD Essential Eight": ["Restrict administrative privileges"]
  }
}
```

- **NIST SP 800-53 Rev.5** — specific control families (AC, IA, SI, SC, CM, etc.)
- **MITRE ATT&CK** — technique IDs (T1078, T1566, T1059, etc.)
- **ISO 27001:2022** — Annex A control references (A.5.x–A.8.x)
- **ASD Essential Eight** — mitigation strategy names
- **HIPAA, PCI DSS v4.0, NIST SP 800-171** — section/requirement references

### Framework Name Normalisation

All 143 policies reference frameworks using **43 canonical names** — no suffixed variants, no separator inconsistencies:

- `NIST SP 800-53 Rev.5` (not `NIST-800-53` or `NIST SP 800-53 Rev 5 - AC-2, IA-5`)
- `ISO 27001:2022` (not `ISO-27001-2022` or `ISO 27001:2022 A.8.1`)
- `MITRE ATT&CK` (not `MITRE-ATT&CK` or `MITRE ATT&CK - T1078.003`)
- `HIPAA` (not `HIPAA - 164.312(a)(2)(iv)`)

### Test Suite

434 automated tests with 100% pass rate covering:

- All 143 policy match rules — fixture-based tests with `configured` and `missing` scenarios
- Scan aggregation logic (all_configured, some_configured, all_missing)
- Framework selection and check requirement aggregation
- Check data integrity (categories, levels, framework references)
- Policy completeness (every policy has a match rule)

Tests run in headless Chromium via Playwright: `npm test`

---

## Features

### Core Platform
- **Compliance Assessment Wizard** — Select frameworks, review applicable CIS controls, mark compliance status, generate score
- **Compliance Dashboard** — Real-time score, framework coverage bars, gap register with prioritisation, executive summary KPIs, strategy/maturity tables for any framework with `hasStrategies`
- **Policy Library** — 143 policies across 10 types, filterable and downloadable
- **Report Generator** — Branded PDF/HTML/Excel compliance reports with configurable sections including strategy maturity breakdowns

### Tenant Integration (Microsoft Graph API)
- **Live Tenant Scanning** — Authenticate via MSAL.js, scan 15+ Graph API endpoints to detect current policy configuration
- **Batch Graph API** — Uses `$batch` endpoint to scan up to 20 endpoints per request
- **Policy Matching** — 143 match rules comparing live tenant config against expected policy state
- **One-Click Deploy** — Deploy policies directly to your tenant via Graph API
- **Pre-Deploy Configuration** — Interactive config forms for policies requiring tenant-specific values
- **PowerShell Deploy & Verify** — Generated PS scripts for Exchange, Purview, and other non-Graph endpoints
- **Bulk Deploy** — Deploy all policies of a type, or deploy an entire organisation profile at once
- **Dependency Graph** — Automatic dependency resolution ensuring correct deploy order

### Analytics & Monitoring
- **Score Forecasting** — Linear regression trend analysis with 95% confidence intervals
- **Framework Overlap Matrix** — Interactive NxN heatmap showing shared CIS controls between frameworks
- **Policy Change Tracking** — Field-level diff detection between consecutive scans
- **Dependency Graph Visualization** — Interactive SVG with deploy status colouring
- **Scan History** — IndexedDB-backed timeline with score trends and sparkline charts
- **Drift Detection** — Compares current scan against previous results

### Operations & Integrations
- **Audit Trail** — Every action logged to IndexedDB with searchable viewer
- **Scheduled Scans** — Configurable auto-scan intervals (hourly, daily, weekly)
- **Webhook Notifications** — Microsoft Teams, Splunk HEC, Microsoft Sentinel, and CEF format
- **GitHub / Azure DevOps Integration** — Create work items from gap register entries
- **Power BI Export** — Structured dataset export (JSON/CSV) with 5 tables
- **Evidence Collector** — ZIP package with scan results, match data, gap register, and reports
- **Multi-Tenant Management** — Switch between tenants with isolated scan data and state

### User Experience
- **Dark / Light Theme** — Toggle with system preference detection
- **Keyboard Shortcuts** — `Ctrl+S` scan, `Ctrl+E` export, `1`–`5` navigate, `/` search, `T` theme, `Shift+?` help
- **Accessibility** — ARIA landmarks, skip link, focus management, screen reader announcements
- **Offline Mode** — Service worker + cache for offline access
- **Progressive Web App** — Installable PWA with manifest and service worker

---

## Architecture

```
site/
├── index.html              # SPA shell — all pages, modals, bootstrap
├── manifest.json           # PWA manifest
├── sw.js                   # Service worker (cache v12)
├── css/
│   ├── design-system.css   # CSS custom properties, dark theme, typography
│   ├── layout.css          # Grid layout, topbar, sidebar, responsive
│   └── components.css      # Cards, tables, modals, badges, buttons
├── js/                     # 35 vanilla JS modules (IIFE pattern)
│   ├── data.js             # Data loader (checks, frameworks, policies)
│   ├── state.js            # Reactive AppState store (get/set/on/notify)
│   ├── auth.js             # MSAL.js 2.x authentication
│   ├── router.js           # Hash-based SPA router
│   ├── tenant-scanner.js   # Graph API scanner with $batch support
│   ├── policy-matcher.js   # 143 match rules engine
│   ├── deploy.js           # Graph API policy deployment
│   ├── dashboard.js        # Dashboard with strategy maturity tables
│   ├── assessment.js       # Assessment wizard with strategy view
│   ├── policies.js         # Policy library page
│   ├── reports.js          # Report generator (PDF/HTML/Excel)
│   ├── test-runner.js      # 434 automated tests
│   └── ...                 # 23 more modules
├── data/
│   ├── checks.json         # 140 CIS Benchmark v6.0.0 checks
│   ├── check-policy-map.json  # Curated check → policy mapping
│   ├── frameworks.json     # 46 frameworks, 9 groups, 12 org profiles
│   ├── policies-all.json   # All 143 policies with normalised framework refs
│   ├── policies/           # Individual policy JSON files (10 types)
│   └── frameworks/         # Per-framework data (strategies, checks, policies)
└── test-fixtures/
    └── graph-fixtures.js   # Test data for all 143 policy match rules
```

### Data Storage

- **localStorage** — Assessment state, selected frameworks, check status, theme preference
- **IndexedDB** (`m365-compliance`, v2) — 5 object stores: scans, policyCache, evidence, tenantState, auditLog

### Authentication

Uses **MSAL.js 2.x** with three token audiences (Microsoft Graph, Exchange Online, Compliance Center). Authentication flow: `loginPopup` → silent token acquisition → popup fallback.

---

## Frameworks Supported (46)

Organised into 9 groups:

| Group | Frameworks |
|-------|-----------|
| EU Regulatory | DORA, NIS2, GDPR (EU) 2016/679, EU Cyber Resilience Act |
| ISO Standards | ISO 27001:2022, ISO 27701:2019, ISO 27017:2015, ISO 22301:2019 |
| NIST / US Federal | NIST CSF 2.0, NIST CSF 1.1, NIST SP 800-53 Rev.5, NIST SP 800-171, FedRAMP Moderate, CMMC v2.0, CISA CPG, CRI Profile v2.0 |
| US Sector | HIPAA, HITRUST CSF v11, SOC 2, PCI DSS v4.0, NYDFS 23 NYCRR 500, FFIEC-CAT, SEC Cyber Rule, CIRCIA, NERC-CIP |
| UK & Ireland | UK NCSC CAF v3.2, UK NCSC Cyber Essentials v3.2, IASME Cyber Assurance, UK CS&R Bill 2025 |
| APAC & Other | ASD Essential Eight, NZ ISM v3.8, Cybersecure Canada, GSMA FS.31 |
| Regional | BSI IT-Grundschutz, ENS (Spain) RD311/22 |
| Sector Specific | TSA Security Directive, CJIS v6, HPH CPGs |
| Cloud & Tech | CSA CCM v4, Microsoft Cloud Security Benchmark, MITRE ATT&CK |

---

## Policy Types (10 types, 143 policies)

| Type | Prefix | Count | Description |
|------|--------|-------|-------------|
| Conditional Access | CA | 18 | MFA, sign-in risk, device compliance, session controls |
| Defender for Office 365 | DEF | 8 | Anti-phishing, safe links, safe attachments |
| Intune | INT | 20 | Device compliance, configuration profiles, ASR rules |
| Entra ID | ENT | 10 | Authentication methods, password policies, tenant settings |
| Exchange Online | EXO | 10 | Transport rules, mailbox auditing, DKIM/DMARC |
| SharePoint Online | SPO | 20 | Sharing settings, access controls, DLP |
| Teams | TEA | 10 | Meeting policies, messaging, external access |
| Purview | PV | 30 | DLP, sensitivity labels, retention, insider risk |
| Governance | GOV | 5 | Access reviews, PIM, tenant audit |
| Defender for Endpoint | MDE | 12 | EDR, vulnerability management, network protection |

---

## Getting Started

### Prerequisites
- A modern web browser (Chrome, Edge, Firefox, Safari)
- A local HTTP server (the app won't work from `file://`)
- For tenant features: an Azure AD app registration with appropriate delegated permissions

### Running Locally

```bash
git clone https://github.com/timothyoelkers-cloud/M365-Compliance-Framework.git
cd M365-Compliance-Framework

npx serve site
# or: python -m http.server 8000 --directory site
```

Then open `http://localhost:8000` and enter the access code.

### Running Tests

```bash
npm install
npm test
# → 434 passed, 0 failed
```

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

## License

Open source. See repository for details.

---

## Contact

For access requests or questions: [timothy.oelkers@outlook.com](mailto:timothy.oelkers@outlook.com)
