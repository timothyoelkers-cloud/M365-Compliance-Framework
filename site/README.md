# M365 Compliance Framework

Open-source compliance toolkit mapping **46 global frameworks** to **CIS Microsoft 365 Benchmark v3** controls, with **110 deployment-ready JSON policies**.

## Features

- **Compliance Assessment** — Step-by-step wizard to select frameworks, review required controls, and track compliance status
- **Dashboard** — Real-time compliance score, framework coverage bars, and prioritised gap register
- **Policy Library** — 110 deployment-ready M365 policies across 8 types (Conditional Access, Defender, Exchange, SharePoint, Teams, Intune, Purview, Entra)
- **Report Generator** — Branded compliance reports exportable as PDF or HTML
- **JSON API** — All data available as structured JSON for programmatic access

## Frameworks Covered (46)

| Region | Frameworks |
|--------|-----------|
| EU Regulatory | DORA, NIS2, GDPR, EU Cyber Resilience Act |
| ISO Standards | ISO 27001:2022, ISO 27701:2019, ISO 27017:2015, ISO 22301:2019 |
| NIST / US Federal | NIST CSF 2.0, NIST CSF 1.1, SP 800-53, SP 800-171, FedRAMP, CMMC, CISA CPG |
| US Sector | HIPAA, HITRUST, SOC 2, PCI DSS v4.0, NYDFS, FFIEC, CRI, CIRCIA, SEC |
| UK & Ireland | NCSC CAF, Cyber Essentials, IASME, UK CS&R Bill 2025 |
| APAC & Other | ASD Essential Eight, NZ ISM, Cybersecure Canada, GSMA FS.31 |
| Regional | BSI IT-Grundschutz, ENS (Spain) |
| Sector Specific | NERC-CIP, TSA, CJIS, HPH CPGs |
| Cloud & Tech | CSA CCM v4, Microsoft Cloud Benchmark, COBIT, MITRE ATT&CK |

## Organisation Profiles (12)

Pre-built framework sets for common compliance scenarios:

EU Financial, EU General, UK Organisation, US Federal, US Healthcare, US Financial, US Listed/Public, Critical Infrastructure, Defence/CMMC, Germany (BSI), Spain (ENS), Cloud/SaaS Vendor

## JSON Data Structure

```
data/
├── index.json              # Master manifest
├── checks.json             # 140 CIS M365 checks
├── frameworks.json         # Framework list, groups, profiles
├── policies-all.json       # All 110 policies
├── policies/
│   ├── index.json          # Policy type metadata
│   ├── conditional-access/ # 18 policies
│   ├── defender/           # 8 policies
│   ├── defender-endpoint/  # 12 policies
│   ├── entra/              # 10 policies
│   ├── exchange/           # 10 policies
│   ├── intune/             # 20 policies
│   ├── purview/            # 12 policies
│   ├── sharepoint/         # 10 policies
│   └── teams/              # 10 policies
└── frameworks/             # 45 cross-reference files
    ├── nist-csf-2-0.json
    ├── iso-27001-2022.json
    └── ...
```

## Local Development

Serve the site directory with any HTTP server:

```bash
# Python
cd site && python -m http.server 8080

# Node.js
npx serve site

# VS Code Live Server
# Open site/index.html and use the Live Server extension
```

Then open `http://localhost:8080`.

> **Note:** The site requires HTTP serving (not `file://`) because it loads JSON data via `fetch()`.

## Deployment

This site is designed for **GitHub Pages**:

1. Push the `site/` directory contents to the `gh-pages` branch, or
2. Set GitHub Pages source to the `site/` folder in repository settings

The `.nojekyll` file is included to bypass Jekyll processing.

## Licence

Open source. Data based on CIS Microsoft 365 Benchmark v3.
