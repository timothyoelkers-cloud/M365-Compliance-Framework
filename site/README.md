# M365 Compliance Framework

Open-source compliance toolkit mapping **46 global frameworks** to **140 CIS Microsoft 365 Benchmark v6.0.0 controls**, with **143 deployment-ready JSON policies** and **11 strategy/maturity models** aligned to official framework structures.

## Accuracy Guarantee

### Verified Data

- **143 policy match rules** — every rule tested with configured and missing scenarios (434 tests, 100% pass rate)
- **140 CIS checks** — every check mapped to at least one remediation policy via curated `check-policy-map.json`
- **43 canonical framework names** — normalised across all policy references, no inconsistent variants
- **11 strategy frameworks** — each with official source citations (URL, publication date, legal reference)
- **Policy-to-strategy integrity** — every policy appears in exactly one strategy at one maturity level per framework

### Source Citations

Every strategy framework JSON includes a `source` object linking to the authoritative document:

```json
{
  "source": {
    "title": "Directive (EU) 2022/2555 (NIS2)",
    "url": "https://eur-lex.europa.eu/eli/dir/2022/2555",
    "versionDate": "2022-12-14",
    "legalReference": "OJ L 333, 27.12.2022, p. 80-152"
  }
}
```

### Strategy/Maturity Models (11 Frameworks)

| Framework | Strategies | Official Structure | Maturity Tiers |
|-----------|-----------|-------------------|---------------|
| ASD Essential Eight | 8 | Mitigation Strategies | ML1 / ML2 / ML3 |
| NIS2 | 10 | Article 21(2)(a)–(j) | Essential / Enhanced / Advanced |
| NIST CSF 2.0 | 6 | Functions (GV/ID/PR/DE/RS/RC) | Partial / Risk Informed / Repeatable |
| ISO 27001:2022 | 4 | Annex A Themes | Documented / Implemented / Optimised |
| CMMC v2.0 | 8 | Domains | Foundational / Advanced / Expert |
| SOC 2 | 5 | Trust Service Criteria | Foundational / Operational / Advanced |
| PCI DSS v4.0 | 6 | Goals | Defined / Implemented / Managed |
| DORA | 5 | Pillars | Basic / Intermediate / Advanced |
| GDPR | 6 | Key Articles | Essential / Enhanced / Comprehensive |
| HIPAA | 4 | Safeguard Types | Required / Addressable / Advanced |
| UK NCSC CAF v3.2 | 4 | Objectives (A–D) | Initial / Achieved / Enhanced |

## Frameworks Covered (46)

| Group | Frameworks |
|-------|-----------|
| EU Regulatory | DORA, NIS2, GDPR (EU) 2016/679, EU Cyber Resilience Act |
| ISO Standards | ISO 27001:2022, ISO 27701:2019, ISO 27017:2015, ISO 22301:2019 |
| NIST / US Federal | NIST CSF 2.0, NIST CSF 1.1, SP 800-53 Rev.5, SP 800-171, FedRAMP, CMMC v2.0, CISA CPG, CRI Profile |
| US Sector | HIPAA, HITRUST, SOC 2, PCI DSS v4.0, NYDFS, FFIEC, SEC, CIRCIA, NERC-CIP |
| UK & Ireland | NCSC CAF v3.2, Cyber Essentials v3.2, IASME, UK CS&R Bill 2025 |
| APAC & Other | ASD Essential Eight, NZ ISM v3.8, Cybersecure Canada, GSMA FS.31 |
| Regional | BSI IT-Grundschutz, ENS (Spain) |
| Sector Specific | TSA Security Directive, CJIS v6, HPH CPGs |
| Cloud & Tech | CSA CCM v4, Microsoft Cloud Benchmark, MITRE ATT&CK |

## Organisation Profiles (12)

Pre-built framework sets: EU Financial, EU General, UK Organisation, US Federal, US Healthcare, US Financial, US Listed/Public, Critical Infrastructure, Defence/CMMC, Germany (BSI), Spain (ENS), Cloud/SaaS Vendor

## JSON Data Structure

```
data/
├── checks.json             # 140 CIS M365 v6.0.0 checks
├── check-policy-map.json   # Curated check → policy mapping (140 checks, 0 unmapped)
├── frameworks.json         # 46 frameworks, 9 groups, 12 org profiles
├── policies-all.json       # 143 policies with normalised framework references
├── policies/
│   ├── index.json          # Policy type metadata
│   ├── conditional-access/ # 18 policies (CA01–CA18)
│   ├── defender/           # 8 policies (DEF01–DEF08)
│   ├── defender-endpoint/  # 12 policies (MDE01–MDE12)
│   ├── entra/              # 10 policies (ENT01–ENT10)
│   ├── exchange/           # 10 policies (EXO01–EXO10)
│   ├── intune/             # 20 policies (INT01–INT20)
│   ├── purview/            # 30 policies (PV01–PV30)
│   ├── sharepoint/         # 20 policies (SPO01–SPO20)
│   ├── teams/              # 10 policies (TEA01–TEA10)
│   └── governance/         # 5 policies (GOV01–GOV05)
└── frameworks/             # Per-framework strategy & check data
    ├── nist-csf-2-0.json   # (hasStrategies + source citation)
    ├── iso-27001-2022.json
    ├── nis2.json
    └── ... (45 total)
```

## Local Development

```bash
# Python
cd site && python -m http.server 8080

# Node.js
npx serve site

# Tests
npm install && npm test
```

> The site requires HTTP serving (not `file://`) because it loads JSON data via `fetch()`.

## Deployment

Designed for **GitHub Pages**: set source to the `site/` folder in repository settings. The `.nojekyll` file bypasses Jekyll processing.

## Licence

Open source. Data based on CIS Microsoft 365 Benchmark v6.0.0.
