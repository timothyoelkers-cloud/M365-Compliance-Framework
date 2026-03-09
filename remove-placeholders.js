// Remove all placeholder values from policy JSON files
// Replaces <PLACEHOLDER> patterns with empty strings or sensible defaults
const fs = require('fs');
const path = require('path');

const policiesDir = path.join(__dirname, 'site', 'data', 'policies');

// Mapping of placeholder patterns to replacement values
const replacements = {
  // Group/ID placeholders -> empty strings (remove the exclusion)
  '<BREAK-GLASS-GROUP-ID>': '',
  '<WINDOWS-DEVICES-GROUP-ID>': '',
  '<MACOS-DEVICES-GROUP-ID>': '',
  '<MOBILE-DEVICES-GROUP-ID>': '',
  '<DEVICE-REGISTRATION-GROUP-ID>': '',
  '<DEVICE-REGISTRATION-GROUP>': '',
  '<WORKSTATION-GROUP-ID>': '',
  '<SERVER-GROUP-ID>': '',
  '<SENSITIVE-SERVERS-GROUP-ID>': '',
  '<SHARED-DEVICE-GROUP-ID>': '',
  '<NETWORK-TESTING-GROUP-ID>': '',
  '<MDE-EXCLUSION-GROUP-ID>': '',
  '<SECURITY-RESEARCH-GROUP-ID>': '',
  '<DEVICE-TAG-GROUP>': '',
  '<APP-CONSENT-REVIEWERS-GROUP-ID>': '',
  '<APP-CONSENT-REVIEWERS-GROUP>': '',
  '<HIGHLY-CONFIDENTIAL-GROUP>': '',
  '<EXECUTIVE-GROUP>': '',
  '<INTERNAL-LABEL-GUID>': '',
  '<DIRECTORY-SETTINGS-ID>': '',
  '<ALLOWED-COUNTRIES-LOCATION-ID>': 'AllTrusted',
  '<AD-DOMAIN-GUID>': '',
  '<TENANT-ID>': '',
  '<GENERATE-UUID>': '',

  // Email placeholders -> remove
  '<SECURITY-TEAM-EMAIL>': '',
  '<SECURITY-MANAGER-EMAIL>': '',
  '<DPO-EMAIL>': '',
  '<HIPAA-PRIVACY-OFFICER-EMAIL>': '',
  '<FINANCE-COMPLIANCE-EMAIL>': '',
  '<VULNERABILITY-MGMT-EMAIL>': '',
  '<DMARC-REPORT-EMAIL>': '',
  '<DMARC-FORENSIC-EMAIL>': '',
  '<SHAREPOINT-ADMIN-UPN>': '',
  '<EXCHANGE-ADMIN-UPN>': '',
  '<SECURITY-ADMIN-UPN>': '',
  '<CTO-EMAIL>': '',
  '<CFO-EMAIL>': '',
  '<CEO-EMAIL>': '',
  '<CTO-DISPLAYNAME>': '',
  '<CFO-DISPLAYNAME>': '',
  '<CEO-DISPLAYNAME>': '',
  '<CEO-LAST-NAME>': '',

  // Org-specific names -> remove
  '<COMPANY-NAME>': '',
  '<PRODUCT-NAME>': '',
  '<COMPANY-ABBREVIATION>': '',
  '<COMPANY-MASCOT>': '',
  '<COMPANY-DOMAIN>': '',
  '<OFFICE-LOCATION>': '',
  '<TENANT-DOMAIN>': '',
  '<TENANT-DOMAIN-DASHES>': '',
  '<TENANT>': '',
  '<DOMAIN>': '',
  '<PARTNER-DOMAIN>': '',

  // Network/URL placeholders -> remove
  '<CORPORATE-IP-RANGES>': '',
  '<IP-ADDRESS>': '',
  '<URL>': '',
  '<MALICIOUS-URL>': '',
  '<MALICIOUS-IP-ADDRESS>': '',
  '<SUSPICIOUS-DOMAIN>': '',
  '<ALLOWED-URL-PLACEHOLDER>': '',
  '<IT-DOCUMENTATION-SITE-URL>': '',
  '<DEVELOPER-WIKI-SITE-URL>': '',

  // Credential/secret placeholders -> remove
  '<ACCESS-TOKEN>': '',
  '<APP-REGISTRATION-CLIENT-ID>': '',
  '<APP-REGISTRATION-CLIENT-SECRET>': '',
  '<CERTIFICATE-SUBJECT>': '',
  '<CERTIFICATE-ISSUER>': '',
  '<KEYVAULT-URL>': '',
  '<STORAGE-ACCOUNT-NAME>': '',
  '<EVENT-HUB-NAMESPACE>': '',
  '<EVENT-HUB-NAME>': '',
  '<SCAN-CREDENTIAL-SECRET-NAME>': '',
  '<TAXII-SERVER-URL>': '',
  '<TAXII-COLLECTION-ID>': '',
  '<TAXII-USERNAME>': '',
  '<TAXII-PASSWORD>': '',

  // Device/scanner placeholders -> remove
  '<SCANNER-HOSTNAME>': '',
  '<SCANNER-DEVICE-ID>': '',
  '<PUBLIC-FOLDER-IDENTITY>': '',
  '<RULE-NAME-FROM-AUDIT>': '',
};

let totalFiles = 0;
let totalReplacements = 0;

function processDir(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      processDir(fullPath);
    } else if (entry.name.endsWith('.json')) {
      let content = fs.readFileSync(fullPath, 'utf8');
      let modified = false;
      let fileReplacements = 0;

      for (const [placeholder, replacement] of Object.entries(replacements)) {
        if (content.includes(placeholder)) {
          content = content.split(placeholder).join(replacement);
          modified = true;
          fileReplacements++;
        }
      }

      // Also catch any remaining <SOMETHING> patterns we might have missed
      const remaining = content.match(/<[A-Z][A-Z0-9_-]+>/g);
      if (remaining) {
        for (const r of remaining) {
          content = content.split(r).join('');
          modified = true;
          fileReplacements++;
        }
      }

      if (modified) {
        // Parse and re-stringify to clean up any empty strings in arrays
        try {
          let obj = JSON.parse(content);
          obj = cleanObject(obj);
          content = JSON.stringify(obj, null, 2);
        } catch (e) {
          // If JSON parse fails, just write the string-replaced version
        }
        fs.writeFileSync(fullPath, content);
        totalFiles++;
        totalReplacements += fileReplacements;
      }
    }
  }
}

function cleanObject(obj) {
  if (Array.isArray(obj)) {
    // Remove empty strings from arrays
    return obj.filter(v => v !== '').map(v => typeof v === 'object' && v !== null ? cleanObject(v) : v);
  }
  if (typeof obj === 'object' && obj !== null) {
    const cleaned = {};
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'object' && value !== null) {
        cleaned[key] = cleanObject(value);
      } else {
        cleaned[key] = value;
      }
    }
    return cleaned;
  }
  return obj;
}

processDir(policiesDir);
console.log(`Processed ${totalFiles} files, ${totalReplacements} placeholder replacements made`);

// Verify no placeholders remain
let remaining = 0;
function checkDir(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) checkDir(fullPath);
    else if (entry.name.endsWith('.json')) {
      const content = fs.readFileSync(fullPath, 'utf8');
      const matches = content.match(/<[A-Z][A-Z0-9_-]+>/g);
      if (matches) {
        console.log(`  REMAINING in ${entry.name}: ${[...new Set(matches)].join(', ')}`);
        remaining += matches.length;
      }
    }
  }
}
checkDir(policiesDir);
if (remaining === 0) console.log('No placeholders remaining - all clean!');
else console.log(`WARNING: ${remaining} placeholders still remain`);
