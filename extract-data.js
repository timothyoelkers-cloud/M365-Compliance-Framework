// Extract data from index (3).html and write JSON files
const fs = require('fs');
const path = require('path');

const html = fs.readFileSync(path.join(__dirname, 'index (3).html'), 'utf8');
const lines = html.split('\n');

// Find the D and MANIFEST lines
let dLine = '', manifestLine = '';
for (let i = 0; i < lines.length; i++) {
  const l = lines[i].trim();
  if (l.startsWith('const D = {')) dLine = l;
  if (l.startsWith('const MANIFEST = {')) manifestLine = l;
}

// Parse D (checks data)
const dJson = dLine.replace(/^const D = /, '').replace(/;$/, '');
const D = JSON.parse(dJson);

// Parse MANIFEST (policies data)
const mJson = manifestLine.replace(/^const MANIFEST = /, '').replace(/;$/, '');
const MANIFEST = JSON.parse(mJson);

const siteDir = path.join(__dirname, 'site', 'data');

// 1. Master manifest
fs.writeFileSync(path.join(siteDir, 'index.json'), JSON.stringify({
  version: MANIFEST.version,
  lastUpdated: MANIFEST.lastUpdated,
  description: MANIFEST.description,
  totalPolicies: MANIFEST.totalPolicies,
  totalChecks: D.checks.length,
  totalFrameworks: D.frameworks.length,
  categories: D.categories,
}, null, 2));
console.log('Wrote index.json');

// 2. Checks
fs.writeFileSync(path.join(siteDir, 'checks.json'), JSON.stringify(D.checks, null, 2));
console.log(`Wrote checks.json (${D.checks.length} checks)`);

// 3. Frameworks
fs.writeFileSync(path.join(siteDir, 'frameworks.json'), JSON.stringify({
  frameworks: D.frameworks,
  fw_groups: D.fw_groups,
  org_profiles: D.org_profiles,
}, null, 2));
console.log(`Wrote frameworks.json (${D.frameworks.length} frameworks)`);

// 4. Policy type manifest
fs.writeFileSync(path.join(siteDir, 'policies', 'index.json'), JSON.stringify({
  policyTypes: MANIFEST.policyTypes,
  totalPolicies: MANIFEST.totalPolicies,
}, null, 2));
console.log('Wrote policies/index.json');

// 5. Individual policy files
let policyCount = 0;
for (const pol of MANIFEST.policies) {
  const typeDir = path.join(siteDir, 'policies', pol.type);
  if (!fs.existsSync(typeDir)) fs.mkdirSync(typeDir, { recursive: true });
  fs.writeFileSync(path.join(typeDir, pol.file), JSON.stringify(pol, null, 2));
  policyCount++;
}
console.log(`Wrote ${policyCount} individual policy JSON files`);

// 6. Framework cross-reference files
function slugify(name) {
  return name.toLowerCase()
    .replace(/[()]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

// Build a reverse lookup: which group does each framework belong to?
const fwToGroup = {};
for (const [group, fws] of Object.entries(D.fw_groups)) {
  for (const fw of fws) fwToGroup[fw] = group;
}

// Build a reverse lookup: which org profiles include each framework?
const fwToProfiles = {};
for (const [profile, fws] of Object.entries(D.org_profiles)) {
  for (const fw of fws) {
    if (!fwToProfiles[fw]) fwToProfiles[fw] = [];
    fwToProfiles[fw].push(profile);
  }
}

let fwCount = 0;
for (const fw of D.frameworks) {
  const slug = slugify(fw);
  const checks = D.checks.filter(c => c.fws.includes(fw)).map(c => c.id);
  const policies = MANIFEST.policies.filter(p => p.frameworks.includes(fw)).map(p => p.id);

  fs.writeFileSync(path.join(siteDir, 'frameworks', `${slug}.json`), JSON.stringify({
    name: fw,
    slug: slug,
    group: fwToGroup[fw] || 'Other',
    checks: checks,
    checkCount: checks.length,
    policies: policies,
    policyCount: policies.length,
    orgProfiles: fwToProfiles[fw] || [],
  }, null, 2));
  fwCount++;
}
console.log(`Wrote ${fwCount} framework cross-reference files`);

console.log('\nDone! All data extracted successfully.');
