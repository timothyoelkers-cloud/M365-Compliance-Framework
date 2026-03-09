// Generate policies-all.json — normalized metadata for the UI
// Raw policy JSON stays in individual files (fetched on-demand for deployment)
const fs = require('fs');
const path = require('path');

const policiesDir = path.join(__dirname, 'site', 'data', 'policies');
const types = fs.readdirSync(policiesDir).filter(f =>
  fs.statSync(path.join(policiesDir, f)).isDirectory()
);

function normalizePolicy(policy, type, file) {
  const meta = policy._metadata || {};

  // ID
  const id = meta.id || meta.policyNumber || policy.id
    || file.replace('.json', '');

  // Display name
  const displayName = policy.displayName
    || meta.title
    || id;

  // Description
  const description = policy.description
    || meta.description
    || '';

  // Frameworks — CA policies use frameworkMappings (object keys), others use array
  let frameworks = policy.frameworks
    || meta.frameworks
    || [];
  if ((!frameworks || frameworks.length === 0) && meta.frameworkMappings) {
    frameworks = Object.keys(meta.frameworkMappings);
  }

  // CIS Checks — normalize "CIS X.Y.Z - text" to just "X.Y.Z"
  let cisChecks = meta.cisChecks
    || meta.cisControls
    || [];
  cisChecks = cisChecks.map(c => {
    if (typeof c !== 'string') return String(c);
    const match = c.match(/CIS\s+([\d.]+)/);
    return match ? match[1] : c;
  });

  // Required licence
  const requiredLicence = meta.requiredLicence
    || (meta.requiredLicences && meta.requiredLicences[0])
    || (meta.requiredLicenses && meta.requiredLicenses[0])
    || '';

  // Import method
  const importMethod = meta.importMethod || '';

  // Deploy state (CA policies have top-level state)
  const deployState = policy.state || '';

  // Version
  const version = meta.version || policy.version || '1.0';

  return {
    id, type, file, displayName, description,
    frameworks, cisChecks, requiredLicence,
    importMethod, deployState, version,
  };
}

const allPolicies = [];
for (const type of types) {
  const typeDir = path.join(policiesDir, type);
  const files = fs.readdirSync(typeDir).filter(f => f.endsWith('.json'));
  for (const file of files) {
    const policy = JSON.parse(fs.readFileSync(path.join(typeDir, file), 'utf8'));
    allPolicies.push(normalizePolicy(policy, type, file));
  }
}

// Sort by ID
allPolicies.sort((a, b) => String(a.id).localeCompare(String(b.id)));

fs.writeFileSync(
  path.join(__dirname, 'site', 'data', 'policies-all.json'),
  JSON.stringify(allPolicies, null, 2)
);

console.log(`Generated policies-all.json with ${allPolicies.length} normalized policies`);
