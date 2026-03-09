#!/usr/bin/env node
// update-frameworks.js — Automated framework version checker + propagation engine
// Zero dependencies: uses only built-in fs, path, https modules
// Usage:
//   node update-frameworks.js                          # Check all, apply updates
//   node update-frameworks.js --dry-run                # Report only, no writes
//   node update-frameworks.js --framework "PCI DSS v4.0"  # Check one
//   node update-frameworks.js --verbose                # Extra logging

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// ─── CLI Args ────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const VERBOSE = args.includes('--verbose');
const SINGLE_FW = (() => {
  const idx = args.indexOf('--framework');
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : null;
})();

// ─── Paths ───────────────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'site', 'data');
const FW_PATH = path.join(DATA_DIR, 'frameworks.json');
const CHECKS_PATH = path.join(DATA_DIR, 'checks.json');
const POLICIES_DIR = path.join(DATA_DIR, 'policies');
const POLICIES_ALL_PATH = path.join(DATA_DIR, 'policies-all.json');
const FW_XREF_DIR = path.join(DATA_DIR, 'frameworks');
const CHANGELOG_DIR = path.join(DATA_DIR, 'changelogs');

// ─── Helpers ─────────────────────────────────────────────────────────────────
function log(msg) { console.log(msg); }
function verbose(msg) { if (VERBOSE) console.log('  [verbose] ' + msg); }

function slugify(name) {
  return name.toLowerCase()
    .replace(/[()]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function fetchUrl(url, timeoutMs) {
  timeoutMs = timeoutMs || 10000;
  return new Promise(function (resolve, reject) {
    var redirects = 0;
    var baseUrl = url; // keep original for resolving relative redirects

    function doFetch(targetUrl) {
      // Resolve relative redirect URLs against the base
      if (targetUrl.startsWith('/')) {
        var parsed = new URL(baseUrl);
        targetUrl = parsed.origin + targetUrl;
      }
      var mod = targetUrl.startsWith('https') ? https : http;
      var req = mod.get(targetUrl, { headers: { 'User-Agent': 'M365-Framework-Updater/1.0' } }, function (res) {
        // Follow redirects (up to 3)
        if ((res.statusCode === 301 || res.statusCode === 302 || res.statusCode === 303) && res.headers.location) {
          redirects++;
          if (redirects > 3) return reject(new Error('Too many redirects'));
          baseUrl = targetUrl; // update base for next redirect
          return doFetch(res.headers.location);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(res.statusCode + ' ' + (res.statusMessage || '')));
        }
        var chunks = [];
        res.on('data', function (chunk) { chunks.push(chunk); });
        res.on('end', function () { resolve(Buffer.concat(chunks).toString('utf8')); });
        res.on('error', reject);
      });
      req.on('error', reject);
      req.setTimeout(timeoutMs, function () {
        req.destroy();
        reject(new Error('Timeout after ' + timeoutMs + 'ms'));
      });
    }

    doFetch(url);
  });
}

function delay(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

// ─── Load Data ───────────────────────────────────────────────────────────────
function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

// ─── Version Checker ─────────────────────────────────────────────────────────
async function checkFrameworkVersion(name, meta) {
  var result = {
    framework: name,
    status: 'skipped',
    currentVersion: meta.version,
    detectedVersion: null,
    newName: null,
    error: null,
  };

  // Skip frameworks with no version check URL or manual strategy
  if (!meta.versionCheckUrl || !meta.versionPattern) {
    result.status = 'skipped';
    verbose(name + ': skipped (no versionCheckUrl or pattern)');
    return result;
  }

  if (meta.updateStrategy === 'manual' && !SINGLE_FW) {
    result.status = 'skipped';
    verbose(name + ': skipped (manual strategy)');
    return result;
  }

  // Build URL list: primary + alternatives
  var urlsToTry = [meta.versionCheckUrl];
  if (meta.alternativeUrls && Array.isArray(meta.alternativeUrls)) {
    urlsToTry = urlsToTry.concat(meta.alternativeUrls);
  }

  var lastError = null;
  for (var u = 0; u < urlsToTry.length; u++) {
    var tryUrl = urlsToTry[u];
    try {
      verbose(name + ': fetching ' + tryUrl + (u > 0 ? ' (alt ' + u + ')' : ''));
      var html = await fetchUrl(tryUrl);
      var regex = new RegExp(meta.versionPattern, 'i');
      var match = html.match(regex);

      if (!match || !match[1]) {
        lastError = 'Pattern not matched at ' + tryUrl;
        verbose(name + ': pattern "' + meta.versionPattern + '" not found at ' + tryUrl);
        continue;  // Try next URL
      }

      var detected = match[1];
      result.detectedVersion = detected;
      result.sourceUsed = tryUrl;
      verbose(name + ': detected version "' + detected + '" (current: "' + meta.version + '") from ' + tryUrl);

      // Compare: either version strings match, or generated name equals current name
      var generatedName = meta.nameTemplate ? meta.nameTemplate.replace('{version}', detected) : null;
      if (detected === String(meta.version) || (generatedName && generatedName === name)) {
        result.status = 'current';
      } else {
        result.status = 'update-available';
        if (generatedName) {
          result.newName = generatedName;
        }
      }
      lastError = null;
      break;  // Success — stop trying alternatives
    } catch (err) {
      lastError = err.message + ' at ' + tryUrl;
      verbose(name + ': error at ' + tryUrl + ' — ' + err.message);
      continue;  // Try next URL
    }
  }

  if (lastError && result.status === 'skipped') {
    result.status = 'error';
    result.error = lastError;
  } else if (lastError && !result.detectedVersion) {
    result.status = 'unknown';
    result.error = lastError;
  }

  return result;
}

// ─── Propagation Engine ──────────────────────────────────────────────────────
// Renames a framework string across all data files.
// Builds changes in-memory, returns a list of file writes to apply.
function buildRenamePlan(oldName, newName, frameworksData, checksData, policyFiles) {
  var plan = {
    filesModified: 0,
    details: [],
  };

  // 1. frameworks.json — frameworks[] array
  var fwIdx = frameworksData.frameworks.indexOf(oldName);
  if (fwIdx >= 0) {
    frameworksData.frameworks[fwIdx] = newName;
    plan.details.push('frameworks.json: frameworks[' + fwIdx + ']');
  }

  // 2. frameworks.json — fw_groups
  for (var group in frameworksData.fw_groups) {
    var arr = frameworksData.fw_groups[group];
    var gIdx = arr.indexOf(oldName);
    if (gIdx >= 0) {
      arr[gIdx] = newName;
      plan.details.push('frameworks.json: fw_groups.' + group + '[' + gIdx + ']');
    }
  }

  // 3. frameworks.json — org_profiles
  for (var profile in frameworksData.org_profiles) {
    var arr2 = frameworksData.org_profiles[profile];
    var pIdx = arr2.indexOf(oldName);
    if (pIdx >= 0) {
      arr2[pIdx] = newName;
      plan.details.push('frameworks.json: org_profiles.' + profile + '[' + pIdx + ']');
    }
  }

  // 4. frameworks.json — frameworkMeta key rename
  if (frameworksData.frameworkMeta && frameworksData.frameworkMeta[oldName]) {
    frameworksData.frameworkMeta[newName] = frameworksData.frameworkMeta[oldName];
    delete frameworksData.frameworkMeta[oldName];
    plan.details.push('frameworks.json: frameworkMeta key "' + oldName + '" → "' + newName + '"');
  }

  // 5. checks.json — each check's fws[] array
  var checksModified = 0;
  for (var i = 0; i < checksData.length; i++) {
    var check = checksData[i];
    if (!check.fws) continue;
    var cIdx = check.fws.indexOf(oldName);
    if (cIdx >= 0) {
      check.fws[cIdx] = newName;
      checksModified++;
    }
  }
  if (checksModified > 0) {
    plan.details.push('checks.json: ' + checksModified + ' checks updated');
    plan.filesModified++;
  }

  // 6. Policy JSON files — _metadata.frameworks[] and _frameworkOverrides keys
  var policiesModified = 0;
  for (var j = 0; j < policyFiles.length; j++) {
    var pf = policyFiles[j];
    var modified = false;

    // _metadata.frameworks[]
    if (pf.data._metadata && Array.isArray(pf.data._metadata.frameworks)) {
      var mIdx = pf.data._metadata.frameworks.indexOf(oldName);
      if (mIdx >= 0) {
        pf.data._metadata.frameworks[mIdx] = newName;
        modified = true;
      }
    }

    // Top-level frameworks[] (some policies use this)
    if (Array.isArray(pf.data.frameworks)) {
      var tIdx = pf.data.frameworks.indexOf(oldName);
      if (tIdx >= 0) {
        pf.data.frameworks[tIdx] = newName;
        modified = true;
      }
    }

    // _metadata.frameworkMappings keys (CA policies)
    if (pf.data._metadata && pf.data._metadata.frameworkMappings && pf.data._metadata.frameworkMappings[oldName]) {
      pf.data._metadata.frameworkMappings[newName] = pf.data._metadata.frameworkMappings[oldName];
      delete pf.data._metadata.frameworkMappings[oldName];
      modified = true;
    }

    // _frameworkOverrides keys
    if (pf.data._frameworkOverrides && pf.data._frameworkOverrides[oldName]) {
      pf.data._frameworkOverrides[newName] = pf.data._frameworkOverrides[oldName];
      delete pf.data._frameworkOverrides[oldName];
      modified = true;
    }

    if (modified) {
      pf.dirty = true;
      policiesModified++;
    }
  }
  if (policiesModified > 0) {
    plan.details.push('Policy JSONs: ' + policiesModified + ' policies updated');
  }

  plan.filesModified = 1 + (checksModified > 0 ? 1 : 0) + policiesModified; // frameworks.json + checks.json + policies
  return plan;
}

// ─── Regenerate Derived Files ────────────────────────────────────────────────
function regeneratePoliciesAll(policyFiles) {
  function normalizePolicy(policy, type, file) {
    var meta = policy._metadata || {};
    var id = meta.id || meta.policyNumber || policy.id || file.replace('.json', '');
    var displayName = policy.displayName || meta.title || id;
    var description = policy.description || meta.description || '';

    var frameworks = policy.frameworks || meta.frameworks || [];
    if ((!frameworks || frameworks.length === 0) && meta.frameworkMappings) {
      frameworks = Object.keys(meta.frameworkMappings);
    }

    var cisChecks = (meta.cisChecks || meta.cisControls || []).map(function (c) {
      if (typeof c !== 'string') return String(c);
      var match = c.match(/CIS\s+([\d.]+)/);
      return match ? match[1] : c;
    });

    var requiredLicence = meta.requiredLicence
      || (meta.requiredLicences && meta.requiredLicences[0])
      || (meta.requiredLicenses && meta.requiredLicenses[0])
      || '';
    var importMethod = meta.importMethod || '';
    var deployState = policy.state || '';
    var version = meta.version || policy.version || '1.0';

    return { id: id, type: type, file: file, displayName: displayName, description: description,
      frameworks: frameworks, cisChecks: cisChecks, requiredLicence: requiredLicence,
      importMethod: importMethod, deployState: deployState, version: version };
  }

  var all = policyFiles.map(function (pf) {
    return normalizePolicy(pf.data, pf.type, pf.file);
  });
  all.sort(function (a, b) { return String(a.id).localeCompare(String(b.id)); });
  return all;
}

function regenerateFrameworkXrefs(frameworksData, checksData, policyFiles) {
  var fwToGroup = {};
  for (var group in frameworksData.fw_groups) {
    frameworksData.fw_groups[group].forEach(function (fw) { fwToGroup[fw] = group; });
  }

  var fwToProfiles = {};
  for (var profile in frameworksData.org_profiles) {
    frameworksData.org_profiles[profile].forEach(function (fw) {
      if (!fwToProfiles[fw]) fwToProfiles[fw] = [];
      fwToProfiles[fw].push(profile);
    });
  }

  var xrefs = {};
  for (var i = 0; i < frameworksData.frameworks.length; i++) {
    var fw = frameworksData.frameworks[i];
    var slug = slugify(fw);
    var checks = checksData.filter(function (c) { return c.fws && c.fws.includes(fw); }).map(function (c) { return c.id; });
    var policies = policyFiles
      .filter(function (pf) {
        var fws = (pf.data._metadata && pf.data._metadata.frameworks) || pf.data.frameworks || [];
        if (fws.length === 0 && pf.data._metadata && pf.data._metadata.frameworkMappings) {
          fws = Object.keys(pf.data._metadata.frameworkMappings);
        }
        return fws.includes(fw);
      })
      .map(function (pf) {
        return (pf.data._metadata && pf.data._metadata.id) || pf.file.replace('.json', '');
      });

    xrefs[slug] = {
      name: fw,
      slug: slug,
      group: fwToGroup[fw] || 'Other',
      checks: checks,
      checkCount: checks.length,
      policies: policies,
      policyCount: policies.length,
      orgProfiles: fwToProfiles[fw] || [],
    };
  }
  return xrefs;
}

// ─── Changelog ───────────────────────────────────────────────────────────────
function generateChangelog(results, changeset) {
  var dateStr = today();
  var checked = results.filter(function (r) { return r.status !== 'skipped'; }).length;
  var updated = changeset.length;
  var unchanged = results.filter(function (r) { return r.status === 'current'; }).length;
  var skipped = results.filter(function (r) { return r.status === 'skipped'; }).length;
  var failed = results.filter(function (r) { return r.status === 'error' || r.status === 'unknown'; }).length;

  // Markdown report
  var md = '# Framework Version Check \u2014 ' + dateStr + '\n\n';
  md += '## Summary\n';
  md += '| Checked | Updated | Unchanged | Skipped | Failed |\n';
  md += '|:---:|:---:|:---:|:---:|:---:|\n';
  md += '| ' + checked + ' | ' + updated + ' | ' + unchanged + ' | ' + skipped + ' | ' + failed + ' |\n\n';

  if (updated > 0) {
    md += '## Updates Applied\n';
    for (var i = 0; i < changeset.length; i++) {
      var c = changeset[i];
      md += '### ' + c.oldName + ' \u2192 ' + c.newName + '\n';
      md += '- Detected version: ' + c.detectedVersion + '\n';
      md += '- Files modified: ' + c.plan.filesModified + '\n';
      for (var d = 0; d < c.plan.details.length; d++) {
        md += '  - ' + c.plan.details[d] + '\n';
      }
      md += '\n';
    }
  } else {
    md += '## No Updates Required\nAll frameworks are at their current versions.\n\n';
  }

  var failures = results.filter(function (r) { return r.status === 'error' || r.status === 'unknown'; });
  if (failures.length > 0) {
    md += '## Issues\n';
    md += '| Framework | Status | Detail |\n';
    md += '|---|---|---|\n';
    for (var f = 0; f < failures.length; f++) {
      md += '| ' + failures[f].framework + ' | ' + failures[f].status + ' | ' + (failures[f].error || 'N/A') + ' |\n';
    }
    md += '\n';
  }

  md += '## All Results\n';
  md += '| Framework | Status | Current | Detected | Source |\n';
  md += '|---|---|---|---|---|\n';
  for (var r = 0; r < results.length; r++) {
    var res = results[r];
    var src = res.sourceUsed ? (res.sourceUsed === results[r].framework ? 'primary' : 'alt') : '-';
    md += '| ' + res.framework + ' | ' + res.status + ' | ' + (res.currentVersion || '-') + ' | ' + (res.detectedVersion || '-') + ' | ' + src + ' |\n';
  }

  // JSON report
  var json = {
    date: dateStr,
    summary: { checked: checked, updated: updated, unchanged: unchanged, skipped: skipped, failed: failed },
    updates: changeset.map(function (c) {
      return { old: c.oldName, new: c.newName, detectedVersion: c.detectedVersion, filesModified: c.plan.filesModified };
    }),
    failures: failures.map(function (f) {
      return { framework: f.framework, status: f.status, error: f.error };
    }),
    results: results.map(function (r) {
      return { framework: r.framework, status: r.status, currentVersion: r.currentVersion, detectedVersion: r.detectedVersion };
    }),
  };

  return { markdown: md, json: json };
}

// ─── Main ────────────────────────────────────────────────────────────────────
async function main() {
  log('=== Framework Version Updater ===');
  log('Mode: ' + (DRY_RUN ? 'DRY RUN (no files will be modified)' : 'LIVE'));
  if (SINGLE_FW) log('Target: ' + SINGLE_FW);
  log('');

  // Load all data
  log('Loading data...');
  var frameworksData = loadJson(FW_PATH);
  var checksData = loadJson(CHECKS_PATH);

  if (!frameworksData.frameworkMeta) {
    log('ERROR: frameworks.json is missing frameworkMeta. Run enrichment first.');
    process.exit(1);
  }

  // Load all policy files
  var policyFiles = [];
  var types = fs.readdirSync(POLICIES_DIR).filter(function (f) {
    return fs.statSync(path.join(POLICIES_DIR, f)).isDirectory();
  });
  for (var t = 0; t < types.length; t++) {
    var typeDir = path.join(POLICIES_DIR, types[t]);
    var files = fs.readdirSync(typeDir).filter(function (f) { return f.endsWith('.json'); });
    for (var fi = 0; fi < files.length; fi++) {
      policyFiles.push({
        type: types[t],
        file: files[fi],
        path: path.join(typeDir, files[fi]),
        data: loadJson(path.join(typeDir, files[fi])),
        dirty: false,
      });
    }
  }
  log('Loaded: ' + frameworksData.frameworks.length + ' frameworks, ' + checksData.length + ' checks, ' + policyFiles.length + ' policies');
  log('');

  // Determine which frameworks to check
  var frameworksToCheck = Object.keys(frameworksData.frameworkMeta);
  if (SINGLE_FW) {
    if (!frameworksData.frameworkMeta[SINGLE_FW]) {
      log('ERROR: Framework "' + SINGLE_FW + '" not found in frameworkMeta.');
      log('Available: ' + frameworksToCheck.join(', '));
      process.exit(1);
    }
    frameworksToCheck = [SINGLE_FW];
  }

  // Check versions
  log('Checking framework versions...');
  var results = [];
  for (var i = 0; i < frameworksToCheck.length; i++) {
    var fwName = frameworksToCheck[i];
    var meta = frameworksData.frameworkMeta[fwName];
    var result = await checkFrameworkVersion(fwName, meta);
    results.push(result);

    // Status indicator
    var icon = result.status === 'current' ? '\u2713'
      : result.status === 'update-available' ? '\u2191'
      : result.status === 'skipped' ? '-'
      : result.status === 'error' ? '\u2717'
      : '?';
    log('  [' + icon + '] ' + fwName + ' — ' + result.status +
      (result.detectedVersion ? ' (detected: ' + result.detectedVersion + ')' : '') +
      (result.error ? ' (' + result.error + ')' : ''));

    // Rate limit: 2s delay between fetches (only if we actually fetched)
    if (result.status !== 'skipped' && i < frameworksToCheck.length - 1) {
      await delay(2000);
    }
  }
  log('');

  // Build changeset
  var changeset = [];
  var updatesAvailable = results.filter(function (r) { return r.status === 'update-available'; });

  for (var u = 0; u < updatesAvailable.length; u++) {
    var upd = updatesAvailable[u];
    var oldName = upd.framework;
    var newName = upd.newName;
    var updMeta = frameworksData.frameworkMeta[oldName];

    if (!newName) {
      log('WARNING: No nameTemplate for "' + oldName + '", cannot auto-rename. Skipping.');
      continue;
    }

    // Handle add-alongside strategy
    if (updMeta.updateStrategy === 'add-alongside') {
      log('INFO: "' + oldName + '" uses add-alongside strategy.');
      log('  New version "' + newName + '" should be added manually alongside the existing entry.');
      log('  The existing entry will be marked as outdated in the report.');
      continue;
    }

    log('Building rename plan: "' + oldName + '" \u2192 "' + newName + '"');
    var plan = buildRenamePlan(oldName, newName, frameworksData, checksData, policyFiles);

    // Update meta for the renamed framework
    if (frameworksData.frameworkMeta[newName]) {
      frameworksData.frameworkMeta[newName].version = upd.detectedVersion;
      frameworksData.frameworkMeta[newName].lastChecked = today();
      frameworksData.frameworkMeta[newName].supersedes = oldName;
    }

    changeset.push({
      oldName: oldName,
      newName: newName,
      detectedVersion: upd.detectedVersion,
      plan: plan,
    });

    for (var d = 0; d < plan.details.length; d++) {
      verbose('  ' + plan.details[d]);
    }
  }

  // Generate changelog
  log('');
  var changelog = generateChangelog(results, changeset);

  // Summary
  var summary = changelog.json.summary;
  log('=== Summary ===');
  log('Checked: ' + summary.checked + '  Updated: ' + summary.updated + '  Unchanged: ' + summary.unchanged +
    '  Skipped: ' + summary.skipped + '  Failed: ' + summary.failed);
  log('');

  // Write files
  if (DRY_RUN) {
    log('DRY RUN — No files modified.');
    log('');
    log('--- Report Preview ---');
    log(changelog.markdown);
    process.exit(changeset.length > 0 ? 2 : 0);
    return;
  }

  if (changeset.length === 0) {
    log('No updates to apply.');
    // Still update lastChecked timestamps for checked frameworks
    var checkedFws = results.filter(function (r) { return r.status === 'current' || r.status === 'unknown' || r.status === 'error'; });
    for (var lc = 0; lc < checkedFws.length; lc++) {
      var fwM = frameworksData.frameworkMeta[checkedFws[lc].framework];
      if (fwM) fwM.lastChecked = today();
    }
    writeJson(FW_PATH, frameworksData);
    log('Updated lastChecked timestamps in frameworks.json');
  } else {
    log('Writing updated files...');

    // frameworks.json (already mutated in-memory by buildRenamePlan)
    writeJson(FW_PATH, frameworksData);
    log('  \u2713 frameworks.json');

    // checks.json
    writeJson(CHECKS_PATH, checksData);
    log('  \u2713 checks.json');

    // Dirty policy files
    var dirtyCount = 0;
    for (var dp = 0; dp < policyFiles.length; dp++) {
      if (policyFiles[dp].dirty) {
        writeJson(policyFiles[dp].path, policyFiles[dp].data);
        dirtyCount++;
      }
    }
    log('  \u2713 ' + dirtyCount + ' policy files');

    // Regenerate policies-all.json
    var allPolicies = regeneratePoliciesAll(policyFiles);
    writeJson(POLICIES_ALL_PATH, allPolicies);
    log('  \u2713 policies-all.json');

    // Regenerate framework cross-reference files
    var xrefs = regenerateFrameworkXrefs(frameworksData, checksData, policyFiles);
    var xrefCount = 0;
    for (var slug in xrefs) {
      writeJson(path.join(FW_XREF_DIR, slug + '.json'), xrefs[slug]);
      xrefCount++;
    }
    log('  \u2713 ' + xrefCount + ' framework cross-reference files');
  }

  // Write changelog
  if (!fs.existsSync(CHANGELOG_DIR)) {
    fs.mkdirSync(CHANGELOG_DIR, { recursive: true });
  }

  var dateStr = today();
  var mdPath = path.join(CHANGELOG_DIR, dateStr + '-framework-update.md');
  var jsonPath = path.join(CHANGELOG_DIR, 'changelog.json');

  fs.writeFileSync(mdPath, changelog.markdown);
  log('  \u2713 ' + path.relative(__dirname, mdPath));

  // Append to or create changelog.json
  var existingLog = { runs: [] };
  if (fs.existsSync(jsonPath)) {
    try { existingLog = loadJson(jsonPath); } catch (e) { /* start fresh */ }
  }
  existingLog.runs.unshift(changelog.json);
  writeJson(jsonPath, existingLog);
  log('  \u2713 changelog.json');

  log('');
  log('Done!');
  process.exit(changeset.length > 0 ? 2 : 0);
}

main().catch(function (err) {
  console.error('Fatal error:', err);
  process.exit(1);
});
