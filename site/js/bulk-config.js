/* ═══════════════════════════════════════════
   BULK CONFIG — Merged configuration form for
   multi-policy deploy / script generation.
   Fields with the same id across policies are
   merged into a single form input.
═══════════════════════════════════════════ */
const BulkConfig = (() => {

  let bulkPolicies = [];       // [{id, pol, rawJson}]
  let mergedFields = [];       // [{id, label, type, ...sources:[{policyId, jsonPaths}]}]
  let currentAction = null;    // 'deploy' | 'script'

  // ─── JSON Path helpers (reuse from PreDeployConfig pattern) ───

  function parsePath(path) {
    var segs = [];
    var re = /([^.\[\]]+)|\[(\d+)\]/g;
    var m;
    while ((m = re.exec(path)) !== null) {
      segs.push(m[2] !== undefined ? parseInt(m[2], 10) : m[1]);
    }
    return segs;
  }

  function setJsonPath(obj, path, value) {
    var segs = parsePath(path);
    var cur = obj;
    for (var i = 0; i < segs.length - 1; i++) {
      if (cur[segs[i]] === undefined || cur[segs[i]] === null) {
        cur[segs[i]] = typeof segs[i + 1] === 'number' ? [] : {};
      }
      cur = cur[segs[i]];
    }
    var last = segs[segs.length - 1];
    if (typeof last === 'number' && Array.isArray(cur)) {
      while (cur.length <= last) cur.push(null);
    }
    cur[last] = value;
  }

  function getJsonPath(obj, path) {
    var segs = parsePath(path);
    var cur = obj;
    for (var i = 0; i < segs.length; i++) {
      if (cur == null || typeof cur !== 'object') return undefined;
      cur = cur[segs[i]];
    }
    return cur;
  }

  function applyTransform(value, transform) {
    if (!transform || !value) return value;
    switch (transform) {
      case 'splitLines':
        return String(value).split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
      case 'splitCsv':
        return String(value).split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      default:
        return value;
    }
  }

  // ─── Collect & Merge Fields ───

  async function collectFields(policyIds) {
    var policies = AppState.get('policies') || [];
    var entries = [];

    for (var i = 0; i < policyIds.length; i++) {
      var pol = policies.find(function (p) { return p.id === policyIds[i]; });
      if (!pol) continue;
      try {
        var rawJson = await DataStore.loadPolicy(pol.type, pol.file);
        entries.push({ id: pol.id, pol: pol, rawJson: JSON.parse(JSON.stringify(rawJson)) });
      } catch (e) {
        console.warn('BulkConfig: failed to load', pol.id, e);
      }
    }
    return entries;
  }

  function mergeFieldsFromEntries(entries) {
    var fieldMap = {};  // fieldId → merged field
    var fieldOrder = [];

    entries.forEach(function (entry) {
      var fields = entry.rawJson._configFields || [];
      fields.forEach(function (field) {
        if (fieldMap[field.id]) {
          // Merge: add source mapping
          fieldMap[field.id]._sources.push({
            policyId: entry.id,
            jsonPaths: field.jsonPaths || [],
            transform: field.transform || null,
          });
        } else {
          // First occurrence: create merged field
          var merged = {
            id: field.id,
            label: field.label,
            type: field.type,
            required: field.required || false,
            description: field.description || '',
            placeholder: field.placeholder || '',
            default: field.default,
            options: field.options || [],
            transform: field.transform || null,
            min: field.min,
            max: field.max,
            _sources: [{
              policyId: entry.id,
              jsonPaths: field.jsonPaths || [],
              transform: field.transform || null,
            }],
          };
          fieldMap[field.id] = merged;
          fieldOrder.push(field.id);
        }
      });
    });

    return fieldOrder.map(function (id) { return fieldMap[id]; });
  }

  // ─── Rendering ───

  function renderField(field, currentValue) {
    var val = currentValue !== undefined && currentValue !== null ? currentValue : (field.default || '');
    var reqMark = field.required ? ' <span class="required">*</span>' : '';
    var helpHtml = field.description ? '<div class="field-help">' + escHtml(field.description) + '</div>' : '';
    var sourceCount = field._sources ? field._sources.length : 0;
    var sourceNote = sourceCount > 1 ? '<div style="font-size:.58rem;color:var(--ink4);margin-top:1px">Applies to ' + sourceCount + ' policies</div>' : '';
    var fullClass = (field.type === 'textarea' || field.type === 'domain-list') ? ' rpt-field-full' : '';

    var html = '<div class="rpt-field' + fullClass + '">';
    html += '<label>' + escHtml(field.label) + reqMark + '</label>';

    switch (field.type) {
      case 'text':
      case 'email':
        html += '<input type="' + field.type + '" id="bcfg-' + field.id + '" value="' + escHtml(String(val)) + '"';
        if (field.placeholder) html += ' placeholder="' + escHtml(field.placeholder) + '"';
        html += '>';
        break;
      case 'number':
        html += '<input type="number" id="bcfg-' + field.id + '" value="' + escHtml(String(val)) + '"';
        if (field.min !== undefined) html += ' min="' + field.min + '"';
        if (field.max !== undefined) html += ' max="' + field.max + '"';
        html += '>';
        break;
      case 'textarea':
      case 'domain-list':
        var textVal = Array.isArray(val) ? val.join('\n') : String(val);
        html += '<textarea id="bcfg-' + field.id + '" rows="3"';
        if (field.placeholder) html += ' placeholder="' + escHtml(field.placeholder) + '"';
        html += '>' + escHtml(textVal) + '</textarea>';
        break;
      case 'select':
        html += '<select id="bcfg-' + field.id + '">';
        (field.options || []).forEach(function (opt) {
          var selected = (opt.value === val) ? ' selected' : '';
          html += '<option value="' + escHtml(opt.value) + '"' + selected + '>' + escHtml(opt.label) + '</option>';
        });
        html += '</select>';
        break;
      case 'toggle':
        var checked = val ? ' checked' : '';
        html += '<label class="rpt-toggle"><input type="checkbox" id="bcfg-' + field.id + '"' + checked + '> ' + escHtml(field.label) + '</label>';
        break;
      default:
        html += '<input type="text" id="bcfg-' + field.id + '" value="' + escHtml(String(val)) + '">';
    }

    html += helpHtml + sourceNote + '</div>';
    return html;
  }

  function showBulkConfigModal(action) {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    currentAction = action;
    var actionLabel = action === 'deploy' ? 'Deploy All to Tenant' : 'Generate All Scripts';
    var actionClass = action === 'deploy' ? 'btn-deploy' : 'btn-script';
    var actionFn = action === 'deploy' ? 'BulkConfig.deployAll()' : 'BulkConfig.scriptAll()';

    // Count policies with/without config
    var withConfig = bulkPolicies.filter(function (e) { return e.rawJson._configFields && e.rawJson._configFields.length > 0; });
    var withoutConfig = bulkPolicies.length - withConfig.length;

    var html = '<div class="modal-header">';
    html += '<h3>Bulk Configuration — ' + bulkPolicies.length + ' Policies</h3>';
    html += '<button class="modal-close" onclick="BulkConfig.cancel()">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';

    // Summary
    html += '<p style="font-size:.74rem;color:var(--ink2);margin-bottom:16px">';
    if (withConfig.length > 0) {
      html += withConfig.length + ' policies have configurable fields. ';
    }
    if (withoutConfig > 0) {
      html += withoutConfig + ' policies will ' + (action === 'deploy' ? 'deploy' : 'generate') + ' with defaults.';
    }
    html += '</p>';

    // Dependency order note
    if (typeof DependencyGraph !== 'undefined') {
      var ordered = DependencyGraph.suggestOrder(bulkPolicies.map(function (e) { return e.id; }));
      var hasReorder = false;
      for (var i = 0; i < ordered.length; i++) {
        if (ordered[i] !== bulkPolicies[i].id) { hasReorder = true; break; }
      }
      if (hasReorder) {
        html += '<div class="dep-info" style="margin-bottom:12px"><strong>Deployment order optimised</strong> based on policy dependencies.</div>';
      }
    }

    // Merged form fields
    if (mergedFields.length > 0) {
      html += '<div class="section-hdr" style="margin-top:0">Shared Configuration</div>';
      html += '<div class="rpt-form" id="bulk-config-form">';
      mergedFields.forEach(function (field) {
        html += renderField(field, field.default);
      });
      html += '</div>';
    }

    // Policy list
    html += '<div class="section-hdr">Policies (' + bulkPolicies.length + ')</div>';
    html += '<div style="max-height:200px;overflow-y:auto">';
    bulkPolicies.forEach(function (entry) {
      var hasFields = entry.rawJson._configFields && entry.rawJson._configFields.length > 0;
      var badge = hasFields ? '<span class="badge badge-amber" style="font-size:.5rem">configurable</span>' : '';
      html += '<div style="display:flex;align-items:center;gap:6px;padding:3px 0;font-size:.72rem">';
      html += '<span style="font-weight:600;color:var(--ink)">' + escHtml(entry.id) + '</span> ';
      html += '<span style="color:var(--ink3);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escHtml(entry.pol.displayName) + '</span>';
      html += badge;
      html += '</div>';
    });
    html += '</div>';

    // Errors
    html += '<div id="bulk-config-errors" class="config-errors" style="display:none"></div>';

    // Actions
    html += '<div class="config-actions">';
    html += '<button class="btn" onclick="BulkConfig.cancel()">Cancel</button>';
    html += '<button class="btn ' + actionClass + '" onclick="' + actionFn + '">' + actionLabel + '</button>';
    html += '</div>';

    html += '</div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  // ─── Form Collection ───

  function collectFormValues() {
    var values = {};
    mergedFields.forEach(function (field) {
      var el = document.getElementById('bcfg-' + field.id);
      if (!el) return;
      if (field.type === 'toggle') {
        values[field.id] = el.checked;
      } else {
        values[field.id] = el.value;
      }
    });
    return values;
  }

  function validateForm() {
    var values = collectFormValues();
    var errors = [];
    mergedFields.forEach(function (field) {
      var v = values[field.id];
      if (field.required && (!v || (typeof v === 'string' && v.trim() === ''))) {
        errors.push(field.label + ' is required');
      }
      if (v && field.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) {
        errors.push(field.label + ' must be a valid email address');
      }
    });
    return { values: values, errors: errors };
  }

  function applyValuesToPolicies(values) {
    bulkPolicies.forEach(function (entry) {
      var fields = entry.rawJson._configFields || [];
      fields.forEach(function (field) {
        var val = values[field.id];
        if (val === undefined || val === '' || val === null) return;
        var transformed = applyTransform(val, field.transform);
        (field.jsonPaths || []).forEach(function (path) {
          var existing = getJsonPath(entry.rawJson, path);
          if (Array.isArray(existing) && typeof transformed === 'string') {
            setJsonPath(entry.rawJson, path, [transformed]);
          } else {
            setJsonPath(entry.rawJson, path, transformed);
          }
        });
      });
    });
  }

  // ─── Actions ───

  async function deployAll() {
    var result = validateForm();
    if (result.errors.length > 0) {
      var errEl = document.getElementById('bulk-config-errors');
      if (errEl) {
        errEl.style.display = 'block';
        errEl.innerHTML = result.errors.map(function (e) { return '<div>' + escHtml(e) + '</div>'; }).join('');
      }
      return;
    }

    applyValuesToPolicies(result.values);

    // Close modal
    document.getElementById('modal-overlay').classList.remove('open');

    // Build entries for deployBulkWithJson
    var entries = bulkPolicies.map(function (e) {
      return { id: e.id, rawJson: e.rawJson };
    });

    await DeployEngine.deployBulkWithJson(entries);
    if (typeof Policies !== 'undefined') Policies.render();
  }

  async function scriptAll() {
    var result = validateForm();
    if (result.errors.length > 0) {
      var errEl = document.getElementById('bulk-config-errors');
      if (errEl) {
        errEl.style.display = 'block';
        errEl.innerHTML = result.errors.map(function (e) { return '<div>' + escHtml(e) + '</div>'; }).join('');
      }
      return;
    }

    applyValuesToPolicies(result.values);

    // Close modal
    document.getElementById('modal-overlay').classList.remove('open');

    // Generate combined script
    var combined = '# M365 Compliance Framework - Bulk Policy Deployment Script\n';
    combined += '# Generated: ' + new Date().toISOString().split('T')[0] + '\n';
    combined += '# Policies: ' + bulkPolicies.length + '\n\n';

    bulkPolicies.forEach(function (entry) {
      combined += '\n' + '#'.repeat(60) + '\n';
      combined += '# ' + entry.id + ' - ' + (entry.pol.displayName || '') + '\n';
      combined += '#'.repeat(60) + '\n\n';
      try {
        combined += DeployEngine.generateScript(entry.rawJson, entry.pol.type);
        combined += '\n';
      } catch (err) {
        combined += '# ERROR: ' + err.message + '\n\n';
      }
    });

    downloadFile(combined, 'M365-Bulk-Deploy-' + bulkPolicies.length + 'policies.ps1', 'text/plain');
    showToast('Downloaded bulk script: ' + bulkPolicies.length + ' policies');
  }

  function cancel() {
    bulkPolicies = [];
    mergedFields = [];
    currentAction = null;
    document.getElementById('modal-overlay').classList.remove('open');
  }

  function downloadFile(content, filename, type) {
    var blob = new Blob([content], { type: type });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ─── Main Entry Point ───

  async function startBulk(policyIds, action) {
    var entries = await collectFields(policyIds);
    if (entries.length === 0) {
      showToast('No policies loaded');
      return;
    }
    bulkPolicies = entries;
    mergedFields = mergeFieldsFromEntries(entries);
    showBulkConfigModal(action);
  }

  // ─── Check if any policy in set has config fields ───

  function anyHasConfig() {
    return bulkPolicies.some(function (e) {
      return e.rawJson._configFields && e.rawJson._configFields.length > 0;
    });
  }

  return {
    startBulk: startBulk,
    deployAll: deployAll,
    scriptAll: scriptAll,
    cancel: cancel,
    anyHasConfig: anyHasConfig,
  };
})();
