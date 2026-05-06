/* ═══════════════════════════════════════════
   PRE-DEPLOY CONFIG — Configuration form for
   tenant-specific values and framework overrides
   before policy deployment or PS1 generation
═══════════════════════════════════════════ */
const PreDeployConfig = (() => {

  let currentPolicy = null;     // Policy metadata from AppState
  let currentRawJson = null;    // Deep-cloned raw policy JSON
  let currentAction = null;     // 'deploy' | 'script'
  let selectedFramework = null; // User's chosen primary framework

  // ─── JSON Path Engine ───

  function parsePath(path) {
    const segs = [];
    const re = /([^.\[\]]+)|\[(\d+)\]/g;
    let m;
    while ((m = re.exec(path)) !== null) {
      segs.push(m[2] !== undefined ? parseInt(m[2], 10) : m[1]);
    }
    return segs;
  }

  function getJsonPath(obj, path) {
    const segs = parsePath(path);
    let cur = obj;
    for (let i = 0; i < segs.length; i++) {
      if (cur == null || typeof cur !== 'object') return undefined;
      cur = cur[segs[i]];
    }
    return cur;
  }

  function setJsonPath(obj, path, value) {
    const segs = parsePath(path);
    let cur = obj;
    for (let i = 0; i < segs.length - 1; i++) {
      if (cur[segs[i]] === undefined || cur[segs[i]] === null) {
        cur[segs[i]] = typeof segs[i + 1] === 'number' ? [] : {};
      }
      cur = cur[segs[i]];
    }
    const last = segs[segs.length - 1];
    if (typeof last === 'number' && Array.isArray(cur)) {
      while (cur.length <= last) cur.push(null);
    }
    cur[last] = value;
    return true;
  }

  // ─── Framework Resolution ───

  function resolveFrameworks(rawJson) {
    const meta = rawJson._metadata || {};
    const overrides = rawJson._frameworkOverrides || {};
    const userFws = AppState.get('selectedFrameworks') || new Set();
    const policyFws = meta.frameworks || [];

    // Frameworks that are in user selection AND have overrides defined
    const matching = policyFws.filter(function (fw) {
      return userFws.has(fw) && overrides[fw];
    });

    return {
      matching: matching,
      needsSelector: matching.length > 1,
      autoSelect: matching.length === 1 ? matching[0] : null,
    };
  }

  function applyFrameworkOverrides(rawJson, fwKey) {
    const ov = (rawJson._frameworkOverrides || {})[fwKey];
    if (!ov) return;

    // Apply jsonOverrides
    if (ov.jsonOverrides) {
      Object.keys(ov.jsonOverrides).forEach(function (path) {
        setJsonPath(rawJson, path, ov.jsonOverrides[path]);
      });
    }

    // Apply policyTipText to common notification paths
    if (ov.policyTipText) {
      var tipPaths = [
        'powershellCommands.createRule.parameters.NotifyPolicyTipCustomText',
        'powershellCommands.createRuleUkPii.parameters.NotifyPolicyTipCustomText',
        'powershellCommands.createRuleEuPii.parameters.NotifyPolicyTipCustomText',
      ];
      tipPaths.forEach(function (p) {
        if (getJsonPath(rawJson, p) !== undefined) {
          setJsonPath(rawJson, p, ov.policyTipText);
        }
      });
    }
  }

  // ─── Transforms ───

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

  // ─── Validation ───

  function validateFields(configFields, values) {
    var errors = [];
    configFields.forEach(function (field) {
      var v = values[field.id];
      if (field.required && (!v || (typeof v === 'string' && v.trim() === ''))) {
        errors.push(field.label + ' is required');
        return;
      }
      if (v && field.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) {
        errors.push(field.label + ' must be a valid email address');
      }
    });
    return errors;
  }

  // ─── Form Rendering ───

  function renderField(field, currentValue) {
    var val = currentValue !== undefined && currentValue !== null ? currentValue : (field.default || '');
    var reqMark = field.required ? ' <span class="required">*</span>' : '';
    var helpHtml = field.description ? '<div class="field-help">' + escHtml(field.description) + '</div>' : '';
    var fullClass = (field.type === 'textarea' || field.type === 'domain-list') ? ' rpt-field-full' : '';

    var html = '<div class="rpt-field' + fullClass + '">';
    html += '<label>' + escHtml(field.label) + reqMark + '</label>';

    switch (field.type) {
      case 'text':
      case 'email':
        html += '<input type="' + field.type + '" id="cfg-' + field.id + '" value="' + escHtml(String(val)) + '"';
        if (field.placeholder) html += ' placeholder="' + escHtml(field.placeholder) + '"';
        html += '>';
        break;

      case 'number':
        html += '<input type="number" id="cfg-' + field.id + '" value="' + escHtml(String(val)) + '"';
        if (field.min !== undefined) html += ' min="' + field.min + '"';
        if (field.max !== undefined) html += ' max="' + field.max + '"';
        html += '>';
        break;

      case 'textarea':
      case 'domain-list':
        var textVal = Array.isArray(val) ? val.join('\n') : String(val);
        html += '<textarea id="cfg-' + field.id + '" rows="3"';
        if (field.placeholder) html += ' placeholder="' + escHtml(field.placeholder) + '"';
        html += '>' + escHtml(textVal) + '</textarea>';
        break;

      case 'select':
        html += '<select id="cfg-' + field.id + '" class="rpt-select">';
        (field.options || []).forEach(function (opt) {
          var selected = (opt.value === val) ? ' selected' : '';
          html += '<option value="' + escHtml(opt.value) + '"' + selected + '>' + escHtml(opt.label) + '</option>';
        });
        html += '</select>';
        break;

      case 'toggle':
        var checked = val ? ' checked' : '';
        html += '<label class="rpt-toggle"><input type="checkbox" id="cfg-' + field.id + '"' + checked + '> ' + escHtml(field.label) + '</label>';
        break;

      default:
        html += '<input type="text" id="cfg-' + field.id + '" value="' + escHtml(String(val)) + '">';
    }

    html += helpHtml + '</div>';
    return html;
  }

  function renderConfigModal(policy, rawJson, action) {
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var configFields = rawJson._configFields || [];
    var meta = rawJson._metadata || {};
    var fwInfo = resolveFrameworks(rawJson);

    // Auto-select single framework match
    if (fwInfo.autoSelect) {
      selectedFramework = fwInfo.autoSelect;
    } else {
      selectedFramework = fwInfo.matching.length > 0 ? fwInfo.matching[0] : null;
    }

    // Apply framework defaults to field values
    var fieldDefaults = {};
    if (selectedFramework && rawJson._frameworkOverrides && rawJson._frameworkOverrides[selectedFramework]) {
      fieldDefaults = rawJson._frameworkOverrides[selectedFramework].fieldDefaults || {};
    }

    var actionLabel = action === 'deploy' ? 'Deploy to Tenant' : 'Generate PowerShell Script';
    var actionClass = action === 'deploy' ? 'btn-deploy' : 'btn-script';
    var actionFn = action === 'deploy' ? 'PreDeployConfig.deployWithConfig()' : 'PreDeployConfig.scriptWithConfig()';

    var html = '<div class="modal-header">';
    html += '<h3>Configure: ' + escHtml(policy.id) + ' | ' + escHtml(policy.displayName || meta.title || '') + '</h3>';
    html += '<button class="modal-close" onclick="PreDeployConfig.cancel()">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';

    // Description
    if (meta.description) {
      html += '<p class="config-policy-desc">' + escHtml(meta.description) + '</p>';
    }

    // Framework selector
    if (fwInfo.matching.length > 0) {
      html += '<div class="config-fw-selector">';
      html += '<div class="section-hdr" style="margin-top:0">Compliance Framework</div>';

      if (fwInfo.needsSelector) {
        html += '<div class="config-fw-pills">';
        fwInfo.matching.forEach(function (fw) {
          var active = fw === selectedFramework ? ' active' : '';
          html += '<button class="filter-pill' + active + '" onclick="PreDeployConfig.selectFramework(\'' + escHtml(fw).replace(/'/g, "\\'") + '\')">' + escHtml(fw) + '</button>';
        });
        html += '</div>';
      } else {
        html += '<div class="config-fw-pills"><span class="filter-pill active">' + escHtml(selectedFramework) + '</span></div>';
      }

      // Info note
      html += '<div id="config-fw-note" class="config-fw-note" style="display:none"></div>';
      html += '</div>';
    }

    // Config fields form
    if (configFields.length > 0) {
      html += '<div class="section-hdr">Tenant Configuration</div>';
      html += '<div class="rpt-form" id="config-form">';
      configFields.forEach(function (field) {
        // Use framework default if available, otherwise read from JSON path
        var curValue = fieldDefaults[field.id];
        if (curValue === undefined && field.jsonPaths && field.jsonPaths.length > 0) {
          curValue = getJsonPath(rawJson, field.jsonPaths[0]);
        }
        if (curValue === undefined) curValue = field.default;
        html += renderField(field, curValue);
      });
      html += '</div>';
    }

    // Validation errors
    html += '<div id="config-errors" class="config-errors" style="display:none"></div>';

    // Action buttons
    html += '<div class="config-actions">';
    html += '<button class="btn" onclick="PreDeployConfig.cancel()">Cancel</button>';
    html += '<button class="btn ' + actionClass + '" onclick="' + actionFn + '">' + actionLabel + '</button>';
    html += '</div>';

    html += '</div>';

    modal.innerHTML = html;
    overlay.classList.add('open');

    // Update framework note
    updateFrameworkNote();
  }

  function updateFrameworkNote() {
    var noteEl = document.getElementById('config-fw-note');
    if (!noteEl || !selectedFramework || !currentRawJson) return;
    var ov = (currentRawJson._frameworkOverrides || {})[selectedFramework];
    if (ov && ov.infoNote) {
      noteEl.textContent = ov.infoNote;
      noteEl.style.display = 'block';
    } else {
      noteEl.style.display = 'none';
    }
  }

  function selectFramework(fw) {
    selectedFramework = fw;

    // Update pills
    var pills = document.querySelectorAll('.config-fw-pills .filter-pill');
    pills.forEach(function (pill) {
      pill.classList.toggle('active', pill.textContent === fw);
    });

    // Update field defaults from this framework
    var ov = (currentRawJson._frameworkOverrides || {})[fw];
    if (ov && ov.fieldDefaults) {
      Object.keys(ov.fieldDefaults).forEach(function (fieldId) {
        var el = document.getElementById('cfg-' + fieldId);
        if (el) {
          if (el.type === 'checkbox') el.checked = !!ov.fieldDefaults[fieldId];
          else el.value = ov.fieldDefaults[fieldId];
        }
      });
    }

    updateFrameworkNote();
  }

  // ─── Form Collection ───

  function collectFormValues(configFields) {
    var values = {};
    configFields.forEach(function (field) {
      var el = document.getElementById('cfg-' + field.id);
      if (!el) return;
      var raw;
      if (field.type === 'toggle') {
        raw = el.checked;
      } else {
        raw = el.value;
      }
      values[field.id] = applyTransform(raw, field.transform);
    });
    return values;
  }

  function applyConfigToJson(rawJson, configFields, values) {
    configFields.forEach(function (field) {
      var val = values[field.id];
      if (val === undefined || val === '' || val === null) return;
      (field.jsonPaths || []).forEach(function (path) {
        // Auto-wrap: if target is an array and value is a plain string, wrap in array
        var existing = getJsonPath(rawJson, path);
        if (Array.isArray(existing) && typeof val === 'string') {
          setJsonPath(rawJson, path, [val]);
        } else {
          setJsonPath(rawJson, path, val);
        }
      });
    });
  }

  // ─── Entry Points ───

  async function interceptDeploy(policyId) {
    var pol = AppState.get('policies').find(function (p) { return p.id === policyId; });
    if (!pol) return;

    var rawJson = await DataStore.loadPolicy(pol.type, pol.file);

    // No config fields — proceed directly (backward compatible)
    if (!rawJson._configFields || rawJson._configFields.length === 0) {
      await DeployEngine.deploySinglePolicy(policyId);
      return;
    }

    // Has config fields — show configuration modal
    currentPolicy = pol;
    currentRawJson = JSON.parse(JSON.stringify(rawJson));
    currentAction = 'deploy';
    renderConfigModal(pol, currentRawJson, 'deploy');
  }

  async function interceptScript(policyId) {
    var pol = AppState.get('policies').find(function (p) { return p.id === policyId; });
    if (!pol) return;

    var rawJson = await DataStore.loadPolicy(pol.type, pol.file);

    // No config fields — generate directly (backward compatible)
    if (!rawJson._configFields || rawJson._configFields.length === 0) {
      var script = DeployEngine.generateScript(rawJson, pol.type);
      downloadConfiguredFile(script, pol.id + '.ps1', 'text/plain');
      showToast('Downloaded ' + pol.id + '.ps1');
      return;
    }

    // Has config fields — show configuration modal
    currentPolicy = pol;
    currentRawJson = JSON.parse(JSON.stringify(rawJson));
    currentAction = 'script';
    renderConfigModal(pol, currentRawJson, 'script');
  }

  // ─── Check if policy needs configuration (for bulk deploy filtering) ───

  async function needsConfig(policyId) {
    var pol = AppState.get('policies').find(function (p) { return p.id === policyId; });
    if (!pol) return false;
    try {
      var rawJson = await DataStore.loadPolicy(pol.type, pol.file);
      return !!(rawJson._configFields && rawJson._configFields.length > 0);
    } catch (e) {
      return false;
    }
  }

  // ─── Action Handlers ───

  async function deployWithConfig() {
    var configFields = currentRawJson._configFields || [];
    var values = collectFormValues(configFields);
    var errors = validateFields(configFields, values);

    if (errors.length > 0) {
      var errEl = document.getElementById('config-errors');
      if (errEl) {
        errEl.style.display = 'block';
        errEl.innerHTML = errors.map(function (e) { return '<div>' + escHtml(e) + '</div>'; }).join('');
      }
      return;
    }

    // Apply framework overrides first
    if (selectedFramework) {
      applyFrameworkOverrides(currentRawJson, selectedFramework);
    }

    // Apply user config values
    applyConfigToJson(currentRawJson, configFields, values);

    // Close modal
    document.getElementById('modal-overlay').classList.remove('open');

    // Deploy using modified JSON
    await DeployEngine.deploySinglePolicyWithJson(currentPolicy.id, currentRawJson);
  }

  async function scriptWithConfig() {
    var configFields = currentRawJson._configFields || [];
    var values = collectFormValues(configFields);
    var errors = validateFields(configFields, values);

    if (errors.length > 0) {
      var errEl = document.getElementById('config-errors');
      if (errEl) {
        errEl.style.display = 'block';
        errEl.innerHTML = errors.map(function (e) { return '<div>' + escHtml(e) + '</div>'; }).join('');
      }
      return;
    }

    // Apply framework overrides first
    if (selectedFramework) {
      applyFrameworkOverrides(currentRawJson, selectedFramework);
    }

    // Apply user config values
    applyConfigToJson(currentRawJson, configFields, values);

    // Close modal
    document.getElementById('modal-overlay').classList.remove('open');

    // Generate PS1 with modified JSON
    var script = DeployEngine.generateScript(currentRawJson, currentPolicy.type);
    downloadConfiguredFile(script, currentPolicy.id + '.ps1', 'text/plain');
    showToast('Downloaded ' + currentPolicy.id + '.ps1');
  }

  function cancel() {
    currentPolicy = null;
    currentRawJson = null;
    currentAction = null;
    selectedFramework = null;
    document.getElementById('modal-overlay').classList.remove('open');
  }

  // ─── Utilities ───

  function downloadConfiguredFile(content, filename, type) {
    var blob = new Blob([content], { type: type });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ─── Public API ───

  return {
    interceptDeploy: interceptDeploy,
    interceptScript: interceptScript,
    needsConfig: needsConfig,
    deployWithConfig: deployWithConfig,
    scriptWithConfig: scriptWithConfig,
    selectFramework: selectFramework,
    cancel: cancel,
  };
})();
