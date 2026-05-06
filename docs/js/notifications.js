/* ═══════════════════════════════════════════
   WEBHOOK NOTIFIER — Teams / generic webhook
   notifications for compliance drift alerts.
═══════════════════════════════════════════ */
const WebhookNotifier = (() => {
  const SETTINGS_KEY = 'm365-webhook-settings';

  // ─── Settings ───

  function getSettings() {
    try {
      var raw = localStorage.getItem(SETTINGS_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) { return null; }
  }

  function saveSettings(settings) {
    try {
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    } catch (e) {}
  }

  // ─── Notification Sending ───

  async function sendNotification(payload) {
    var settings = getSettings();
    if (!settings || !settings.enabled || !settings.url) return false;

    var body;
    switch (settings.type) {
      case 'teams':    body = buildTeamsAdaptiveCard(payload); break;
      case 'splunk':   body = buildSplunkHEC(payload); break;
      case 'sentinel': body = buildSentinelFormat(payload); break;
      case 'cef':      body = buildCEFFormat(payload); break;
      default:         body = buildGenericWebhook(payload); break;
    }

    try {
      var response = await fetch(settings.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        console.warn('[Webhook] Send failed:', response.status);
        return false;
      }
      return true;
    } catch (e) {
      console.warn('[Webhook] Send error:', e);
      return false;
    }
  }

  function buildTeamsAdaptiveCard(payload) {
    var facts = (payload.facts || []).map(function (f) {
      return { title: f.title, value: String(f.value) };
    });

    var body = [
      { type: 'TextBlock', text: 'M365 Compliance Alert', weight: 'Bolder', size: 'Large', color: 'Attention' },
      { type: 'TextBlock', text: payload.message || '', wrap: true },
    ];

    if (facts.length > 0) {
      body.push({ type: 'FactSet', facts: facts });
    }

    if (payload.timestamp) {
      body.push({ type: 'TextBlock', text: 'Timestamp: ' + new Date(payload.timestamp).toLocaleString(), size: 'Small', isSubtle: true });
    }

    return {
      type: 'message',
      attachments: [{
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.4',
          body: body,
        },
      }],
    };
  }

  function buildGenericWebhook(payload) {
    return {
      event: payload.event || 'compliance_alert',
      timestamp: payload.timestamp || Date.now(),
      tenantId: payload.tenantId || AppState.get('authTenantId') || null,
      message: payload.message || '',
      data: payload,
    };
  }

  // ─── Trigger Logic ───

  async function checkAndNotify(currentScore, previousScore, driftPolicies) {
    var settings = getSettings();
    if (!settings || !settings.enabled) return;

    var threshold = settings.threshold || 70;

    // Score dropped below threshold
    if (currentScore < threshold && previousScore >= threshold) {
      await sendNotification({
        event: 'score_below_threshold',
        timestamp: Date.now(),
        message: 'Compliance score dropped to ' + currentScore + '% (threshold: ' + threshold + '%)',
        facts: [
          { title: 'Current Score', value: currentScore + '%' },
          { title: 'Previous Score', value: previousScore + '%' },
          { title: 'Threshold', value: threshold + '%' },
        ],
      });
    }

    // Drift detected
    if (driftPolicies && driftPolicies.length > 0) {
      var driftFacts = driftPolicies.slice(0, 8).map(function (p) {
        return { title: p.id, value: 'configured \u2192 missing' };
      });
      if (driftPolicies.length > 8) {
        driftFacts.push({ title: '...', value: '+' + (driftPolicies.length - 8) + ' more' });
      }

      await sendNotification({
        event: 'drift_detected',
        timestamp: Date.now(),
        message: driftPolicies.length + ' policies changed from configured to missing',
        facts: driftFacts,
      });
    }
  }

  // ─── Test ───

  async function sendTestNotification() {
    var result = await sendNotification({
      event: 'test',
      timestamp: Date.now(),
      message: 'Test notification from M365 Compliance Framework',
      facts: [
        { title: 'Status', value: 'Test successful' },
        { title: 'Time', value: new Date().toLocaleString() },
      ],
    });

    if (result) {
      showToast('Test notification sent successfully');
    } else {
      showToast('Failed to send test notification — check webhook URL');
    }
  }

  // ─── SIEM Formats ───

  function buildSplunkHEC(payload) {
    return {
      event: {
        sourcetype: 'm365_compliance',
        source: 'M365ComplianceFramework',
        host: window.location.hostname || 'localhost',
        time: Math.floor((payload.timestamp || Date.now()) / 1000),
        event: {
          action: payload.event || 'compliance_alert',
          message: payload.message || '',
          tenantId: payload.tenantId || AppState.get('authTenantId') || '',
          score: payload.score || null,
          severity: payload.severity || 'info',
          facts: payload.facts || [],
        },
      },
    };
  }

  function buildSentinelFormat(payload) {
    return [{
      TimeGenerated: new Date(payload.timestamp || Date.now()).toISOString(),
      Source_s: 'M365ComplianceFramework',
      Action_s: payload.event || 'compliance_alert',
      Message_s: payload.message || '',
      TenantId_g: payload.tenantId || AppState.get('authTenantId') || '',
      Score_d: payload.score || 0,
      Severity_s: payload.severity || 'Informational',
      Details_s: JSON.stringify(payload.facts || payload.data || {}),
      Computer_s: window.location.hostname || 'localhost',
    }];
  }

  function buildCEFFormat(payload) {
    var severity = payload.severity || 5;
    var sevNum = typeof severity === 'string' ?
      ({ low: 3, medium: 5, high: 7, critical: 9, info: 1 }[severity.toLowerCase()] || 5) :
      severity;
    var tenantId = payload.tenantId || AppState.get('authTenantId') || '';
    var score = payload.score || 0;
    var rt = payload.timestamp || Date.now();

    var cef = 'CEF:0|M365ComplianceFramework|ComplianceMonitor|1.0|' +
      (payload.event || 'COMPLIANCE_ALERT') + '|' +
      (payload.message || '').replace(/\|/g, '\\|') + '|' +
      sevNum + '|' +
      'tenantId=' + tenantId +
      ' score=' + score +
      ' rt=' + rt +
      ' src=' + (window.location.hostname || 'localhost');

    return { message: cef };
  }

  // ─── Settings UI ───

  function renderSettingsModal() {
    var settings = getSettings() || { url: '', type: 'teams', threshold: 70, enabled: false };
    var overlay = document.getElementById('modal-overlay');
    var modal = document.getElementById('modal');
    if (!overlay || !modal) return;

    var html = '<div class="modal-header">';
    html += '<h3>Webhook Notifications</h3>';
    html += '<button class="modal-close" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">&times;</button>';
    html += '</div>';
    html += '<div class="modal-body">';

    html += '<div style="font-size:.72rem;color:var(--ink4);margin-bottom:16px">';
    html += 'Configure a webhook to receive alerts when compliance score drops or policies drift.</div>';

    html += '<div class="form-row" style="margin-bottom:12px">';
    html += '<label style="font-size:.72rem;font-weight:600;display:block;margin-bottom:4px">Webhook URL</label>';
    html += '<input type="url" id="webhook-url" value="' + escHtml(settings.url) + '" placeholder="https://your-org.webhook.office.com/..." style="width:100%;font-size:.72rem;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg2);color:var(--ink1)">';
    html += '</div>';

    html += '<div class="form-row" style="margin-bottom:12px;display:flex;gap:16px">';
    html += '<div>';
    html += '<label style="font-size:.72rem;font-weight:600;display:block;margin-bottom:4px">Type</label>';
    html += '<select id="webhook-type" style="font-size:.72rem;padding:4px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg2);color:var(--ink1)">';
    html += '<option value="teams" ' + (settings.type === 'teams' ? 'selected' : '') + '>Microsoft Teams</option>';
    html += '<option value="generic" ' + (settings.type === 'generic' ? 'selected' : '') + '>Generic Webhook</option>';
    html += '<option value="splunk" ' + (settings.type === 'splunk' ? 'selected' : '') + '>Splunk HEC</option>';
    html += '<option value="sentinel" ' + (settings.type === 'sentinel' ? 'selected' : '') + '>Microsoft Sentinel</option>';
    html += '<option value="cef" ' + (settings.type === 'cef' ? 'selected' : '') + '>CEF (Syslog)</option>';
    html += '</select>';
    html += '</div>';
    html += '<div>';
    html += '<label style="font-size:.72rem;font-weight:600;display:block;margin-bottom:4px">Score Threshold</label>';
    html += '<input type="number" id="webhook-threshold" value="' + settings.threshold + '" min="0" max="100" style="width:60px;font-size:.72rem;padding:4px 8px;border:1px solid var(--border);border-radius:6px;background:var(--bg2);color:var(--ink1)">';
    html += '<span style="font-size:.62rem;color:var(--ink4);margin-left:4px">%</span>';
    html += '</div>';
    html += '</div>';

    html += '<div class="form-row" style="margin-bottom:16px">';
    html += '<label style="font-size:.72rem;display:flex;align-items:center;gap:6px;cursor:pointer">';
    html += '<input type="checkbox" id="webhook-enabled" ' + (settings.enabled ? 'checked' : '') + '>';
    html += '<span>Enable notifications</span>';
    html += '</label>';
    html += '</div>';

    html += '<div class="config-actions">';
    html += '<button class="btn btn-primary" onclick="WebhookNotifier.saveFromForm()">Save</button> ';
    html += '<button class="btn" onclick="WebhookNotifier.sendTestNotification()">Send Test</button> ';
    html += '<button class="btn" onclick="document.getElementById(\'modal-overlay\').classList.remove(\'open\')">Cancel</button>';
    html += '</div></div>';

    modal.innerHTML = html;
    overlay.classList.add('open');
  }

  function saveFromForm() {
    var url = document.getElementById('webhook-url').value.trim();
    var type = document.getElementById('webhook-type').value;
    var threshold = parseInt(document.getElementById('webhook-threshold').value, 10) || 70;
    var enabled = document.getElementById('webhook-enabled').checked;

    saveSettings({ url: url, type: type, threshold: threshold, enabled: enabled });
    showToast('Webhook settings saved');
    document.getElementById('modal-overlay').classList.remove('open');
  }

  return {
    getSettings: getSettings,
    saveSettings: saveSettings,
    sendNotification: sendNotification,
    checkAndNotify: checkAndNotify,
    sendTestNotification: sendTestNotification,
    renderSettingsModal: renderSettingsModal,
    saveFromForm: saveFromForm,
  };
})();
