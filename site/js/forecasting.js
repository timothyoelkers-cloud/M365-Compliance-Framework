/* ═══════════════════════════════════════════
   SCORE FORECASTER — Linear regression on
   scan history to project compliance score
   trends with confidence intervals.
═══════════════════════════════════════════ */
const ScoreForecaster = (() => {

  /**
   * Ordinary least squares linear regression.
   * @param {{ x: number, y: number }[]} points
   * @returns {{ slope: number, intercept: number, r2: number, n: number }}
   */
  function linearRegression(points) {
    var n = points.length;
    if (n < 2) return { slope: 0, intercept: points.length ? points[0].y : 0, r2: 0, n: n };

    var sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumY2 = 0;
    for (var i = 0; i < n; i++) {
      sumX += points[i].x;
      sumY += points[i].y;
      sumXY += points[i].x * points[i].y;
      sumX2 += points[i].x * points[i].x;
      sumY2 += points[i].y * points[i].y;
    }

    var denom = n * sumX2 - sumX * sumX;
    if (denom === 0) return { slope: 0, intercept: sumY / n, r2: 0, n: n };

    var slope = (n * sumXY - sumX * sumY) / denom;
    var intercept = (sumY - slope * sumX) / n;

    // R-squared
    var meanY = sumY / n;
    var ssTot = 0, ssRes = 0;
    for (var j = 0; j < n; j++) {
      var predicted = slope * points[j].x + intercept;
      ssTot += (points[j].y - meanY) * (points[j].y - meanY);
      ssRes += (points[j].y - predicted) * (points[j].y - predicted);
    }
    var r2 = ssTot > 0 ? 1 - (ssRes / ssTot) : 0;

    return { slope: slope, intercept: intercept, r2: r2, n: n };
  }

  /**
   * Compute standard error of estimate for confidence interval.
   */
  function standardError(points, slope, intercept) {
    var n = points.length;
    if (n <= 2) return 10; // fallback

    var sumResidual2 = 0;
    for (var i = 0; i < n; i++) {
      var predicted = slope * points[i].x + intercept;
      sumResidual2 += (points[i].y - predicted) * (points[i].y - predicted);
    }
    return Math.sqrt(sumResidual2 / (n - 2));
  }

  /**
   * Project score forward with 95% confidence interval.
   * @param {Array} timeline - From ScanHistory.buildTimeline()
   * @param {number} daysForward - Days to project
   * @returns {{ projected, lower, upper, targetDate, confidence, regression, points }|null}
   */
  function forecast(timeline, daysForward) {
    if (!timeline || timeline.length < 3) return null;

    daysForward = daysForward || 30;
    var firstTs = timeline[0].timestamp;

    // Build regression points
    var points = [];
    for (var i = 0; i < timeline.length; i++) {
      var daysSinceFirst = (timeline[i].timestamp - firstTs) / (1000 * 60 * 60 * 24);
      points.push({ x: daysSinceFirst, y: timeline[i].score });
    }

    var reg = linearRegression(points);
    var se = standardError(points, reg.slope, reg.intercept);

    // T-value for 95% CI (approx for n > 3)
    var tVal = 2.0; // rough approximation for small samples
    var lastDay = points[points.length - 1].x;
    var targetDay = lastDay + daysForward;
    var projected = Math.max(0, Math.min(100, reg.slope * targetDay + reg.intercept));
    var margin = tVal * se * Math.sqrt(1 + 1 / points.length);

    return {
      projected: Math.round(projected),
      lower: Math.max(0, Math.round(projected - margin)),
      upper: Math.min(100, Math.round(projected + margin)),
      targetDate: new Date(Date.now() + daysForward * 24 * 60 * 60 * 1000),
      confidence: 0.95,
      regression: reg,
      points: points,
      daysForward: daysForward,
    };
  }

  /**
   * Render forecast chart: extends existing sparkline with dashed projection.
   */
  function renderForecastChart(containerId, daysForward) {
    var container = document.getElementById(containerId);
    if (!container) return;

    if (typeof ScanHistory === 'undefined') return;

    ScanHistory.getScans(AppState.get('authTenantId'), 50).then(function (scans) {
      if (scans.length < 3) return;

      var timeline = ScanHistory.buildTimeline(scans);
      var result = forecast(timeline, daysForward || 30);
      if (!result) return;

      // Find the sparkline SVG (rendered by ScanHistory.renderTimeline)
      var svg = container.querySelector('svg');
      if (!svg) {
        // Render a standalone forecast section
        renderStandaloneForecast(container, result, timeline);
        return;
      }

      // Append forecast indicator below the timeline
      renderStandaloneForecast(container, result, timeline);
    }).catch(function () {});
  }

  function renderStandaloneForecast(container, result, timeline) {
    var div = document.createElement('div');
    div.className = 'forecast-summary';
    div.style.cssText = 'margin-top:8px;padding:10px 14px;border-radius:8px;background:var(--surface);border:1px solid var(--border);font-size:.68rem';

    var trendIcon = result.regression.slope > 0.1 ? '&#9650;' : result.regression.slope < -0.1 ? '&#9660;' : '&#9644;';
    var trendColor = result.regression.slope > 0.1 ? 'var(--green)' : result.regression.slope < -0.1 ? 'var(--red)' : 'var(--ink4)';
    var trendLabel = result.regression.slope > 0.1 ? 'Improving' : result.regression.slope < -0.1 ? 'Declining' : 'Stable';

    var html = '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">';
    html += '<div><strong>Score Forecast</strong> <span style="color:var(--ink4)">(next ' + result.daysForward + ' days)</span></div>';
    html += '<div style="display:flex;gap:16px;align-items:center">';
    html += '<div><span style="color:' + trendColor + ';font-weight:600">' + trendIcon + ' ' + trendLabel + '</span></div>';
    html += '<div>Projected: <strong style="color:var(--blue)">' + result.projected + '%</strong>';
    html += ' <span style="color:var(--ink4)">(' + result.lower + '–' + result.upper + '%)</span></div>';
    html += '<div style="color:var(--ink4)">R&sup2;: ' + result.regression.r2.toFixed(2) + '</div>';
    html += '</div></div>';

    // Mini trend sparkline
    if (result.points.length >= 3) {
      html += renderMiniTrendline(result);
    }

    div.innerHTML = html;

    // Remove any existing forecast
    var existing = container.querySelector('.forecast-summary');
    if (existing) existing.remove();

    container.appendChild(div);
  }

  function renderMiniTrendline(result) {
    var pts = result.points;
    var w = 200, h = 40;
    var maxX = pts[pts.length - 1].x + result.daysForward;
    var minY = 0, maxY = 100;

    function px(x) { return (x / maxX) * w; }
    function py(y) { return h - ((y - minY) / (maxY - minY)) * h; }

    var svg = '<svg width="' + w + '" height="' + h + '" style="margin-top:6px;display:block">';

    // Actual data line
    var pathD = 'M';
    for (var i = 0; i < pts.length; i++) {
      pathD += (i > 0 ? 'L' : '') + px(pts[i].x).toFixed(1) + ',' + py(pts[i].y).toFixed(1);
    }
    svg += '<path d="' + pathD + '" fill="none" stroke="var(--blue)" stroke-width="1.5"/>';

    // Forecast line (dashed)
    var lastPt = pts[pts.length - 1];
    var projX = maxX;
    var projY = Math.max(0, Math.min(100, result.regression.slope * projX + result.regression.intercept));
    svg += '<line x1="' + px(lastPt.x).toFixed(1) + '" y1="' + py(lastPt.y).toFixed(1) + '" x2="' + px(projX).toFixed(1) + '" y2="' + py(projY).toFixed(1) + '" stroke="var(--accent)" stroke-width="1.5" stroke-dasharray="4,3"/>';

    // Confidence band
    var upperY = Math.min(100, result.regression.slope * projX + result.regression.intercept + (result.upper - result.projected));
    var lowerY = Math.max(0, result.regression.slope * projX + result.regression.intercept - (result.projected - result.lower));
    svg += '<polygon points="' +
      px(lastPt.x).toFixed(1) + ',' + py(lastPt.y).toFixed(1) + ' ' +
      px(projX).toFixed(1) + ',' + py(upperY).toFixed(1) + ' ' +
      px(projX).toFixed(1) + ',' + py(lowerY).toFixed(1) +
      '" fill="var(--accent)" fill-opacity="0.1"/>';

    // Data dots
    for (var j = 0; j < pts.length; j++) {
      svg += '<circle cx="' + px(pts[j].x).toFixed(1) + '" cy="' + py(pts[j].y).toFixed(1) + '" r="2" fill="var(--blue)"/>';
    }

    svg += '</svg>';
    return svg;
  }

  /**
   * Return forecast summary HTML string for executive view.
   */
  function renderForecastSummary() {
    // Synchronous check — use cached data if available
    return '<div id="forecast-exec-placeholder"></div>';
  }

  /**
   * Async render of forecast into a placeholder element.
   */
  async function renderForecastAsync(containerId) {
    var container = document.getElementById(containerId);
    if (!container || typeof ScanHistory === 'undefined') return;

    try {
      var scans = await ScanHistory.getScans(AppState.get('authTenantId'), 50);
      if (scans.length < 3) {
        container.innerHTML = '<div style="font-size:.62rem;color:var(--ink4)">Need 3+ scans for forecasting</div>';
        return;
      }
      var timeline = ScanHistory.buildTimeline(scans);
      var result = forecast(timeline, 30);
      if (!result) return;

      var trendColor = result.regression.slope > 0.1 ? 'var(--green)' : result.regression.slope < -0.1 ? 'var(--red)' : 'var(--ink4)';
      container.innerHTML = '<div style="font-size:.72rem"><strong style="color:' + trendColor + '">' + result.projected + '%</strong> projected in 30 days <span style="color:var(--ink4)">(' + result.lower + '–' + result.upper + '%)</span></div>';
    } catch (e) {}
  }

  return {
    linearRegression: linearRegression,
    forecast: forecast,
    renderForecastChart: renderForecastChart,
    renderForecastSummary: renderForecastSummary,
    renderForecastAsync: renderForecastAsync,
  };
})();
