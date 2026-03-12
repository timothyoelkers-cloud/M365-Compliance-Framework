/**
 * Playwright test runner — opens test.html in headless Chromium,
 * waits for results, and exits with 0 (pass) or 1 (fail).
 *
 * Usage: npx playwright test  (via playwright.config.js)
 *   -or- node run-tests.js     (standalone)
 */
const { chromium } = require('playwright');
const { createServer } = require('http');
const { readFileSync, existsSync, statSync } = require('fs');
const { join, extname } = require('path');

const SITE_DIR = join(__dirname, 'site');
const PORT = 8723;
const TIMEOUT_MS = 30000;

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

// Simple static file server
function startServer() {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let filePath = join(SITE_DIR, req.url === '/' ? 'index.html' : req.url.split('?')[0]);
      if (!existsSync(filePath) || !statSync(filePath).isFile()) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }
      const ext = extname(filePath);
      const mime = MIME_TYPES[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime });
      res.end(readFileSync(filePath));
    });
    server.listen(PORT, () => resolve(server));
  });
}

async function runTests() {
  const server = await startServer();
  console.log(`[test] Static server on http://localhost:${PORT}`);

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  // Collect console output
  page.on('console', (msg) => {
    if (msg.type() === 'error') console.error('[browser]', msg.text());
  });

  await page.goto(`http://localhost:${PORT}/test.html`, { waitUntil: 'networkidle' });

  // Wait for test-status to contain "passed" or "failed"
  await page.waitForFunction(
    () => {
      const el = document.getElementById('test-status');
      return el && (el.textContent.includes('passed') || el.textContent.includes('Error'));
    },
    { timeout: TIMEOUT_MS }
  );

  const statusText = await page.$eval('#test-status', (el) => el.textContent);
  console.log(`[test] ${statusText}`);

  // Extract pass/fail counts
  const match = statusText.match(/(\d+) passed, (\d+) failed/);
  const passed = match ? parseInt(match[1], 10) : 0;
  const failed = match ? parseInt(match[2], 10) : 0;

  // Print suite details if failures
  if (failed > 0) {
    const details = await page.$$eval('#test-results div[style*="dc2626"]', (els) =>
      els.map((el) => el.textContent.trim()).filter(Boolean)
    );
    console.log('\n--- Failed tests ---');
    details.forEach((d) => console.log('  ' + d));
  }

  console.log(`\n[test] Result: ${passed} passed, ${failed} failed`);

  await browser.close();
  server.close();

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
  console.error('[test] Fatal:', err.message);
  process.exit(1);
});
