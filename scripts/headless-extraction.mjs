// Disposable browser diagnostic; no gateway or app imports.
import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
const out = 'verification/headless';
await mkdir(out, { recursive: true });
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
const page = await context.newPage();
const responses = [];
page.on('response', response => {
  if (response.request().resourceType() === 'document') responses.push({ url: response.url(), status: response.status(), headers: response.headers() });
});
try {
  console.log(JSON.stringify({ startedAt: new Date().toISOString(), runId: process.env.GITHUB_RUN_ID, browser: browser.version(), headless: true }));
  await page.goto('https://vidsrc.to/embed/movie/550', { waitUntil: 'domcontentloaded', timeout: 45000 }).catch(e => console.log(JSON.stringify({ navigationError: e.message })));
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    if (await page.locator('iframe').count() && !/Just a moment|Attention Required/i.test(await page.title())) break;
    await page.waitForTimeout(2000);
  }
  const title = await page.title();
  const text = await page.locator('body').innerText();
  const html = await page.content();
  await page.screenshot({ path: `${out}/browser.png` });
  await writeFile(`${out}/page.html`, html);
  await writeFile(`${out}/page-text.txt`, text);
  await writeFile(`${out}/responses.json`, JSON.stringify(responses, null, 2));
  const evidence = { title, pageText: text.slice(0,3000), responses, challengeMarkers: { mitigated: responses.some(r => r.headers['cf-mitigated'] === 'challenge'), challengePlatform: html.includes('/cdn-cgi/challenge-platform/'), turnstile: /turnstile/i.test(html) } };
  console.log(JSON.stringify(evidence));
  if (/Just a moment|Attention Required/i.test(title) || !await page.locator('iframe').count()) {
    console.log(JSON.stringify({ result: 'BROWSER_CHALLENGE_BLOCKED', wasm: 'NOT_REACHED', freshToken: 'NOT_REACHED', master: 'NOT_REACHED', variant: 'NOT_REACHED', segment: 'NOT_REACHED' }));
    process.exitCode = 2;
  } else {
    // Reuse established extraction checks with browser-context cookies.
    globalThis.probeBrowserFetch = async (url, headers) => {
      const response = await context.request.get(url, { headers, timeout: 25000 });
      const result = new Response(await response.body(), { status: response.status(), headers: response.headers() });
      Object.defineProperty(result, 'url', { value: response.url() });
      return result;
    };
    await import('./full-extraction.mjs');
  }
} finally { await browser.close(); }
