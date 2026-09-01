// Phase 0 spike: can a GitHub-hosted runner reach npmjs.com's login page with a
// cold headless Chromium profile, or does Cloudflare serve an interstitial?
//
// This decides whether the Puppeteer publish flow can work on GitHub Actions at
// all. It uses NO secrets and performs NO login: it only loads public pages and
// reports what came back.
//
// Exit code is always 0 (except on internal error) so the workflow can upload
// artifacts and print a verdict rather than failing opaquely.
import { spawn, spawnSync } from 'node:child_process';
import fsPromises from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import puppeteer from 'puppeteer-core';

const EXECUTABLE = process.env.CHROMIUM_PATH ?? '/usr/bin/chromium';
const OUT_DIR = process.env.SPIKE_OUT_DIR ?? path.join(process.cwd(), 'spike-out');
const NAV_TIMEOUT_MS = 45000;
const SETTLE_MS = 20000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function chromeMajor() {
  const probe = spawnSync(EXECUTABLE, ['--version'], { encoding: 'utf8' });
  const version = (probe.stdout ?? '').match(/(\d+)\.\d+\.\d+\.\d+/);
  return version?.[1] ?? '151';
}

// Mirrors chromium.mjs so the spike measures the real configuration.
const headedUA = () =>
  `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeMajor()}.0.0.0 Safari/537.36`;

async function launch({ headless, spoofUA }) {
  const port = await freePort();
  const profile = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'spike-chromium-'));
  const args = [
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${profile}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--disable-popup-blocking',
    '--password-store=basic',
    '--use-mock-keychain',
    '--no-sandbox',
    '--disable-setuid-sandbox',
  ];
  if (headless) {
    args.push('--headless=new', '--disable-gpu', '--window-size=1280,900');
    if (spoofUA) args.push(`--user-agent=${headedUA()}`);
  }
  const child = spawn(EXECUTABLE, [...args, 'about:blank'], { stdio: 'ignore' });

  let exited = false;
  const exitPromise = new Promise((r) => child.once('exit', () => { exited = true; r(); }));
  const endpoint = `http://127.0.0.1:${port}`;

  const close = async () => {
    if (!exited) {
      child.kill('SIGTERM');
      const timer = setTimeout(() => { if (!exited) child.kill('SIGKILL'); }, 3000);
      await exitPromise;
      clearTimeout(timer);
    }
    await fsPromises.rm(profile, { recursive: true, force: true });
  };

  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${endpoint}/json/version`, { signal: AbortSignal.timeout(1500) });
      if (res.ok) return { endpoint, close };
    } catch { /* not up yet */ }
    await sleep(250);
  }
  await close();
  throw new Error(`Chromium did not expose CDP on ${endpoint}`);
}

const CHALLENGE = /just a moment|performing security verification|attention required|checking your browser|enable javascript and cookies/i;

async function inspect(page) {
  return page.evaluate(() => ({
    url: location.href,
    title: document.title,
    // Slice keeps logs readable; enough to classify the page.
    text: (document.body?.innerText ?? '').replace(/\s+/g, ' ').slice(0, 300),
    hasUsername: !!document.querySelector('input[name="username"]'),
    hasPassword: !!document.querySelector('input[name="password"]'),
    hasCfChallenge: !!document.querySelector('#challenge-form, [id*="cf-chl"], iframe[src*="challenge"]'),
  }));
}

// Cloudflare interstitials often clear themselves after a few seconds. Poll so a
// slow-but-passing check is not misreported as a hard block.
async function settle(page) {
  const deadline = Date.now() + SETTLE_MS;
  let last = await inspect(page);
  while (Date.now() < deadline) {
    if (!CHALLENGE.test(last.title) && !CHALLENGE.test(last.text) && !last.hasCfChallenge) return { state: last, waitedMs: 0 };
    await sleep(1000);
    last = await inspect(page);
  }
  return { state: last, waitedMs: SETTLE_MS };
}

async function probe({ headless, spoofUA, label }) {
  const result = { label, headless, spoofUA };
  let browser;
  let launched;
  try {
    launched = await launch({ headless, spoofUA });
    browser = await puppeteer.connect({ browserURL: launched.endpoint });
    const page = await browser.newPage();
    page.setDefaultNavigationTimeout(NAV_TIMEOUT_MS);

    result.reportedUA = await page.evaluate(() => navigator.userAgent);

    const targets = [
      ['home', 'https://www.npmjs.com/'],
      ['login', 'https://www.npmjs.com/login'],
    ];
    result.pages = [];
    for (const [name, url] of targets) {
      let httpStatus = null;
      try {
        const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS });
        httpStatus = response?.status() ?? null;
      } catch (error) {
        result.pages.push({ name, url, error: error.message.slice(0, 200) });
        continue;
      }
      const { state, waitedMs } = await settle(page);
      const blocked = CHALLENGE.test(state.title) || CHALLENGE.test(state.text) || state.hasCfChallenge;
      result.pages.push({
        name,
        httpStatus,
        finalUrl: state.url,
        title: state.title,
        blocked,
        waitedMs,
        loginFormPresent: state.hasUsername && state.hasPassword,
        text: state.text,
      });
      await fsPromises.mkdir(OUT_DIR, { recursive: true });
      await page.screenshot({ path: path.join(OUT_DIR, `${label}-${name}.png`), fullPage: false }).catch(() => {});
    }

    const loginPage = result.pages.find((p) => p.name === 'login');
    result.verdict = loginPage?.blocked ? 'BLOCKED'
      : loginPage?.loginFormPresent ? 'OK'
      : 'UNCLEAR';
    await page.close().catch(() => {});
  } catch (error) {
    result.verdict = 'ERROR';
    result.error = error.message.slice(0, 300);
  } finally {
    if (browser) await browser.disconnect().catch(() => {});
    if (launched) await launched.close().catch(() => {});
  }
  return result;
}

// Also check whether the registry API itself is reachable. If the API works but
// the website is challenged, that is a useful distinction: it means Cloudflare
// is gating the browser flow specifically, not the runner's whole network.
async function probeRegistry() {
  const out = {};
  try {
    const res = await fetch('https://registry.npmjs.org/gettodaysdate', { signal: AbortSignal.timeout(15000) });
    out.status = res.status;
    const body = await res.json();
    out.latest = body['dist-tags']?.latest ?? null;
  } catch (error) {
    out.error = error.message.slice(0, 200);
  }
  return out;
}

async function publishOutputs(summary) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  const login = summary.results.find((r) => r.label === 'headless-spoofed-ua')?.pages?.find((p) => p.name === 'login');
  const lines = [
    `verdict=${summary.productionVerdict}`,
    `verdict_default_ua=${summary.verdicts['headless-default-ua'] ?? 'ERROR'}`,
    `registry_status=${summary.registry.status ?? 'error'}`,
    `login_http=${login?.httpStatus ?? 'none'}`,
    `login_form=${login?.loginFormPresent ?? false}`,
  ];
  await fsPromises.appendFile(file, `${lines.join('\n')}\n`);
}

async function publishJobSummary(summary) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (!file) return;
  const rows = summary.results.flatMap((r) =>
    (r.pages ?? []).map((p) => `| ${r.label} | ${p.name} | ${p.httpStatus ?? '-'} | ${p.blocked ? 'blocked' : 'ok'} | ${p.loginFormPresent ?? '-'} |`));
  const md = [
    `## Cloudflare spike: ${summary.productionVerdict}`,
    '',
    `Runner egress reached the registry API with status \`${summary.registry.status ?? 'error'}\` (latest \`${summary.registry.latest ?? '?'}\`).`,
    '',
    '| config | page | http | state | login form |',
    '| --- | --- | --- | --- | --- |',
    ...rows,
    '',
  ].join('\n');
  await fsPromises.appendFile(file, md);
}

async function main() {
  await fsPromises.mkdir(OUT_DIR, { recursive: true });
  const meta = {
    at: new Date().toISOString(),
    ci: process.env.GITHUB_ACTIONS === 'true',
    runner: process.env.RUNNER_NAME ?? 'local',
    chromium: (spawnSync(EXECUTABLE, ['--version'], { encoding: 'utf8' }).stdout ?? '').trim(),
    node: process.version,
  };
  console.log('=== environment ===');
  console.log(JSON.stringify(meta, null, 2));

  console.log('\n=== registry API reachability ===');
  const registry = await probeRegistry();
  console.log(JSON.stringify(registry, null, 2));

  // Headless+spoofed UA is our production config, so it is listed first.
  const configs = [
    { label: 'headless-spoofed-ua', headless: true, spoofUA: true },
    { label: 'headless-default-ua', headless: true, spoofUA: false },
  ];

  const results = [];
  for (const config of configs) {
    console.log(`\n=== probe: ${config.label} ===`);
    const result = await probe(config);
    results.push(result);
    console.log(JSON.stringify(result, null, 2));
  }

  const production = results.find((r) => r.label === 'headless-spoofed-ua');
  const summary = {
    meta,
    registry,
    verdicts: Object.fromEntries(results.map((r) => [r.label, r.verdict])),
    productionVerdict: production?.verdict ?? 'ERROR',
    results,
  };
  await fsPromises.writeFile(path.join(OUT_DIR, 'spike-result.json'), `${JSON.stringify(summary, null, 2)}\n`);

  // Artifact and log downloads need a token, but step conclusions are readable
  // without one. Publish the verdict as a step output so the workflow can turn
  // it into pass/skip on named steps, making the result visible unauthenticated.
  await publishOutputs(summary);
  await publishJobSummary(summary);

  console.log('\n=== VERDICT ===');
  for (const [label, verdict] of Object.entries(summary.verdicts)) console.log(`${label}: ${verdict}`);
  console.log(`\nPRODUCTION CONFIG (headless + spoofed UA): ${summary.productionVerdict}`);
  if (summary.productionVerdict === 'OK') {
    console.log('Cloudflare is not blocking the runner. The Puppeteer publish flow is viable on GitHub Actions.');
  } else if (summary.productionVerdict === 'BLOCKED') {
    console.log('Cloudflare is challenging the runner IP. GitHub-hosted runners will not work; a self-hosted runner is required.');
  } else {
    console.log('Inconclusive - inspect spike-result.json and the screenshots.');
  }
}

main().catch((error) => {
  console.error('spike failed:', error);
  process.exit(1);
});
