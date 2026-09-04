// Deterministic release pipeline for the `gettodaysdate` package.
//
// Steps:
//   1. Rewrite source files (index.js, test.js, README.md) for the target date.
//   2. Bump package.json version.
//   3. Run the package test suite and verify the publish file list.
//   4. Ensure npm CLI auth (web login via browser WebAuthn shim if needed).
//   5. Run `npm publish` under a PTY, capture the CLI auth URL, answer its
//      "Press ENTER" prompt, and complete 2FA in Chromium with our P-256 key.
//   6. Verify the new version is live on the registry.
//
// Usage:
//   node release.mjs [--date=YYYY-MM-DD] [--release=patch|minor|major|X.Y.Z]
//                    [--dry-run] [--no-publish]
//                    [--reuse-browser] [--headed] [--keep-profile]
//
// Default: launch a fresh headless Chromium with a throwaway user-data-dir and
// tear it down afterwards, so no browser state carries between releases.
//
// A fresh profile is signed out, and npm's CLI escalation can only escalate a
// signed-in browser session, so the run performs a browser login first. That
// step is verified by requiring a real WebAuthn assertion (npm whoami cannot be
// trusted here: a stale-but-valid CLI token makes it pass regardless).
// Cloudflare sometimes challenges a cold profile, so login is retried.
//
// Paths are env-overridable so the same script runs from a local checkout and
// from CI, where the key material lives in a temp dir written from a secret:
//   NPM_PACKAGE_DIR  directory containing the package.json to publish
//   NPM_KEY_DIR      directory containing private.pem for the P-256 credential
//   NPM_RUN_DIR      scratch directory for the PTY log, FIFO and auth trace
//   NPM_CREDENTIAL_ID  base64url credential id registered with npm
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import puppeteer from 'puppeteer-core';
import { ensureChromium, launchEphemeral } from './chromium.mjs';
import { installShim, loadSigner, shimInstalled } from './webauthn-shim.mjs';

const ROOT = path.dirname(new URL(import.meta.url).pathname);
// This script lives in <package>/.release, so the package is its parent.
const PACKAGE_DIR = process.env.NPM_PACKAGE_DIR ?? path.dirname(ROOT);
const PACKAGE_NAME = 'gettodaysdate';
const KEY_DIR = process.env.NPM_KEY_DIR ?? path.join(ROOT, 'keys');
const CREDENTIAL_ID = process.env.NPM_CREDENTIAL_ID ?? 'FQRIOkxGu8zgBLJfZX3hywy3828CZsMtpR60vzbJx8w';
const RUN_DIR = process.env.NPM_RUN_DIR ?? path.join(ROOT, 'run');
const EXPECTED_FILES = ['LICENSE', 'README.md', 'index.js', 'package.json'];
const STEP_TIMEOUT_MS = 15000;
const AUTH_ATTEMPTS = 3;
// npm's auth pages are React apps that fetch their escalation context after
// first paint. Clicking the instant a control appears raced that: the Sept 2
// failure signed an assertion and was then bounced to the homepage. Pause
// between browser steps so the page is actually ready, with jitter so we are not
// in lockstep with any rate limiter.
const SETTLE_MIN_MS = 3000;
const SETTLE_MAX_MS = 5000;
// Generous, because the settle pauses above are deliberate spend.
const PAGE_DEADLINE_MS = STEP_TIMEOUT_MS * 8;
const PUBLISH_2FA_ATTEMPTS = 2;
const PUBLISH_OK = /\+\s*\S+@\d+\.\d+\.\d+/;

const args = process.argv.slice(2);
const flag = (name) => args.some((a) => a === `--${name}`);
const value = (name, fallback) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};

const TODAY = new Date().toISOString().slice(0, 10);
const DATE = value('date', TODAY);
const RELEASE = value('release', 'patch');
const DRY_RUN = flag('dry-run');
const NO_PUBLISH = flag('no-publish') || DRY_RUN;
const HEADLESS = !flag('headed');
const REUSE_BROWSER = flag('reuse-browser');
const KEEP_PROFILE = flag('keep-profile');

if (!/^\d{4}-\d{2}-\d{2}$/.test(DATE)) throw new Error(`--date must be YYYY-MM-DD, got "${DATE}"`);
if (!/^(patch|minor|major|\d+\.\d+\.\d+)$/.test(RELEASE)) throw new Error(`--release must be patch|minor|major|X.Y.Z, got "${RELEASE}"`);

// --------------------------------------------------------------- observability

// Everything here exists because CI failures are only debuggable after the fact:
// the browser is gone, the runner is gone, and a one-line error message is not
// enough to tell "npm rejected us" from "the page never rendered".
const RUN_STARTED = Date.now();
const runEvents = [];
const authCalls = [];
let shotSeq = 0;

const log = (step, detail) => {
  runEvents.push({ at: new Date().toISOString(), ms: Date.now() - RUN_STARTED, step, detail });
  console.log(`[${step}] ${detail}`);
};
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// Deliberate pause between browser interactions. Reported so the logs explain
// where wall-clock time went.
async function settle(why) {
  const ms = SETTLE_MIN_MS + Math.floor(Math.random() * (SETTLE_MAX_MS - SETTLE_MIN_MS + 1));
  log('settle', `${(ms / 1000).toFixed(1)}s — ${why}`);
  await sleep(ms);
}

// Screenshots are the only way to see what the headless browser actually showed.
// Failures are silent otherwise: a redirect to the homepage and a rejected
// assertion look identical in the text trace.
async function capture(page, label) {
  shotSeq += 1;
  const name = `${String(shotSeq).padStart(2, '0')}-${label.replace(/[^a-z0-9]+/gi, '-').toLowerCase().slice(0, 40)}.png`;
  try {
    await fsPromises.mkdir(RUN_DIR, { recursive: true });
    await page.screenshot({ path: path.join(RUN_DIR, name) });
    return name;
  } catch {
    return null;
  }
}

async function flushDiagnostics(outcome) {
  try {
    await fsPromises.mkdir(RUN_DIR, { recursive: true });
    await fsPromises.writeFile(
      path.join(RUN_DIR, 'auth-trace.json'),
      `${JSON.stringify({ calls: authCalls }, null, 2)}\n`,
    );
    await fsPromises.writeFile(
      path.join(RUN_DIR, 'run-summary.json'),
      `${JSON.stringify({
        startedAt: new Date(RUN_STARTED).toISOString(),
        durationMs: Date.now() - RUN_STARTED,
        outcome,
        events: runEvents,
      }, null, 2)}\n`,
    );
  } catch { /* diagnostics must never mask the real error */ }
}

// Surfaces the outcome on the workflow run page, so a failure does not require
// downloading an artifact to understand.
async function writeStepSummary(outcome) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (!file) return;
  const rows = runEvents.map((e) => `| ${(e.ms / 1000).toFixed(1)}s | ${e.step} | ${e.detail.replace(/\|/g, '\\|').slice(0, 160)} |`);
  const body = [
    `## Release ${outcome.ok ? 'succeeded' : 'failed'}`,
    '',
    outcome.ok ? '' : `**${outcome.error}**`,
    '',
    '| t | step | detail |',
    '| --- | --- | --- |',
    ...rows,
    '',
  ].join('\n');
  await fsPromises.appendFile(file, body).catch(() => {});
}

// ---------------------------------------------------------------- source files

const indexSource = (date) => `'use strict';

function getTodaysDate() {
  return '${date}';
}

module.exports = { getTodaysDate };
`;

const testSource = (date) => `'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getTodaysDate } = require('./index.js');

test('getTodaysDate returns the fixed ISO date', () => {
  assert.equal(getTodaysDate(), '${date}');
});
`;

const readmeSource = (date) => `# ${PACKAGE_NAME}

Returns a fixed ISO date.

\`\`\`js
const { getTodaysDate } = require('${PACKAGE_NAME}');

getTodaysDate(); // '${date}'
\`\`\`

## License

WTFPL
`;

// The README is hand-maintained (badges, prose), so it is NOT regenerated from
// the template when one already exists: only the example date is rewritten in
// place. Regenerating would silently delete everything the template does not
// know about. The template is a fallback for a fresh checkout.
function updateReadme(existing, date) {
  const pattern = /getTodaysDate\(\);\s*\/\/\s*'(\d{4}-\d{2}-\d{2})'/;
  const match = existing.match(pattern);
  if (!match) {
    throw new Error("README.md has no \"getTodaysDate(); // 'YYYY-MM-DD'\" line to update; refusing to overwrite it");
  }
  if (match[1] === date) return { content: existing, changed: false };
  return { content: existing.replace(pattern, `getTodaysDate(); // '${date}'`), changed: true };
}

async function writeSources(date) {
  const written = [];
  for (const [name, content] of Object.entries({
    'index.js': indexSource(date),
    'test.js': testSource(date),
  })) {
    await fsPromises.writeFile(path.join(PACKAGE_DIR, name), content);
    written.push(name);
  }

  const readmePath = path.join(PACKAGE_DIR, 'README.md');
  const existing = await fsPromises.readFile(readmePath, 'utf8').catch(() => null);
  if (existing === null) {
    await fsPromises.writeFile(readmePath, readmeSource(date));
    written.push('README.md (created from template)');
  } else {
    const { content, changed } = updateReadme(existing, date);
    if (changed) await fsPromises.writeFile(readmePath, content);
    written.push(changed ? 'README.md (date updated in place)' : 'README.md (already current)');
  }
  return written;
}

function nextVersion(current, release) {
  if (/^\d+\.\d+\.\d+$/.test(release)) return release;
  const [major, minor, patch] = current.split('.').map(Number);
  if (release === 'major') return `${major + 1}.0.0`;
  if (release === 'minor') return `${major}.${minor + 1}.0`;
  return `${major}.${minor}.${patch + 1}`;
}

async function bumpVersion(release) {
  const manifestPath = path.join(PACKAGE_DIR, 'package.json');
  const raw = await fsPromises.readFile(manifestPath, 'utf8');
  const manifest = JSON.parse(raw);
  const from = manifest.version;

  // Idempotency: if the local version was prepared but never landed on the
  // registry (e.g. a previous run failed at the 2FA step), reuse it instead of
  // burning another version number.
  if (!isPublished(from)) return { from, to: from, reused: true };

  // The registry is the source of truth, not package.json. A run that published
  // but failed afterwards (before its bump commit landed) leaves the checkout
  // behind the registry, and a plain bump would then target a version that
  // already exists and fail with E403. Walk forward until the target is free.
  let to = nextVersion(from, release);
  const skipped = [];
  for (let guard = 0; isPublished(to) && guard < 50; guard += 1) {
    skipped.push(to);
    to = nextVersion(to, release);
  }
  if (isPublished(to)) throw new Error(`Could not find an unpublished version after ${from}`);

  manifest.version = to;
  await fsPromises.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { from, to, reused: false, skipped };
}

function isPublished(version) {
  const view = runNpm(['view', `${PACKAGE_NAME}@${version}`, 'version'], { cwd: PACKAGE_DIR });
  return view.status === 0 && view.stdout.trim() === version;
}

// ------------------------------------------------------------------ npm checks

function runNpm(npmArgs, { cwd = PACKAGE_DIR, timeout = STEP_TIMEOUT_MS * 2 } = {}) {
  const result = spawnSync('npm', npmArgs, { cwd, encoding: 'utf8', timeout, env: process.env });
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function verifyPackList() {
  const result = runNpm(['pack', '--dry-run', '--json']);
  if (result.status !== 0) throw new Error(`npm pack --dry-run failed:\n${result.stderr}`);
  const parsed = JSON.parse(result.stdout);
  const files = parsed[0].files.map((f) => f.path).sort();
  const expected = [...EXPECTED_FILES].sort();
  if (JSON.stringify(files) !== JSON.stringify(expected)) {
    throw new Error(`Unexpected publish file list.\n  got:      ${files.join(', ')}\n  expected: ${expected.join(', ')}`);
  }
  return files;
}

// ----------------------------------------------------------- browser 2FA drive

// Drives an npm auth page to completion. Handles both shapes we see:
//   - /login?next=... which asks for username+password, then the security key
//   - /auth/cli/<uuid> which (when already signed in) goes straight to the key
// Signing in here also warms the browser profile for later publishes.
async function driveAuthPage(authUrl, { endpoint, signer, keepOpen = false, label = 'auth' }) {
  const username = process.env.NPM_USERNAME;
  const password = process.env.NPM_PASSWORD;
  const browser = await puppeteer.connect({ browserURL: endpoint });
  let page;
  let done = false;
  const trace = [];
  const shots = [];
  const call = { label, authUrl: authUrl.replace(/[0-9a-f-]{36}/, '<session>'), startedAt: new Date().toISOString(), trace, shots };
  authCalls.push(call);
  const record = (entry) => {
    const last = trace.at(-1);
    if (!last || last.url !== entry.url || last.text !== entry.text) trace.push(entry);
  };
  const shoot = async (why) => {
    const name = await capture(page, `${label}-${why}`);
    if (name) shots.push({ name, why, at: new Date().toISOString() });
  };
  const release = async () => {
    if (page && !keepOpen) await page.close().catch(() => {});
    await browser.disconnect();
  };
  const result = async (fields) => {
    call.outcome = fields.ok ? 'ok' : (fields.reason ?? 'failed');
    call.finishedAt = new Date().toISOString();
    call.final = fields.final ?? null;
    await flushDiagnostics({ ok: false, error: 'in progress' });
    return { ...fields, cleanup: release };
  };
  try {
    page = await browser.newPage();
    // A realistic viewport: npm's layout is responsive and the security key
    // button can land off-screen in a tiny default window.
    await page.setViewport({ width: 1280, height: 900 });
    await page.goto('about:blank');
    if (!(await installShim(page, signer))) throw new Error('WebAuthn shim failed to install on about:blank');
    await page.goto(authUrl, { waitUntil: 'networkidle2', timeout: STEP_TIMEOUT_MS * 2 });
    if (!(await shimInstalled(page))) throw new Error('WebAuthn shim missing after navigation');
    await settle('page loaded; letting npm\'s app finish hydrating');
    await shoot('loaded');

    let clicked = false;
    let submittedLogin = false;
    const deadline = Date.now() + PAGE_DEADLINE_MS;
    while (Date.now() < deadline) {
      const state = await page.evaluate(() => {
        const has = (sel) => document.querySelector(sel);
        const controls = [...document.querySelectorAll('button, a')].map((c) => c.textContent?.trim() ?? '');
        return {
          url: location.href,
          needsLogin: !!has('input[name="username"], input[type="email"]') && !!has('input[name="password"], input[type="password"]'),
          hasKeyButton: controls.some((t) => /use security key/i.test(t)),
          text: document.body.innerText.replace(/\s+/g, ' ').slice(0, 300),
        };
      });

      record({
        url: state.url,
        text: state.text.replace(/^.*Learn how to prepare \u2192 \u00d7 /, '').slice(0, 160),
        hasKeyButton: state.hasKeyButton,
        needsLogin: state.needsLogin,
        clicked,
        at: new Date().toISOString(),
      });

      if (/Authentication Successful|You can close this tab|authorized/i.test(state.text)) {
        await shoot('authenticated');
        // Do NOT navigate or close here. npm finishes the handshake from this
        // page (it redirects to /auth/cli/<uuid>, which is what releases the
        // waiting CLI). Touching the page at this moment aborts that step.
        const settled = await observeCliHandshake(page, record);
        done = true;
        return result({ ok: true, clicked, settled, final: await snapshot(page) });
      }
      if (/Just a moment|Performing security verification|Verifying you are human/i.test(state.text)) {
        // Cloudflare interstitials can clear on their own; wait rather than
        // burning the whole attempt immediately.
        await shoot('cloudflare');
        log('page', 'Cloudflare interstitial; waiting for it to clear');
        await settle('Cloudflare challenge in progress');
        continue;
      }
      if (/Something went wrong/i.test(state.text) && clicked) {
        await shoot('rejected');
        return result({ ok: false, reason: 'npm rejected the assertion', final: await snapshot(page) });
      }
      // Bounced to the homepage or dashboard after clicking: npm dropped the
      // escalation context. Distinguishing this from a timeout matters, because
      // the fix is a retry with a fresh session, not more waiting.
      if (clicked && /^https:\/\/www\.npmjs\.com\/?$/.test(state.url)) {
        await shoot('bounced-home');
        return result({ ok: false, reason: 'npm redirected to the homepage instead of completing the handshake', final: await snapshot(page) });
      }
      if (state.needsLogin) {
        if (submittedLogin) {
          await shoot('reprompted');
          return result({ ok: false, reason: 'npm re-prompted for credentials (wrong password or rate limited)', final: await snapshot(page) });
        }
        if (!username || !password) {
          throw new Error('Browser session is signed out; set NPM_USERNAME and NPM_PASSWORD');
        }
        log('page', 'submitting credentials');
        await (await page.$('input[name="username"], input[type="email"]')).type(username, { delay: 40 });
        await settle('between username and password');
        await (await page.$('input[name="password"], input[type="password"]')).type(password, { delay: 40 });
        await settle('before submitting the login form');
        await page.click('button[type="submit"]');
        submittedLogin = true;
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: STEP_TIMEOUT_MS }).catch(() => {});
        await settle('after login submit; waiting for the 2FA step');
        await shoot('after-login');
        continue;
      }
      if (state.hasKeyButton && !clicked) {
        // The click triggers navigator.credentials.get. If npm has not finished
        // wiring up its escalation context, the assertion is signed and then
        // discarded, which is exactly the Sept 2 failure.
        await settle('security key button present; letting the page settle before clicking');
        clicked = await page.evaluate(() => {
          const target = [...document.querySelectorAll('button, a')].find((c) => /use security key/i.test(c.textContent?.trim() ?? ''));
          if (!target) return false;
          target.click();
          return true;
        });
        log('page', `clicked "Use security key" (${clicked ? 'ok' : 'button vanished'})`);
        await shoot('clicked-key');
        continue;
      }
      await sleep(500);
    }
    await shoot('timeout');
    return result({ ok: false, reason: 'timed out waiting for npm confirmation', clicked, final: await snapshot(page) });
  } finally {
    // On success with keepOpen the caller closes via cleanup(); otherwise tidy up now.
    if (!(done && keepOpen)) await release();
  }
}

async function snapshot(page) {
  return {
    url: page.url(),
    title: await page.title(),
    text: (await page.evaluate(() => document.body.innerText)).replace(/\s+/g, ' ').slice(0, 400),
  };
}

// After a successful assertion npm redirects the page to /auth/cli/<uuid>,
// which is what notifies the waiting CLI. We only watch; navigating or closing
// the tab during this window breaks the handshake.
async function observeCliHandshake(page, record) {
  // Longer than the old 15s: the redirect is npm's server-side step and the
  // publish depends on it, so waiting is strictly better than proceeding.
  const deadline = Date.now() + STEP_TIMEOUT_MS * 3;
  while (Date.now() < deadline) {
    const url = page.url();
    if (/\/(auth|login)\/cli\//.test(url)) {
      record({ url, text: 'landed on CLI session page', at: new Date().toISOString() });
      return true;
    }
    await sleep(300);
  }
  record({ url: page.url(), text: 'no CLI redirect observed', at: new Date().toISOString() });
  return false;
}

// ------------------------------------------------------------------- npm login

// Establishes both halves of auth: a usable CLI token and a signed-in browser
// session. `requireBrowserSession` forces the web-login flow even when a CLI
// token already works, because a fresh browser profile has no npm cookie.
async function ensureLoggedIn({ endpoint, signer, requireBrowserSession = false }) {
  const who = runNpm(['whoami'], { cwd: ROOT });
  if (who.status === 0 && !requireBrowserSession) {
    const username = who.stdout.trim();
    log('auth', `already logged in as ${username}`);
    return username;
  }
  log('auth', requireBrowserSession
    ? 'fresh browser profile: running web login to establish a browser session'
    : 'npm CLI token missing or rejected; starting web login');

  for (let attempt = 1; attempt <= AUTH_ATTEMPTS; attempt += 1) {
    const before = signer.signCounts.length;
    const child = spawn('npm', ['login', '--auth-type=web', '--browser=false'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, BROWSER: 'true' } });
    let output = '';
    let authUrl;
    const collect = (chunk) => {
      output += chunk.toString();
      const match = output.match(/https:\/\/www\.npmjs\.com\/(?:login\?next=\S+|login\/cli\/[A-Za-z0-9-]+)/);
      if (match && !authUrl) authUrl = match[0];
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);

    const urlDeadline = Date.now() + STEP_TIMEOUT_MS;
    while (!authUrl && Date.now() < urlDeadline) await sleep(150);
    if (!authUrl) {
      child.kill('SIGTERM');
      throw new Error(`npm login did not print an auth URL.\n${output}`);
    }
    log('auth', `login URL: ${authUrl}`);

    const result = await driveAuthPage(authUrl, { endpoint, signer, label: `login-${attempt}` });
    const exitDeadline = Date.now() + STEP_TIMEOUT_MS * 2;
    while (child.exitCode === null && child.signalCode === null && Date.now() < exitDeadline) await sleep(250);
    if (child.exitCode !== 0) child.kill('SIGTERM');

    // Let the CLI finish writing ~/.npmrc before asking whoami; on a loaded
    // runner the token write can lag the browser handshake.
    await settle('letting the npm CLI persist its token');

    // A signed assertion is the only proof the browser session was escalated;
    // whoami would also pass on a pre-existing token.
    const signedAssertion = signer.signCounts.length > before;
    const after = runNpm(['whoami'], { cwd: ROOT });
    if (after.status === 0 && (signedAssertion || !requireBrowserSession)) {
      const username = after.stdout.trim();
      log('auth', `logged in as ${username}${signedAssertion ? ` (signCount ${signer.signCounts.at(-1)})` : ''}`);
      return username;
    }
    const why = result.reason ?? (signedAssertion ? 'unknown' : 'no assertion signed (login page never reached the security key step)');
    log('auth', `attempt ${attempt} failed: ${why}`);
    if (attempt < AUTH_ATTEMPTS) {
      // Escalating backoff: a rate limiter or a Cloudflare reputation check
      // needs more than a fixed pause to forget about us.
      const backoff = 15000 * attempt;
      log('auth', `backing off ${backoff / 1000}s before retry (Cloudflare challenges cold profiles)`);
      await sleep(backoff);
    }
  }
  throw new Error('Unable to establish an authenticated browser session after retries');
}

// The npm CLI writes the token itself once the browser authorizes the session.

// --------------------------------------------------------------- publish (PTY)

// `npm publish --auth-type=web` prints the CLI auth URL only on a TTY and then
// blocks on "Press ENTER to open in the browser...". We give it a PTY via
// script(1) and feed ENTER through a FIFO once we have captured the URL.
async function publishWithBrowserAuth({ endpoint, signer, attemptLabel = '1' }) {
  await fsPromises.mkdir(RUN_DIR, { recursive: true });
  const logPath = path.join(RUN_DIR, 'publish-tty.log');
  const fifoPath = path.join(RUN_DIR, 'publish-stdin.fifo');
  for (const file of [logPath, fifoPath]) await fsPromises.rm(file, { force: true });
  const mkfifo = spawnSync('mkfifo', [fifoPath]);
  if (mkfifo.status !== 0) throw new Error('mkfifo failed; a POSIX FIFO is required to answer npm\'s ENTER prompt');

  // O_RDWR keeps the FIFO open without blocking and lets us write the newline.
  const fifoFd = fs.openSync(fifoPath, fs.constants.O_RDWR);
  // --browser=false stops npm from launching the system default browser
  // (Firefox here), which has no shim and would race us for the auth session.
  // npm prints the URL and waits instead.
  const child = spawn('script', ['-qfe', '-c', 'npm publish --auth-type=web --browser=false', logPath], {
    cwd: PACKAGE_DIR,
    stdio: [fifoFd, 'ignore', 'ignore'],
    env: { ...process.env, BROWSER: 'true' },
  });

  const readLog = () => {
    try {
      return fs.readFileSync(logPath, 'utf8');
    } catch {
      return '';
    }
  };
  const clean = (text) => text.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').replace(/[\x00-\x08\x0b-\x1f]/g, '');

  try {
    let authUrl;
    const urlDeadline = Date.now() + STEP_TIMEOUT_MS * 2;
    while (!authUrl && Date.now() < urlDeadline) {
      await sleep(200);
      const match = readLog().match(/https:\/\/www\.npmjs\.com\/auth\/cli\/[A-Za-z0-9-]+/);
      if (match) authUrl = match[0];
      // Publish can also finish or fail without asking for auth.
      if (!authUrl && (child.exitCode !== null || child.signalCode !== null)) break;
    }
    const logText = clean(readLog());
    if (!authUrl) {
      if (PUBLISH_OK.test(logText)) return { published: true, usedBrowserAuth: false, tail: logText.slice(-600) };
      throw new Error(`npm publish did not request browser auth.\n${logText.slice(-800)}`);
    }
    log('publish', `auth URL: ${authUrl}`);

    fs.writeSync(fifoFd, '\n'); // answer "Press ENTER to open in the browser..."
    // npm needs a moment to register the session server-side before the page is
    // driven; navigating too early can land on a session that is not ready.
    await settle('CLI session opened; letting npm register it before driving the page');
    const auth = await driveAuthPage(authUrl, { endpoint, signer, keepOpen: true, label: `publish-2fa-${attemptLabel}` });
    log('publish', `2FA ${auth.ok ? 'succeeded' : 'failed'} (clicked=${auth.clicked}, landed=${auth.settled ?? false}, signCount=${signer.signCounts.at(-1)})`);
    if (!auth.ok) {
      await auth.cleanup?.();
      throw new Error(`Browser 2FA failed: ${auth.reason}\n${auth.final?.text ?? ''}`);
    }

    // Wait for npm to finish uploading; poll the log for its success marker.
    const exitDeadline = Date.now() + STEP_TIMEOUT_MS * 6;
    let finalLog = '';
    while (Date.now() < exitDeadline) {
      finalLog = clean(readLog());
      if (PUBLISH_OK.test(finalLog) || /npm error/.test(finalLog)) break;
      if (child.exitCode !== null || child.signalCode !== null) break;
      await sleep(500);
    }
    await auth.cleanup?.();
    finalLog = clean(readLog());
    if (/npm error/.test(finalLog)) throw new Error(`npm publish reported an error.\n${finalLog.slice(-800)}`);
    return { published: PUBLISH_OK.test(finalLog), usedBrowserAuth: true, tail: finalLog.slice(-600) };
  } finally {
    fs.closeSync(fifoFd);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    await fsPromises.rm(fifoPath, { force: true });
  }
}

// The 2FA page is the flakiest step in the pipeline (npm bounced us to the
// homepage on Sept 2 after a perfectly good assertion), and a failure there
// leaves nothing published, so it is safe to retry the whole publish. Guarded by
// a registry check: if a previous attempt actually landed, stop rather than
// retrying into an E403.
async function publishWithRetries({ endpoint, signer, version }) {
  let lastError;
  for (let attempt = 1; attempt <= PUBLISH_2FA_ATTEMPTS; attempt += 1) {
    try {
      return await publishWithBrowserAuth({ endpoint, signer, attemptLabel: String(attempt) });
    } catch (error) {
      lastError = error;
      log('publish', `attempt ${attempt} failed: ${error.message.split('\n')[0]}`);
      if (isPublished(version)) {
        log('publish', `${version} is on the registry despite the error; treating as published`);
        return { published: true, usedBrowserAuth: true, tail: 'recovered: registry already serves this version' };
      }
      // A rejected assertion or a taken version will not fix itself.
      if (/rejected the assertion|cannot publish over|E403|EPRIVATE/i.test(error.message)) throw error;
      if (attempt < PUBLISH_2FA_ATTEMPTS) {
        log('publish', 'retrying publish with a fresh CLI session');
        await sleep(15000);
      }
    }
  }
  throw lastError;
}

// ------------------------------------------------------------------------ main

async function main() {
  log('plan', `date=${DATE} release=${RELEASE} publish=${!NO_PUBLISH} headless=${HEADLESS} browser=${REUSE_BROWSER ? 'reuse-or-launch' : 'ephemeral'}`);

  const written = await writeSources(DATE);
  log('source', `wrote ${written.join(', ')} with date ${DATE}`);

  const { from, to, reused, skipped } = await bumpVersion(RELEASE);
  log('version', reused ? `${to} (reused; not yet on registry)` : `${from} -> ${to}`);
  if (skipped?.length) {
    log('version', `skipped ${skipped.join(', ')}: already on the registry (checkout was behind)`);
  }

  const test = runNpm(['test']);
  if (test.status !== 0) throw new Error(`Tests failed:\n${test.stdout}\n${test.stderr}`);
  log('test', 'package tests pass');

  const files = verifyPackList();
  log('pack', `publish set: ${files.join(', ')}`);

  if (NO_PUBLISH) {
    log('done', `${DRY_RUN ? 'dry run' : 'publish skipped'}; ${PACKAGE_NAME}@${to} prepared locally`);
    return;
  }

  // An ephemeral browser starts signed out, so credentials are needed to
  // establish the session during CLI authorization.
  if (!REUSE_BROWSER && (!process.env.NPM_USERNAME || !process.env.NPM_PASSWORD)) {
    throw new Error('An ephemeral browser starts signed out; set NPM_USERNAME and NPM_PASSWORD');
  }

  const chromium = REUSE_BROWSER
    ? await ensureChromium({ headless: HEADLESS })
    : await launchEphemeral({ headless: HEADLESS, keepProfile: KEEP_PROFILE });
  const describeBrowser = REUSE_BROWSER
    ? `${chromium.endpoint} ${chromium.launched ? '(launched)' : '(reused)'}`
    : `${chromium.endpoint} (ephemeral, ${HEADLESS ? 'headless' : 'headed'}, profile ${chromium.profile})`;
  log('browser', `CDP ${describeBrowser}`);

  try {
    const signer = await loadSigner({ keyDir: KEY_DIR, credentialId: CREDENTIAL_ID });
    if (signer.keyType !== 'ec') {
      throw new Error(`npm only accepts P-256/ES256 assertions; key in ${KEY_DIR} is ${signer.keyType}`);
    }
    log('key', `P-256 credential ${signer.credentialIdText.slice(0, 12)}... ready`);

    const username = await ensureLoggedIn({ endpoint: chromium.endpoint, signer, requireBrowserSession: !REUSE_BROWSER });
    log('auth', `authenticated as ${username}`);

    const result = await publishWithRetries({ endpoint: chromium.endpoint, signer, version: to });
    if (!result.published) throw new Error(`Publish did not confirm.\n${result.tail}`);
    log('publish', `npm reported + ${PACKAGE_NAME}@${to}`);

    // Registry read-after-write can lag briefly.
    let live;
    const verifyDeadline = Date.now() + STEP_TIMEOUT_MS * 2;
    while (Date.now() < verifyDeadline) {
      const view = runNpm(['view', `${PACKAGE_NAME}@${to}`, 'version'], { cwd: ROOT });
      if (view.status === 0 && view.stdout.trim() === to) {
        live = view.stdout.trim();
        break;
      }
      await sleep(1500);
    }
    if (!live) throw new Error(`Published but registry has not served ${PACKAGE_NAME}@${to} yet`);
    log('verify', `registry serves ${PACKAGE_NAME}@${live}`);
    log('done', `released ${PACKAGE_NAME}@${live} returning ${DATE} (signCounts: ${signer.signCounts.join(', ')})`);
  } finally {
    if (chromium.close) {
      const { profileRemoved, warning } = await chromium.close();
      log('browser', `ephemeral Chromium closed${profileRemoved ? '' : ` (profile retained: ${warning ?? chromium.profile})`}`);
    }
  }
}

let exitCode = 0;
let outcome = { ok: true };
try {
  await main();
} catch (error) {
  exitCode = 1;
  outcome = { ok: false, error: error.message };
  log('error', error.message.split('\n')[0]);
  console.error(`\n[error] ${error.message}`);
}
// Diagnostics are written on both paths: a failed run is exactly when they are
// needed, and the browser is already gone by the time anyone reads the log.
await flushDiagnostics(outcome);
await writeStepSummary(outcome);
if (runEvents.some((e) => e.step === 'settle')) {
  const settleMs = runEvents.filter((e) => e.step === 'settle').length;
  log('timing', `total ${(Date.now() - RUN_STARTED) / 1000}s across ${runEvents.length} steps (${settleMs} deliberate pauses)`);
}
process.exit(exitCode);
