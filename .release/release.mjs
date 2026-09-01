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

const log = (step, detail) => console.log(`[${step}] ${detail}`);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

async function writeSources(date) {
  const files = {
    'index.js': indexSource(date),
    'test.js': testSource(date),
    'README.md': readmeSource(date),
  };
  for (const [name, content] of Object.entries(files)) {
    await fsPromises.writeFile(path.join(PACKAGE_DIR, name), content);
  }
  return Object.keys(files);
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

  const to = nextVersion(from, release);
  manifest.version = to;
  await fsPromises.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { from, to, reused: false };
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
async function driveAuthPage(authUrl, { endpoint, signer, keepOpen = false }) {
  const username = process.env.NPM_USERNAME;
  const password = process.env.NPM_PASSWORD;
  const browser = await puppeteer.connect({ browserURL: endpoint });
  let page;
  let done = false;
  const trace = [];
  const record = (entry) => {
    const last = trace.at(-1);
    if (!last || last.url !== entry.url || last.text !== entry.text) trace.push(entry);
  };
  const release = async () => {
    if (page && !keepOpen) await page.close().catch(() => {});
    await browser.disconnect();
  };
  const result = async (fields) => {
    await fsPromises.mkdir(RUN_DIR, { recursive: true });
    await fsPromises.writeFile(path.join(RUN_DIR, 'auth-trace.json'), `${JSON.stringify({ authUrl, trace }, null, 2)}\n`);
    return { ...fields, cleanup: release };
  };
  try {
    page = await browser.newPage();
    await page.goto('about:blank');
    if (!(await installShim(page, signer))) throw new Error('WebAuthn shim failed to install on about:blank');
    await page.goto(authUrl, { waitUntil: 'networkidle2', timeout: STEP_TIMEOUT_MS * 2 });
    if (!(await shimInstalled(page))) throw new Error('WebAuthn shim missing after navigation');

    let clicked = false;
    let submittedLogin = false;
    const deadline = Date.now() + STEP_TIMEOUT_MS * 4;
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


      record({ url: state.url, text: state.text.slice(0, 160), hasKeyButton: state.hasKeyButton, needsLogin: state.needsLogin, at: new Date().toISOString() });

      if (/Authentication Successful|You can close this tab|authorized/i.test(state.text)) {
        // Do NOT navigate or close here. npm finishes the handshake from this
        // page (it redirects to /auth/cli/<uuid>, which is what releases the
        // waiting CLI). Touching the page at this moment aborts that step.
        const settled = await observeCliHandshake(page, record);
        done = true;
        return result({ ok: true, clicked, settled, final: await snapshot(page) });
      }
      if (/Just a moment/i.test(state.text)) {
        return result({ ok: false, reason: 'Cloudflare throttled the request', final: await snapshot(page) });
      }
      if (/Something went wrong/i.test(state.text) && clicked) {
        return result({ ok: false, reason: 'npm rejected the assertion', final: await snapshot(page) });
      }
      if (state.needsLogin) {
        if (submittedLogin) {
          return result({ ok: false, reason: 'npm re-prompted for credentials (wrong password or rate limited)', final: await snapshot(page) });
        }
        if (!username || !password) {
          throw new Error('Browser session is signed out; set NPM_USERNAME and NPM_PASSWORD');
        }
        await (await page.$('input[name="username"], input[type="email"]')).type(username);
        await (await page.$('input[name="password"], input[type="password"]')).type(password);
        await page.click('button[type="submit"]');
        submittedLogin = true;
        await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: STEP_TIMEOUT_MS }).catch(() => {});
        continue;
      }
      if (state.hasKeyButton && !clicked) {
        clicked = await page.evaluate(() => {
          const target = [...document.querySelectorAll('button, a')].find((c) => /use security key/i.test(c.textContent?.trim() ?? ''));
          if (!target) return false;
          target.click();
          return true;
        });
        continue;
      }
      await sleep(500);
    }
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
  const deadline = Date.now() + STEP_TIMEOUT_MS;
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

    const result = await driveAuthPage(authUrl, { endpoint, signer });
    const exitDeadline = Date.now() + STEP_TIMEOUT_MS * 2;
    while (child.exitCode === null && child.signalCode === null && Date.now() < exitDeadline) await sleep(250);
    if (child.exitCode !== 0) child.kill('SIGTERM');

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
      log('auth', 'backing off before retry (Cloudflare challenges cold profiles)');
      await sleep(15000);
    }
  }
  throw new Error('Unable to establish an authenticated browser session after retries');
}

// The npm CLI writes the token itself once the browser authorizes the session.

// --------------------------------------------------------------- publish (PTY)

// `npm publish --auth-type=web` prints the CLI auth URL only on a TTY and then
// blocks on "Press ENTER to open in the browser...". We give it a PTY via
// script(1) and feed ENTER through a FIFO once we have captured the URL.
async function publishWithBrowserAuth({ endpoint, signer }) {
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
    const auth = await driveAuthPage(authUrl, { endpoint, signer, keepOpen: true });
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

// ------------------------------------------------------------------------ main

async function main() {
  log('plan', `date=${DATE} release=${RELEASE} publish=${!NO_PUBLISH} headless=${HEADLESS} browser=${REUSE_BROWSER ? 'reuse-or-launch' : 'ephemeral'}`);

  const written = await writeSources(DATE);
  log('source', `wrote ${written.join(', ')} with date ${DATE}`);

  const { from, to, reused } = await bumpVersion(RELEASE);
  log('version', reused ? `${to} (reused; not yet on registry)` : `${from} -> ${to}`);

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

    const result = await publishWithBrowserAuth({ endpoint: chromium.endpoint, signer });
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
      await chromium.close();
      log('browser', `ephemeral Chromium closed${KEEP_PROFILE ? ` (profile kept at ${chromium.profile})` : ''}`);
    }
  }
}

let exitCode = 0;
try {
  await main();
} catch (error) {
  exitCode = 1;
  console.error(`\n[error] ${error.message}`);
}
process.exit(exitCode);
