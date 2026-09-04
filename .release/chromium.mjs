// Chromium lifecycle helpers for CDP-driven automation.
//
// Two modes:
//   ensureChromium()   - reuse an already-running browser, else launch one.
//   launchEphemeral()  - always launch a private, disposable instance on its own
//                        port and profile; caller closes it when done.
import { spawn, spawnSync } from 'node:child_process';
import fsPromises from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const ROOT = path.dirname(new URL(import.meta.url).pathname);

export const CDP_PORT = Number(process.env.CHROMIUM_PORT ?? 9222);
export const CDP_ENDPOINT = process.env.BROWSER_ENDPOINT ?? `http://127.0.0.1:${CDP_PORT}`;
const EXECUTABLE = process.env.CHROMIUM_PATH ?? '/usr/bin/chromium';

export async function cdpAlive(endpoint = CDP_ENDPOINT, timeoutMs = 1500) {
  try {
    const response = await fetch(`${endpoint}/json/version`, { signal: AbortSignal.timeout(timeoutMs) });
    return response.ok;
  } catch {
    return false;
  }
}

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

function baseArgs({ port, profile, headless }) {
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
    // Chrome's modern headless still speaks full CDP and runs the real renderer,
    // which the WebAuthn shim needs.
    args.push('--headless=new', '--disable-gpu', '--window-size=1280,900');
    // Default headless UA contains "HeadlessChrome", which Cloudflare challenges
    // on npmjs.com. Present the equivalent headed UA instead.
    args.push(`--user-agent=${headedUserAgent()}`);
  }
  return args;
}

// Mirrors the headed Chrome UA for the installed build.
let cachedUserAgent;
export function headedUserAgent() {
  if (!cachedUserAgent) {
    const probe = spawnSync(EXECUTABLE, ['--version'], { encoding: 'utf8' });
    const version = (probe.stdout ?? '').match(/(\d+\.\d+\.\d+\.\d+)/)?.[1] ?? '151.0.0.0';
    const major = version.split('.')[0];
    cachedUserAgent = `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;
  }
  return cachedUserAgent;
}

async function waitForCdp(endpoint, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await cdpAlive(endpoint)) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return false;
}

// Launches a detached Chromium on the shared port. Used by ensureChromium.
export async function launchChromium({ userDataDir, url = 'about:blank', headless = false } = {}) {
  const profile = userDataDir ?? process.env.CHROMIUM_USER_DATA_DIR ?? path.join(ROOT, 'chromium-profile');
  await fsPromises.mkdir(profile, { recursive: true });
  const child = spawn(EXECUTABLE, [...baseArgs({ port: CDP_PORT, profile, headless }), url], {
    detached: true,
    stdio: 'ignore',
  });
  child.unref();
  return { profile, pid: child.pid };
}

// Reuses a running browser when present so an interactive session is preserved.
export async function ensureChromium({ userDataDir, headless = false, timeoutMs = 20000 } = {}) {
  if (await cdpAlive()) return { endpoint: CDP_ENDPOINT, launched: false };
  const { profile } = await launchChromium({ userDataDir, headless });
  if (await waitForCdp(CDP_ENDPOINT, timeoutMs)) {
    return { endpoint: CDP_ENDPOINT, launched: true, profile, headless };
  }
  throw new Error(`Chromium did not expose CDP on ${CDP_ENDPOINT} within ${timeoutMs}ms`);
}

// Always starts a brand-new instance with a throwaway profile on a free port,
// so it cannot collide with (or inherit state from) any other browser.
// Returns { endpoint, profile, pid, headless, close }.
export async function launchEphemeral({ headless = true, keepProfile = false, timeoutMs = 25000 } = {}) {
  const port = await freePort();
  const profile = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'kiro-chromium-'));
  const endpoint = `http://127.0.0.1:${port}`;
  // Not detached: we own this process and tear it down deterministically.
  const child = spawn(EXECUTABLE, [...baseArgs({ port, profile, headless }), 'about:blank'], {
    stdio: 'ignore',
  });

  let exited = false;
  const exitPromise = new Promise((resolve) => child.once('exit', () => { exited = true; resolve(); }));

  // Returns { profileRemoved, warning } instead of throwing. Chromium's helper
  // processes can still be flushing into the profile when the main process
  // exits, so rm can race them and report ENOTEMPTY. A leftover temp directory
  // is not a reason to fail a release, so retry briefly and then give up
  // quietly. (This raced roughly 1 run in 3 when it did throw.)
  const close = async () => {
    if (!exited) {
      child.kill('SIGTERM');
      const timer = setTimeout(() => { if (!exited) child.kill('SIGKILL'); }, 3000);
      await exitPromise;
      clearTimeout(timer);
    }
    if (keepProfile) return { profileRemoved: false };
    let lastError;
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      try {
        await fsPromises.rm(profile, { recursive: true, force: true });
        return { profileRemoved: true };
      } catch (error) {
        lastError = error;
        await new Promise((resolve) => setTimeout(resolve, attempt * 400));
      }
    }
    return { profileRemoved: false, warning: `could not remove ${profile}: ${lastError?.code ?? lastError?.message}` };
  };

  if (!(await waitForCdp(endpoint, timeoutMs))) {
    await close();
    throw new Error(`Ephemeral Chromium did not expose CDP on ${endpoint} within ${timeoutMs}ms`);
  }
  return { endpoint, profile, pid: child.pid, headless, close };
}
