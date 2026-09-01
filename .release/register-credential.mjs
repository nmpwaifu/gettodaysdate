// Registers a locally generated P-256 keypair as a WebAuthn credential on a
// relying party (npm by default), by shimming navigator.credentials.create in a
// page you have already navigated to the "add security key" screen.
//
// Deterministic by design:
//   - Takes the key directory and expects private.pem / public.pem in it.
//   - Derives the COSE public key from public.pem; nothing is generated here
//     except the credential id (32 random bytes, the only value that must be new).
//   - Writes a manifest recording the credential id, so the value needed later is
//     never left to be copied off a screen.
//
// Usage:
//   node register-credential.mjs --key-dir=/path/to/keys [--label="My key"]
//                               [--endpoint=http://127.0.0.1:9222]
//                               [--rp=www.npmjs.com] [--page-match=manageTfa]
//
// Requires: a Chromium already running with --remote-debugging-port, with the
// registration page open. This script never launches or closes the browser.
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import puppeteer from 'puppeteer-core';

const args = process.argv.slice(2);
const value = (name, fallback) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};

const KEY_DIR = value('key-dir', process.env.WEBAUTHN_KEY_DIR);
const LABEL = value('label', process.env.WEBAUTHN_KEY_LABEL ?? 'Local P-256 key');
const ENDPOINT = value('endpoint', process.env.BROWSER_ENDPOINT ?? 'http://127.0.0.1:9222');
const RP_ID = value('rp', 'www.npmjs.com');
const PAGE_MATCH = value('page-match', 'manageTfa');
const STEP_TIMEOUT_MS = 15000;

if (!KEY_DIR) {
  console.error('error: --key-dir is required (directory containing private.pem and public.pem)');
  process.exit(2);
}

const b64url = (v) => Buffer.from(v).toString('base64url');
const sha256 = (v) => crypto.createHash('sha256').update(v).digest();
const clientDataJSON = (type, challenge, origin) =>
  Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));

// ------------------------------------------------------------- minimal CBOR
// Only the shapes an attestation object needs. Hand-rolled to avoid adding a
// dependency to a script that handles key material.

const cborUint = (n) => {
  if (n < 24) return Buffer.from([n]);
  if (n < 0x100) return Buffer.from([0x18, n]);
  if (n < 0x10000) return Buffer.from([0x19, n >> 8, n & 0xff]);
  throw new Error(`cborUint out of supported range: ${n}`);
};
const cborNegInt = (n) => {
  // Major type 1 encodes -1-n.
  const v = -1 - n;
  if (v < 24) return Buffer.from([0x20 | v]);
  if (v < 0x100) return Buffer.from([0x38, v]);
  throw new Error(`cborNegInt out of supported range: ${n}`);
};
const cborInt = (n) => (n < 0 ? cborNegInt(n) : cborUint(n));
const cborBytes = (buf) => {
  const b = Buffer.from(buf);
  const len = b.length;
  if (len < 24) return Buffer.concat([Buffer.from([0x40 | len]), b]);
  if (len < 0x100) return Buffer.concat([Buffer.from([0x58, len]), b]);
  if (len < 0x10000) return Buffer.concat([Buffer.from([0x59, len >> 8, len & 0xff]), b]);
  throw new Error(`cborBytes too long: ${len}`);
};
const cborText = (str) => {
  const b = Buffer.from(str, 'utf8');
  if (b.length < 24) return Buffer.concat([Buffer.from([0x60 | b.length]), b]);
  return Buffer.concat([Buffer.from([0x78, b.length]), b]);
};
// entries: array of [encodedKey, encodedValue]
const cborMap = (entries) => {
  const n = entries.length;
  if (n >= 24) throw new Error('cborMap supports < 24 entries');
  return Buffer.concat([Buffer.from([0xa0 | n]), ...entries.flat()]);
};

// COSE_Key for an EC2 P-256 public key using ES256.
//   1:2 (kty EC2)  3:-7 (alg ES256)  -1:1 (crv P-256)  -2:x  -3:y
const coseKey = (x, y) => cborMap([
  [cborInt(1), cborInt(2)],
  [cborInt(3), cborInt(-7)],
  [cborInt(-1), cborInt(1)],
  [cborInt(-2), cborBytes(x)],
  [cborInt(-3), cborBytes(y)],
]);

// ------------------------------------------------------------- attestation

// Flags 0x45 = User Present | User Verified | Attested credential data included.
function authenticatorData({ rpId, credentialId, x, y }) {
  const idLength = Buffer.alloc(2);
  idLength.writeUInt16BE(credentialId.length);
  return Buffer.concat([
    sha256(Buffer.from(rpId)),
    Buffer.from([0x45]),
    Buffer.alloc(4), // signature counter, zero at registration
    Buffer.alloc(16), // AAGUID, all-zero for a software authenticator
    idLength,
    credentialId,
    coseKey(x, y),
  ]);
}

// "none" attestation: the RP gets the public key but no authenticator identity.
const attestationObject = (authData) => cborMap([
  [cborText('fmt'), cborText('none')],
  [cborText('attStmt'), cborMap([])],
  [cborText('authData'), cborBytes(authData)],
]);

// ------------------------------------------------------------------ the shim

// Serialized into the page, so it must stay dependency-free.
function pageShim() {
  const encode = (value) => {
    const bytes = value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : ArrayBuffer.isView(value)
        ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        : value;
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  };
  const decode = (value) =>
    Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)).buffer;
  const revive = (payload) => ({
    type: payload.type,
    id: payload.id,
    rawId: decode(payload.rawId),
    response: Object.fromEntries(Object.entries(payload.response).map(([k, v]) =>
      [k, v && k !== 'userHandle' ? decode(v) : v])),
    getClientExtensionResults: () => ({}),
  });
  const credentials = {
    async create({ publicKey }) {
      return revive(await window.__registerCreate({
        rpId: publicKey.rp?.id ?? location.hostname,
        challenge: encode(publicKey.challenge),
        origin: location.origin,
        algorithms: (publicKey.pubKeyCredParams ?? []).map((p) => p.alg),
      }));
    },
    // Some flows immediately assert after registering; unsupported here on purpose.
    async get() { throw new Error('register-credential.mjs does not implement credentials.get'); },
  };
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
  window.__registerShim = true;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const privatePem = await fs.readFile(path.join(KEY_DIR, 'private.pem'), 'utf8');
  const publicPem = await fs.readFile(path.join(KEY_DIR, 'public.pem'), 'utf8');

  // Validate the key before touching the browser: a wrong curve fails at npm's
  // verification step much later and far less legibly.
  const priv = crypto.createPrivateKey(privatePem);
  if (priv.asymmetricKeyType !== 'ec') {
    throw new Error(`private.pem must be an EC key, got ${priv.asymmetricKeyType}`);
  }
  const pub = crypto.createPublicKey(publicPem);
  const jwk = pub.export({ format: 'jwk' });
  if (jwk.crv !== 'P-256') throw new Error(`public.pem must be P-256, got ${jwk.crv}`);

  // Confirm the two PEMs are actually a pair, so a mismatched public key cannot
  // be registered against a private key that will never satisfy it.
  const probe = crypto.randomBytes(32);
  const signature = crypto.sign('sha256', probe, priv);
  if (!crypto.verify('sha256', probe, pub, signature)) {
    throw new Error('private.pem and public.pem are not a matching keypair');
  }

  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const credentialId = crypto.randomBytes(32);
  const credentialIdText = credentialId.toString('base64url');

  const browser = await puppeteer.connect({ browserURL: ENDPOINT });
  const manifest = {
    startedAt: new Date().toISOString(),
    keyDirectory: path.resolve(KEY_DIR),
    credentialId: credentialIdText,
    label: LABEL,
    rpId: RP_ID,
    algorithm: -7,
    curve: 'P-256',
    registered: false,
  };
  const manifestPath = path.join(KEY_DIR, 'credential-manifest.json');
  const save = async () => {
    manifest.finishedAt = new Date().toISOString();
    await fs.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  };

  try {
    const pages = await browser.pages();
    const page = pages.find((p) => p.url().includes(PAGE_MATCH));
    if (!page) {
      throw new Error(`No open tab matching "${PAGE_MATCH}". Open the add-security-key page first.\nTabs: ${pages.map((p) => p.url()).join(', ') || '(none)'}`);
    }
    manifest.pageUrl = page.url();

    await page.exposeFunction('__registerCreate', async ({ rpId, challenge, origin, algorithms }) => {
      // Refuse rather than silently register a credential the RP will reject.
      if (algorithms?.length && !algorithms.includes(-7)) {
        throw new Error(`Relying party did not offer ES256 (-7); offered ${algorithms.join(', ')}`);
      }
      const json = clientDataJSON('webauthn.create', challenge, origin);
      const authData = authenticatorData({ rpId, credentialId, x, y });
      manifest.createRequest = { rpId, origin, algorithms };
      return {
        type: 'public-key',
        id: credentialIdText,
        rawId: credentialIdText,
        response: {
          clientDataJSON: b64url(json),
          attestationObject: b64url(attestationObject(authData)),
        },
      };
    });

    const source = `(${pageShim.toString()})();`;
    const client = await page.createCDPSession();
    await client.send('Page.addScriptToEvaluateOnNewDocument', { source });
    await page.evaluate(source);
    if (!(await page.evaluate(() => window.__registerShim === true))) {
      throw new Error('Shim failed to install');
    }
    console.log(`[shim] installed on ${page.url()}`);

    const clickAdd = () => page.evaluate(() => {
      const button = [...document.querySelectorAll('button, a')].find((el) =>
        /add security key|add passkey|register/i.test(el.textContent?.trim() ?? ''));
      if (!button) return false;
      button.click();
      return true;
    });

    if (!(await clickAdd())) throw new Error('Could not find an "Add security key" control on the page');
    console.log('[page] clicked add-security-key');

    // npm asks for a nickname after the authenticator responds.
    const deadline = Date.now() + STEP_TIMEOUT_MS;
    let nameInput = null;
    while (Date.now() < deadline && !nameInput) {
      nameInput = await page.$('input[name="nickname"], input[name="name"]');
      if (!nameInput) await sleep(250);
    }
    if (nameInput) {
      await nameInput.type(LABEL);
      await clickAdd();
      console.log(`[page] submitted label "${LABEL}"`);
    } else {
      console.log('[page] no nickname field appeared; assuming this RP does not ask for one');
    }

    await sleep(3000);
    const final = await page.evaluate(() => ({
      url: location.href,
      text: document.body.innerText.replace(/\s+/g, ' ').slice(-600),
    }));
    manifest.finalPage = final;

    // Treat an explicit error string as failure; otherwise report what was seen
    // and let the operator confirm in the RP's UI.
    const failed = /something went wrong|failed|error|try again/i.test(final.text);
    manifest.registered = !failed;
    await save();

    console.log('\n--- result ---');
    console.log(`credential id : ${credentialIdText}`);
    console.log(`manifest      : ${manifestPath}`);
    console.log(`final url     : ${final.url}`);
    console.log(`page tail     : ${final.text.slice(-200)}`);
    if (failed) {
      console.log('\nThe page reported a problem. The credential id above was NOT registered.');
      process.exitCode = 1;
    } else {
      console.log('\nRegistration submitted. Verify it appears in the relying party\'s key list,');
      console.log('then record the credential id above (it is also in the manifest).');
    }
  } catch (error) {
    manifest.error = error.message;
    await save();
    throw error;
  } finally {
    await browser.disconnect();
  }
}

try {
  await main();
} catch (error) {
  console.error(`\n[error] ${error.message}`);
  process.exit(1);
}
