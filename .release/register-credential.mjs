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
//                               [--credential-id=<base64url>] [--credential-id-bytes=32]
//                               [--endpoint=http://127.0.0.1:9222]
//                               [--rp=www.npmjs.com] [--page-match=manageTfa]
//
// --credential-id chooses the id instead of using 32 random bytes. The text is
// padded with '_' and canonicalized to exactly --credential-id-bytes bytes; see
// normalizeChosenId.
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
const CREDENTIAL_ID_ARG = value('credential-id', process.env.WEBAUTHN_CREDENTIAL_ID);
const TARGET_ID_BYTES = Number(value('credential-id-bytes', '32'));
const ENDPOINT = value('endpoint', process.env.BROWSER_ENDPOINT ?? 'http://127.0.0.1:9222');
const RP_ID = value('rp', 'www.npmjs.com');
const PAGE_MATCH = value('page-match', 'manageTfa');
const STEP_TIMEOUT_MS = 15000;

if (!KEY_DIR) {
  console.error('error: --key-dir is required (directory containing private.pem and public.pem)');
  process.exit(2);
}

// A credential id is BYTES; base64url is only the wire form. A hand-written id
// must therefore survive a decode/encode round trip, or the value registered and
// the value sent at login will differ and the relying party will reject the
// assertion as an unknown credential.
//
// Real authenticators emit fixed-width ids (commonly 32 bytes), so a chosen id is
// padded out to TARGET_ID_BYTES rather than left at whatever length the text
// happened to decode to. Padding is applied in the string domain with '_' so the
// requested text stays readable at the front of the wire form, then the value is
// canonicalized: base64url carries 6 bits per character, so the final character
// of a non-multiple-of-4 string has spare low bits which must be zero.
function normalizeChosenId(text, targetBytes) {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) {
    throw new Error(`--credential-id must contain only base64url characters (A-Z a-z 0-9 - _); got "${text}"`);
  }
  // Characters needed to carry targetBytes: ceil(bytes * 8 / 6).
  const targetChars = Math.ceil((targetBytes * 8) / 6);
  if (text.length > targetChars) {
    throw new Error(`--credential-id "${text}" is ${text.length} characters, too long for ${targetBytes} bytes (max ${targetChars})`);
  }
  const padded = text + '_'.repeat(targetChars - text.length);
  // Re-encoding zeroes the final character's spare bits, giving the canonical
  // form the relying party will echo back at login.
  const canonical = Buffer.from(padded, 'base64url').toString('base64url');
  const bytes = Buffer.from(canonical, 'base64url');
  if (bytes.length !== targetBytes) {
    throw new Error(`internal: expected ${targetBytes} bytes, got ${bytes.length} from "${canonical}"`);
  }
  if (Buffer.from(canonical, 'base64url').toString('base64url') !== canonical) {
    throw new Error(`internal: "${canonical}" is not stable under base64url round trip`);
  }
  if (!canonical.startsWith(text)) {
    throw new Error(`internal: canonical id "${canonical}" no longer starts with "${text}"`);
  }
  return { bytes, text: canonical, padChars: targetChars - text.length };
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
  // Validate the chosen id before touching files or the browser: it is pure
  // string work, and a typo should fail immediately rather than behind a
  // missing-key error.
  const chosen = CREDENTIAL_ID_ARG ? normalizeChosenId(CREDENTIAL_ID_ARG, TARGET_ID_BYTES) : null;

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
  const credentialId = chosen ? chosen.bytes : crypto.randomBytes(32);
  const credentialIdText = credentialId.toString('base64url');
  if (chosen) {
    console.log(`[id] requested : ${CREDENTIAL_ID_ARG}`);
    console.log(`[id] wire form  : ${credentialIdText}`);
    console.log(`[id] ${credentialId.length} bytes (${chosen.padChars} padding chars added)`);
  }

  const browser = await puppeteer.connect({ browserURL: ENDPOINT });
  const manifest = {
    startedAt: new Date().toISOString(),
    keyDirectory: path.resolve(KEY_DIR),
    credentialId: credentialIdText,
    credentialIdChosen: Boolean(CREDENTIAL_ID_ARG),
    credentialIdRequested: CREDENTIAL_ID_ARG ?? null,
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

    // Record only url/status/short body for registration traffic, so a failure is
    // diagnosable. Headers are deliberately excluded: they carry session cookies.
    page.on('response', async (response) => {
      const url = response.url();
      if (!/webauthn|tfa|register|credential/i.test(url)) return;
      const entry = { url, status: response.status() };
      try {
        entry.body = (await response.text()).slice(0, 400);
      } catch { /* body unavailable */ }
      (manifest.responses ??= []).push(entry);
    });

    await page.exposeFunction('__registerCreate', async ({ rpId, challenge, origin, algorithms }) => {
      // Refuse rather than silently register a credential the RP will reject.
      if (algorithms?.length && !algorithms.includes(-7)) {
        throw new Error(`Relying party did not offer ES256 (-7); offered ${algorithms.join(', ')}`);
      }
      const json = clientDataJSON('webauthn.create', challenge, origin);
      const authData = authenticatorData({ rpId, credentialId, x, y });
      manifest.createRequest = { rpId, origin, algorithms, credentialIdBytes: credentialId.length };
      console.log(`[shim] signing create for rpId=${rpId} origin=${origin} (offered algs ${algorithms?.join(', ')})`);
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
    // Reload so the shim is present on a fresh document before npm's app code
    // runs. Installing only on the live document can leave a React bundle holding
    // the original navigator.credentials reference it captured at load.
    await page.reload({ waitUntil: 'networkidle2', timeout: STEP_TIMEOUT_MS * 2 });
    await page.evaluate(source);
    if (!(await page.evaluate(() => window.__registerShim === true))) {
      throw new Error('Shim failed to install');
    }
    console.log(`[shim] installed on ${page.url()}`);

    const findNickname = () => page.$('input[name="nickname"], input[name="name"]');
    const clickAdd = () => page.evaluate(() => {
      const button = [...document.querySelectorAll('button, a')].find((el) =>
        /add security key|add passkey|register/i.test(el.textContent?.trim() ?? ''));
      if (!button) return false;
      button.click();
      return true;
    });

    // npm shows the name field either immediately or after a first click,
    // depending on how the page was reached. Handle both orders.
    let nameInput = await findNickname();
    if (!nameInput) {
      if (!(await clickAdd())) throw new Error('Could not find an "Add security key" control on the page');
      console.log('[page] clicked add-security-key to open the form');
      const deadline = Date.now() + STEP_TIMEOUT_MS;
      while (Date.now() < deadline && !nameInput) {
        nameInput = await findNickname();
        if (!nameInput) await sleep(250);
      }
    }

    if (nameInput) {
      await nameInput.click({ clickCount: 3 }).catch(() => {});
      await nameInput.type(LABEL);
      console.log(`[page] entered label "${LABEL}"`);
    } else {
      console.log('[page] no name field appeared; this relying party may not ask for one');
    }

    // This click is what triggers navigator.credentials.create, i.e. the shim.
    if (!(await clickAdd())) throw new Error('Could not find the submit control');
    console.log('[page] submitted; waiting for the relying party');

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
