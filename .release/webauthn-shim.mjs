// Reusable page-level WebAuthn shim backed by a local PEM private key.
//
// npm's browser 2FA is satisfied by overriding navigator.credentials.get in the
// page and signing the challenge in Node with our own key. npm verifies the
// assertion against the public key it stored at registration time.
//
// Notes learned the hard way:
//  - npm accepts P-256/ES256 (alg -7) and rejects Ed25519/EdDSA (alg -8).
//  - npm persists the signature counter server-side and requires it to strictly
//    increase, so the counter comes from signcount.mjs (Unix epoch based).
//  - The shim must be installed before navigation, hence addScriptToEvaluateOnNewDocument
//    plus an immediate evaluate() for the current (blank) document.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { nextSignCount } from './signcount.mjs';

export const EXPOSED_FN = '__kiroWebAuthnGet';
export const SHIM_FLAG = '__kiroWebAuthnShim';

export const b64url = (value) => Buffer.from(value).toString('base64url');
export const sha256 = (value) => crypto.createHash('sha256').update(value).digest();

export const clientDataJSON = (type, challenge, origin) =>
  Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));

export async function loadSigner({ keyDir, credentialId }) {
  const privateKey = crypto.createPrivateKey(await fs.readFile(path.join(keyDir, 'private.pem'), 'utf8'));
  const keyType = privateKey.asymmetricKeyType;
  // Ed25519 signs with algorithm=null; EC P-256 signs with sha256.
  const digest = keyType === 'ed25519' ? null : 'sha256';
  const credentialIdText = Buffer.from(credentialId, 'base64url').toString('base64url');
  const signCounts = [];

  const sign = ({ rpId, challenge, origin }) => {
    const json = clientDataJSON('webauthn.get', challenge, origin);
    const signCount = nextSignCount(keyDir, credentialIdText);
    signCounts.push(signCount);
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(signCount);
    // flags 0x01 = User Present
    const authenticatorData = Buffer.concat([sha256(Buffer.from(rpId)), Buffer.from([0x01]), counter]);
    const signature = crypto.sign(digest, Buffer.concat([authenticatorData, sha256(json)]), privateKey);
    return {
      type: 'public-key',
      id: credentialIdText,
      rawId: credentialIdText,
      response: {
        clientDataJSON: b64url(json),
        authenticatorData: b64url(authenticatorData),
        signature: b64url(signature),
        userHandle: null,
      },
    };
  };

  return { sign, signCounts, keyType, credentialIdText };
}

// Runs inside the page. Kept dependency-free so it can be stringified.
function shimSource(exposedFn, flag) {
  const encode = (value) => {
    const bytes = value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : ArrayBuffer.isView(value)
        ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        : value;
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  };
  const decode = (value) =>
    Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)).buffer;
  const revive = (payload) => ({
    type: payload.type,
    id: payload.id,
    rawId: decode(payload.rawId),
    response: Object.fromEntries(
      Object.entries(payload.response).map(([key, value]) => [key, value && key !== 'userHandle' ? decode(value) : value]),
    ),
    getClientExtensionResults: () => ({}),
  });
  const credentials = {
    async get({ publicKey }) {
      const allow = (publicKey.allowCredentials ?? []).map((item) => encode(item.id));
      const payload = await window[exposedFn]({
        rpId: publicKey.rpId ?? location.hostname,
        challenge: encode(publicKey.challenge),
        origin: location.origin,
        allow,
      });
      return revive(payload);
    },
    async create() {
      throw new Error('credentials.create is not supported by this shim');
    },
  };
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: credentials });
  window[flag] = true;
}

// Installs the shim on `page` so it survives navigations. Call while on about:blank.
export async function installShim(page, signer) {
  await page.exposeFunction(EXPOSED_FN, async (request) => signer.sign(request));
  const source = `(${shimSource.toString()})(${JSON.stringify(EXPOSED_FN)}, ${JSON.stringify(SHIM_FLAG)});`;
  const client = await page.createCDPSession();
  await client.send('Page.enable');
  await client.send('Page.addScriptToEvaluateOnNewDocument', { source });
  await page.evaluate(source);
  return page.evaluate((flag) => window[flag] === true, SHIM_FLAG);
}

export const shimInstalled = (page) => page.evaluate((flag) => window[flag] === true, SHIM_FLAG);
