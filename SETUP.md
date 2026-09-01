# Registering a custom P-256 key as a WebAuthn credential

This walks through registering a keypair **you generate and hold as PEM files** as
a security key on a relying party (npm here, but the same steps work anywhere
that accepts ES256 WebAuthn credentials).

Normally the browser or a hardware token generates the key and never lets you
have the private half. Here you supply the key, so it can later sign assertions
from a script — which is what makes headless CI publishing possible.

## What you get

- A P-256 keypair on disk as `private.pem` / `public.pem`.
- A credential registered against your account, backed by that key.
- A **credential ID**, recorded to a file, which you need for every later login.

## Prerequisites

| Requirement | Notes |
| --- | --- |
| OpenSSL 3.x | `openssl version` |
| Node.js 18+ | `node --version` |
| Chromium or Chrome | Any recent build |
| `puppeteer-core` | `cd .release && npm ci` |

The relying party must accept **ES256 (COSE algorithm `-7`)**. npm does.

> npm rejects Ed25519 (`-8`) credentials at login even though its UI accepts the
> registration. Use P-256; do not substitute Ed25519.

---

## Step 1 — Generate the keypair

Pick a directory outside any git repository:

```bash
mkdir -p ~/webauthn-keys/npm-p256
cd ~/webauthn-keys/npm-p256
```

Generate the private key, then derive the public key:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private.pem
chmod 600 private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

Confirm the curve:

```bash
openssl pkey -in private.pem -noout -text | grep -i 'NIST CURVE'
# NIST CURVE: P-256
```

You should now have exactly:

```
private.pem   -----BEGIN PRIVATE KEY-----   (mode 600)
public.pem    -----BEGIN PUBLIC KEY-----
```

Notes:

- `genpkey` emits PKCS#8 (`BEGIN PRIVATE KEY`). The older
  `openssl ecparam -genkey` emits SEC1 (`BEGIN EC PRIVATE KEY`); both work, but
  PKCS#8 is the modern default.
- `prime256v1`, `secp256r1`, and `P-256` are three names for the same curve.
- **`private.pem` is the credential.** Anyone holding it can authenticate as you
  on any account where you registered it. Never commit it.

---

## Step 2 — Launch Chromium with a remote debugging port

The registration script attaches to a browser you control; it never launches or
closes one. Start Chromium yourself with a debugging port and a dedicated
profile:

```bash
mkdir -p ~/webauthn-keys/chrome-profile

chromium \
  --remote-debugging-port=9222 \
  --user-data-dir=$HOME/webauthn-keys/chrome-profile \
  --no-first-run \
  --no-default-browser-check \
  https://www.npmjs.com/login
```

Use `google-chrome` or the full path if `chromium` is not on your `PATH`.

A separate `--user-data-dir` matters: Chrome refuses to open a debugging port on
an already-running default profile, and an isolated profile keeps this session
away from your normal browsing.

Verify the port is live:

```bash
curl -s http://127.0.0.1:9222/json/version | head -3
```

Leave this browser open for the rest of the process.

---

## Step 3 — Navigate to the add-security-key screen

Do this by hand, in the browser window from Step 2.

1. **Sign in** to npm with your username and password.
   If 2FA is already enabled, complete it with your existing method.
2. Go to **Account settings → Two-factor authentication**, or directly to:

   ```
   https://www.npmjs.com/settings/YOUR_USERNAME/tfa
   ```

3. Click **Add security key** (labelled "passkey" in some UI revisions). The
   page should land on:

   ```
   https://www.npmjs.com/settings/YOUR_USERNAME/tfa/manageTfa?action=register-key
   ```

4. **Stop here.** Do not click the button that starts the browser's own passkey
   prompt — if Chrome's native dialog appears, Chrome generates the key and you
   lose the ability to hold the private half. If a dialog does open, dismiss it
   and reload the page.

The tab must be sitting on the `manageTfa?action=register-key` URL when you hand
over to the script.

---

## Step 4 — Hand control to the registration script

The script replaces `navigator.credentials.create` in that tab, builds a WebAuthn
attestation from your `public.pem`, and submits it — so npm stores *your* key.

```bash
cd .release
npm ci    # once, if you have not already

node register-credential.mjs \
  --key-dir="$HOME/webauthn-keys/npm-p256" \
  --label="CI publishing key"
```

Options:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--key-dir` | *(required)* | Directory holding `private.pem` and `public.pem` |
| `--label` | `Local P-256 key` | Name shown in the account's key list |
| `--credential-id` | *(random)* | Choose the credential ID text instead of using 32 random bytes |
| `--credential-id-bytes` | `32` | Byte length the chosen ID is padded out to |
| `--endpoint` | `http://127.0.0.1:9222` | CDP endpoint from Step 2 |
| `--rp` | `www.npmjs.com` | Relying party ID |
| `--page-match` | `manageTfa` | Substring identifying the open tab |

Before touching the browser the script checks that `private.pem` is an EC P-256
key and that the two PEMs are a real pair, so a mismatch fails immediately
instead of producing a credential that can never authenticate.

### Choosing your own credential ID

By default the ID is 32 random bytes, which is what a hardware authenticator
would produce and what you should normally use. If you want a recognisable ID,
pass `--credential-id`:

```bash
node register-credential.mjs \
  --key-dir="$HOME/webauthn-keys/npm-p256" \
  --label="CI publishing key" \
  --credential-id=my-ci-key
```

A credential ID is *bytes*; base64url is only how those bytes are written down.
So the text you pass is treated as base64url and must contain only `A-Z a-z 0-9
- _`. It is then padded with `_` and canonicalized to exactly
`--credential-id-bytes` bytes, which is why the reported ID is longer than what
you typed and ends in a character you did not choose:

```
[id] requested : my-ci-key
[id] wire form  : my-ci-key_________________________________8
[id] 32 bytes (34 padding chars added)
```

Record the **wire form**, not what you typed — that is the value the relying
party stores and the value your automation must send back.

Two caveats. Because `_` is the padding character, IDs differing only in
trailing underscores collide (`my-key` and `my-key_` produce the same wire
form). And the ID appears in `allowCredentials` on the login page, so anyone can
see which credential guards the account; that is normal for WebAuthn, but do not
put anything meaningful in it.

Expected output:

```
[shim] installed on https://www.npmjs.com/settings/you/tfa/manageTfa?action=register-key
[page] entered label "CI publishing key"
[page] submitted; waiting for the relying party
[shim] signing create for rpId=www.npmjs.com origin=https://www.npmjs.com (offered algs -7, -257)

--- result ---
credential id : k7Qm2Xb9TfLpR4wNvZs8YcHj1AeUoD6i_gBxKtEnMqY
manifest      : /home/you/webauthn-keys/npm-p256/credential-manifest.json
final url     : https://www.npmjs.com/settings/you/tfa/list
```

The `[shim] signing create` line only prints from inside the shim, so its
presence is your proof that *your* key answered the request rather than the
browser's own authenticator.

---

## Step 5 — Record the credential ID

The credential ID identifies which key to use during login. It is **not secret**,
but without it you cannot authenticate, and the relying party will not show it to
you again.

The script writes it to `credential-manifest.json` beside your keys:

```bash
cat ~/webauthn-keys/npm-p256/credential-manifest.json
```

```json
{
  "credentialId": "k7Qm2Xb9TfLpR4wNvZs8YcHj1AeUoD6i_gBxKtEnMqY",
  "label": "CI publishing key",
  "rpId": "www.npmjs.com",
  "algorithm": -7,
  "curve": "P-256",
  "registered": true
}
```

Then confirm in the real UI, since the script only reads what the page rendered:

1. Open `https://www.npmjs.com/settings/YOUR_USERNAME/tfa` and check your label
   appears in the key list.
2. Store the credential ID where your automation reads it, e.g.
   `NPM_CREDENTIAL_ID`.

Keep a copy somewhere durable. Losing the ID while keeping the PEMs means
deleting the credential and registering again.

---

## Using the credential

With `private.pem` and the credential ID, a script can sign assertions and log in
without any hardware token. In this repo that is `.release/webauthn-shim.mjs`:

```js
import { loadSigner, installShim } from './webauthn-shim.mjs';

const signer = await loadSigner({
  keyDir: process.env.NPM_KEY_DIR,
  credentialId: process.env.NPM_CREDENTIAL_ID,
});
await installShim(page, signer);
```

One important detail: relying parties track the WebAuthn **signature counter**
and reject any assertion whose counter is not above the last one seen — that is
how they detect cloned authenticators. `.release/signcount.mjs` derives it from
Unix epoch seconds (`max(epochSeconds, last + 1)`), which is monotonic without
persisting state and therefore works on throwaway CI runners.

---

## Troubleshooting

**`No open tab matching "manageTfa"`**
The tab is not on the registration page, or the browser on `--endpoint` is a
different one. The error lists the tabs it found.

**`Relying party did not offer ES256 (-7)`**
The RP is asking for other algorithms. Registering anyway would produce a
credential it cannot verify, so the script stops.

**`private.pem and public.pem are not a matching keypair`**
`public.pem` was derived from a different private key. Regenerate it:
`openssl pkey -in private.pem -pubout -out public.pem`.

**`Could not find an "Add security key" control`**
npm changed its wording. Check the button text and pass a different
`--page-match`, or update the selector in `register-credential.mjs`.

**Chrome's own passkey dialog appears**
The shim was not installed before the click. Reload the registration page and
rerun the script; it injects on both the current document and any new one.

**Registration succeeds but login fails with "Something went wrong"**
Usually a stale signature counter, or an Ed25519 key. Confirm ES256 and that
your counter exceeds the RP's stored value.

---

## Security notes

- `private.pem` is a full authentication factor. Mode `600`, never in git.
  A `.gitignore` covering `*.pem` is the minimum.
- Registering the same key on multiple accounts means one file compromises all
  of them. Generate a separate key per account.
- In CI, pass the key as a secret written to a temp file and delete it afterwards
  — see `.github/workflows/publish.yml`.
- Keep a second, independent 2FA method registered. If you lose these PEMs, that
  is your only way back into the account.
- This bypasses the hardware-backed guarantee of a real security key: the private
  key is a readable file, not sealed in a device. That is the deliberate tradeoff
  for automation, and it means the file deserves the same care as a password.
