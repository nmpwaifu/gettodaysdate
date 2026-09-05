# gettodaysdate

[![npm version](https://img.shields.io/npm/v/gettodaysdate)](https://www.npmjs.com/package/gettodaysdate)
[![npm downloads](https://img.shields.io/npm/dm/gettodaysdate)](https://www.npmjs.com/package/gettodaysdate)
[![license](https://img.shields.io/npm/l/gettodaysdate)](./LICENSE)
[![published by puppeteer + a custom passkey](https://github.com/nmpwaifu/gettodaysdate/actions/workflows/publish.yml/badge.svg)](https://github.com/nmpwaifu/gettodaysdate/actions/workflows/publish.yml)

Returns a fixed ISO date.

```js
const { getTodaysDate } = require('gettodaysdate');

getTodaysDate(); // '2026-09-05'
```

# Why?

This is a PoC and a middle finger to NPM's change to force passkeys for publishing on everyone, because they think their users are too dumb.

Sure, there have been supply chain attacks, yeah tokens got leaked, whatever. That's the users fault. I mean you guys already blocked scripts and git etc. by default on npm 12, but forcing either passkeys or OIDC on a few providers is dumb.

Well, I will use my own passkeys, via keys I generate with OpenSSL! And guess what, since I can set the credentialId to any 32 bytes I want, I will have some fun with it:

<img width="1280" alt="Custom credentialId for passkeys I register via shim" src="https://github.com/user-attachments/assets/41c35340-54a4-4201-9598-bd826ded2546" />

## How?

Review the [SETUP.md](./SETUP.md) doc on how to register a custom passkey via a shim, and the [release](./.release/) folder for how the publishing works via puppeteer + custom passkeys

## AI Use

This was primarily done via some human webauthn research, and then prompting an LLM to help write shims, docs and the rest.

## License

WTFPL
