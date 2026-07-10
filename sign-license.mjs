#!/usr/bin/env node
'use strict';
/* tools/sign-license.mjs — generate the Ed25519 keypair and sign Pro licenses.
   AIDEV-SECURITY: writes the private key ONLY to ./keys/private.pem, which is
   gitignored. Never commit it. If it ever lands in git history, rotate:
   run --keygen again, paste the new public key into verify.js, and reissue keys.

   Usage:
     node tools/sign-license.mjs --keygen
       → creates keys/private.pem, prints PUBLIC key for verify.js
     node tools/sign-license.mjs --name "Jane Consultant" [--exp 20271231]
       → prints a signed license key */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const KEY_PATH = path.join(process.cwd(), 'keys', 'private.pem');
const args = process.argv.slice(2);
const flag = (f) => { const i = args.indexOf(f); return i >= 0 ? (args[i + 1] ?? true) : null; };

if (flag('--keygen')) {
  if (fs.existsSync(KEY_PATH)) {
    console.error('keys/private.pem already exists — refusing to overwrite. Delete it to rotate.');
    process.exit(1);
  }
  // Guard: the .gitignore entry must exist BEFORE the key does.
  const gi = fs.existsSync('.gitignore') ? fs.readFileSync('.gitignore', 'utf8') : '';
  if (!/^keys\/$/m.test(gi)) {
    console.error('ABORT: .gitignore does not contain "keys/". Add it first.');
    process.exit(1);
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.mkdirSync(path.dirname(KEY_PATH), { recursive: true });
  fs.writeFileSync(KEY_PATH, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  console.log('Private key written to keys/private.pem (gitignored).');
  console.log('Paste this into verify.js as PUBLIC_KEY_B64URL:\n');
  console.log(raw.toString('base64url'));
  process.exit(0);
}

const name = flag('--name');
if (!name) {
  console.error('Usage: --keygen | --name "Buyer Name" [--exp YYYYMMDD]');
  process.exit(1);
}
if (!fs.existsSync(KEY_PATH)) {
  console.error('No keys/private.pem — run with --keygen first.');
  process.exit(1);
}
const priv = crypto.createPrivateKey(fs.readFileSync(KEY_PATH));
const payload = { plan: 'pro', name: String(name), iat: +new Date().toISOString().slice(0, 10).replace(/-/g, '') };
const exp = flag('--exp');
if (exp) payload.exp = +exp;
const bytes = Buffer.from(JSON.stringify(payload));
const sig = crypto.sign(null, bytes, priv);
console.log(`inboxproof-v1.${bytes.toString('base64url')}.${sig.toString('base64url')}`);
