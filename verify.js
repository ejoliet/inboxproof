'use strict';
/* verify.js — offline Ed25519 license verification for inboxproof.
   AIDEV-SECURITY: this file contains ONLY the raw 32-byte PUBLIC key.
   The private signing key lives outside the repo (keys/ is gitignored).
   Rotate this key (tools/sign-license.mjs --keygen) before selling licenses:
   the demo key shipped here is for local testing only.

   License format: inboxproof-v1.<base64url(JSON payload)>.<base64url(signature)>
   Payload: {"plan":"pro","name":"...","iat":YYYYMMDD}  (exp optional: YYYYMMDD) */

(function () {
  // AIDEV-LICENSE: replace after running `node tools/sign-license.mjs --keygen`
  const PUBLIC_KEY_B64URL = 'EW8pLC5zv0CbbadoshMFRIvvSK4z7vwYA0KAXaDmMtc';

  function b64urlToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  let keyPromise = null;
  function getKey() {
    if (!keyPromise) {
      // AIDEV: Ed25519 in WebCrypto is supported in current Safari/Firefox/Chrome;
      // importKey throws on very old browsers → caught and reported as unsupported.
      keyPromise = crypto.subtle.importKey(
        'raw', b64urlToBytes(PUBLIC_KEY_B64URL),
        { name: 'Ed25519' }, false, ['verify']
      );
    }
    return keyPromise;
  }

  window.inboxproofVerifyLicense = async function (key) {
    try {
      if (!key || typeof key !== 'string') return { valid: false, reason: 'empty key' };
      const parts = key.trim().split('.');
      if (parts.length !== 3 || parts[0] !== 'inboxproof-v1')
        return { valid: false, reason: 'not an inboxproof-v1 key' };
      const payloadBytes = b64urlToBytes(parts[1]);
      const sig = b64urlToBytes(parts[2]);
      let pub;
      try { pub = await getKey(); }
      catch (e) { return { valid: false, reason: 'this browser lacks Ed25519 WebCrypto — try a current Chrome/Firefox/Safari' }; }
      const ok = await crypto.subtle.verify({ name: 'Ed25519' }, pub, sig, payloadBytes);
      if (!ok) return { valid: false, reason: 'signature does not match' };
      const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
      if (payload.plan !== 'pro') return { valid: false, reason: 'unknown plan' };
      if (payload.exp) {
        const today = +new Date().toISOString().slice(0, 10).replace(/-/g, '');
        if (today > payload.exp) return { valid: false, reason: 'license expired' };
      }
      return { valid: true, payload };
    } catch (e) {
      return { valid: false, reason: 'malformed key' };
    }
  };
})();
