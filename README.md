# inboxproof

Instant email-authentication report card for any domain. Paste a domain, get a graded
SPF / DKIM / DMARC / MX / BIMI report with plain-English fixes. Free, no signup,
**zero backend** — the entire app is one static `index.html`.

> Why zero backend: the only external dependency is public DNS-over-HTTPS
> (Cloudflare + Google), which is keyless, free, and CORS-open. There is nothing
> to host, nothing to leak, nothing to scale.

## Quick start

```bash
git clone https://github.com/ejoliet/inboxproof && cd inboxproof
python3 -m http.server 8080
# open http://localhost:8080          — live checks
# open http://localhost:8080/?mock=1  — sample report, no network needed
```

No build step. No dependencies. Vanilla JS.

## Files

| File | Purpose |
|---|---|
| `index.html` | The whole app: UI, DoH client, parsers, grade engine, exports, bulk mode |
| `verify.js` | Offline Ed25519 license verification (**public key only**) |
| `mock.json` | Canned DNS answers for `?mock=1` demo mode |
| `tools/sign-license.mjs` | Keygen + license signing (private key → gitignored `keys/`) |
| `tools/test.mjs` | Headless test suite (`node tools/test.mjs`) |

## Deploy to GitHub Pages

1. Push to GitHub.
2. Repo **Settings → Pages → Source: Deploy from branch → `main` / root**.
3. Done. HTTPS is required for the Clipboard API and is provided by Pages.
4. Optional custom domain: add a `CNAME` file and DNS record.

Every file is static; there are no environment variables and no secrets in the repo.

## Privacy model

- **Only DNS query names leave the browser** (e.g. `_dmarc.acme.com` TXT), sent to
  Cloudflare `cloudflare-dns.com` with Google `dns.google` as automatic fallback —
  the same class of lookup a browser performs on any page load.
- Reports, history (last 20 checks), and license state live in `localStorage`
  under the `inboxproof.*` namespace, with an in-memory fallback where storage
  is blocked. Nothing is ever POSTed anywhere.
- No analytics, no cookies, no third-party scripts or fonts.
- Permalinks (`?d=acme.com`) carry only the domain; the recipient's browser
  re-runs the check live.

## API notes (DNS-over-HTTPS)

| | Cloudflare (primary) | Google (fallback) |
|---|---|---|
| Endpoint | `https://cloudflare-dns.com/dns-query?name=X&type=TXT` | `https://dns.google/resolve?name=X&type=TXT` |
| Required header | `accept: application/dns-json` | none |
| Auth | none | none |
| CORS | `Access-Control-Allow-Origin: *` | `Access-Control-Allow-Origin: *` |
| Docs | developers.cloudflare.com → 1.1.1.1 → DNS over HTTPS → JSON | developers.google.com/speed/public-dns/docs/doh/json |

Response shape: `{ "Status": 0, "Answer": [{ "type": 16, "data": "\"v=spf1 …\"" }] }`.
`Status: 3` = NXDOMAIN. TXT strings may arrive split (`"a" "b"`) and are joined.
DoH resolvers follow CNAME chains inside the Answer array, so CNAME-published
DMARC records work without extra handling.

### Rate-limit handling

Neither provider publishes a hard limit for the JSON endpoints. The app stays
polite anyway: per-run response cache (SPF include recursion reuses lookups),
6-second timeouts, automatic provider failover, and bulk mode throttled to
4 concurrent domains with a 300 ms gap per worker (~100 domains in a couple of
minutes). If both resolvers fail, the UI shows a retry panel and offers mock mode.

## Checks implemented

| Check | What it verifies | Hard failures |
|---|---|---|
| SPF | record present, **single** (multiple = permerror), syntax, `all` qualifier, recursive DNS-lookup count vs the RFC 7208 limit of 10, macro detection | `+all`, multiple records, >10 lookups |
| DMARC | `_dmarc.` TXT (org-domain fallback for subdomains), `p=` policy, `rua=` reporting, `pct` | missing record |
| MX | mail servers present; implicit-A fallback; RFC 7505 null-MX recognized | no MX and no A |
| DKIM | probes 8 common selectors (`google, selector1, selector2, s1, s2, k1, default, mail`) + custom-selector input. **Heuristic — labeled as such**; absence is a warning, never a hard fail | — |
| BIMI | `default._bimi` TXT. Bonus only; never lowers the grade | — |

Grade: DMARC 40 pts, SPF 25, DKIM 25, MX 10. No DMARC caps the grade at D;
`+all` or multiple SPF records force F.

Known limitation: the subdomain→org-domain fallback uses a small common-2LD list,
not the full public-suffix list. SPF macros are detected but not evaluated.

## Pro license (offline, no accounts)

Bulk mode (up to 100 domains → table + CSV) and watermark-free exports are gated
behind an Ed25519-signed license key, verified entirely in the browser.

```bash
node tools/sign-license.mjs --keygen                 # once; prints new public key
#   → paste the printed key into verify.js (PUBLIC_KEY_B64URL)
node tools/sign-license.mjs --name "Jane Consultant" # prints a license key
node tools/sign-license.mjs --name "Trial" --exp 20260801
```

Security invariants:

- `keys/` and `*.pem` are gitignored **before** any key exists; the keygen
  script refuses to run if the ignore rule is missing.
- `verify.js` ships only the raw 32-byte public key.
- **The public key currently in `verify.js` is a demo key. Rotate it
  (`--keygen`, paste, commit) before selling licenses.** Demo key for local
  testing:

```
inboxproof-v1.eyJwbGFuIjoicHJvIiwibmFtZSI6IkRFTU8iLCJpYXQiOjIwMjYwNzA5fQ.1-0T59KtGX4WROeM5z89QR32wxm76M1VDK5YIKcbEdHJavwn8vOSFEWJuPf1BJz9xXUfA_0WtmLQ0oTZjzx1Bw
```

Monetization placeholder: wire the "Get a Pro license" button
(`AIDEV-MONETIZATION` in `index.html`) to a Lemon Squeezy / Polar checkout URL.

## Test checklist

Headless (no network):

```bash
node tools/test.mjs   # parsers, grade engine, IDN normalization, license crypto
```

Manual, in a browser (live DNS):

- [ ] `gmail.com` → SPF pass (`~all`), DMARC found, MX pass; grade renders
- [ ] A DMARC-less domain (many small-business domains) → DMARC FAIL row with copyable fix; grade capped at D
- [ ] `thisdomaindoesnotexist-xyz123.com` → NXDOMAIN error panel with retry + sample-report buttons
- [ ] IDN: `bücher.de` → normalized to `xn--bcher-kva.de` and checked
- [ ] `?mock=1` → sample-company.com report renders offline from `mock.json`
- [ ] `?d=github.com` permalink auto-runs on load
- [ ] PNG export downloads a card with the airmail border and grade stamp
- [ ] PDF export (print dialog) hides chrome, shows all check details
- [ ] Demo license key activates Pro; garbage key shows a reason; reload re-verifies
- [ ] Bulk mode: paste 5 domains → streaming table + CSV download
- [ ] Block network in devtools → dual-resolver failure panel appears
- [ ] Phone width: rows wrap, input usable

## License

MIT — see `LICENSE`.
