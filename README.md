# PayShield Check

Check a payment link before you pay it. Paste any payment or checkout URL and
get a deterministic **Safe / Caution / Unsafe** verdict, with every reason
traced to a shown fact. No login, no paid service, no AI verdict.

Live demo: https://charry99.github.io/payshield-check/

Built for the [Kane CLI Hackathon](https://kaneclihack.sh) (deadline Nov 26,
2026, 11:59 PM IST). Entry: fresh repo, fresh code — the idea is reused from
the author's PayShield work, the codebase is new.

## What it checks (all free and keyless)

- **HTTPS** — plain HTTP is a flag; anything else is a hard flag.
- **Domain age** — public RDAP (`rdap.org`); domains under 30 days old are a
  flag, over a year old is a plus. No record at all is a flag.
- **Redirect chain** — the final address is fetched; a redirect to a different
  host is a flag.
- **Lookalike / typosquat heuristics** — brand names used as subdomains of
  another domain, brand names with extra words attached, one-or-two-letter
  lookalikes, punycode (`xn--`), suspicious TLDs, lure words (`airdrop`,
  `claim-now`, `verify-wallet`, …), deep subdomain chains.
- **BNB contract addresses in the link** — if the URL carries a `0x…`
  address, it is read on-chain via a public BSC RPC (contract vs wallet) and
  its source-verification status is checked on Sourcify.

A failed network check is reported as a fact, never silently treated as a
pass or a fail. A “Safe” result is not a guarantee — decide for yourself.

## Verdict rules

Score starts at 0; each reason adds its weight (shown next to the reason).

- Any **critical** reason (impersonation, IP/local host, odd protocol) →
  **Unsafe**.
- Score ≤ −30 → **Unsafe**. Score < 0 → **Caution**. Otherwise → **Safe**.

## Run it

```bash
npm install
npm run dev      # local dev server
npm test         # unit tests for the verdict logic (vitest)
npm run build    # tsc + vite build
```

## Verify with Kane CLI

The three flows in `tests/` are plain-English `*_test.md` files:

- `happy-path_test.md` — a known-good link shows Safe.
- `suspicious-link_test.md` — a lookalike airdrop link shows Unsafe.
- `invalid-input_test.md` — garbage input shows a clean error, no crash.

```bash
# needs: kane-cli installed + logged in, TestMu AI credits on the account
./scripts/verify.sh
```

`scripts/verify.sh` points Kane at the live GitHub Pages URL and runs
`kane-cli testrun run --headless tests/`. Every run seals a `.evidence` file
viewable at evidence.lambdatest.com. See [docs/kane-loop.md](docs/kane-loop.md)
for how Kane's results feed back into fixes.

A GitHub Action (`.github/workflows/kane.yml`) runs the same flows on every
push, gated on the `TESTMU_USERNAME` / `TESTMU_ACCESS_KEY` repo secrets.
The Pages deploy runs on every push (`.github/workflows/deploy.yml`).

## Bugs Kane caught

None yet — the first Kane run happens after the TestMu AI account is set up
and `kane-cli login` is done. Caught bugs will be listed here with the fix
and the re-run result.
