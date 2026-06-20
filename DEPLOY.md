# Deploy Guide — Mainnet, via Vercel

This deploys the Compliance Diligence Suite as a live, paid API on Tempo
**mainnet**. Read the one blocker first — it'll save you money.

---

## ⛔ The one thing you MUST do first (or payments fail)

The code ships with **no currency address**, on purpose. You have to
supply the **mainnet** pathUSD/USDC token address, because the testnet
one (`0x20c0…0000`) does not exist on mainnet and every payment against
it would fail. The server is built to **refuse to start** if you try to
use the testnet token in mainnet mode, so you can't deploy this wrong by
accident — but it does mean you need the real address before you begin.

**Where to get it:** your **Stripe Dashboard → in live mode → Payment
methods → Crypto / Stablecoins**, in the "Run live mode transactions"
section (this is where Stripe's own MPP docs point for the mainnet
pathUSD/USDC contract address). Copy that `0x…` address. You'll paste it
into Vercel as `TEMPO_CURRENCY_ADDRESS` in Step 4.

If you can't find it there, the alternative source is Tempo's official
mainnet token documentation. Do **not** guess it.

---

## Why this isn't drag-and-drop (unlike DoomStreak)

DoomStreak was one static HTML file, so Netlify Drop worked. This is a
**backend server**: it runs code, holds secret API keys, and calls
Chainalysis + Companies House on every request. A drag-and-drop static
host can't run code or keep secrets, so it physically can't host this.
You need a platform that runs Node functions with environment variables —
that's the Git-connected flow below. It's still only a few steps.

---

## Step 1 — Put the project on GitHub

Vercel deploys from a Git repo. From the project folder:

```bash
git init
git add .
git commit -m "Compliance Diligence Suite"
```

Then create an empty repo on github.com (New repository → name it e.g.
`compliance-diligence-suite` → **Private** is fine → Create), and follow
the "push an existing repository" lines GitHub shows you, which look like:

```bash
git remote add origin https://github.com/YOUR_USERNAME/compliance-diligence-suite.git
git branch -M main
git push -u origin main
```

**Before you push, double-check `.env` is NOT included** (it's in
`.gitignore`, so it shouldn't be). Run `git status` — if you see `.env`
listed, stop and remove it. Your secrets must never hit GitHub.

---

## Step 2 — Import into Vercel

1. Go to **vercel.com** and log in (you already have an account).
2. Click **Add New… → Project**.
3. Find your `compliance-diligence-suite` repo and click **Import**.
4. Vercel auto-detects it. It now natively understands Hono, so you don't
   need to set a build command or output directory — leave the defaults.

**Don't click Deploy yet.** Set the environment variables first (next
step), or the first deploy will boot, fail its config check, and you'll
just have to redeploy.

---

## Step 3 — (still on the import screen) Expand "Environment Variables"

There's an **Environment Variables** section on the import/configure
screen. Add each of these as a separate key/value pair.

| Key | Value |
|-----|-------|
| `COMPANIES_HOUSE_API_KEY` | your Companies House REST key |
| `MPP_RECIPIENT_ADDRESS` | your Tempo wallet address (`0x…`, 40 hex chars) |
| `TEMPO_CURRENCY_ADDRESS` | the **mainnet** pathUSD/USDC address from Step 0 |
| `TEMPO_TESTNET` | `false` |
| `MPP_SECRET_KEY` | a 32-byte random secret (generate it — see below) |
| `ATTESTATION_PRIVATE_KEY` | Ed25519 PKCS8 PEM for signing responses (generate it — see below). Optional but recommended; without it responses are unsigned. |

There is **no Chainalysis API key** — sanctions screening uses the public
on-chain oracle (no key, no signup). Optionally set `SANCTIONS_ORACLE_RPC_URL`
to a dedicated Ethereum RPC if the default public one throttles you under
load; otherwise leave it unset.

Generate the `MPP_SECRET_KEY` on your machine and paste the output:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Generate the `ATTESTATION_PRIVATE_KEY` (Ed25519 signing key) and paste the
whole multi-line PRIVATE block:

```bash
node -e "console.log(require('crypto').generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'}))"
```

Do **not** set `PORT` — Vercel handles that itself.

---

## Step 4 — Deploy

Click **Deploy**. Vercel installs, builds, and gives you a live URL like
`compliance-diligence-suite.vercel.app`.

---

## Step 5 — Verify it's actually live and correct

Replace `YOUR-URL` with your real Vercel URL:

```bash
# 1. Service info — should return JSON listing the routes (free, no payment)
curl https://YOUR-URL.vercel.app/

# 2. A paid route with NO payment — should return HTTP 402 Payment Required
curl -i https://YOUR-URL.vercel.app/screen/0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226d

# 3. Discovery doc — should return OpenAPI JSON
curl https://YOUR-URL.vercel.app/openapi.json
```

A **402** on the second one is success — it's the payment challenge, not
an error. Check the challenge header: it should show `method="tempo"` and
your real recipient address. If the JSON `currency` in the OpenAPI doc
shows your mainnet address (not `0x20c0…0000`), you're correctly on
mainnet.

**Two other responses you might see, both intentional, not bugs:**

- **503 "upstream temporarily unavailable"** — the health gate ran before
  payment and found Chainalysis or Companies House unreachable right now.
  No payment was requested. This protects callers from paying for a call
  that would fail. Retry shortly.
- **429 "rate limit exceeded"** — you (or one caller) exceeded the
  per-caller cap (default 30/min). This protects the shared free-tier
  upstream budget. The `Retry-After` header says how long to wait.

If instead you get a **500 / function crash**, open the Vercel dashboard →
your project → the latest deployment → **Logs**. The most likely message
is the config guard telling you exactly what's wrong (missing var, or the
testnet-token-on-mainnet block). Fix the env var in Settings →
Environment Variables, then **Redeploy**.

You'll also see structured `{"kind":"payment",...}` lines in those logs on
every settled or failed payment — that's the payment log (see README's
"Payment failure handling" section).

---

## Step 6 — Your first real paid call (the transaction count you wanted)

This is what generates the on-chain transaction count for your portfolio.

1. Fund a Tempo wallet with a small amount of pathUSD/USDC (a dollar is
   plenty — each call is ~$0.01–0.015). Use whatever exchange/bridge
   route Tempo documents for getting stablecoins onto mainnet.
2. Use the mppx CLI to make a real paid call:

```bash
npx mppx account create          # creates + shows a Tempo account (fund this one)
npx mppx account view --show-key # see its address to fund it
# …fund it, then:
npx mppx https://YOUR-URL.vercel.app/screen/0xf39Fd6e51aad88F6F4ce6aB8827279cffFb9226d
```

The CLI handles the whole 402 → pay → retry → receipt flow. On success
you get the screening JSON back plus a receipt, and there's now a real
settled transaction on Tempo mainnet against your recipient address.

3. Repeat against `/company/00000006` (a real Companies House number) and
   `/diligence?wallet=0x…&company=00000006` to exercise all three routes.

---

## Updating later

Any push to your `main` branch auto-deploys. Change code locally, commit,
`git push`, and Vercel redeploys in ~a minute — same flow as ArcFX.

---

## Custom domain (optional)

Vercel dashboard → your project → **Settings → Domains → Add**. If you
want something like `diligence.yourdomain.xyz`, add it here and follow the
DNS instructions (same as you did for doomstreak.xyz, just on Vercel
instead of the registrar's nameservers).

---

## Quick reference — what each env var does

- `COMPANIES_HOUSE_API_KEY` — auth for the company-data upstream. Free to
  obtain. (Sanctions screening needs no key — it reads the public on-chain
  oracle.)
- `MPP_RECIPIENT_ADDRESS` — where your per-call fees land.
- `TEMPO_CURRENCY_ADDRESS` — which token clients pay in. **Mainnet value
  required.**
- `TEMPO_TESTNET` — `false` for mainnet. The code reads this explicitly.
- `MPP_SECRET_KEY` — secures payment challenges. Treat like a password;
  never commit it; rotate if exposed.
