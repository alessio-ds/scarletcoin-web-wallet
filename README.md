# ScarletCoin Web Wallet

A ScarletCoin wallet that runs entirely in the browser — no download, no
desktop application, works on a phone. It is the sibling of
[ScarletCoin](https://github.com/alessio-ds/ScarletCoin): the Python project
holds the node, the miner and the desktop/CLI wallets; this repository holds
only the browser wallet.

```
┌──────────────────┐          JSON-RPC (HTTPS)         ┌───────────────┐
│  this web app    │ ────────────────────────────────► │  scarlet-node │
│  (keys in browser│   balances, history, broadcast    │  (--rpc-public)│
└──────────────────┘        keys never leave           └───────────────┘
```

## What it is

A static single-page application. It reimplements, in TypeScript, the parts of
the Python wallet that must run on the user's device:

* **Keys** — secp256k1 key generation, compressed public keys, Base58Check
  addresses and WIF (`src/lib/keys.ts`, `src/lib/base58.ts`).
* **Signing** — ECDSA with canonical low-`s` signatures, deterministic
  (RFC6979) nonces (`src/lib/keys.ts`).
* **Transactions** — the same wire serialisation, transaction ids and signature
  hash as the node (`src/lib/serialize.ts`, `src/lib/transaction.ts`).
* **Coin selection** — fee estimation, change and dust handling
  (`src/lib/builder.ts`).
* **Wallet file** — the same JSON format as the desktop/CLI wallet, encrypted
  with AES-256-GCM behind scrypt (`src/lib/keystore.ts`, `src/lib/encryption.ts`),
  so a wallet can be exported here and opened there, and the other way around.

Keys are generated, stored and used to sign **only in the browser**. The node it
talks to never sees a private key, only finished transactions.

## Security model

* **Keys stay on your device.** They live in your browser's storage (IndexedDB),
  optionally encrypted with a password. Nothing secret ever leaves the browser.
* **You trust the node for your balance.** Like any light wallet, this app asks
  a node for balances and history. Prefer a node at the same height as the
  others, or [run your own](https://github.com/alessio-ds/ScarletCoin) and point
  this app at it.
* **It must be served over HTTPS.** GitHub Pages provides this. A wallet over
  plain HTTP can have its JavaScript replaced.
* **Import/export is your backup.** Export the wallet file (Settings ▸ Export)
  and keep it somewhere safe; it contains your private keys.

## Using it

The wallet is published at:

```
https://<you>.github.io/scarletcoin-web-wallet/
```

It needs a node that serves its public JSON-RPC methods (started with
`--rpc-public`). By default it connects to the network's published public nodes;
use **Settings** to point it at another node (for example one you run yourself).

A node must also allow browser access from another origin: the Python node
answers CORS preflight requests and sends `Access-Control-Allow-Origin` when
started with `--rpc-public` (or `--rpc-cors <origin>`).

## Developing

```sh
npm install
npm run dev       # local dev server
npm test          # unit + cross-implementation golden tests
npm run build     # typecheck + production build into dist/
```

### Cross-implementation tests

The test suite must reproduce values produced by the Python wallet byte-for-byte.
The fixtures in `test/fixtures/golden.json` are generated from the ScarletCoin
checkout:

```sh
uv run python tools/generate_web_fixtures.py
```

This keeps the two implementations from drifting apart: addresses, WIF strings,
transaction bodies and transaction ids must be identical, and every signature
must verify under the node's rules.

## Deploying

Push to `main` and GitHub Actions builds and publishes the site to GitHub Pages
(`.github/workflows/deploy.yml`). In the repository settings, enable GitHub
Pages with **GitHub Actions** as the source.

## License

MIT. See [LICENSE](LICENSE).
