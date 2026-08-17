import { Wallet } from "./lib/wallet.js";
import { Keystore, type WalletDocument, WalletError } from "./lib/keystore.js";
import { RpcClient } from "./lib/rpc.js";
import { NETWORKS, getParams } from "./lib/params.js";
import { formatAmount, parseAmount } from "./lib/units.js";
import { isValidAddress, privateKeyFromWif } from "./lib/keys.js";
import { serialize } from "./lib/transaction.js";
import { toHex, reverseBytes } from "./lib/util.js";
import {
  clearWallet,
  loadSettings,
  loadWalletDocument,
  saveSettings,
  saveWalletDocument,
} from "./lib/storage.js";
import { Miner, type MinerState } from "./lib/miner.js";
import { generateMnemonic, mnemonicToSeed, validateMnemonic, MnemonicError } from "./lib/bip39.js";

const app = document.getElementById("app")!;

let keystore: Keystore | null = null;
let wallet: Wallet | null = null;
let miner: Miner | null = null;
let network = "mainnet";
let nodeUrl = getParams("mainnet").publicNodes[0] ?? "http://127.0.0.1:20332";
let activeTab = "send";

function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const EXPLORER_URL = "https://scarletcoin.remotewire.net";

function explorerLink(kind: "tx" | "address" | "block", value: string | number): string {
  return `${EXPLORER_URL}/${kind}/${encodeURIComponent(String(value))}`;
}

function linkHtml(href: string, label: string, className = "hash"): string {
  return `<a class="${className}" href="${href}" target="_blank" rel="noopener">${escapeHtml(label)}</a>`;
}

function displayTxid(txidInternal: Uint8Array): string {
  return toHex(reverseBytes(txidInternal));
}

function params() {
  return getParams(network);
}

function client(): RpcClient {
  return new RpcClient(nodeUrl);
}

// ------------------------------------------------------------------ persistence

async function persist(): Promise<void> {
  if (!keystore) return;
  const document = await keystore.toDocument();
  await saveWalletDocument(document as unknown as Record<string, unknown>);
}

// ------------------------------------------------------------------ rendering

function renderShell(): void {
  app.innerHTML = `
    <header class="app">
      <h1>ScarletCoin Wallet</h1>
      <span class="node" id="node-status"></span>
      <div class="spacer"></div>
      <a class="button-link" href="${EXPLORER_URL}/" target="_blank" rel="noopener">Block explorer</a>
      <button class="secondary" id="refresh-btn">Refresh</button>
    </header>
    <div id="content"></div>
    <footer class="app-footer">
      <a href="https://github.com/alessio-ds/scarletcoin-web-wallet">github.com/alessio-ds/scarletcoin-web-wallet</a>
    </footer>
  `;
  document.getElementById("refresh-btn")!.addEventListener("click", () => void refresh());
}

function setStatus(text: string, isError = false): void {
  const el = document.getElementById("node-status");
  if (el) {
    el.textContent = text;
    el.className = isError ? "node error" : "node";
  }
}

async function refresh(): Promise<void> {
  if (!keystore || !wallet) return;
  await renderMain();
}

// ------------------------------------------------------------------ onboarding

function renderOnboarding(error = ""): void {
  app.innerHTML = `
    <header class="app"><h1>ScarletCoin Wallet</h1></header>
    <div class="card">
      <h2 style="margin-top:0">Create a wallet</h2>
      <p class="hint">A 12-word recovery phrase will be shown &mdash; write it down.</p>
      <label>Network</label>
      <select id="create-network">
        ${Object.keys(NETWORKS).map((n) => `<option value="${n}">${n}</option>`).join("")}
      </select>
      <label>Password (optional — encrypts the keys)</label>
      <input type="password" id="create-password" autocomplete="new-password" />
      <div class="status" style="margin-top:12px"><button id="create-btn">Create</button></div>
      <div id="create-mnemonic" class="status" style="display:none;margin-top:8px"></div>
    </div>
    <div class="card">
      <h2 style="margin-top:0">Restore from seed phrase</h2>
      <p class="hint">Enter the 12 words you wrote down when the wallet was created.</p>
      <label>Recovery phrase</label>
      <textarea id="restore-words" rows="3" placeholder="abandon abandon abandon..." autocomplete="off"></textarea>
      <label>Network</label>
      <select id="restore-network">
        ${Object.keys(NETWORKS).map((n) => `<option value="${n}">${n}</option>`).join("")}
      </select>
      <label>Password (optional)</label>
      <input type="password" id="restore-password" autocomplete="new-password" placeholder="Optional wallet password" />
      <div class="status" style="margin-top:12px"><button id="restore-btn">Restore</button></div>
    </div>
    <div class="card">
      <h2 style="margin-top:0">Restore from a wallet file</h2>
      <label>ScarletCoin wallet file (JSON)</label>
      <input type="file" id="import-file" accept="application/json,.json" />
      <p class="hint">The same format as the desktop and command-line wallet.</p>
    </div>
    <div class="card">
      <h2 style="margin-top:0">Import a private key</h2>
      <p class="hint">Enter a WIF private key to create a wallet from a single key.</p>
      <label>Network</label>
      <select id="wif-network">
        ${Object.keys(NETWORKS).map((n) => `<option value="${n}">${n}</option>`).join("")}
      </select>
      <label>Private key (WIF)</label>
      <input type="password" id="wif-input" autocomplete="off" placeholder="Enter your WIF private key" />
      <label>Password (optional — encrypts the key)</label>
      <input type="password" id="wif-password" autocomplete="new-password" placeholder="Optional wallet password" />
      <div class="status" style="margin-top:12px"><button id="import-wif-btn">Import</button></div>
    </div>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <footer class="app-footer">
      <a href="https://github.com/alessio-ds/scarletcoin-web-wallet">github.com/alessio-ds/scarletcoin-web-wallet</a>
    </footer>
  `;

  document.getElementById("create-btn")!.addEventListener("click", () => void createWallet());
  document.getElementById("restore-btn")!.addEventListener("click", () => void restoreFromSeed());
  document.getElementById("import-file")!.addEventListener("change", (event) => {
    void importFile((event.target as HTMLInputElement).files?.[0]);
  });
  document.getElementById("import-wif-btn")!.addEventListener("click", () => void importWifRestore());
}

async function createWallet(): Promise<void> {
  const networkValue = (document.getElementById("create-network") as HTMLSelectElement).value;
  const password = (document.getElementById("create-password") as HTMLInputElement).value;
  network = networkValue;
  nodeUrl = getParams(network).publicNodes[0] ?? `http://127.0.0.1:${getParams(network).defaultRpcPort}`;
  const mnemonic = generateMnemonic();
  const seed = await mnemonicToSeed(mnemonic);
  keystore = await Keystore.fromSeed(seed, network, password || undefined);
  keystore.newKey("second");
  await persist();
  await saveSettings({ network, nodeUrl });
  // Show the recovery phrase in the create card.
  const el = document.getElementById("create-mnemonic")!;
  el.innerHTML = `
    <p style="margin:0"><strong>Recovery phrase</strong> – write these 12 words down. Anyone who has them
    can spend the coins. They are shown only now.</p>
    <pre style="background:var(--bg-card);padding:8px;border-radius:4px;
      margin:6px 0 0;white-space:pre-wrap;word-break:break-word">${escapeHtml(mnemonic)}</pre>
  `;
  (el as HTMLElement).style.display = "block";
  wallet = new Wallet(keystore, client());
  await renderMain();
}

async function restoreFromSeed(): Promise<void> {
  const networkValue = (document.getElementById("restore-network") as HTMLSelectElement).value;
  const password = (document.getElementById("restore-password") as HTMLInputElement).value;
  const words = (document.getElementById("restore-words") as HTMLTextAreaElement).value;

  const mnemonic = words.trim().replace(/\s+/g, " ");
  if (!mnemonic) return;
  try {
    validateMnemonic(mnemonic);
  } catch (error) {
    renderOnboarding(error instanceof MnemonicError ? error.message : "invalid recovery phrase");
    return;
  }
  try {
    const seed = await mnemonicToSeed(mnemonic);
    network = networkValue;
    nodeUrl = getParams(network).publicNodes[0] ?? `http://127.0.0.1:${getParams(network).defaultRpcPort}`;
    keystore = await Keystore.fromSeed(seed, network, password || undefined);
    await persist();
    await saveSettings({ network, nodeUrl });
    wallet = new Wallet(keystore, client());
    await renderMain();
  } catch (error) {
    renderOnboarding(`Could not restore that wallet: ${error instanceof Error ? error.message : error}`);
  }
}

async function importFile(file: File | undefined): Promise<void> {
  if (!file) return;
  try {
    const text = await file.text();
    const document = JSON.parse(text) as WalletDocument;
    keystore = await Keystore.fromDocument(document);
    network = keystore.network;
    const saved = await loadSettings();
    nodeUrl = saved?.nodeUrl ?? getParams(network).publicNodes[0] ?? `http://127.0.0.1:${getParams(network).defaultRpcPort}`;
    await saveSettings({ network, nodeUrl });
    wallet = new Wallet(keystore, client());
    await renderMain();
  } catch (error) {
    renderOnboarding(`Could not open that wallet: ${error instanceof Error ? error.message : error}`);
  }
}

async function importWifRestore(): Promise<void> {
  const networkValue = (document.getElementById("wif-network") as HTMLSelectElement).value;
  const wif = (document.getElementById("wif-input") as HTMLInputElement).value.trim();
  const password = (document.getElementById("wif-password") as HTMLInputElement).value;

  if (!wif) {
    renderOnboarding("Please enter a WIF private key.");
    return;
  }

  try {
    const params = getParams(networkValue);
    const secret = privateKeyFromWif(wif, params.wifVersion);
    network = networkValue;
    nodeUrl = params.publicNodes[0] ?? `http://127.0.0.1:${params.defaultRpcPort}`;
    keystore = await Keystore.fromSecret(secret, network, password || undefined);
    await persist();
    await saveSettings({ network, nodeUrl });
    wallet = new Wallet(keystore, client());
    await renderMain();
  } catch (error) {
    renderOnboarding(`Invalid private key: ${error instanceof Error ? error.message : error}`);
  }
}

// ------------------------------------------------------------------ main view

async function renderMain(): Promise<void> {
  renderShell();
  const content = document.getElementById("content")!;
  content.innerHTML = `
    <div class="balance" id="balance">…</div>
    <div class="detail" id="detail">…</div>
    <div class="tabs">
      <button data-tab="send">Send</button>
      <button data-tab="receive">Receive</button>
      <button data-tab="history">History</button>
      <button data-tab="coins">Coins</button>
      <button data-tab="mine">Mine</button>
      <button data-tab="settings">Settings</button>
    </div>
    <div id="tab"></div>
  `;
  const tabButtons = content.querySelectorAll<HTMLButtonElement>(".tabs button");
  for (const button of tabButtons) {
    button.addEventListener("click", () => {
      activeTab = button.dataset.tab!;
      for (const b of tabButtons) b.classList.toggle("active", b.dataset.tab === activeTab);
      void renderTab();
    });
    if (button.dataset.tab === activeTab) button.classList.add("active");
  }
  await refreshSummary();
  await renderTab();
}

async function refreshSummary(): Promise<void> {
  if (!wallet) return;
  try {
    const [balance, info] = await Promise.all([wallet.balance(), wallet.nodeInfo()]);
    const balanceEl = document.getElementById("balance");
    const detailEl = document.getElementById("detail");
    if (!balanceEl || !detailEl) return;
    balanceEl.textContent = `${formatAmount(balance.spendable)} SCT`;
    const details = [`${balance.utxoCount} unspent outputs`];
    if (balance.immature > 0n) details.push(`${formatAmount(balance.immature)} SCT still maturing`);
    detailEl.textContent = details.join("  ·  ");
    if (info.error) {
      setStatus(`no node: ${info.error}`, true);
    } else {
      setStatus(`${info.network} · height ${info.height} · ${info.peers} peers`);
    }
  } catch (error) {
    setStatus(`node error: ${error instanceof Error ? error.message : error}`, true);
  }
}

async function renderTab(): Promise<void> {
  const tab = document.getElementById("tab")!;
  if (activeTab === "send") return renderSend(tab);
  if (activeTab === "receive") return renderReceive(tab);
  if (activeTab === "history") return renderHistory(tab);
  if (activeTab === "coins") return renderCoins(tab);
  if (activeTab === "mine") return renderMine(tab);
  return renderSettings(tab);
}

// ------------------------------------------------------------------ send

async function renderSend(tab: HTMLElement): Promise<void> {
  const locked = keystore?.locked ?? false;
  tab.innerHTML = `
    <div class="card">
      ${locked
        ? `<p class="lock">This wallet is locked. <a href="#" id="unlock-link">Unlock it</a> to spend.</p>`
        : ""}
      <label>Pay to</label>
      <input id="send-address" placeholder="destination address" class="mono" />
      <label>Amount (SCT, or "all")</label>
      <input id="send-amount" placeholder="0.00000000" />
      <label>Fee rate (scar per kB)</label>
      <input id="send-fee" type="number" value="${params().minRelayFeePerKb}" />
      <div class="status"><button id="send-btn" ${locked ? "disabled" : ""}>Send</button>
        <span id="send-status" class="muted"></span></div>
    </div>
  `;
  document.getElementById("send-btn")!.addEventListener("click", () => void doSend());
  const unlockLink = document.getElementById("unlock-link");
  if (unlockLink) unlockLink.addEventListener("click", (e) => { e.preventDefault(); void unlockFlow(); });
}

async function unlockFlow(): Promise<void> {
  if (!keystore) return;
  const password = prompt("Wallet password:");
  if (password == null) return;
  try {
    await keystore.unlock(password);
    await renderTab();
  } catch (error) {
    alert(error instanceof Error ? error.message : String(error));
  }
}

async function doSend(): Promise<void> {
  if (!wallet) return;
  const address = (document.getElementById("send-address") as HTMLInputElement).value.trim();
  const amountText = (document.getElementById("send-amount") as HTMLInputElement).value.trim();
  const feeText = (document.getElementById("send-fee") as HTMLInputElement).value;
  const status = document.getElementById("send-status")!;
  status.textContent = "";
  status.className = "muted";

  if (!address) return showSendError("Enter the address you want to pay.");
  if (!isValidAddress(address, params().addressVersion)) {
    return showSendError("That is not a valid address for this network.");
  }
  const sendAll = amountText.toLowerCase() === "all";
  let amount = 0n;
  if (!sendAll) {
    try {
      amount = parseAmount(amountText);
    } catch (error) {
      return showSendError(error instanceof Error ? error.message : String(error));
    }
  }
  const feePerKb = BigInt(Math.max(0, Number(feeText) || 0));

  const button = document.getElementById("send-btn") as HTMLButtonElement;
  button.disabled = true;
  try {
    const result = sendAll
      ? await wallet.sendEverything(address, { feePerKb, broadcast: false })
      : await wallet.send(address, amount, { feePerKb, broadcast: false });

    const paid = result.transaction.outputs.reduce((s, o) => s + o.value, 0n) - result.change;
    const confirm = window.confirm(
      `Pay ${formatAmount(paid)} SCT to\n${address}\n\nFee: ${formatAmount(result.fee)} SCT\n\nBroadcast this transaction?`,
    );
    if (!confirm) {
      status.textContent = "cancelled";
      button.disabled = false;
      return;
    }
    status.textContent = "broadcasting…";
    const txid = await wallet.client.sendRawTransaction(toHex(serialize(result.transaction)));
    status.innerHTML = `sent: ${linkHtml(explorerLink("tx", txid), txid)}`;
    (document.getElementById("send-address") as HTMLInputElement).value = "";
    (document.getElementById("send-amount") as HTMLInputElement).value = "";
    await refreshSummary();
  } catch (error) {
    showSendError(error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = false;
  }
}

function showSendError(message: string): void {
  const status = document.getElementById("send-status")!;
  status.textContent = message;
  status.className = "error";
}

// ------------------------------------------------------------------ receive

function renderReceive(tab: HTMLElement): void {
  if (!keystore) return;
  const rows = keystore.addresses()
    .map((record) => {
      const row = `<tr>
        <td class="mono">${linkHtml(explorerLink("address", record.address), record.address)}</td>
        <td>${escapeHtml(record.label || "")}</td>
        <td class="mono"><button class="secondary" data-copy="${escapeHtml(record.address)}">Copy</button></td>
      </tr>`;
      return row;
    })
    .join("");
  tab.innerHTML = `
    <div class="card">
      <p class="hint">Give any of these addresses to whoever is paying you. A new address per
      payment keeps your history private.</p>
      <table><thead><tr><th>Address</th><th>Label</th><th></th></tr></thead><tbody>${rows}</tbody></table>
      <div class="status" style="margin-top:12px"><button id="new-address-btn">New address</button></div>
    </div>
  `;
  tab.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", () => void copyText(button.getAttribute("data-copy")!));
  });
  document.getElementById("new-address-btn")!.addEventListener("click", () => void newAddress());
}

async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    prompt("Copy this address:", text);
  }
}

async function newAddress(): Promise<void> {
  if (!keystore) return;
  if (keystore.locked) return void alert("Unlock the wallet first.");
  const label = prompt("Label (optional):") ?? "";
  wallet!.newAddress(label);
  await persist();
  await renderTab();
}

// ------------------------------------------------------------------ history

async function renderHistory(tab: HTMLElement): Promise<void> {
  if (!wallet) return;
  tab.innerHTML = `<div class="card"><table><thead><tr>
    <th class="num">Height</th><th class="num">Amount</th><th class="num">Conf</th><th>Transaction</th>
  </tr></thead><tbody id="history-rows"><tr><td colspan="4" class="muted">loading…</td></tr></tbody></table></div>`;
  try {
    const entries = await wallet.history(50);
    const rows = entries.length
      ? entries.map((item) => {
          const net = BigInt(item.net ?? 0);
          const sign = net >= 0n ? "+" : "-";
          const cls = net >= 0n ? "amount" : "amount neg";
          return `<tr>
            <td class="num">${item.height ?? "mempool"}</td>
            <td class="num ${cls}">${sign}${escapeHtml(formatAmount(net < 0n ? -net : net))}</td>
            <td class="num">${item.confirmations ?? 0}</td>
            <td class="mono">${linkHtml(explorerLink("tx", item.txid), item.txid)}</td>
          </tr>`;
        }).join("")
      : `<tr><td colspan="4" class="muted">No transactions yet.</td></tr>`;
    document.getElementById("history-rows")!.innerHTML = rows;
  } catch (error) {
    document.getElementById("history-rows")!.innerHTML =
      `<tr><td colspan="4" class="error">${escapeHtml(error instanceof Error ? error.message : error)}</td></tr>`;
  }
}

// ------------------------------------------------------------------ coins

async function renderCoins(tab: HTMLElement): Promise<void> {
  if (!wallet) return;
  tab.innerHTML = `<div class="card"><table><thead><tr>
    <th class="num">Amount</th><th>Type</th><th>Output</th>
  </tr></thead><tbody id="coins-rows"><tr><td colspan="3" class="muted">loading…</td></tr></tbody></table></div>`;
  try {
    const coins = await wallet.coins(false);
    const rows = coins.length
      ? coins.map((coin) => `<tr>
          <td class="num amount">${escapeHtml(formatAmount(coin.value))}</td>
          <td>payment</td>
          <td class="mono">${linkHtml(explorerLink("tx", displayTxid(coin.outpoint.txid)), displayTxid(coin.outpoint.txid))}:${coin.outpoint.index}</td>
        </tr>`).join("")
      : `<tr><td colspan="3" class="muted">No unspent outputs.</td></tr>`;
    document.getElementById("coins-rows")!.innerHTML = rows;
  } catch (error) {
    document.getElementById("coins-rows")!.innerHTML =
      `<tr><td colspan="3" class="error">${escapeHtml(error instanceof Error ? error.message : error)}</td></tr>`;
  }
}

// ------------------------------------------------------------------ mine

function formatHashrate(hs: number): string {
  if (hs >= 1_000_000) return `${(hs / 1_000_000).toFixed(1)} MH/s`;
  if (hs >= 1_000) return `${(hs / 1_000).toFixed(1)} kH/s`;
  return `${hs} H/s`;
}

function renderMine(tab: HTMLElement): void {
  if (!keystore || !wallet) return;

  const addresses = keystore.addresses();
  const savedAddress = localStorage.getItem("scarletcoin_mine_address") ?? addresses[0]?.address ?? "";
  const state = miner?.getState() ?? { status: "idle" as const, hashrate: 0, blocksFound: Number(localStorage.getItem("scarletcoin_blocks_found") ?? "0"), height: 0, difficulty: 0, address: savedAddress };

  const isMining = state.status === "mining" || state.status === "submitting";

  tab.innerHTML = `
    <div class="card">
      <p class="hint">Mine ScarletCoin directly from this browser. Your device computes SHA-256 hashes
      to find the next block. Finding a block is unlikely on mainnet — think of it as a lottery.</p>
    </div>
    <div class="card">
      <label>Mine to address</label>
      <select id="mine-address">
        ${addresses.map((a) => `<option value="${escapeHtml(a.address)}" ${a.address === state.address ? "selected" : ""}>${escapeHtml(a.address)} ${escapeHtml(a.label || "")}</option>`).join("")}
      </select>
      <div class="status" style="margin-top:12px">
        <button id="mine-toggle" ${!wallet ? "disabled" : ""}>${isMining ? "Stop" : "Start"} Mining</button>
        <span id="mine-status" class="${state.status === "error" ? "error" : "muted"}">
          ${state.status === "mining" ? "mining…" : state.status === "submitting" ? "submitting block…" : state.status === "error" ? "error" : "idle"}
        </span>
      </div>
    </div>
    <div class="card" id="mine-stats">
      <div class="mining-stats">
        <div class="mining-stat">
          <span class="mining-stat-label">Hashrate</span>
          <span class="mining-stat-value" id="mine-hashrate">${formatHashrate(state.hashrate)}</span>
        </div>
        <div class="mining-stat">
          <span class="mining-stat-label">Block Height</span>
          <span class="mining-stat-value" id="mine-height">${state.height || "…"}</span>
        </div>
        <div class="mining-stat">
          <span class="mining-stat-label">Difficulty</span>
          <span class="mining-stat-value" id="mine-difficulty">${state.difficulty ? state.difficulty.toFixed(2) : "…"}</span>
        </div>
        <div class="mining-stat">
          <span class="mining-stat-label">Blocks Found</span>
          <span class="mining-stat-value" id="mine-found">${state.blocksFound}</span>
        </div>
      </div>
    </div>
  `;

  document.getElementById("mine-toggle")!.addEventListener("click", () => void toggleMining());
}

function initMiner(): Miner {
  if (!miner) {
    miner = new Miner(client());
    miner.setListener(onMinerState);
  }
  return miner;
}

function onMinerState(state: MinerState): void {
  const statusEl = document.getElementById("mine-status");
  if (statusEl) {
    if (state.status === "mining") statusEl.textContent = "mining…";
    else if (state.status === "submitting") statusEl.textContent = "submitting block…";
    else if (state.status === "error") statusEl.textContent = "error";
    else statusEl.textContent = "idle";
    statusEl.className = state.status === "error" ? "error" : "muted";
  }

  const hashEl = document.getElementById("mine-hashrate");
  if (hashEl) hashEl.textContent = formatHashrate(state.hashrate);

  const heightEl = document.getElementById("mine-height");
  if (heightEl) heightEl.textContent = String(state.height || "…");

  const diffEl = document.getElementById("mine-difficulty");
  if (diffEl) diffEl.textContent = state.difficulty ? state.difficulty.toFixed(2) : "…";

  const foundEl = document.getElementById("mine-found");
  if (foundEl) foundEl.textContent = String(state.blocksFound);

  const toggleBtn = document.getElementById("mine-toggle");
  if (toggleBtn) {
    const isMining = state.status === "mining" || state.status === "submitting";
    toggleBtn.textContent = isMining ? "Stop Mining" : "Start Mining";
  }
}

async function toggleMining(): Promise<void> {
  if (!keystore || !wallet) return;
  const m = initMiner();

  if (m.getState().status === "idle") {
    const address = (document.getElementById("mine-address") as HTMLSelectElement).value;
    localStorage.setItem("scarletcoin_mine_address", address);
    try {
      await m.start(address, params().addressVersion);
    } catch (error) {
      alert(error instanceof Error ? error.message : String(error));
    }
  } else {
    m.stop();
  }
}

// ------------------------------------------------------------------ settings

function renderSettings(tab: HTMLElement): void {
  if (!keystore) return;
  tab.innerHTML = `
    <div class="card">
      <label>Network</label>
      <select id="settings-network">
        ${Object.keys(NETWORKS).map((n) => `<option value="${n}" ${n === network ? "selected" : ""}>${n}</option>`).join("")}
      </select>
      <label>Node RPC URL</label>
      <input id="settings-node" value="${escapeHtml(nodeUrl)}" class="mono" />
      <div class="status" style="margin-top:12px"><button id="settings-save">Save connection</button></div>
    </div>
    <div class="card">
      <h2 style="margin-top:0">Wallet</h2>
      <div class="row">
        <button id="export-btn" class="secondary">Export wallet file</button>
        <button id="import-wif-btn" class="secondary">Import private key (WIF)</button>
        <button id="password-btn" class="secondary">Set / change password</button>
      </div>
      <div class="row" style="margin-top:10px">
        <button id="wipe-btn" class="danger">Forget this wallet</button>
      </div>
      <p class="hint">Forgetting removes the wallet from this browser. Export it first if you
      want to keep the keys.</p>
    </div>
  `;
  document.getElementById("settings-save")!.addEventListener("click", () => void saveConnection());
  document.getElementById("export-btn")!.addEventListener("click", () => void exportWallet());
  document.getElementById("import-wif-btn")!.addEventListener("click", () => void importWif());
  document.getElementById("password-btn")!.addEventListener("click", () => void setPassword());
  document.getElementById("wipe-btn")!.addEventListener("click", () => void wipeWallet());
}

async function saveConnection(): Promise<void> {
  network = (document.getElementById("settings-network") as HTMLSelectElement).value;
  nodeUrl = (document.getElementById("settings-node") as HTMLInputElement).value.trim();
  await saveSettings({ network, nodeUrl });
  if (keystore && keystore.network !== network) {
    // A wallet belongs to one network; changing network requires reloading it.
    keystore = await Keystore.fromDocument(await keystore.toDocument());
  }
  wallet = new Wallet(keystore!, client());
  await renderMain();
}

async function exportWallet(): Promise<void> {
  if (!keystore) return;
  const walletDoc = await keystore.toDocument();
  const blob = new Blob([JSON.stringify(walletDoc, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `scarletcoin-${keystore.network}-wallet.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function importWif(): Promise<void> {
  if (!keystore || !wallet) return;
  if (keystore.locked) return void alert("Unlock the wallet first.");
  const wif = prompt("Private key (WIF):");
  if (!wif?.trim()) return;
  try {
    wallet.importWif(wif.trim());
    await persist();
    await renderTab();
  } catch (error) {
    alert(error instanceof Error ? error.message : String(error));
  }
}

async function setPassword(): Promise<void> {
  if (!keystore) return;
  if (keystore.locked) return void alert("Unlock the wallet first.");
  const password = prompt("New password (leave empty to remove encryption):");
  if (password == null) return;
  await keystore.setPassword(password || null);
  await persist();
  alert(password ? "The wallet is now encrypted." : "The wallet is no longer encrypted.");
}

async function wipeWallet(): Promise<void> {
  if (!window.confirm("Forget this wallet from this browser? This cannot be undone.")) return;
  if (miner) miner.stop();
  await clearWallet();
  keystore = null;
  wallet = null;
  miner = null;
  renderOnboarding();
}

// ------------------------------------------------------------------ bootstrap

function registerServiceWorker(): void {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("sw.js").catch(() => {
      // Non-critical: a missing service worker does not affect wallet behaviour.
    });
  }
}

async function init(): Promise<void> {
  const saved = await loadSettings();
  network = saved?.network ?? "mainnet";
  nodeUrl = saved?.nodeUrl ?? getParams(network).publicNodes[0] ?? `http://127.0.0.1:${getParams(network).defaultRpcPort}`;

  const document = await loadWalletDocument();
  if (!document) {
    renderOnboarding();
    return;
  }
  try {
    keystore = await Keystore.fromDocument(document as unknown as WalletDocument);
    network = keystore.network;
    wallet = new Wallet(keystore, client());
    await renderMain();
  } catch (error) {
    renderOnboarding(`Could not load the saved wallet: ${error instanceof Error ? error.message : error}`);
  }
}

void init();
registerServiceWorker();
