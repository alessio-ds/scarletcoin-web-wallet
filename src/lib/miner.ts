import { RpcClient } from "./rpc.js";
import { decodeAddress } from "./keys.js";
import {
  parseBlockTemplate,
  buildCandidateBlock,
  setHeaderNonce,
  rebuildBlockHex,
  type CandidateBlock,
} from "./template.js";

export type MinerStatus = "idle" | "mining" | "submitting" | "error";

export interface MinerState {
  status: MinerStatus;
  hashrate: number;
  blocksFound: number;
  height: number;
  difficulty: number;
  address: string;
}

export type MinerListener = (state: MinerState) => void;

/** How often a fresh block template is fetched, in milliseconds. */
const REFRESH_INTERVAL_MS = 30_000;

/** How often the chain tip is checked so a stale template is noticed early. */
const TIP_POLL_INTERVAL_MS = 5_000;

export class Miner {
  private worker: Worker | null = null;
  private client: RpcClient;
  private listener: MinerListener | null = null;
  private address: string = "";
  private pubkeyHash: Uint8Array = new Uint8Array(0);
  private status: MinerStatus = "idle";
  private hashrate: number = 0;
  private blocksFound: number = 0;
  private height: number = 0;
  private difficulty: number = 0;
  private currentCandidate: CandidateBlock | null = null;
  /** Bumped every time a new candidate replaces the old one. */
  private candidateGeneration = 0;
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private tipTimer: ReturnType<typeof setInterval> | null = null;
  private stopped = false;

  constructor(client: RpcClient) {
    this.client = client;
  }

  /** Point the miner at the node the rest of the wallet is currently using. */
  setClient(client: RpcClient): void {
    this.client = client;
  }

  setListener(listener: MinerListener | null): void {
    this.listener = listener;
  }

  async start(address: string, addressVersion: number): Promise<void> {
    this.address = address;
    const decoded = decodeAddress(address, addressVersion);
    this.pubkeyHash = decoded.hash;
    this.stopped = false;
    this.blocksFound = Number(localStorage.getItem("scarletcoin_blocks_found") ?? "0");

    // Fetch the first template before reporting success: if the node will not
    // hand out work, the caller must hear about it rather than see a miner that
    // claims to be running while it has nothing to hash.
    await this.refreshTemplate(true);
    if (this.stopped) return;

    this.setStatus("mining");
    this.refreshTimer = setInterval(() => void this.refreshTemplate(), REFRESH_INTERVAL_MS);
    this.tipTimer = setInterval(() => void this.pollTip(), TIP_POLL_INTERVAL_MS);
  }

  stop(): void {
    this.stopped = true;
    this.stopWorker();
    this.stopTimers();
    this.setStatus("idle");
    this.hashrate = 0;
    this.emit();
  }

  getState(): MinerState {
    return {
      status: this.status,
      hashrate: this.hashrate,
      blocksFound: this.blocksFound,
      height: this.height,
      difficulty: this.difficulty,
      address: this.address,
    };
  }

  private stopTimers(): void {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (this.tipTimer) {
      clearInterval(this.tipTimer);
      this.tipTimer = null;
    }
  }

  /**
   * Fetch a new template and the difficulty, then (re)start the worker on it.
   *
   * When ``throwOnError`` is set the failure is propagated so ``start`` can
   * report it; the periodic caller logs and keeps the previous candidate.
   */
  private async refreshTemplate(throwOnError = false): Promise<void> {
    try {
      const raw = await this.client.getBlockTemplate();
      const template = parseBlockTemplate(raw);
      this.height = template.height;
      try {
        this.difficulty = await this.client.getDifficulty();
      } catch {
        // A missing difficulty only affects the display; keep the last value.
      }

      const extraNonce = new Uint8Array(4);
      const dv = new DataView(extraNonce.buffer);
      dv.setUint32(0, Math.floor(Math.random() * 0xffffffff), true);

      this.installCandidate(buildCandidateBlock(template, this.pubkeyHash, extraNonce));
    } catch (error) {
      console.error("Failed to refresh block template:", error);
      if (throwOnError) {
        this.setStatus("error");
        throw error;
      }
    }
  }

  private installCandidate(candidate: CandidateBlock): void {
    this.currentCandidate = candidate;
    this.candidateGeneration += 1;
    this.stopWorker();
    if (!this.stopped) this.startWorker();
  }

  /** Refresh the template as soon as the chain has moved on from ours. */
  private async pollTip(): Promise<void> {
    if (this.stopped || !this.currentCandidate) return;
    try {
      const count = await this.client.getBlockCount();
      if (count >= this.height) {
        await this.refreshTemplate();
      }
    } catch {
      // A transient RPC failure is not fatal; the periodic refresh will retry.
    }
  }

  private startWorker(): void {
    const candidate = this.currentCandidate;
    if (!candidate) return;
    // Capture the candidate and its generation: a solution found for an older
    // template must never be submitted against a newer one.
    const generation = this.candidateGeneration;

    const worker = new Worker(new URL("../workers/miner.worker.ts", import.meta.url), {
      type: "module",
    });
    this.worker = worker;

    worker.onmessage = (e: MessageEvent) => {
      const msg = e.data;
      if (generation !== this.candidateGeneration) return;
      if (msg.type === "hashrate") {
        this.hashrate = msg.elapsed > 0 ? Math.round(msg.hashes / msg.elapsed) : 0;
        this.emit();
      } else if (msg.type === "solution") {
        void this.submitSolution(candidate, msg.nonce);
      } else if (msg.type === "exhausted") {
        // The 32-bit nonce space is used up; a new template rolls a new extra
        // nonce in the coinbase, which gives the worker fresh room.
        void this.refreshTemplate();
      }
    };

    worker.onerror = (err) => {
      console.error("Miner worker error:", err);
      this.setStatus("error");
      this.emit();
    };

    worker.postMessage({
      type: "start",
      header: Array.from(candidate.header),
      target: candidate.target.toString(),
      startNonce: 0,
    });
  }

  private stopWorker(): void {
    if (this.worker) {
      this.worker.postMessage({ type: "stop" });
      this.worker.terminate();
      this.worker = null;
    }
  }

  private async submitSolution(candidate: CandidateBlock, nonce: number): Promise<void> {
    if (this.stopped || candidate !== this.currentCandidate) return;

    this.setStatus("submitting");
    const solvedHeader = setHeaderNonce(candidate.header, nonce);
    const blockHex = rebuildBlockHex(solvedHeader, candidate.transactions);

    let connected = false;
    try {
      const result = await this.client.submitBlock(blockHex);
      // "side-branch" and "orphan" mean the block was well formed but did not
      // extend the chain; only a connected block is a block we actually mined.
      connected = result.status === "connected";
      if (connected) {
        this.blocksFound++;
        localStorage.setItem("scarletcoin_blocks_found", String(this.blocksFound));
        console.log(`Block found and accepted! Hash: ${result.hash}, Height: ${result.height}`);
      } else {
        console.warn(`Block not accepted (${result.status}); fetching fresh work`);
      }
      this.emit();
    } catch (error) {
      console.error("Block rejected:", error);
    }

    // Either way the template we were mining is spent — it was accepted, or the
    // chain moved on. Never restart the worker on the same stale candidate.
    if (this.stopped) return;
    await this.refreshTemplate();
    if (this.stopped) return;
    this.setStatus(this.status === "error" ? "error" : "mining");
    this.emit();
  }

  private setStatus(status: MinerStatus): void {
    this.status = status;
    this.emit();
  }

  private emit(): void {
    if (this.listener) {
      this.listener(this.getState());
    }
  }
}