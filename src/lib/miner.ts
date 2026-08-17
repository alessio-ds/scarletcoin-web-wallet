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
  private refreshTimer: ReturnType<typeof setInterval> | null = null;
  private stopped = false;

  constructor(client: RpcClient) {
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

    await this.refreshTemplate();
    if (this.stopped) return;

    this.setStatus("mining");
    this.startWorker();
    this.refreshTimer = setInterval(() => {
      void this.refreshTemplate();
    }, 30_000);
  }

  stop(): void {
    this.stopped = true;
    this.stopWorker();
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
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

  private async refreshTemplate(): Promise<void> {
    try {
      const [raw, difficulty] = await Promise.all([
        this.client.getBlockTemplate(),
        this.client.getDifficulty(),
      ]);
      const template = parseBlockTemplate(raw);
      this.height = template.height;
      this.difficulty = difficulty;

      const extraNonce = new Uint8Array(4);
      const dv = new DataView(extraNonce.buffer);
      dv.setUint32(0, Math.floor(Math.random() * 0xffffffff), true);

      const candidate = buildCandidateBlock(template, this.pubkeyHash, extraNonce);
      this.currentCandidate = candidate;

      this.stopWorker();
      if (!this.stopped) {
        this.startWorker();
      }
    } catch (error) {
      console.error("Failed to refresh block template:", error);
    }
  }

  private startWorker(): void {
    if (!this.currentCandidate) return;

    this.worker = new Worker(
      new URL("../workers/miner.worker.ts", import.meta.url),
      { type: "module" },
    );

    this.worker.onmessage = (e: MessageEvent) => {
      const msg = e.data;
      if (msg.type === "hashrate") {
        this.hashrate = msg.elapsed > 0 ? Math.round(msg.hashes / msg.elapsed) : 0;
        this.emit();
      } else if (msg.type === "solution") {
        void this.submitSolution(msg.nonce);
      }
    };

    this.worker.onerror = (err) => {
      console.error("Miner worker error:", err);
      this.setStatus("error");
      this.emit();
    };

    this.worker.postMessage({
      type: "start",
      header: Array.from(this.currentCandidate.header),
      target: this.currentCandidate.target.toString(),
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

  private async submitSolution(nonce: number): Promise<void> {
    if (!this.currentCandidate) return;

    this.setStatus("submitting");
    const solvedHeader = setHeaderNonce(this.currentCandidate.header, nonce);
    const blockHex = rebuildBlockHex(solvedHeader, this.currentCandidate.transactions);

    try {
      const result = await this.client.submitBlock(blockHex);
      this.blocksFound++;
      localStorage.setItem("scarletcoin_blocks_found", String(this.blocksFound));

      console.log(`Block found and accepted! Hash: ${result.hash}, Height: ${result.height}`);
      this.emit();

      await this.refreshTemplate();
      if (!this.stopped && this.status !== "error") {
        this.setStatus("mining");
      }
    } catch (error) {
      console.error("Block rejected:", error);
      this.stopWorker();
      if (!this.stopped) {
        this.startWorker();
      }
      this.setStatus("mining");
      this.emit();
    }
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