import { sha256 } from "@noble/hashes/sha256";

function doubleSha256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

function hashToBigIntLE(hash: Uint8Array): bigint {
  let result = 0n;
  for (let i = 31; i >= 0; i--) {
    result = (result << 8n) | BigInt(hash[i]!);
  }
  return result;
}

interface StartMessage {
  type: "start";
  header: number[];
  target: string;
  startNonce: number;
}

interface StopMessage {
  type: "stop";
}

type WorkerMessage = { type: "hashrate"; hashes: number; elapsed: number } | { type: "solution"; nonce: number };

let running = false;

self.onmessage = (e: MessageEvent<StartMessage | StopMessage>) => {
  const msg = e.data;

  if (msg.type === "stop") {
    running = false;
    return;
  }

  if (msg.type === "start") {
    const header = new Uint8Array(msg.header);
    const target = BigInt(msg.target);

    if (header.length !== 80) {
      self.postMessage({ type: "error", message: "header must be 80 bytes" });
      return;
    }

    running = true;
    let nonce = msg.startNonce;
    const start = performance.now();
    let hashes = 0;
    const reportInterval = 500;
    let lastReport = start;

    while (running && nonce < 0x100000000) {
      const dv = new DataView(header.buffer, header.byteOffset, 80);
      dv.setUint32(76, nonce, true);
      const hash = doubleSha256(header);
      hashes++;

      if (hashToBigIntLE(hash) <= target) {
        self.postMessage({ type: "solution", nonce });
        return;
      }

      nonce++;
      const now = performance.now();
      if (now - lastReport >= reportInterval) {
        self.postMessage({ type: "hashrate", hashes, elapsed: (now - lastReport) / 1000 });
        lastReport = now;
        hashes = 0;
      }
    }

    const elapsed = (performance.now() - start) / 1000;
    if (hashes > 0) {
      self.postMessage({ type: "hashrate", hashes, elapsed });
    }
    self.postMessage({ type: "exhausted" });
  }
};