import { fromHex, toHex } from "./util.js";
import { serialize, txid } from "./transaction.js";
import {
  computeTxidFromSerialized,
  computeMerkleRoot,
  serializeBlockHeader,
  serializeBlock,
  buildCoinbase,
} from "./transaction_node.js";

export interface BlockTemplate {
  height: number;
  previousBlock: Uint8Array;
  bits: number;
  target: bigint;
  minTime: number;
  currentTime: number;
  coinbaseValue: bigint;
  version: number;
  transactions: Uint8Array[];
}

export interface CandidateBlock {
  blockHex: string;
  header: Uint8Array;
  target: bigint;
  transactions: Uint8Array[];
}

export function parseBlockTemplate(raw: {
  height: number;
  previous_block: string;
  bits: string;
  target: string;
  min_time: number;
  current_time: number;
  coinbase_value: number;
  version: number;
  transactions: string[];
}): BlockTemplate {
  return {
    height: raw.height,
    previousBlock: fromHex(raw.previous_block).slice().reverse(),
    bits: parseInt(raw.bits, 16),
    target: BigInt("0x" + raw.target),
    minTime: raw.min_time,
    currentTime: raw.current_time,
    coinbaseValue: BigInt(raw.coinbase_value),
    version: raw.version ?? 1,
    transactions: raw.transactions.map((t: string) => fromHex(t)),
  };
}

export function buildCandidateBlock(
  template: BlockTemplate,
  pubkeyHash: Uint8Array,
  extraNonce: Uint8Array,
): CandidateBlock {
  const coinbase = buildCoinbase(template.height, template.coinbaseValue, pubkeyHash, extraNonce);
  const coinbaseSerialized = serialize(coinbase);

  const txids: Uint8Array[] = [txid(coinbase)];
  for (const tx of template.transactions) {
    txids.push(computeTxidFromSerialized(tx));
  }

  const merkleRoot = computeMerkleRoot(txids);
  const timestamp = Math.max(Math.floor(Date.now() / 1000), template.minTime + 1);

  const header = serializeBlockHeader(
    template.version,
    template.previousBlock,
    merkleRoot,
    timestamp,
    template.bits,
    0,
  );

  const serializedTxs: Uint8Array[] = [coinbaseSerialized, ...template.transactions];
  const block = serializeBlock(header, serializedTxs);

  return {
    blockHex: toHex(block),
    header,
    target: template.target,
    transactions: serializedTxs,
  };
}

export function setHeaderNonce(header: Uint8Array, nonce: number): Uint8Array {
  const result = new Uint8Array(header);
  const dv = new DataView(result.buffer);
  dv.setUint32(76, nonce, true);
  return result;
}

export function rebuildBlockHex(header: Uint8Array, transactions: Uint8Array[]): string {
  return toHex(serializeBlock(header, transactions));
}
