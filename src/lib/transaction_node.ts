import { hash256 } from "./hashing.js";
import { Writer } from "./serialize.js";

const NULL_HASH = new Uint8Array(32);
const NULL_INDEX = 0xFFFFFFFF;
const SEQUENCE_FINAL = 0xFFFFFFFF;
const OUTPUT_P2PKH = 0;

export interface CoinbaseTxInput {
  txid: Uint8Array;
  index: number;
  sequence: number;
}

export interface CoinbaseTxOutput {
  type: number;
  value: bigint;
  payload: Uint8Array;
}

export interface CoinbaseTransaction {
  version: number;
  inputs: CoinbaseTxInput[];
  outputs: CoinbaseTxOutput[];
  lockTime: number;
  coinbaseData: Uint8Array;
}

export function coinbaseInput(): CoinbaseTxInput {
  return { txid: NULL_HASH, index: NULL_INDEX, sequence: SEQUENCE_FINAL };
}

export function p2pkhOutput(value: bigint, pubkeyHash: Uint8Array): CoinbaseTxOutput {
  return { type: OUTPUT_P2PKH, value, payload: pubkeyHash };
}

export function serializeBodyNode(tx: CoinbaseTransaction): Uint8Array {
  const writer = new Writer();
  writer.uint32(tx.version);
  writer.varint(tx.inputs.length);
  for (const input of tx.inputs) {
    writer.hash32(input.txid).uint32(input.index).uint32(input.sequence);
  }
  writer.varint(tx.outputs.length);
  for (const output of tx.outputs) {
    writer.uint8(output.type).uint64(output.value).raw(output.payload);
  }
  writer.uint32(tx.lockTime);
  writer.varbytes(tx.coinbaseData);
  return writer.getvalue();
}

export function serializeNode(tx: CoinbaseTransaction): Uint8Array {
  const writer = new Writer();
  writer.raw(serializeBodyNode(tx));
  for (const _input of tx.inputs) {
    writer.varint(0);
  }
  return writer.getvalue();
}

export function txidNode(tx: CoinbaseTransaction): Uint8Array {
  return hash256(serializeBodyNode(tx));
}

export function encodeCoinbaseData(height: number, extra: Uint8Array = new Uint8Array(0)): Uint8Array {
  const result = new Uint8Array(4 + extra.length);
  const dv = new DataView(result.buffer);
  dv.setUint32(0, height, true);
  result.set(extra, 4);
  return result;
}

export function buildCoinbase(
  height: number,
  reward: bigint,
  pubkeyHash: Uint8Array,
  extra: Uint8Array = new Uint8Array(0),
): CoinbaseTransaction {
  return {
    version: 1,
    inputs: [coinbaseInput()],
    outputs: [p2pkhOutput(reward, pubkeyHash)],
    lockTime: 0,
    coinbaseData: encodeCoinbaseData(height, extra),
  };
}

function readVarint(bytes: Uint8Array, offset: number): { value: number; bytesRead: number } {
  if (offset >= bytes.length) throw new Error("truncated varint");
  const first = bytes[offset]!;
  if (first < 0xfd) return { value: first, bytesRead: 1 };
  if (first === 0xfd) {
    if (offset + 3 > bytes.length) throw new Error("truncated varint");
    return { value: new DataView(bytes.buffer, bytes.byteOffset + offset + 1, 2).getUint16(0, true), bytesRead: 3 };
  }
  if (first === 0xfe) {
    if (offset + 5 > bytes.length) throw new Error("truncated varint");
    return { value: new DataView(bytes.buffer, bytes.byteOffset + offset + 1, 4).getUint32(0, true), bytesRead: 5 };
  }
  if (offset + 9 > bytes.length) throw new Error("truncated varint");
  return { value: Number(new DataView(bytes.buffer, bytes.byteOffset + offset + 1, 8).getBigUint64(0, true)), bytesRead: 9 };
}

export function computeTxidFromSerialized(serialized: Uint8Array): Uint8Array {
  let offset = 4;
  const inputCount = readVarint(serialized, offset);
  offset += inputCount.bytesRead;
  offset += inputCount.value * 40;
  const outputCount = readVarint(serialized, offset);
  offset += outputCount.bytesRead;
  offset += outputCount.value * 29;
  offset += 4;
  const coinbaseLen = readVarint(serialized, offset);
  offset += coinbaseLen.bytesRead;
  offset += coinbaseLen.value;
  return hash256(serialized.slice(0, offset));
}

export function serializeBlockHeader(
  version: number,
  prevHash: Uint8Array,
  merkleRoot: Uint8Array,
  timestamp: number,
  bits: number,
  nonce: number,
): Uint8Array {
  const writer = new Writer();
  writer.uint32(version);
  writer.hash32(prevHash);
  writer.hash32(merkleRoot);
  writer.uint32(timestamp);
  writer.uint32(bits);
  writer.uint32(nonce);
  return writer.getvalue();
}

export function serializeBlock(
  header: Uint8Array,
  transactions: Uint8Array[],
): Uint8Array {
  const writer = new Writer();
  writer.raw(header);
  writer.varint(transactions.length);
  for (const tx of transactions) {
    writer.raw(tx);
  }
  return writer.getvalue();
}

export function computeMerkleRoot(txids: Uint8Array[]): Uint8Array {
  if (txids.length === 0) throw new Error("cannot compute merkle root of zero transactions");
  let level: Uint8Array[] = txids.map((txid) => new Uint8Array(txid));
  while (level.length > 1) {
    if (level.length % 2 !== 0) {
      level.push(level[level.length - 1]!);
    }
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const combined = new Uint8Array(64);
      combined.set(level[i]!, 0);
      combined.set(level[i + 1]!, 32);
      next.push(hash256(combined));
    }
    level = next;
  }
  return level[0]!;
}