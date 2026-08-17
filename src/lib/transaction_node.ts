import { hash256 } from "./hashing.js";
import { Writer } from "./serialize.js";
import type { Transaction } from "./transaction.js";

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
): Transaction {
  return {
    version: 1,
    inputs: [
      {
        prevout: { txid: new Uint8Array(32), index: 0xffffffff },
        publicKey: new Uint8Array(0),
        signature: new Uint8Array(0),
      },
    ],
    outputs: [{ value: reward, pubkeyHash }],
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
  offset += inputCount.value * 36;
  const outputCount = readVarint(serialized, offset);
  offset += outputCount.bytesRead;
  offset += outputCount.value * 28;
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

export function serializeBlock(header: Uint8Array, transactions: Uint8Array[]): Uint8Array {
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
