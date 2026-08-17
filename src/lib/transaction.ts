/**
 * Transactions, matching ``scarletcoin.core.transaction``. The wallet only ever
 * builds and signs; parsing happens server-side, so this module implements the
 * writing half plus the txid and signature-hash computation.
 */
import { hash256 } from "./hashing.js";
import { Writer } from "./serialize.js";
import { reverseBytes, toHex } from "./util.js";

export const MAX_MONEY = 21_000_000n * 100_000_000n;

const SIGHASH_TAG = new TextEncoder().encode("ScarletCoin/sighash/1");

export interface OutPoint {
  /** Transaction id in internal (little-endian) byte order. */
  txid: Uint8Array;
  index: number;
}

export interface TxOutput {
  value: bigint;
  pubkeyHash: Uint8Array;
}

export interface TxInput {
  prevout: OutPoint;
  publicKey: Uint8Array;
  signature: Uint8Array;
}

export interface Transaction {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  lockTime: number;
  coinbaseData: Uint8Array;
}

export function serializeBody(tx: Transaction): Uint8Array {
  const writer = new Writer();
  writer.uint32(tx.version);
  writer.varint(tx.inputs.length);
  for (const input of tx.inputs) {
    writer.hash32(input.prevout.txid).uint32(input.prevout.index);
  }
  writer.varint(tx.outputs.length);
  for (const output of tx.outputs) {
    writer.uint64(output.value).raw(output.pubkeyHash);
  }
  writer.uint32(tx.lockTime);
  writer.varbytes(tx.coinbaseData);
  return writer.getvalue();
}

export function serialize(tx: Transaction): Uint8Array {
  const writer = new Writer();
  writer.raw(serializeBody(tx));
  for (const input of tx.inputs) {
    writer.varbytes(input.publicKey).varbytes(input.signature);
  }
  return writer.getvalue();
}

/** Transaction id in internal byte order (double SHA-256 of the body). */
export function txid(tx: Transaction): Uint8Array {
  return hash256(serializeBody(tx));
}

/** Transaction id as a big-endian hex string (the display order the RPC uses). */
export function txidHex(tx: Transaction): string {
  return toHex(reverseBytes(txid(tx)));
}

export function signatureHash(
  tx: Transaction,
  inputIndex: number,
  prevoutValue: bigint,
): Uint8Array {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new Error(`no input at index ${inputIndex}`);
  }
  const writer = new Writer();
  writer.varbytes(SIGHASH_TAG);
  writer.raw(serializeBody(tx));
  writer.uint32(inputIndex);
  writer.uint64(prevoutValue);
  return hash256(writer.getvalue());
}

export function size(tx: Transaction): number {
  return serialize(tx).length;
}

export function totalOutput(tx: Transaction): bigint {
  return tx.outputs.reduce((sum, output) => sum + output.value, 0n);
}