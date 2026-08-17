/**
 * Coin selection and transaction building, matching ``scarletcoin.wallet.builder``.
 * This is the only place in the wallet that creates spending transactions.
 */
import { derivePublicKey, sign } from "./keys.js";
import {
  type OutPoint,
  type Transaction,
  type TxInput,
  type TxOutput,
  serialize,
  signatureHash,
} from "./transaction.js";
import { toHex } from "./util.js";

export const PER_INPUT_BYTES = 135;
export const PER_OUTPUT_BYTES = 28;
export const BASE_BYTES = 11;

export interface Coin {
  outpoint: OutPoint;
  value: bigint;
  pubkeyHash: Uint8Array;
}

export interface Destination {
  hash: Uint8Array;
  value: bigint;
}

export interface BuiltTransaction {
  transaction: Transaction;
  fee: bigint;
  change: bigint;
  totalInput: bigint;
  coins: Coin[];
}

export class InsufficientFundsError extends Error {}

export function estimateSize(inputCount: number, outputCount: number): number {
  return BASE_BYTES + inputCount * PER_INPUT_BYTES + outputCount * PER_OUTPUT_BYTES;
}

export function feeForSize(size: number, feePerKb: bigint): bigint {
  if (feePerKb <= 0n) return 0n;
  const value = (BigInt(size) * feePerKb + 999n) / 1000n;
  return value < 1n ? 1n : value;
}

export function dustThreshold(feePerKb: bigint): bigint {
  return feeForSize(PER_INPUT_BYTES, feePerKb) * 3n;
}

export function selectCoins(
  coins: Coin[],
  amount: bigint,
  feePerKb: bigint,
  outputCount: number,
): { chosen: Coin[]; fee: bigint } {
  if (amount < 0n) throw new Error("amount must not be negative");

  const required = (count: number): bigint =>
    amount + feeForSize(estimateSize(count, outputCount + 1), feePerKb);

  const usable = [...coins].sort((a, b) => (b.value < a.value ? -1 : b.value > a.value ? 1 : 0));
  const exact = usable.filter((coin) => coin.value >= required(1));
  if (exact.length > 0) {
    const chosen = [exact.reduce((best, coin) => (coin.value < best.value ? coin : best))];
    return { chosen, fee: feeForSize(estimateSize(1, outputCount + 1), feePerKb) };
  }

  const chosen: Coin[] = [];
  let total = 0n;
  for (const coin of usable) {
    chosen.push(coin);
    total += coin.value;
    if (total >= required(chosen.length)) {
      return { chosen, fee: feeForSize(estimateSize(chosen.length, outputCount + 1), feePerKb) };
    }
  }
  const need = required(Math.max(chosen.length, 1));
  throw new InsufficientFundsError(
    `need ${need} scar (payment plus fee) but only ${total} scar is available`,
  );
}

function resolveHash(destination: Uint8Array): Uint8Array {
  if (destination.length !== 20) {
    throw new Error("a destination must be a 20-byte public-key hash");
  }
  return destination;
}

function findKey(keys: Map<string, Uint8Array>, pubkeyHash: Uint8Array): Uint8Array {
  const key = keys.get(toHex(pubkeyHash));
  if (!key) throw new Error(`no private key for coin`);
  return key;
}

function signInputs(
  unsigned: Transaction,
  coins: Coin[],
  keys: Map<string, Uint8Array>,
): Transaction {
  const inputs = unsigned.inputs.map((input, index) => {
    const coin = coins[index]!;
    const key = findKey(keys, coin.pubkeyHash);
    const digest = signatureHash(unsigned, index, coin.value);
    return {
      prevout: input.prevout,
      publicKey: derivePublicKey(key),
      signature: sign(digest, key),
    } satisfies TxInput;
  });
  return { ...unsigned, inputs };
}

export function buildSweepTransaction(params: {
  spendableCoins: Coin[];
  keys: Map<string, Uint8Array>;
  destination: Uint8Array;
  feePerKb: bigint;
  lockTime?: number;
}): BuiltTransaction {
  const { spendableCoins, keys, feePerKb, lockTime = 0 } = params;
  if (spendableCoins.length === 0) throw new InsufficientFundsError("there are no coins to spend");
  const pubkeyHash = resolveHash(params.destination);
  const total = spendableCoins.reduce((sum, coin) => sum + coin.value, 0n);
  const fee = feeForSize(estimateSize(spendableCoins.length, 1), feePerKb);
  const amount = total - fee;
  if (amount <= 0n) {
    throw new InsufficientFundsError(`the ${total} scar available does not cover the ${fee} scar fee`);
  }
  const unsigned: Transaction = {
    version: 1,
    inputs: spendableCoins.map((coin) => ({
      prevout: coin.outpoint,
      publicKey: new Uint8Array(0),
      signature: new Uint8Array(0),
    })),
    outputs: [{ value: amount, pubkeyHash }],
    lockTime,
    coinbaseData: new Uint8Array(0),
  };
  return {
    transaction: signInputs(unsigned, spendableCoins, keys),
    fee,
    change: 0n,
    totalInput: total,
    coins: spendableCoins,
  };
}

export function buildTransaction(params: {
  spendableCoins: Coin[];
  keys: Map<string, Uint8Array>;
  outputs: Destination[];
  changeHash: Uint8Array;
  feePerKb: bigint;
  lockTime?: number;
}): BuiltTransaction {
  const { spendableCoins, keys, feePerKb, changeHash, lockTime = 0 } = params;
  if (params.outputs.length === 0) throw new Error("a transaction must pay at least one output");
  const targets = params.outputs.map((output) => ({
    hash: resolveHash(output.hash),
    value: output.value,
  }));
  for (const target of targets) {
    if (target.value <= 0n) throw new Error("output amounts must be positive");
  }
  const amount = targets.reduce((sum, target) => sum + target.value, 0n);

  const { chosen, fee: selectedFee } = selectCoins(spendableCoins, amount, feePerKb, targets.length);
  let fee = selectedFee;
  const totalInput = chosen.reduce((sum, coin) => sum + coin.value, 0n);
  let change = totalInput - amount - fee;
  if (change < 0n) throw new InsufficientFundsError("selected coins do not cover the fee");

  const txOutputs: TxOutput[] = targets.map((target) => ({
    value: target.value,
    pubkeyHash: target.hash,
  }));
  if (change > dustThreshold(feePerKb)) {
    txOutputs.push({ value: change, pubkeyHash: changeHash });
  } else {
    // Too small to be worth its own output: leave it to the miner as extra fee.
    fee += change;
    change = 0n;
  }

  const unsigned: Transaction = {
    version: 1,
    inputs: chosen.map((coin) => ({
      prevout: coin.outpoint,
      publicKey: new Uint8Array(0),
      signature: new Uint8Array(0),
    })),
    outputs: txOutputs,
    lockTime,
    coinbaseData: new Uint8Array(0),
  };

  return {
    transaction: signInputs(unsigned, chosen, keys),
    fee,
    change,
    totalInput,
    coins: chosen,
  };
}

/** Serialise a built transaction to hex, ready for ``sendrawtransaction``. */
export function builtTxHex(built: BuiltTransaction): string {
  return toHex(serialize(built.transaction));
}

export function builtTxSize(built: BuiltTransaction): number {
  return serialize(built.transaction).length;
}

export function coinHasKey(coin: Coin, keys: Map<string, Uint8Array>): boolean {
  return keys.has(toHex(coin.pubkeyHash));
}