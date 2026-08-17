/**
 * BIP-0039 mnemonic sentences, matching ``scarletcoin.crypto.bip39``.
 * Only the English word list is bundled.
 */
import { sha256 } from "@noble/hashes/sha256";
import { pbkdf2Async } from "@noble/hashes/pbkdf2";
import { sha512 } from "@noble/hashes/sha512";
import { WORDLIST } from "./wordlist.js";

export const ENTROPY_BITS: Record<number, number> = {
  128: 12,
  160: 15,
  192: 18,
  224: 21,
  256: 24,
};

export class MnemonicError extends Error {}

function wordIndex(word: string): number {
  // The wordlist is small enough (2048) for a linear scan to be fast.
  const index = WORDLIST.indexOf(word);
  if (index === -1) throw new MnemonicError(`unknown mnemonic word: ${JSON.stringify(word)}`);
  return index;
}

export function entropyToMnemonic(entropy: Uint8Array): string {
  if (!ENTROPY_BITS[entropy.length * 8]) {
    throw new MnemonicError(
      `entropy must be ${Object.keys(ENTROPY_BITS).map(Number).join(", ")} bits`,
    );
  }
  const checksumBits = entropy.length / 4;
  const hash = sha256(entropy);
  const checksum = hash[0]! >> (8 - checksumBits);
  let bits = BigInt(0);
  for (const byte of entropy) bits = (bits << 8n) | BigInt(byte);
  bits = (bits << BigInt(checksumBits)) | BigInt(checksum);
  const totalBits = entropy.length * 8 + checksumBits;
  const words: string[] = [];
  for (let shift = totalBits - 11; shift >= 0; shift -= 11) {
    const index = Number((bits >> BigInt(shift)) & 0x7ffn);
    words.push(WORDLIST[index]!);
  }
  return words.join(" ");
}

export function mnemonicToSeed(mnemonic: string, passphrase = ""): Promise<Uint8Array> {
  const normalized = normalizeMnemonic(mnemonic);
  const salt = new TextEncoder().encode("mnemonic" + normalizeMnemonic(passphrase));
  return pbkdf2Async(sha512, normalized, salt, { c: 2048, dkLen: 64 });
}

export function validateMnemonic(mnemonic: string): void {
  const words = mnemonic.trim().split(/\s+/);
  if (!Object.values(ENTROPY_BITS).some((count: number) => count === words.length)) {
    throw new MnemonicError(`a mnemonic has ${[...new Set(Object.values(ENTROPY_BITS))].sort().join(", ")} words`);
  }
  let value = 0n;
  for (const word of words) {
    value = (value << 11n) | BigInt(wordIndex(word));
  }
  const strength = words.length * 32 / 3;
  const checksumBits = strength / 32;
  const entropy = value >> BigInt(checksumBits);
  const checksum = Number(value & ((1n << BigInt(checksumBits)) - 1n));
  const expected = sha256(bigIntToBytes(entropy, strength / 8))[0]! >> (8 - checksumBits);
  if (checksum !== expected) {
    throw new MnemonicError("the mnemonic's checksum does not match its words");
  }
}

export function generateMnemonic(strength: number = 128): string {
  if (!ENTROPY_BITS[strength]) {
    throw new Error(`entropy strength must be one of ${Object.keys(ENTROPY_BITS).join(", ")}`);
  }
  return entropyToMnemonic(crypto.getRandomValues(new Uint8Array(strength / 8)));
}

function normalizeMnemonic(text: string): Uint8Array {
  return new TextEncoder().encode(text.normalize("NFKD").trim().replace(/\s+/g, " "));
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}