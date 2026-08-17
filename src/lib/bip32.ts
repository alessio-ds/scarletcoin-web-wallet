/**
 * BIP-0032 hierarchical deterministic derivation, matching
 * ``scarletcoin.crypto.bip32``: hardened and non-hardened private-key
 * derivation (CKDpriv), which is all a wallet that holds the seed needs.
 */
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { concatBytes } from "@noble/hashes/utils";
import * as secp256k1 from "@noble/secp256k1";

const N = secp256k1.CURVE.n;
const HARDENED = 0x80000000;
const SEED_KEY = new TextEncoder().encode("Bitcoin seed");

function bigIntFromBytes(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) result = (result << 8n) | BigInt(byte);
  return result;
}

function bigIntToBytes(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function ser32(index: number): Uint8Array {
  const out = new Uint8Array(4);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, index, false); // big-endian, as BIP-0032 requires
  return out;
}

function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha512, key, data);
}

export interface ExtendedPrivateKey {
  secret: Uint8Array;
  chainCode: Uint8Array;
}

export function masterFromSeed(seed: Uint8Array): ExtendedPrivateKey {
  const I = hmacSha512(SEED_KEY, seed);
  return { secret: I.slice(0, 32), chainCode: I.slice(32) };
}

export function deriveChild(
  key: ExtendedPrivateKey,
  index: number,
): ExtendedPrivateKey {
  const hardened = index >= HARDENED;
  const data = hardened
    ? concatBytes(new Uint8Array([0x00]), key.secret, ser32(index))
    : concatBytes(secp256k1.getPublicKey(key.secret, true), ser32(index));
  const I = hmacSha512(key.chainCode, data);
  const il = bigIntFromBytes(I.slice(0, 32));
  const child = (il + bigIntFromBytes(key.secret)) % N;
  if (il >= N || child === 0n) {
    throw new Error("derived key out of range; increment the index");
  }
  return { secret: bigIntToBytes(child), chainCode: I.slice(32) };
}

export function parsePath(path: string): number[] {
  const parts = path.split("/");
  if (parts[0] !== "m" && parts[0] !== "M") {
    throw new Error(`path must start with "m" or "M", got ${JSON.stringify(path)}`);
  }
  return parts.slice(1).map((part) => {
    const hardened = part.endsWith("'") || part.endsWith("h") || part.endsWith("H");
    const digits = hardened ? part.slice(0, -1) : part;
    const value = Number.parseInt(digits, 10);
    if (!Number.isInteger(value) || value < 0 || digits === "") {
      throw new Error(`bad derivation path component ${JSON.stringify(part)}`);
    }
    return hardened ? value + HARDENED : value;
  });
}

export function deriveFromSeed(seed: Uint8Array, path: string): Uint8Array {
  let key = masterFromSeed(seed);
  for (const index of parsePath(path)) {
    key = deriveChild(key, index);
  }
  return key.secret;
}
