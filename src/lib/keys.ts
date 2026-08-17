/**
 * secp256k1 keys, addresses and ECDSA signatures, matching
 * ``scarletcoin.crypto.keys``: compressed public keys, Base58Check addresses and
 * WIF, canonical low-s signatures.
 */
import * as secp256k1 from "@noble/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";
import { b58checkDecode, b58checkEncode, Base58Error } from "./base58.js";
import { hash160, PUBKEY_HASH_LENGTH } from "./hashing.js";

// @noble/secp256k1 needs an HMAC-SHA256 hook for deterministic (RFC6979)
// signing; wire it to @noble/hashes once, at import time.
secp256k1.etc.hmacSha256Sync = (key: Uint8Array, ...msgs: Uint8Array[]) =>
  hmac(sha256, key, concatBytes(...msgs));

export const PRIVATE_KEY_LENGTH = 32;
export const PUBLIC_KEY_LENGTH = 33;
export const SIGNATURE_LENGTH = 64;

export class InvalidKeyError extends Error {}

export interface DecodedAddress {
  version: number;
  hash: Uint8Array;
}

export function generatePrivateKey(): Uint8Array {
  return secp256k1.utils.randomPrivateKey();
}

export function privateKeyFromBytes(secret: Uint8Array): Uint8Array {
  if (secret.length !== PRIVATE_KEY_LENGTH) {
    throw new InvalidKeyError(
      `private key must be ${PRIVATE_KEY_LENGTH} bytes, got ${secret.length}`,
    );
  }
  if (!secp256k1.utils.isValidPrivateKey(secret)) {
    throw new InvalidKeyError("private key is out of the valid secp256k1 range");
  }
  return new Uint8Array(secret);
}

export function derivePublicKey(secret: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(secret, true);
}

export function addressFromPublicKey(pubkey: Uint8Array, version: number): string {
  return b58checkEncode(version, hash160(pubkey));
}

export function addressFromPrivateKey(secret: Uint8Array, version: number): string {
  return addressFromPublicKey(derivePublicKey(secret), version);
}

export function privateKeyToWif(secret: Uint8Array, wifVersion: number): string {
  const payload = new Uint8Array(PRIVATE_KEY_LENGTH + 1);
  payload.set(secret, 0);
  payload[PRIVATE_KEY_LENGTH] = 0x01;
  return b58checkEncode(wifVersion, payload);
}

export function privateKeyFromWif(wif: string, expectedVersion?: number): Uint8Array {
  let version: number;
  let payload: Uint8Array;
  try {
    ({ version, payload } = b58checkDecode(wif, expectedVersion));
  } catch (error) {
    if (error instanceof Base58Error) {
      throw new InvalidKeyError(`invalid private key: ${error.message}`);
    }
    throw error;
  }
  void version;
  // A trailing 0x01 marks "the public key is compressed", as in Bitcoin WIF.
  if (payload.length === PRIVATE_KEY_LENGTH + 1 && payload[payload.length - 1] === 0x01) {
    payload = payload.slice(0, PRIVATE_KEY_LENGTH);
  }
  if (payload.length !== PRIVATE_KEY_LENGTH) {
    throw new InvalidKeyError("invalid private key: wrong payload length");
  }
  return privateKeyFromBytes(payload);
}

export function sign(digest: Uint8Array, secret: Uint8Array): Uint8Array {
  if (digest.length !== 32) {
    throw new InvalidKeyError(`expected a 32-byte digest, got ${digest.length} bytes`);
  }
  const signature = secp256k1.sign(digest, secret, { lowS: true, extraEntropy: false });
  return signature.toBytes();
}

export function verifySignature(
  digest: Uint8Array,
  signature: Uint8Array,
  pubkey: Uint8Array,
): boolean {
  return secp256k1.verify(signature, digest, pubkey, { lowS: true });
}

export function decodeAddress(text: string, expectedVersion?: number): DecodedAddress {
  let version: number;
  let payload: Uint8Array;
  try {
    ({ version, payload } = b58checkDecode(text.trim(), expectedVersion));
  } catch (error) {
    if (error instanceof Base58Error) {
      throw new InvalidKeyError(`invalid address ${JSON.stringify(text)}: ${error.message}`);
    }
    throw error;
  }
  if (payload.length !== PUBKEY_HASH_LENGTH) {
    throw new InvalidKeyError(`invalid address ${JSON.stringify(text)}: wrong payload length`);
  }
  return { version, hash: payload };
}

export function isValidAddress(text: string, expectedVersion?: number): boolean {
  try {
    decodeAddress(text, expectedVersion);
  } catch {
    return false;
  }
  return true;
}