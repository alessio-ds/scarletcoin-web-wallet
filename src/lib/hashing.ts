/**
 * Hash helpers, matching ``scarletcoin.crypto.hashing``: SHA-256 only.
 */
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";

export const PUBKEY_HASH_LENGTH = 20;

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

export function hash256(data: Uint8Array): Uint8Array {
  return nobleSha256(nobleSha256(data));
}

export function hash160(data: Uint8Array): Uint8Array {
  return hash256(data).slice(0, PUBKEY_HASH_LENGTH);
}