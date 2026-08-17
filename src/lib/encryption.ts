/**
 * Password-based encryption for wallet keys, matching
 * ``scarletcoin.crypto.encryption``: AES-256-GCM with a scrypt-derived key.
 */
import { scrypt } from "scrypt-js";
import { fromHex, toHex } from "./util.js";

const KDF = "scrypt";
const CIPHER = "aes-256-gcm";
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const NONCE_LENGTH = 12;
const SCRYPT_N = 2 ** 16;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

export interface Envelope {
  kdf: string;
  kdf_params: { n: number; r: number; p: number; salt: string };
  cipher: string;
  nonce: string;
  ciphertext: string;
}

export class DecryptionError extends Error {}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

async function deriveKey(password: string, salt: Uint8Array, n: number, r: number, p: number): Promise<Uint8Array> {
  return scrypt(textEncoder.encode(password), salt, n, r, p, KEY_LENGTH);
}

async function aesGcmKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", keyBytes.buffer as ArrayBuffer, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptBlob(
  password: string,
  plaintext: Uint8Array,
  associatedData: Uint8Array,
): Promise<Envelope> {
  if (!password) throw new Error("password must not be empty");
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const key = await deriveKey(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce.buffer as ArrayBuffer, additionalData: associatedData.buffer as ArrayBuffer },
      await aesGcmKey(key),
      plaintext.buffer as ArrayBuffer,
    ),
  );
  return {
    kdf: KDF,
    kdf_params: { n: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, salt: toHex(salt) },
    cipher: CIPHER,
    nonce: toHex(nonce),
    ciphertext: toHex(ciphertext),
  };
}

export async function decryptBlob(
  password: string,
  envelope: Envelope,
  associatedData: Uint8Array,
): Promise<Uint8Array> {
  if (envelope.kdf !== KDF || envelope.cipher !== CIPHER) {
    throw new DecryptionError("unsupported wallet encryption parameters");
  }
  const params = envelope.kdf_params;
  const salt = fromHex(params.salt);
  const nonce = fromHex(envelope.nonce);
  const ciphertext = fromHex(envelope.ciphertext);
  const { n, r, p } = params;
  if (n <= 1 || (n & (n - 1)) !== 0 || r < 1 || p < 1 || n * r * 128 * p > 256 * 1024 * 1024) {
    throw new DecryptionError("refusing unreasonable scrypt parameters");
  }
  const key = await deriveKey(password, salt, n, r, p);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce.buffer as ArrayBuffer, additionalData: associatedData.buffer as ArrayBuffer },
      await aesGcmKey(key),
      ciphertext.buffer as ArrayBuffer,
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new DecryptionError("wrong password, or the wallet data was modified");
  }
}

export function walletAssociatedData(network: string): Uint8Array {
  return textEncoder.encode(`scarletcoin-wallet-v1:${network}`);
}

export function decodeUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

export function encodeUtf8(text: string): Uint8Array {
  return textEncoder.encode(text);
}