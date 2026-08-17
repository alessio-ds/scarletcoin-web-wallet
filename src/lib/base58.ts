/**
 * Base58 and Base58Check, matching ``scarletcoin.crypto.base58``: the classic
 * Bitcoin alphabet, double SHA-256 checksum, one-byte version prefix.
 */
import { hash256 } from "./hashing.js";

export const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const INDEX = new Map<string, number>();
for (let i = 0; i < ALPHABET.length; i++) INDEX.set(ALPHABET[i]!, i);

const CHECKSUM_LENGTH = 4;

/** bigint -> big-endian bytes, as ``int.to_bytes(n, "big")``. */
function fromBigIntBE(value: bigint): Uint8Array {
  if (value === 0n) return new Uint8Array([0]);
  const hex = value.toString(16);
  const length = hex.length % 2 ? hex.length + 1 : hex.length;
  const padded = hex.padStart(length, "0");
  const bytes = new Uint8Array(length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export class Base58Error extends Error {}

export function b58encode(data: Uint8Array): string {
  let leadingZeros = 0;
  while (leadingZeros < data.length && data[leadingZeros] === 0) leadingZeros++;

  // Big-endian number, as in the Python ``int.from_bytes(data, "big")``.
  let number = 0n;
  for (let i = 0; i < data.length; i++) {
    number = (number << 8n) | BigInt(data[i]!);
  }

  const digits: string[] = [];
  while (number > 0n) {
    const remainder = number % 58n;
    number /= 58n;
    digits.push(ALPHABET[Number(remainder)]!);
  }
  return "1".repeat(leadingZeros) + digits.reverse().join("");
}

export function b58decode(text: string): Uint8Array {
  if (!text) return new Uint8Array(0);
  let number = 0n;
  for (const char of text) {
    const value = INDEX.get(char);
    if (value === undefined) throw new Base58Error(`invalid Base58 character ${char}`);
    number = number * 58n + BigInt(value);
  }
  let leadingZeros = 0;
  while (leadingZeros < text.length && text[leadingZeros] === "1") leadingZeros++;
  const body = fromBigIntBE(number);
  const result = new Uint8Array(leadingZeros + body.length);
  result.set(body, leadingZeros);
  return result;
}

export function b58checkEncode(version: number, payload: Uint8Array): string {
  if (version < 0 || version > 0xff) throw new Base58Error("version byte out of range");
  const body = new Uint8Array(1 + payload.length);
  body[0] = version;
  body.set(payload, 1);
  const checksum = hash256(body).slice(0, CHECKSUM_LENGTH);
  const full = new Uint8Array(body.length + CHECKSUM_LENGTH);
  full.set(body, 0);
  full.set(checksum, body.length);
  return b58encode(full);
}

export function b58checkDecode(
  text: string,
  expectedVersion?: number,
): { version: number; payload: Uint8Array } {
  const raw = b58decode(text);
  if (raw.length < 1 + CHECKSUM_LENGTH) throw new Base58Error("Base58Check string is too short");
  const body = raw.slice(0, raw.length - CHECKSUM_LENGTH);
  const checksum = raw.slice(raw.length - CHECKSUM_LENGTH);
  if (!bytesEqual(hash256(body).slice(0, CHECKSUM_LENGTH), checksum)) {
    throw new Base58Error("bad checksum: the string was mistyped or corrupted");
  }
  const version = body[0]!;
  if (expectedVersion !== undefined && version !== expectedVersion) {
    throw new Base58Error(
      `unexpected version byte 0x${version.toString(16)}, wanted 0x${expectedVersion.toString(16)}`,
    );
  }
  return { version, payload: body.slice(1) };
}