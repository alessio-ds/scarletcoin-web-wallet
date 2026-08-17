/**
 * The wallet's key store, matching ``scarletcoin.wallet.keystore``: a JSON
 * document, optionally sealed with AES-256-GCM behind scrypt.  Both the version
 * 1 format (a list of WIF keys) and the version 2 format (a BIP-0032 seed plus
 * imported keys) are supported; version 2 wallets keep their seed so they can be
 * exported back to the desktop wallet unchanged.  Addresses stay in the clear
 * even when the wallet is encrypted.
 */
import {
  addressFromPrivateKey,
  derivePublicKey,
  generatePrivateKey,
  InvalidKeyError,
  privateKeyFromWif,
  privateKeyToWif,
} from "./keys.js";
import { hash160 } from "./hashing.js";
import { getParams } from "./params.js";
import { toHex, fromHex } from "./util.js";
import { deriveFromSeed } from "./bip32.js";
import {
  DecryptionError,
  type Envelope,
  decodeUtf8,
  encodeUtf8,
  encryptBlob,
  decryptBlob,
  walletAssociatedData,
} from "./encryption.js";

export const WALLET_VERSION_1 = 1;
export const WALLET_VERSION_2 = 2;

export class WalletError extends Error {}
export class WalletLocked extends WalletError {}

export interface KeyRecord {
  secret: Uint8Array;
  label: string;
  created: number;
}

export interface AddressRecord {
  address: string;
  label: string;
  created: number;
  path?: string;
}

export interface WalletDocument {
  version: number;
  network: string;
  encrypted: boolean;
  next_index?: number;
  addresses: { address: string; label: string; created: number; path?: string }[];
  keys?: { wif: string; label: string; created: number }[];
  seed?: string;
  imported?: { wif: string; label: string; created: number }[];
  crypto?: Envelope;
}

function derivationPath(coinType: number, index: number): string {
  return `m/44'/${coinType}'/0'/0/${index}`;
}

export class Keystore {
  private seed: Uint8Array | null = null;
  private nextIndex = 0;
  private importedKeys: KeyRecord[] = [];
  private addressRecords: AddressRecord[] = [];
  private envelope: Envelope | null = null;
  private password: string | null = null;
  private walletVersion: number = WALLET_VERSION_1;

  constructor(public readonly network: string) {}

  get params() {
    return getParams(this.network);
  }

  get version(): number {
    return this.walletVersion;
  }

  get encrypted(): boolean {
    return this.envelope !== null || this.password !== null;
  }

  get locked(): boolean {
    return this.encrypted && this.password === null;
  }

  /** Every private key: the seed-derived ones plus the imported ones. */
  private get keyRecords(): KeyRecord[] {
    const derived = this.addressRecords
      .filter((record) => record.path !== undefined)
      .map((record) => ({
        secret: deriveFromSeed(this.seed!, record.path!),
        label: record.label,
        created: record.created,
      }));
    return [...derived, ...this.importedKeys];
  }

  static async create(network: string, password?: string): Promise<Keystore> {
    const keystore = new Keystore(network);
    if (password) keystore.password = password;
    keystore.newKey("default");
    return keystore;
  }

  static async fromSeed(seed: Uint8Array, network: string, password?: string): Promise<Keystore> {
    const keystore = new Keystore(network);
    keystore.walletVersion = WALLET_VERSION_2;
    keystore.seed = seed;
    if (password) keystore.password = password;
    keystore.newKey("default");
    return keystore;
  }

  static async fromSecret(secret: Uint8Array, network: string, password?: string): Promise<Keystore> {
    const keystore = new Keystore(network);
    if (password) keystore.password = password;
    keystore.importedKeys.push({ secret, label: "imported", created: Math.floor(Date.now() / 1000) });
    keystore.addressRecords.push({
      address: addressFromPrivateKey(secret, keystore.params.addressVersion),
      label: "imported",
      created: Math.floor(Date.now() / 1000),
    });
    return keystore;
  }

  static async fromDocument(document: WalletDocument, password?: string): Promise<Keystore> {
    if (document.version !== WALLET_VERSION_1 && document.version !== WALLET_VERSION_2) {
      throw new WalletError(`this is not a version 1 or 2 ScarletCoin wallet`);
    }
    const keystore = new Keystore(document.network);
    keystore.walletVersion = document.version;
    keystore.nextIndex = Number(document.next_index ?? 0);
    keystore.addressRecords = (document.addresses ?? []).map((item) => ({
      address: String(item.address),
      label: String(item.label ?? ""),
      created: Number(item.created ?? 0),
      path: item.path !== undefined ? String(item.path) : undefined,
    }));
    if (document.encrypted) {
      if (!document.crypto || typeof document.crypto !== "object") {
        throw new WalletError("wallet is marked encrypted but has no encrypted data");
      }
      keystore.envelope = document.crypto;
      if (password !== undefined) await keystore.unlock(password);
    } else {
      if (document.version === WALLET_VERSION_2) {
        keystore.seed = keystore.decodeSeed(document.seed);
        keystore.importedKeys = keystore.decodeKeys(document.imported ?? []);
      } else {
        keystore.importedKeys = keystore.decodeKeys(document.keys ?? []);
      }
    }
    return keystore;
  }

  // ---------------------------------------------------------------- locking

  async unlock(password: string): Promise<void> {
    if (this.envelope === null) return;
    let plaintext: Uint8Array;
    try {
      plaintext = await decryptBlob(
        password,
        this.envelope,
        walletAssociatedData(this.network, this.walletVersion),
      );
    } catch (error) {
      if (error instanceof DecryptionError) throw new WalletError(error.message);
      throw error;
    }
    let payload: unknown;
    try {
      payload = JSON.parse(decodeUtf8(plaintext));
    } catch {
      throw new WalletError("the wallet's encrypted data is corrupt");
    }
    if (Array.isArray(payload)) {
      // Version 1: a flat list of WIF records.
      this.seed = null;
      this.importedKeys = this.decodeKeys(payload);
    } else if (payload && typeof payload === "object") {
      // Version 2: { seed, imported }.
      const entry = payload as { seed?: unknown; imported?: unknown };
      this.seed = this.decodeSeed(entry.seed);
      this.importedKeys = this.decodeKeys(entry.imported ?? []);
    } else {
      throw new WalletError("the wallet's key list is malformed");
    }
    this.password = password;
  }

  lock(): void {
    if (this.encrypted) {
      this.importedKeys = [];
      this.password = null;
    }
  }

  async setPassword(password: string | null): Promise<void> {
    this.requireKeys();
    this.password = password;
    if (password === null) this.envelope = null;
  }

  // ---------------------------------------------------------------- storage

  async toDocument(): Promise<WalletDocument> {
    this.requireKeys();
    const addresses = this.addressRecords.map((record) => ({
      address: record.address,
      label: record.label,
      created: record.created,
      ...(record.path !== undefined ? { path: record.path } : {}),
    }));
    const imported = this.importedKeys.map((record) => ({
      wif: privateKeyToWif(record.secret, this.params.wifVersion),
      label: record.label,
      created: record.created,
    }));
    const document: WalletDocument = {
      version: this.version,
      network: this.network,
      encrypted: this.password !== null,
      next_index: this.seed !== null ? this.nextIndex : undefined,
      addresses,
    };
    if (this.seed !== null) {
      const payload = { seed: toHex(this.seed), imported };
      if (this.password !== null) {
        document.crypto = await encryptBlob(
          this.password,
          encodeUtf8(JSON.stringify(payload)),
          walletAssociatedData(this.network, WALLET_VERSION_2),
        );
        this.envelope = document.crypto;
      } else {
        document.seed = toHex(this.seed);
        document.imported = imported;
      }
    } else if (this.password !== null) {
      document.crypto = await encryptBlob(
        this.password,
        encodeUtf8(JSON.stringify(imported)),
        walletAssociatedData(this.network, WALLET_VERSION_1),
      );
      this.envelope = document.crypto;
    } else {
      document.keys = imported;
    }
    return document;
  }

  // ---------------------------------------------------------------- keys

  private requireKeys(): void {
    if (this.locked) throw new WalletLocked("this wallet is encrypted; a password is required");
  }

  private decodeSeed(seed: unknown): Uint8Array {
    if (seed === undefined || seed === null) {
      throw new WalletError("the wallet's seed is missing");
    }
    const bytes = fromHex(String(seed));
    if (bytes.length !== 64) {
      throw new WalletError(`the wallet's seed must be 64 bytes, got ${bytes.length}`);
    }
    return bytes;
  }

  private decodeKeys(payload: unknown): KeyRecord[] {
    if (!Array.isArray(payload)) throw new WalletError("the wallet's key list is malformed");
    const records: KeyRecord[] = [];
    for (const item of payload) {
      if (!item || typeof item !== "object") {
        throw new WalletError("the wallet contains an unusable key");
      }
      const entry = item as { wif?: unknown; label?: unknown; created?: unknown };
      try {
        const secret = privateKeyFromWif(String(entry.wif), this.params.wifVersion);
        records.push({
          secret,
          label: String(entry.label ?? ""),
          created: Number(entry.created ?? 0),
        });
      } catch (error) {
        if (error instanceof InvalidKeyError) {
          throw new WalletError(`the wallet contains an unusable key: ${error.message}`);
        }
        throw error;
      }
    }
    return records;
  }

  newKey(label = ""): string {
    this.requireKeys();
    const created = Math.floor(Date.now() / 1000);
    if (this.seed !== null) {
      const path = derivationPath(this.params.bip44CoinType, this.nextIndex);
      const secret = deriveFromSeed(this.seed, path);
      this.nextIndex += 1;
      this.addressRecords.push({
        address: addressFromPrivateKey(secret, this.params.addressVersion),
        label,
        created,
        path,
      });
      return addressFromPrivateKey(secret, this.params.addressVersion);
    }
    const secret = generatePrivateKey();
    this.importedKeys.push({ secret, label, created });
    this.addressRecords.push({
      address: addressFromPrivateKey(secret, this.params.addressVersion),
      label,
      created,
    });
    return addressFromPrivateKey(secret, this.params.addressVersion);
  }

  importWif(wif: string, label = "imported"): string {
    this.requireKeys();
    let secret: Uint8Array;
    try {
      secret = privateKeyFromWif(wif, this.params.wifVersion);
    } catch (error) {
      if (error instanceof InvalidKeyError) throw new WalletError(error.message);
      throw error;
    }
    if (this.keyRecords.some((record) => toHex(record.secret) === toHex(secret))) {
      throw new WalletError("that key is already in this wallet");
    }
    const created = Math.floor(Date.now() / 1000);
    this.importedKeys.push({ secret, label, created });
    this.addressRecords.push({
      address: addressFromPrivateKey(secret, this.params.addressVersion),
      label,
      created,
    });
    return addressFromPrivateKey(secret, this.params.addressVersion);
  }

  exportWif(address: string): string {
    this.requireKeys();
    for (const record of this.keyRecords) {
      if (addressFromPrivateKey(record.secret, this.params.addressVersion) === address) {
        return privateKeyToWif(record.secret, this.params.wifVersion);
      }
    }
    throw new WalletError(`${address} is not in this wallet`);
  }

  keysByHash(): Map<string, Uint8Array> {
    this.requireKeys();
    const map = new Map<string, Uint8Array>();
    for (const record of this.keyRecords) {
      map.set(toHex(hash160(derivePublicKey(record.secret))), record.secret);
    }
    return map;
  }

  addresses(): AddressRecord[] {
    return this.addressRecords.map((record) => ({ ...record }));
  }

  addressStrings(): string[] {
    return this.addressRecords.map((record) => record.address);
  }

  defaultAddress(): string {
    const addresses = this.addressStrings();
    if (addresses.length === 0) throw new WalletError("this wallet has no addresses");
    return addresses[0]!;
  }
}
