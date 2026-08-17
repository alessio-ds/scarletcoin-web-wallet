/**
 * The wallet's key store, matching ``scarletcoin.wallet.keystore``: a JSON
 * document of private keys, optionally sealed with AES-256-GCM behind scrypt.
 * Addresses stay in the clear even when the wallet is encrypted.
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
import { toHex } from "./util.js";
import {
  DecryptionError,
  type Envelope,
  decodeUtf8,
  encodeUtf8,
  encryptBlob,
  decryptBlob,
  walletAssociatedData,
} from "./encryption.js";

export const WALLET_VERSION = 1;

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
}

export interface WalletDocument {
  version: number;
  network: string;
  encrypted: boolean;
  addresses: { address: string; label: string; created: number }[];
  keys?: { wif: string; label: string; created: number }[];
  crypto?: Envelope;
}

export class Keystore {
  private keyRecords: KeyRecord[] = [];
  private addressRecords: AddressRecord[] = [];
  private envelope: Envelope | null = null;
  private password: string | null = null;

  constructor(public readonly network: string) {}

  get params() {
    return getParams(this.network);
  }

  get encrypted(): boolean {
    return this.envelope !== null || this.password !== null;
  }

  get locked(): boolean {
    return this.encrypted && this.password === null;
  }

  static async create(network: string, password?: string): Promise<Keystore> {
    const keystore = new Keystore(network);
    if (password) keystore.password = password;
    keystore.newKey("default");
    return keystore;
  }

  static async fromDocument(document: WalletDocument, password?: string): Promise<Keystore> {
    if (document.version !== WALLET_VERSION) {
      throw new WalletError(`this is not a version ${WALLET_VERSION} ScarletCoin wallet`);
    }
    const keystore = new Keystore(document.network);
    keystore.addressRecords = (document.addresses ?? []).map((item) => ({
      address: String(item.address),
      label: String(item.label ?? ""),
      created: Number(item.created ?? 0),
    }));
    if (document.encrypted) {
      if (!document.crypto || typeof document.crypto !== "object") {
        throw new WalletError("wallet is marked encrypted but has no encrypted data");
      }
      keystore.envelope = document.crypto;
      if (password !== undefined) await keystore.unlock(password);
    } else {
      keystore.keyRecords = keystore.decodeKeys(document.keys ?? []);
    }
    return keystore;
  }

  // ---------------------------------------------------------------- locking

  async unlock(password: string): Promise<void> {
    if (this.envelope === null) return;
    let plaintext: Uint8Array;
    try {
      plaintext = await decryptBlob(password, this.envelope, walletAssociatedData(this.network));
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
    if (!Array.isArray(payload)) throw new WalletError("the wallet's key list is malformed");
    this.keyRecords = this.decodeKeys(payload);
    this.password = password;
  }

  lock(): void {
    if (this.encrypted) {
      this.keyRecords = [];
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
    const addresses = this.keyRecords.map((record) => ({
      address: addressFromPrivateKey(record.secret, this.params.addressVersion),
      label: record.label,
      created: record.created,
    }));
    const payload = this.keyRecords.map((record) => ({
      wif: privateKeyToWif(record.secret, this.params.wifVersion),
      label: record.label,
      created: record.created,
    }));
    const document: WalletDocument = {
      version: WALLET_VERSION,
      network: this.network,
      encrypted: this.password !== null,
      addresses,
    };
    if (this.password !== null) {
      document.crypto = await encryptBlob(
        this.password,
        encodeUtf8(JSON.stringify(payload)),
        walletAssociatedData(this.network),
      );
      this.envelope = document.crypto;
    } else {
      document.keys = payload;
    }
    this.addressRecords = addresses;
    return document;
  }

  // ---------------------------------------------------------------- keys

  private requireKeys(): void {
    if (this.locked) throw new WalletLocked("this wallet is encrypted; a password is required");
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
    const secret = generatePrivateKey();
    this.keyRecords.push({ secret, label, created: Math.floor(Date.now() / 1000) });
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
    this.keyRecords.push({ secret, label, created: Math.floor(Date.now() / 1000) });
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
    if (this.locked) return [...this.addressRecords];
    return this.keyRecords.map((record) => ({
      address: addressFromPrivateKey(record.secret, this.params.addressVersion),
      label: record.label,
      created: record.created,
    }));
  }

  addressStrings(): string[] {
    return this.addresses().map((record) => record.address);
  }

  defaultAddress(): string {
    const addresses = this.addressStrings();
    if (addresses.length === 0) throw new WalletError("this wallet has no addresses");
    return addresses[0]!;
  }
}